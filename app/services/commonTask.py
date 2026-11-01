import hashlib
import ipaddress
import os
import time
from urllib.parse import parse_qsl, unquote, urljoin, urlparse
from bson import ObjectId
from pymongo import UpdateOne
from app import utils
from app import services
from app.config import Config
from app.modules import CollectSource, SiteAutoTag, WebSiteFetchStatus, WebSiteFetchOption
from app.services.nuclei_scan import nuclei_scan
from app.services import run_risk_cruising, BaseUpdateTask
from app.services.storage import save_site_documents, save_url_page_map
from app.services.edgeAsset import (
    classify_edge_host,
    classify_edge_infrastructure,
)
from app.services.assetPolicy import (
    has_strong_edge_marker,
    http_access_profile,
    merge_directory_scan_profiles,
    merge_directory_scan_route_keys,
)
from app.services.entryAsset import EntryAssetTracker
from app.services.katanaSpider import normalize_entry_candidate
from app.services.pathDiscovery import redirect_destination_metadata
from app.services.siteQuality import refresh_site_quality_clusters
from app.services.taskStage import split_stage_summary
from app.helpers.task import is_nuclei_scan_enabled
from app.utils.site_quality import (
    SITE_QUALITY_VERSION,
    preferred_site_title,
    site_needs_browser_title,
)
from app.utils.site_scope import formal_pipeline_query, formal_site_query, visible_site_query
logger = utils.get_logger()


RISKY_URL_KEYWORDS = {
    "cancel", "clear", "confirm", "del", "delete", "disable", "drop",
    "edit", "enable", "logout", "modify", "order", "pay", "refund",
    "remove", "reset", "restart", "save", "start", "stop", "submit",
    "truncate", "update",
}

WIH_SCRIPT_RESOURCE_EXTENSIONS = {
    ".js", ".mjs", ".map",
}

RUNTIME_ARTIFACT_SCRIPT_SEED_EXTENSIONS = {
    ".js", ".mjs",
}

RUNTIME_ARTIFACT_MAP_SEED_EXTENSIONS = {
    ".map",
}

DYNAMIC_BROWSER_SPA_MARKERS = (
    "angular", "next.js", "nextjs", "nuxt", "react", "umi.js", "umijs", "vue",
)

DYNAMIC_BROWSER_BUNDLER_MARKERS = (
    "webpack", "vite",
)

DYNAMIC_BROWSER_INTERACTIVE_MARKERS = (
    "admin", "api doc", "api documentation", "console", "knife4j", "login",
    "openapi", "portal", "redoc", "sign in", "sso", "swagger", "后台",
    "登录", "管理系统", "统一认证",
)

DYNAMIC_BROWSER_BUILD_MARKERS = (
    "/_next/static/", "/_nuxt/", "/assets/", "/static/js/", ".chunk.",
    "webpack", "vite", "/runtime.",
)

DYNAMIC_BROWSER_REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}


def is_risky_crawler_url(url):
    parsed = urlparse(url)
    path = unquote(parsed.path or "").lower()
    segments = [x for x in path.strip("/").split("/") if x]
    query_keys = [key.lower() for key, _ in parse_qsl(parsed.query or "", keep_blank_values=True)]
    values = segments + query_keys

    for value in values:
        for keyword in RISKY_URL_KEYWORDS:
            if len(keyword) <= 3 and value == keyword:
                return True, keyword
            if len(keyword) > 3 and keyword in value:
                return True, keyword
    return False, ""


def normalize_wih_content(record_type, content):
    content = str(content or "").strip()
    if record_type == "domain":
        if " (" in content:
            content = content.split(" (", 1)[0].strip()
        return content.strip(".").lower()

    if record_type in ("url", "all_url"):
        parsed = urlparse(content)
        if parsed.scheme in ("http", "https") and parsed.netloc:
            path = parsed.path or "/"
            normalized = "{}://{}{}".format(parsed.scheme, parsed.netloc.lower(), path)
            if parsed.query:
                normalized = "{}?{}".format(normalized, parsed.query)
            if parsed.fragment:
                normalized = "{}#{}".format(normalized, parsed.fragment)
            return normalized

    return content


def wih_content_hash(task_id, record_type, content):
    key = "{}|{}|{}".format(task_id, record_type, normalize_wih_content(record_type, content))
    return hashlib.md5(key.encode("utf-8")).hexdigest()


def wih_ip_target_allowed(host):
    try:
        ip = ipaddress.ip_address(str(host or "").strip("[]"))
    except ValueError:
        return True

    if ip.is_global:
        return True

    return bool(getattr(Config, "KATANA_FETCH_NON_GLOBAL_IP_URLS", False))


def runtime_artifact_script_seed_urls(crawl_result):
    """Return JS-like URLs already observed by Katana for runtime archiving."""
    seeds = []
    seen = set()
    for field, browser_hint in (
        ("crawler_urls", True),
        ("all_urls", False),
    ):
        for value in (crawl_result or {}).get(field, []) or []:
            value = str(value or "").strip()
            if not value:
                continue
            try:
                parsed = urlparse(value)
            except (TypeError, ValueError):
                continue
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                continue
            path = unquote(parsed.path or "").lower()
            extension = os.path.splitext(path)[1]
            script_like = extension in RUNTIME_ARTIFACT_SCRIPT_SEED_EXTENSIONS
            build_chunk_like = browser_hint and any(
                marker in path for marker in DYNAMIC_BROWSER_BUILD_MARKERS)
            if not script_like and not build_chunk_like:
                continue
            if value in seen:
                continue
            seen.add(value)
            seeds.append(value)
    return seeds


def runtime_artifact_map_seed_urls(crawl_result):
    """Return source-map URLs already observed by Katana for direct archiving."""
    seeds = []
    seen = set()
    for field in ("crawler_urls", "all_urls"):
        for value in (crawl_result or {}).get(field, []) or []:
            value = str(value or "").strip()
            if not value:
                continue
            try:
                parsed = urlparse(value)
            except (TypeError, ValueError):
                continue
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                continue
            path = unquote(parsed.path or "").lower()
            extension = os.path.splitext(path)[1]
            if extension not in RUNTIME_ARTIFACT_MAP_SEED_EXTENSIONS:
                continue
            if value in seen:
                continue
            seen.add(value)
            seeds.append(value)
    return seeds


# 任务类中一些相关公共类
class CommonTask(object):
    def __init__(self, task_id):
        self.task_id = task_id

    def insert_task_stat(self):
        query = {
            "_id": ObjectId(self.task_id)
        }

        stat = utils.arl.task_statistic(self.task_id)

        logger.info("insert task stat")

        update = {"$set": {"statistic": stat}}

        utils.conn_db('task').update_one(query, update)
        return stat

    def insert_finger_stat(self):
        finger_stat_map = utils.arl.gen_stat_finger_map(self.task_id)
        logger.info("insert finger stat {}".format(len(finger_stat_map)))

        utils.conn_db('stat_finger').delete_many({"task_id": self.task_id})
        for key in finger_stat_map:
            data = finger_stat_map[key].copy()
            data["task_id"] = self.task_id
            query = {"task_id": self.task_id, "name": data.get("name")}
            utils.conn_db('stat_finger').update_one(query, {"$set": data}, upsert=True)
        return len(finger_stat_map)

    def insert_cip_stat(self):
        cip_map = utils.arl.gen_cip_map(self.task_id)
        logger.info("insert cip stat {}".format(len(cip_map)))

        utils.conn_db('cip').delete_many({"task_id": self.task_id})
        for cidr_ip in cip_map:
            item = cip_map[cidr_ip]
            ip_list = list(item["ip_set"])
            domain_list = list(item["domain_set"])

            data = {
                "cidr_ip": cidr_ip,
                "ip_count": len(ip_list),
                "ip_list": ip_list,
                "domain_count": len(domain_list),
                "domain_list": domain_list,
                "task_id": self.task_id
            }

            query = {"task_id": self.task_id, "cidr_ip": cidr_ip}
            utils.conn_db('cip').update_one(query, {"$set": data}, upsert=True)
        return len(cip_map)

    # 资产同步
    def sync_asset(self):
        options = getattr(self, 'options', {})
        if not options:
            logger.warning("not found options {}".format(self.task_id))
            return

        related_scope_id = options.get("related_scope_id", "")
        if not related_scope_id:
            return

        if len(related_scope_id) != 24:
            logger.warning("related_scope_id len not eq 24 {}".format(self.task_id, related_scope_id))
            return

        return services.sync_asset(task_id=self.task_id, scope_id=related_scope_id)

    def common_run(self):
        finger_count = self.insert_finger_stat()
        cip_count = self.insert_cip_stat()
        statistic = self.insert_task_stat() or {}
        sync_result = self.sync_asset()
        return {
            "input_count": 1,
            "output_count": 1,
            "finger_count": finger_count,
            "cip_count": cip_count,
            "statistic": statistic,
            "asset_sync_enabled": bool(
                (getattr(self, "options", {}) or {}).get("related_scope_id")),
            "asset_sync_completed": sync_result is not False,
        }


# *** 对用户提交的站点或者是发现的站点进行后续处理
class WebSiteFetch(object):
    TRANSIENT_FETCH_STATUS_CODES = {
        408, 418, 425, 429, 500, 501, 502, 503, 504,
    }
    OBSERVER_TERMINAL_SKIP_STATUS_CODES = {400, 404, 405, 410}

    def __init__(self, task_id: str, sites: list, options: dict, scope_domain: list = None):
        self.task_id = task_id
        self.sites = sites  # ** 这个是用户提交的目标
        self.options = options
        self.base_update_task = BaseUpdateTask(self.task_id)
        self.site_info_list = []  # *** 这个是来自 services.fetch_site 的结果
        self.available_sites = []  # *** 这个是存活的站点
        self.wih_domain_set = set()  # 用于保存来自wih的域名，已添加的域名不再添加
        self.wih_record_set = set()  # 用于保存来自wih的记录，已添加的记录不再添加

        # 用于判断应该收集的子域名
        if not scope_domain:
            scope_domain = []

        self.scope_domain = scope_domain
        self.page_url_set = set()
        self.site_spider_domain_set = set()
        self.site_spider_domain_evidence_set = set()
        self.site_spider_domain_url_map = {}
        self.site_spider_all_url_set = set()
        self.site_spider_all_url_evidence_set = set()
        self.site_spider_wih_targets = []
        self.site_spider_wih_entry_target_count = 0
        self.site_spider_wih_resource_target_count = 0
        self.wih_entry_url_set = set()
        self.wih_entry_url_sources = {}
        self.file_leak_target_profiles = {}
        self.file_leak_target_route_keys = {}
        self.search_engines_result = dict()
        self._poc_sites = None  # 用于PoC 执行， 文件目录爆破 的目标
        self._task_domain_set = None  # 用于保存任务中的域名
        self._edge_site_cache = {}
        self.fetch_site_skipped_low_quality = 0
        self.fetch_site_skipped_duplicate = 0
        self.fetch_site_incremental_site_keys = set()
        self.fetch_site_meta = {}
        self.wih_target_selection_meta = {}
        self.runtime_artifact_targets = []
        self.runtime_artifact_full_targets = []
        self.runtime_artifact_seed_urls = set()
        self.runtime_artifact_seed_map_urls = set()
        self.runtime_artifact_target_reasons = {}
        self.entry_tracker = EntryAssetTracker(
            self.task_id, scope_domains=self.scope_domain)

    @property
    def task_domain_set(self):
        if self._task_domain_set is None:
            self._task_domain_set = set(utils.arl.get_domain_by_id(self.task_id))

        return self._task_domain_set

    def __str__(self):
        return "<WebSiteFetch> task_id:{}, sites: {}, available_sites:{}".format(
            self.task_id, len(self.sites), len(self.available_sites))

    def is_edge_site(self, site):
        site = str(site or "").strip()
        if not site:
            return True
        if site in self._edge_site_cache:
            return self._edge_site_cache[site]

        parsed = urlparse(site)
        host = (parsed.hostname or "").strip(".").lower()
        query = {
            "task_id": self.task_id,
            "$or": [{"site": site}, {"url": site}]
        }
        if host:
            query["$or"].extend([{"host": host}, {"ip": host}])

        fields = {
            "_id": 0, "cdn": 1, "cdn_name": 1, "is_cdn": 1, "waf": 1,
            "waf_name": 1, "is_waf": 1, "edge": 1, "edge_name": 1,
            "tag": 1, "title": 1, "status": 1, "status_code": 1,
            "webserver": 1, "cname": 1,
        }
        docs = []
        docs.extend(list(utils.conn_db("site").find(
            formal_site_query(query), fields).limit(2)))
        docs.extend(list(utils.conn_db("asset_seed_alive").find(
            formal_pipeline_query(query), fields).limit(2)))

        for item in docs:
            infrastructure = classify_edge_infrastructure(" ".join([
                str(item.get("webserver") or ""),
                " ".join(item.get("cname") or []) if isinstance(item.get("cname"), list)
                else str(item.get("cname") or ""),
                str(item.get("cdn_name") or ""),
                str(item.get("waf_name") or ""),
            ]))
            if has_strong_edge_marker(item) or infrastructure:
                self._edge_site_cache[site] = True
                return True

        title = ""
        status_code = None
        if docs:
            title = docs[0].get("title", "")
            status_code = docs[0].get("status") or docs[0].get("status_code")
        extra_text = ""
        if docs:
            cname = docs[0].get("cname") or ""
            if isinstance(cname, list):
                cname = " ".join([str(value) for value in cname])
            extra_text = " ".join([
                str(docs[0].get("webserver") or ""),
                str(cname),
            ])
        edge_info = classify_edge_host(
            site,
            self.scope_domain[0] if self.scope_domain else "",
            title=title,
            status_code=status_code,
            extra_text=extra_text,
        )
        self._edge_site_cache[site] = bool(edge_info.get("is_edge"))
        return self._edge_site_cache[site]

    def should_skip_web_discovery_site(self, site):
        """Keep shared edge IPs out while allowing owned hostnames behind CDN/WAF."""
        if not self.is_edge_site(site):
            return False

        origin = self.canonical_origin(site)
        parsed = urlparse(origin)
        host = (parsed.hostname or "").strip(".").lower()
        if not host:
            return True
        try:
            ipaddress.ip_address(host.strip("[]"))
            return True
        except ValueError:
            pass

        if not self.scope_domain or not domain_in_scope_domain(host, self.scope_domain):
            return True

        edge_info = classify_edge_host(
            origin,
            self.scope_domain[0] if self.scope_domain else "",
        )
        return bool(edge_info.get("is_edge"))

    def save_site_info(self):
        logger.info("save_site_info site:{}, {}".format(len(self.site_info_list), self.__str__()))
        save_site_documents(self.task_id, self.site_info_list)
        if self.options.get(WebSiteFetchOption.SITE_IDENTIFY):
            CommonTask(self.task_id).insert_finger_stat()

    def save_site_info_batch(self, site_info_list, progress):
        if not site_info_list:
            return

        save_site_documents(self.task_id, site_info_list)
        for item in site_info_list:
            site = str(item.get("site") or "").strip()
            if site:
                self.fetch_site_incremental_site_keys.add(site)

        common_task = CommonTask(self.task_id)
        if self.options.get(WebSiteFetchOption.SITE_IDENTIFY):
            common_task.insert_finger_stat()
        common_task.insert_task_stat()
        self.base_update_task.update_stage_progress(
            WebSiteFetchStatus.FETCH_SITE,
            {
                "input_count": progress.get("input_count", len(self.sites)),
                "output_count": progress.get("output_count", len(self.fetch_site_incremental_site_keys)),
                "reused_site_count": progress.get("reused_site_count", 0),
                "reused_probe_count": progress.get("reused_probe_count", 0),
                "probed_target_count": progress.get("probed_target_count", 0),
                "batch_index": progress.get("batch_index", 0),
                "total_batches": progress.get("total_batches", 0),
            },
        )

    def upsert_wih_item(self, item):
        record_type = item.get("record_type")
        content = normalize_wih_content(record_type, item.get("content"))
        if not record_type or not content:
            return False

        item["content"] = content
        item["fnv_hash"] = wih_content_hash(self.task_id, record_type, content)
        item.setdefault("save_date", utils.curr_date())
        if not item.get("site"):
            item.pop("site", None)
        if not item.get("discovered_from"):
            item.pop("discovered_from", None)
        source = item.get("source", "")
        collector = str(item.get("collector") or "").strip()
        evidence_sources = []
        for value in (
            item.get("discovered_from"),
            item.get("evidence_source"),
            item.get("site") if str(item.get("site") or "").startswith(("http://", "https://")) else "",
            source if str(source).startswith(("http://", "https://")) else "",
        ):
            value = str(value or "").strip()
            if value and value not in evidence_sources:
                evidence_sources.append(value)
        item.pop("evidence_source", None)
        discovered_url = str(item.get("discovered_url") or "").strip()
        query = {
            "task_id": self.task_id,
            "fnv_hash": item["fnv_hash"],
        }
        update = {
            "$set": item,
            "$setOnInsert": {"first_save_date": item.get("save_date")},
        }
        if source:
            update["$addToSet"] = {"sources": source}
        if collector:
            update.setdefault("$addToSet", {})["collectors"] = collector
        if evidence_sources:
            update.setdefault("$addToSet", {})["evidence_sources"] = {"$each": evidence_sources}
        if discovered_url:
            update.setdefault("$addToSet", {})["discovered_urls"] = discovered_url

        utils.conn_db("wih").update_one(query, update, upsert=True)
        return True

    def save_site_spider_domain_evidence(self, domain, source_url="", discovered_url=""):
        domain = str(domain or "").strip(".").lower()
        if not domain:
            return False

        source_url = str(source_url or "").strip()
        discovered_url = str(discovered_url or "").strip()
        self.entry_tracker.register_domain(
            domain,
            source_url=source_url,
            discovered_url=discovered_url,
            collector="katana",
        )
        evidence_key = (domain, source_url, discovered_url)
        if evidence_key in self.site_spider_domain_evidence_set:
            return False
        item = {
            "task_id": self.task_id,
            "record_type": "domain",
            "content": domain,
            "site": source_url,
            "source": "katana_js",
            "fnv_hash": wih_content_hash(self.task_id, "domain", domain),
            "evidence_type": "crawler_discovered_domain",
            "discovered_from": source_url,
            "discovered_url": discovered_url,
            "evidence_source": source_url,
            "collector": "katana",
            "save_date": utils.curr_date(),
        }
        self.upsert_wih_item(item)
        self.site_spider_domain_evidence_set.add(evidence_key)
        self.site_spider_domain_set.add(domain)
        return True

    def save_site_spider_entry_candidate(self, url, source_url="", status="pending"):
        return self.entry_tracker.register_url(
            url,
            source_urls=[source_url],
            collector="katana",
            status=status,
        )

    def save_site_spider_all_url_evidence(
        self,
        absolute_url,
        source_url="",
        discovery_kind="",
    ):
        absolute_url = normalize_wih_content("all_url", absolute_url)
        if not absolute_url:
            return False

        parsed = urlparse(absolute_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return False

        source_url = str(source_url or "").strip()
        discovery_kind = str(discovery_kind or "body_all_url").strip().lower()
        if discovery_kind not in {
            "body_all_url", "plain_all_url", "browser_xhr",
            "browser_network", "browser_script",
        }:
            discovery_kind = "body_all_url"
        evidence_key = (absolute_url, source_url)
        if evidence_key in self.site_spider_all_url_evidence_set:
            return False
        is_new = absolute_url not in self.site_spider_all_url_set
        url_site = "{}://{}".format(parsed.scheme, parsed.netloc)
        item = {
            "task_id": self.task_id,
            "record_type": "all_url",
            "content": absolute_url,
            "site": source_url or url_site,
            "source": (
                "katana_{}".format(discovery_kind)
                if discovery_kind.startswith("browser_") else "katana_all_url"
            ),
            "fnv_hash": wih_content_hash(self.task_id, "all_url", absolute_url),
            "evidence_type": (
                "browser_network_url"
                if discovery_kind.startswith("browser_") else "hae_all_url"
            ),
            "discovery_kind": discovery_kind,
            "crawler_engine": "katana",
            "discovered_from": source_url,
            "evidence_source": source_url,
            "collector": "katana",
            "url_site": url_site,
            "url_host": parsed.netloc,
            "url_path": parsed.path or "/",
            "save_date": utils.curr_date(),
        }
        self.upsert_wih_item(item)
        self.site_spider_all_url_evidence_set.add(evidence_key)
        self.site_spider_all_url_set.add(absolute_url)
        return is_new

    def save_site_spider_all_url_callback(self, absolute_url, source_url="", discovery_kind=""):
        return self.save_site_spider_all_url_evidence(
            absolute_url,
            source_url=source_url,
            discovery_kind=discovery_kind,
        )

    @staticmethod
    def merge_crawl_results(results):
        merged = {
            "domains": set(),
            "urls": [],
            "all_urls": [],
            "crawler_urls": set(),
            "crawler_url_sources": {},
            "domain_entry_urls": {},
            "domain_sources": {},
            "url_sources": {},
            "entry_url_sources": {},
            "meta": {},
        }
        seen_urls = set()
        seen_all_urls = set()
        partial_errors = []
        for result in results or []:
            if not result:
                continue
            merged["domains"].update(result.get("domains", []) or [])
            merged["crawler_urls"].update(result.get("crawler_urls", []) or [])
            for url, source in (result.get("crawler_url_sources", {}) or {}).items():
                if url not in merged["crawler_url_sources"] and source:
                    merged["crawler_url_sources"][url] = source
            for value in result.get("urls", []) or []:
                if value not in seen_urls:
                    seen_urls.add(value)
                    merged["urls"].append(value)
            for value in result.get("all_urls", []) or []:
                if value not in seen_all_urls:
                    seen_all_urls.add(value)
                    merged["all_urls"].append(value)
            for key in ("domain_entry_urls", "domain_sources", "url_sources"):
                for name, value in (result.get(key, {}) or {}).items():
                    if name not in merged[key] and value:
                        merged[key][name] = value
            for url, values in (result.get("entry_url_sources", {}) or {}).items():
                if isinstance(values, str):
                    values = [values]
                current = merged["entry_url_sources"].setdefault(url, [])
                for value in values or []:
                    if value and value not in current:
                        current.append(value)
            meta = result.get("meta", {}) or {}
            if meta.get("partial_error"):
                partial_errors.append(str(meta["partial_error"]))
            for key in (
                "raw_output_count", "all_url_count", "domain_count",
                "ip_url_host_count", "entry_url_count", "seed_endpoint_count",
                "crawler_endpoint_count", "body_all_url_count",
                "browser_xhr_url_count", "browser_network_url_count",
                "browser_script_url_count", "external_network_filtered_count",
            ):
                merged["meta"][key] = int(merged["meta"].get(key, 0) or 0) + int(
                    meta.get(key, 0) or 0)
            if meta.get("entry_cap_reached"):
                merged["meta"]["entry_cap_reached"] = True
        merged["domains"] = sorted(merged["domains"])
        merged["crawler_urls"] = sorted(merged["crawler_urls"])
        if partial_errors:
            merged["meta"]["partial_error"] = "; ".join(dict.fromkeys(partial_errors))
        return merged

    def probe_entry_urls(
        self,
        urls,
        source_map=None,
        collector="katana",
        discovery_source="katana_all_url",
        url_type="js_web_entry",
    ):
        source_map = source_map or {}
        safe_urls = []
        risky_url_count = 0
        for url in urls or []:
            risky, keyword = is_risky_crawler_url(url)
            if risky:
                risky_url_count += 1
                self.entry_tracker.mark_url_probe_error(
                    url, "risky_url_skipped:{}".format(keyword))
                continue
            safe_urls.append(url)

        probe_urls = self.entry_tracker.pending_urls(safe_urls)
        if not probe_urls:
            return {
                "input_count": len(urls or []),
                "probe_count": 0,
                "output_count": 0,
                "risky_url_count": risky_url_count,
                "initial_probe_error_count": 0,
                "retry_probe_count": 0,
                "retry_recovered_count": 0,
                "probe_error_count": 0,
                "retry_deferred_count": 0,
                "external_redirect_count": 0,
            }

        external_redirect_before = self.entry_tracker.counts().get(
            "external_redirect_count", 0)
        try:
            external_redirect_before = int(external_redirect_before or 0)
        except (TypeError, ValueError):
            external_redirect_before = 0
        page_map = services.page_fetch(probe_urls, task_id=self.task_id)
        initial_missing = [url for url in probe_urls if not page_map.get(url)]
        retry_targets = []
        if (
            initial_missing and
            bool(getattr(Config, "ENTRY_PROBE_RETRY_ENABLE", True))
        ):
            retry_limit = int(getattr(
                Config, "ENTRY_PROBE_RETRY_MAX_TARGETS", 300) or 0)
            retry_targets = (
                initial_missing[:retry_limit] if retry_limit > 0
                else initial_missing
            )
            retry_map = services.page_fetch(
                retry_targets,
                concurrency=max(1, int(getattr(
                    Config, "ENTRY_PROBE_RETRY_CONCURRENCY", 4) or 1)),
                batch_size=max(1, int(getattr(
                    Config, "ENTRY_PROBE_RETRY_BATCH_SIZE", 50) or 1)),
                task_id=self.task_id,
            )
            page_map.update(retry_map)
        recovered_count = sum(
            1 for url in retry_targets if page_map.get(url))
        final_missing_count = sum(
            1 for url in probe_urls if not page_map.get(url))
        unique_page_map = {}
        for url in probe_urls:
            page_info = page_map.get(url)
            if not page_info:
                self.entry_tracker.mark_url_probe_error(url)
                continue
            sources = source_map.get(url, [])
            if isinstance(sources, str):
                sources = [sources] if sources else []
            sources = [str(value).strip() for value in sources if str(value).strip()]
            page_info["discovery_source"] = discovery_source
            page_info["collector"] = collector
            if sources:
                page_info["discovered_from"] = sources[0]
                page_info["discovered_sources"] = sources
            finalized = self.entry_tracker.finalize_url(
                url, page_info, collector=collector)
            if finalized:
                final_url, final_page_info = finalized
                unique_page_map[final_url] = final_page_info

        if unique_page_map:
            save_url_page_map(
                self.task_id,
                unique_page_map,
                CollectSource.SITESPIDER,
                url_type=url_type,
                extra_fields={"crawler_engine": "katana", "collector": collector},
            )
        external_redirect_after = self.entry_tracker.counts().get(
            "external_redirect_count", 0)
        try:
            external_redirect_after = int(external_redirect_after or 0)
        except (TypeError, ValueError):
            external_redirect_after = external_redirect_before
        return {
            "input_count": len(urls or []),
            "probe_count": len(probe_urls),
            "output_count": len(unique_page_map),
            "risky_url_count": risky_url_count,
            "initial_probe_error_count": len(initial_missing),
            "retry_probe_count": len(retry_targets),
            "retry_recovered_count": recovered_count,
            "probe_error_count": final_missing_count,
            "retry_deferred_count": max(
                0, len(initial_missing) - len(retry_targets)),
            "external_redirect_count": max(
                external_redirect_after - external_redirect_before, 0),
        }

    @staticmethod
    def canonical_origin(site):
        site = str(site or "").strip()
        if not site:
            return ""
        try:
            normalized = utils.normal_url(site) or site
            parsed = urlparse(normalized)
        except (TypeError, ValueError):
            return ""
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return ""
        return "{}://{}".format(parsed.scheme, parsed.netloc)

    def load_site_spider_quality(self):
        quality = {}

        def status_score(value):
            if value is not None and 200 <= value < 400:
                return 3
            if http_access_profile(value) == "restricted":
                return 2
            if value is None:
                return 1
            return 0

        fields = {
            "_id": 0,
            "site": 1,
            "status": 1,
            "status_code": 1,
            "tag": 1,
            "title": 1,
            "body_length": 1,
            "content_length": 1,
            "content_type": 1,
            "location": 1,
            "tech": 1,
            "finger": 1,
            "http_server": 1,
            "webserver": 1,
            "fetch_site_complete": 1,
            "observer_ward_complete": 1,
            "quality_state": 1,
            "display_eligible": 1,
            "pipeline_mode": 1,
            "quality_reason": 1,
            "route_confirmed_urls": 1,
            "asset_quality": 1,
            "browser_title": 1,
            "browser_title_source": 1,
            "browser_spa_detected": 1,
            "runtime_script_count": 1,
            "spa_signals": 1,
            "spa_profile": 1,
            "spa_score": 1,
            "spa_confidence": 1,
            "spa_framework": 1,
            "spa_render_mode": 1,
            "spa_route_mode": 1,
        }
        for item in utils.conn_db("site").find(
                formal_site_query({"task_id": self.task_id}), fields):
            origin = self.canonical_origin(item.get("site"))
            if not origin:
                continue
            status = item.get("status")
            if status is None:
                status = item.get("status_code")
            try:
                status = int(status) if status is not None else None
            except (TypeError, ValueError):
                status = None

            candidate = {
                "status": status,
                "tag": item.get("tag") or [],
                "title": preferred_site_title(item),
                "body_length": item.get("body_length") or item.get("content_length") or 0,
                "content_type": item.get("content_type") or "",
                "location": item.get("location") or "",
                "tech": item.get("tech") or [],
                "finger": item.get("finger") or [],
                "http_server": item.get("http_server") or item.get("webserver") or "",
                "fetch_site_complete": bool(item.get("fetch_site_complete")),
                "observer_ward_complete": bool(item.get("observer_ward_complete")),
                "quality_state": item.get("quality_state") or "",
                "display_eligible": item.get("display_eligible"),
                "pipeline_mode": item.get("pipeline_mode") or "",
                "quality_reason": item.get("quality_reason") or "",
                "asset_quality": item.get("asset_quality") or "",
                "browser_title": item.get("browser_title") or "",
                "browser_title_source": item.get("browser_title_source") or "",
                "browser_spa_detected": bool(item.get("browser_spa_detected")),
                "runtime_script_count": int(item.get("runtime_script_count") or 0),
                "spa_signals": list(item.get("spa_signals") or []),
                "spa_profile": item.get("spa_profile") or {},
                "spa_score": int(item.get("spa_score") or 0),
                "spa_confidence": item.get("spa_confidence") or "",
                "spa_framework": item.get("spa_framework") or "",
                "spa_render_mode": item.get("spa_render_mode") or "",
                "spa_route_mode": item.get("spa_route_mode") or "",
                "route_confirmed_urls": list(
                    item.get("route_confirmed_urls") or []),
            }
            current = quality.get(origin)
            candidate_rank = (
                status_score(status),
                bool(candidate["title"]),
                int(candidate["body_length"] or 0),
                candidate["fetch_site_complete"],
                candidate["observer_ward_complete"],
            )
            current_rank = (
                status_score((current or {}).get("status")),
                bool((current or {}).get("title")),
                int((current or {}).get("body_length", 0) or 0),
                bool((current or {}).get("fetch_site_complete")),
                bool((current or {}).get("observer_ward_complete")),
            )
            if current is None or candidate_rank > current_rank:
                quality[origin] = candidate
        return quality

    def site_spider_target_allowed(self, origin, quality_map):
        item = quality_map.get(origin) or {}
        status = item.get("status")
        if item.get("quality_state") == "route_confirmed":
            return True, "route_confirmed"
        if (
            getattr(Config, "RESTRICTED_HTTP_DISCOVERY", True) and
            http_access_profile(status) == "restricted"
        ):
            return True, "restricted"

        browser_pending_shell = bool(
            status == 200 and
            item.get("quality_reason") in {
                "small_untitled_page", "untitled_html_page",
            }
        )
        if item.get("quality_state") != "route_confirmed" and (
            item.get("display_eligible") is False or
            item.get("pipeline_mode") == "route_probe_only"
        ):
            if browser_pending_shell:
                return True, "untitled_html_shell"
            return False, "quality_{}".format(
                item.get("quality_state") or "hidden")

        tags = item.get("tag") or []
        if isinstance(tags, str):
            tags = [tags]
        if SiteAutoTag.INVALID in tags:
            return False, "invalid"

        skip_raw = str(getattr(
            Config,
            "KATANA_SKIP_STATUS_CODES",
            "400,401,403,404,405,410,418,429,500,501,502,503,504",
        ) or "")
        skip_status = set()
        for value in skip_raw.split(","):
            try:
                skip_status.add(int(value.strip()))
            except (TypeError, ValueError):
                continue
        if status in skip_status:
            return False, "status_{}".format(status)
        if status is not None and status >= 400:
            return False, "status_4xx_5xx"
        return True, ""

    @staticmethod
    def _dynamic_quality_text(item):
        values = [
            item.get("title") or "",
            item.get("browser_title") or "",
            item.get("http_server") or "",
            item.get("spa_framework") or "",
            item.get("spa_confidence") or "",
            item.get("spa_render_mode") or "",
            item.get("spa_route_mode") or "",
        ]
        tech = item.get("tech") or []
        if not isinstance(tech, (list, tuple, set)):
            tech = [tech]
        values.extend(str(value) for value in tech if value)
        finger = item.get("finger") or []
        if not isinstance(finger, (list, tuple, set)):
            finger = [finger]
        for value in finger:
            if isinstance(value, dict):
                value = value.get("name") or ""
            if value:
                values.append(str(value))
        values.extend(str(value) for value in (item.get("spa_signals") or []) if value)
        return " ".join(values).lower()

    @staticmethod
    def _dynamic_build_artifact_url(value):
        try:
            path = unquote(urlparse(str(value or "")).path or "").lower()
        except (TypeError, ValueError):
            return False
        if not path:
            return False
        extension = os.path.splitext(path)[1]
        if extension not in WIH_SCRIPT_RESOURCE_EXTENSIONS and not (
                "/_next/" in path or "/_nuxt/" in path):
            return False
        return any(marker in path for marker in DYNAMIC_BROWSER_BUILD_MARKERS)

    def _dynamic_redirect_metadata(self, origin, item):
        status = item.get("status")
        try:
            status = int(status) if status is not None else None
        except (TypeError, ValueError):
            status = None
        if status not in DYNAMIC_BROWSER_REDIRECT_STATUS_CODES:
            return {}
        location = str(item.get("location") or "").strip()
        if not location:
            return {}
        metadata = redirect_destination_metadata(location, origin)
        target = str(metadata.get("redirect_url") or "").strip()
        try:
            parsed = urlparse(target)
        except (TypeError, ValueError):
            return {}
        host = (parsed.hostname or "").strip(".").lower()
        if parsed.scheme not in ("http", "https") or not host:
            return {}
        if not self.scope_domain or domain_in_scope_domain(host, self.scope_domain):
            return {
                "target": target,
                "host": host,
                "kind": "in_scope_redirect",
            }

        if not getattr(Config, "KATANA_DYNAMIC_SSO_ENABLE", True):
            return {}
        if metadata.get("redirect_type") != "sso":
            return {}
        try:
            ipaddress.ip_address(host.strip("[]"))
            return {}
        except ValueError:
            pass
        if host == "localhost" or host.endswith(".localhost"):
            return {}
        return {
            "target": target,
            "host": host,
            "kind": "cross_origin_sso",
        }

    def _dynamic_redirect_target(self, origin, item):
        return self._dynamic_redirect_metadata(origin, item).get("target", "")

    @staticmethod
    def _dynamic_sso_host_is_public(host):
        resolved_ips = utils.get_ip(str(host or "").strip(), log_flag=False)
        has_valid_ip = False
        for value in resolved_ips:
            try:
                address = ipaddress.ip_address(value)
                has_valid_ip = True
                if not address.is_global:
                    return False
            except (TypeError, ValueError):
                continue
        return has_valid_ip

    def dynamic_crawl_signal_map(self, crawl_result):
        signal_map = {}

        def signal_for(value, source=""):
            source_origin = self.canonical_origin(source)
            value_origin = self.canonical_origin(value)
            origin = source_origin or value_origin
            if not origin:
                return None
            return signal_map.setdefault(origin, {
                "all_urls": set(),
                "script_resources": set(),
                "map_resources": set(),
                "build_artifact": False,
            })

        url_sources = crawl_result.get("url_sources", {}) or {}
        for value in crawl_result.get("all_urls", []) or []:
            source = url_sources.get(value, "")
            signal = signal_for(value, source)
            if not signal:
                continue
            signal["all_urls"].add(value)
            try:
                extension = os.path.splitext(urlparse(value).path.lower())[1]
            except (TypeError, ValueError):
                extension = ""
            if extension in RUNTIME_ARTIFACT_MAP_SEED_EXTENSIONS:
                signal["map_resources"].add(value)
            if self._dynamic_build_artifact_url(value):
                signal["build_artifact"] = True

        crawler_sources = crawl_result.get("crawler_url_sources", {}) or {}
        for value in crawl_result.get("crawler_urls", []) or []:
            source = crawler_sources.get(value, "")
            signal = signal_for(value, source)
            if not signal:
                continue
            try:
                extension = os.path.splitext(urlparse(value).path.lower())[1]
            except (TypeError, ValueError):
                extension = ""
            if extension in WIH_SCRIPT_RESOURCE_EXTENSIONS:
                signal["script_resources"].add(value)
            if extension in RUNTIME_ARTIFACT_MAP_SEED_EXTENSIONS:
                signal["map_resources"].add(value)
            if self._dynamic_build_artifact_url(value):
                signal["build_artifact"] = True

        return {
            origin: {
                "all_url_count": len(signal["all_urls"]),
                "script_resource_count": len(signal["script_resources"]),
                "map_resource_count": len(signal["map_resources"]),
                "build_artifact": bool(signal["build_artifact"]),
            }
            for origin, signal in signal_map.items()
        }

    def dynamic_browser_reasons(self, origin, item, signal, allow_restricted=False):
        item = item or {}
        signal = signal or {}
        status = item.get("status")
        try:
            status = int(status) if status is not None else None
        except (TypeError, ValueError):
            status = None
        if (
            status is not None and status >= 400 and
            not (allow_restricted and status in (401, 403))
        ):
            return [], ""

        content_type = str(item.get("content_type") or "").lower()
        if content_type and "html" not in content_type and "xhtml" not in content_type:
            return [], ""

        reasons = []
        quality_text = self._dynamic_quality_text(item)
        if int(signal.get("map_resource_count", 0) or 0) > 0:
            reasons.append("source_map_seed")
        if any(marker in quality_text for marker in DYNAMIC_BROWSER_SPA_MARKERS):
            reasons.append("spa_framework")
        try:
            if int(item.get("spa_score") or 0) >= 55 and "spa_framework" not in reasons:
                reasons.append("spa_framework")
        except (TypeError, ValueError):
            pass
        if (
            any(marker in quality_text for marker in DYNAMIC_BROWSER_BUNDLER_MARKERS) or
            signal.get("build_artifact")
        ):
            reasons.append("webpack_vite_chunks")

        low_yield_threshold = max(int(getattr(
            Config, "KATANA_DYNAMIC_LOW_YIELD_THRESHOLD", 3) or 0), 0)
        min_scripts = max(int(getattr(
            Config, "KATANA_DYNAMIC_MIN_SCRIPT_RESOURCES", 2) or 0), 1)
        if (
            int(signal.get("script_resource_count", 0) or 0) >= min_scripts and
            int(signal.get("all_url_count", 0) or 0) <= low_yield_threshold
        ):
            reasons.append("low_yield_js")

        if (
            status == 200 and
            item.get("quality_reason") in {
                "small_untitled_page", "untitled_html_page",
            }
        ):
            reasons.append("untitled_html_shell")
        elif site_needs_browser_title(item):
            # HTTPX can miss a title on a larger hydrated shell. Schedule a
            # bounded browser probe without changing crawl or WIH matching.
            reasons.append("untitled_html_title_probe")

        redirect_metadata = self._dynamic_redirect_metadata(origin, item)
        location_text = str(item.get("location") or "")
        if location_text:
            try:
                location_host = (urlparse(urljoin(
                    origin.rstrip("/") + "/", location_text,
                )).hostname or "").strip(".").lower()
            except (TypeError, ValueError):
                location_host = ""
            if (
                location_host and self.scope_domain and
                not domain_in_scope_domain(location_host, self.scope_domain) and
                redirect_metadata.get("kind") != "cross_origin_sso"
            ):
                location_text = ""
        interactive_text = " ".join([
            quality_text,
            str(item.get("title") or ""),
            location_text,
            str(origin or ""),
        ]).lower()
        if any(marker in interactive_text for marker in DYNAMIC_BROWSER_INTERACTIVE_MARKERS):
            reasons.append("login_admin_api_docs")

        redirect_target = redirect_metadata.get("target", "")
        redirect_location = str(item.get("location") or "").strip()
        if redirect_metadata.get("kind") == "cross_origin_sso":
            reasons.append("cross_origin_sso")
        elif (
            status in DYNAMIC_BROWSER_REDIRECT_STATUS_CODES and
            (not redirect_location or redirect_target)
        ):
            reasons.append("in_scope_redirect")
        return reasons, redirect_target

    @staticmethod
    def _dynamic_ip_origin(origin):
        try:
            ipaddress.ip_address(urlparse(str(origin or "")).hostname or "")
            return True
        except ValueError:
            return False

    def _dynamic_preferred_target(
        self,
        origin,
        values,
        redirect_target,
        allow_external_redirect=False,
    ):
        candidates = [redirect_target] if redirect_target else []
        candidates.extend(values[1:])
        valid = []
        for value in candidates:
            value = str(value or "").strip()
            if not value:
                continue
            try:
                parsed = urlparse(value)
            except (TypeError, ValueError):
                continue
            host = (parsed.hostname or "").strip(".").lower()
            if parsed.scheme not in ("http", "https") or not host:
                continue
            if (
                self.scope_domain and
                not domain_in_scope_domain(host, self.scope_domain) and
                not (allow_external_redirect and value == redirect_target)
            ):
                continue
            valid.append(value)

        if redirect_target and valid:
            return valid[0]
        for value in valid:
            if any(marker in value.lower() for marker in DYNAMIC_BROWSER_INTERACTIVE_MARKERS):
                return value
        for value in valid:
            if (urlparse(value).path or "/") not in ("", "/"):
                return value
        return origin

    @staticmethod
    def _normalize_dynamic_target(value):
        value = str(value or "").strip()
        if not value:
            return ""
        try:
            parsed = urlparse(value)
            port = parsed.port
        except (TypeError, ValueError):
            return ""
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return ""
        scheme = parsed.scheme.lower()
        host = parsed.hostname.lower()
        if ":" in host and not host.startswith("["):
            host = "[{}]".format(host)
        default_port = 80 if scheme == "http" else 443
        netloc = host
        if port and port != default_port:
            netloc = "{}:{}".format(host, port)
        path = parsed.path or "/"
        normalized = "{}://{}{}".format(scheme, netloc, path)
        if parsed.query:
            normalized = "{}?{}".format(normalized, parsed.query)
        if parsed.fragment:
            normalized = "{}#{}".format(normalized, parsed.fragment)
        return normalized

    def build_dynamic_spider_targets(
        self,
        entry_urls_list,
        quality_map,
        crawl_result,
        restricted_origins=None,
    ):
        signal_map = self.dynamic_crawl_signal_map(crawl_result)
        candidates = []
        restricted_origins = {
            self.canonical_origin(value) for value in (restricted_origins or [])
            if self.canonical_origin(value)
        }
        reason_weights = {
            "spa_framework": 140,
            "source_map_seed": 135,
            "webpack_vite_chunks": 130,
            "untitled_html_shell": 120,
            "untitled_html_title_probe": 105,
            "cross_origin_sso": 110,
            "low_yield_js": 80,
            "login_admin_api_docs": 60,
            "in_scope_redirect": 50,
            "restricted_browser": 40,
        }

        for group in entry_urls_list or []:
            values = [group] if isinstance(group, str) else list(group or [])
            if not values:
                continue
            origin = self.canonical_origin(values[0])
            if not origin:
                continue
            is_restricted = origin in restricted_origins
            quality_item = quality_map.get(origin) or {}
            status = quality_item.get("status")
            try:
                status = int(status) if status is not None else None
            except (TypeError, ValueError):
                status = None
            content_type = str(quality_item.get("content_type") or "").lower()
            if (
                status is not None and status >= 400 and
                not (is_restricted and status in (401, 403))
            ):
                continue
            if content_type and "html" not in content_type and "xhtml" not in content_type:
                continue
            reasons, redirect_target = self.dynamic_browser_reasons(
                origin,
                quality_item,
                signal_map.get(origin) or {},
                allow_restricted=is_restricted,
            )
            entry_text = " ".join(str(value or "") for value in values).lower()
            if (
                any(marker in entry_text
                    for marker in DYNAMIC_BROWSER_INTERACTIVE_MARKERS) and
                "login_admin_api_docs" not in reasons
            ):
                reasons.append("login_admin_api_docs")
            if not reasons:
                continue
            if is_restricted:
                high_value_reasons = {
                    "spa_framework", "webpack_vite_chunks", "login_admin_api_docs",
                }
                if not high_value_reasons.intersection(reasons):
                    continue
                reasons.append("restricted_browser")

            is_cross_origin_sso = "cross_origin_sso" in reasons
            target = self._dynamic_preferred_target(
                origin,
                values,
                redirect_target,
                allow_external_redirect=is_cross_origin_sso,
            )
            target_key = self._normalize_dynamic_target(target)
            if not target_key:
                continue

            candidates.append({
                "origin": origin,
                "target": target,
                "target_key": target_key,
                "reasons": reasons,
                "score": sum(reason_weights.get(reason, 0) for reason in reasons),
                "is_ip": self._dynamic_ip_origin(origin),
                "restricted": is_restricted,
                "cross_origin_sso": is_cross_origin_sso,
                "redirect_host": (
                    (urlparse(target).hostname or "").strip(".").lower()
                    if is_cross_origin_sso else ""
                ),
            })

        candidates.sort(key=lambda item: (
            -item["score"], item["is_ip"], item["restricted"], item["origin"]))
        max_targets = max(int(getattr(
            Config, "KATANA_DYNAMIC_MAX_TARGETS", 16) or 0), 0)
        normal_candidates = [
            item for item in candidates if not item["cross_origin_sso"]
        ]
        sso_candidates = [
            item for item in candidates if item["cross_origin_sso"]
        ]
        selection_limit = min(
            max_targets or len(normal_candidates), len(normal_candidates))
        ip_percent = min(max(int(getattr(
            Config, "KATANA_DYNAMIC_IP_TARGET_PERCENT", 20) or 0), 0), 100)
        ip_target_limit = (
            selection_limit if ip_percent >= 100 else
            max((selection_limit * ip_percent) // 100, 1)
            if ip_percent > 0 and selection_limit else 0
        )
        restricted_target_limit = max(int(getattr(
            Config, "KATANA_DYNAMIC_RESTRICTED_MAX_TARGETS", 2) or 0), 0)
        selected = []
        selected_origins = set()
        selected_targets = set()
        selected_ip_count = 0
        selected_restricted_count = 0

        def candidate_allowed(item):
            if item["target_key"] in selected_targets:
                return False
            if item["is_ip"] and selected_ip_count >= ip_target_limit:
                return False
            if item["restricted"] and selected_restricted_count >= restricted_target_limit:
                return False
            return True

        def select_item(item):
            nonlocal selected_ip_count, selected_restricted_count
            selected.append(item)
            selected_origins.add(item["origin"])
            selected_targets.add(item["target_key"])
            selected_ip_count += int(item["is_ip"])
            selected_restricted_count += int(item["restricted"])

        family_order = tuple(
            reason for reason in reason_weights if reason != "cross_origin_sso")
        family_queues = {
            reason: [
                item for item in normal_candidates if reason in item["reasons"]
            ]
            for reason in family_order
        }
        family_indexes = {reason: 0 for reason in family_order}
        while len(selected) < selection_limit:
            progress = False
            for reason in family_order:
                queue = family_queues[reason]
                index = family_indexes[reason]
                while (
                    index < len(queue) and
                    (
                        queue[index]["origin"] in selected_origins or
                        not candidate_allowed(queue[index])
                    )
                ):
                    index += 1
                family_indexes[reason] = index
                if index >= len(queue):
                    continue
                item = queue[index]
                family_indexes[reason] = index + 1
                select_item(item)
                progress = True
                if len(selected) >= selection_limit:
                    break
            if not progress:
                break

        if len(selected) < selection_limit:
            for item in normal_candidates:
                if item["origin"] in selected_origins or not candidate_allowed(item):
                    continue
                select_item(item)
                if len(selected) >= selection_limit:
                    break

        sso_target_limit = max(int(getattr(
            Config, "KATANA_DYNAMIC_SSO_MAX_TARGETS", 8) or 0), 0)
        sso_per_origin_limit = max(int(getattr(
            Config, "KATANA_DYNAMIC_SSO_ENTRY_URLS_PER_ORIGIN", 2) or 0), 1)
        selected_sso_count = 0
        selected_sso_items = []
        sso_rejected_non_public_count = 0
        sso_origin_counts = {}
        for item in sso_candidates:
            if selected_sso_count >= sso_target_limit:
                break
            redirect_origin = self.canonical_origin(item["target"])
            if not redirect_origin or item["target_key"] in selected_targets:
                continue
            if sso_origin_counts.get(redirect_origin, 0) >= sso_per_origin_limit:
                continue
            if not self._dynamic_sso_host_is_public(item["redirect_host"]):
                sso_rejected_non_public_count += 1
                continue
            select_item(item)
            selected_sso_items.append(item)
            selected_sso_count += 1
            sso_origin_counts[redirect_origin] = (
                sso_origin_counts.get(redirect_origin, 0) + 1)
        if selected_sso_items:
            sso_origins = {item["origin"] for item in selected_sso_items}
            selected = selected_sso_items + [
                item for item in selected if item["origin"] not in sso_origins
            ]
        reason_counts = {}
        for item in selected:
            for reason in item["reasons"]:
                reason_counts[reason] = reason_counts.get(reason, 0) + 1
        candidate_reason_counts = {}
        for item in candidates:
            for reason in item["reasons"]:
                candidate_reason_counts[reason] = (
                    candidate_reason_counts.get(reason, 0) + 1)
        unselected_reason_counts = {}
        for item in candidates:
            if item["origin"] in selected_origins:
                continue
            for reason in item["reasons"]:
                unselected_reason_counts[reason] = (
                    unselected_reason_counts.get(reason, 0) + 1)

        # The runtime title pass is lightweight and may use a wider pool than
        # the expensive dynamic crawl. SSO entries are retained only after the
        # existing public-IP validation above. This private field is consumed
        # in memory and is never copied into task_stage documents.
        selected_sso_keys = {
            item["target_key"] for item in selected_sso_items
        }
        runtime_candidates = [
            {
                "origin": item["origin"],
                "target": item["target"],
                "target_key": item["target_key"],
                "reasons": list(item["reasons"]),
                "score": item["score"],
                "is_ip": item["is_ip"],
                "restricted": item["restricted"],
                "cross_origin_sso": item["cross_origin_sso"],
            }
            for item in candidates
            if (
                not item["cross_origin_sso"] or
                item["target_key"] in selected_sso_keys
            )
        ]
        return [[item["target"]] for item in selected], {
            "candidate_count": len(candidates),
            "candidate_reason_counts": candidate_reason_counts,
            "unselected_reason_counts": unselected_reason_counts,
            "selected_count": len(selected),
            "selected_source_count": len(selected_origins),
            "unique_target_count": len(selected_targets),
            "selected_named_count": len(selected) - selected_ip_count,
            "selected_ip_count": selected_ip_count,
            "selected_restricted_count": selected_restricted_count,
            "sso_candidate_count": len(sso_candidates),
            "sso_selected_count": selected_sso_count,
            "sso_target_limit": sso_target_limit,
            "sso_rejected_non_public_count": sso_rejected_non_public_count,
            "sso_redirect_hosts": sorted({
                item["redirect_host"] for item in selected
                if item["cross_origin_sso"] and item["redirect_host"]
            }),
            "ip_target_limit": ip_target_limit,
            "reason_counts": reason_counts,
            "selection_strategy": "reason_round_robin",
            "target_reasons": {
                item["origin"]: item["reasons"] for item in selected
            },
            "target_urls": {
                item["origin"]: item["target"] for item in selected
            },
            "_runtime_candidates": runtime_candidates,
        }

    def _runtime_navigation_target(self, origin, preferred):
        preferred = str(preferred or origin).strip()
        preferred_origin = self.canonical_origin(preferred)
        navigation_target = preferred if preferred_origin == origin else origin
        return self._normalize_dynamic_target(navigation_target)

    def build_runtime_artifact_targets(self, selection_meta):
        """Select a balanced title-probe plan from the full candidate pool."""
        selection_meta = selection_meta or {}
        target_urls = selection_meta.get("target_urls", {}) or {}
        target_reasons = selection_meta.get("target_reasons", {}) or {}
        raw_candidates = list(selection_meta.get("_runtime_candidates", []) or [])
        if not raw_candidates:
            raw_candidates = [
                {
                    "origin": origin,
                    "target": target_urls.get(origin) or origin,
                    "reasons": list(target_reasons.get(origin) or []),
                    "score": 0,
                    "cross_origin_sso": (
                        "cross_origin_sso" in (target_reasons.get(origin) or [])
                    ),
                }
                for origin in target_urls
            ]
        else:
            raw_candidate_origins = {
                str(item.get("origin") or "").strip()
                for item in raw_candidates if isinstance(item, dict)
            }
            raw_candidates.extend(
                {
                    "origin": origin,
                    "target": target_urls.get(origin) or origin,
                    "reasons": list(target_reasons.get(origin) or []),
                    "score": 0,
                    "cross_origin_sso": (
                        "cross_origin_sso" in (target_reasons.get(origin) or [])
                    ),
                }
                for origin in target_urls
                if origin not in raw_candidate_origins
            )

        candidates = []
        seen_origins = set()
        for raw in raw_candidates:
            origin = str(raw.get("origin") or "").strip()
            if not origin or origin in seen_origins:
                continue
            target = self._runtime_navigation_target(
                origin, raw.get("target") or target_urls.get(origin) or origin)
            if not target:
                continue
            reasons = list(dict.fromkeys(
                str(value or "").strip()
                for value in (raw.get("reasons") or target_reasons.get(origin) or [])
                if str(value or "").strip()
            ))
            seen_origins.add(origin)
            candidates.append({
                "origin": origin,
                "target": target,
                "reasons": reasons,
                "score": int(raw.get("score", 0) or 0),
                "cross_origin_sso": bool(
                    raw.get("cross_origin_sso") or
                    "cross_origin_sso" in reasons),
            })

        reason_order = (
            "source_map_seed", "spa_framework", "untitled_html_shell",
            "untitled_html_title_probe", "webpack_vite_chunks",
            "cross_origin_sso", "low_yield_js", "login_admin_api_docs",
            "in_scope_redirect", "restricted_browser",
        )
        try:
            title_probe_limit = max(int(getattr(
                Config, "RUNTIME_TITLE_PROBE_MAX_TARGETS", 0) or 0), 0)
        except (TypeError, ValueError):
            title_probe_limit = 0
        try:
            artifact_limit = max(int(getattr(
                Config, "RUNTIME_ARTIFACT_MAX_TARGETS", 8) or 0), 0)
        except (TypeError, ValueError):
            artifact_limit = 8

        candidate_by_origin = {
            item["origin"]: item for item in candidates
        }
        required_origins = []
        required_target_origins = selection_meta.get(
            "runtime_artifact_target_origins", []) or []
        if not required_target_origins:
            required_target_origins = list(target_urls)
        for origin in required_target_origins:
            if origin in candidate_by_origin and origin not in required_origins:
                required_origins.append(origin)
            if artifact_limit and len(required_origins) >= artifact_limit:
                break

        sso_candidates = [
            item for item in candidates if item["cross_origin_sso"]
        ]
        if title_probe_limit:
            sso_reserve = min(
                len(sso_candidates), max(title_probe_limit // 2, 1))
        else:
            sso_reserve = len(sso_candidates)
        for item in sso_candidates[:sso_reserve]:
            if item["origin"] not in required_origins:
                required_origins.append(item["origin"])

        ordered = []
        selected_origins = set()

        def append_candidate(item):
            if not item or item["origin"] in selected_origins:
                return False
            ordered.append(item)
            selected_origins.add(item["origin"])
            return True

        for origin in required_origins:
            append_candidate(candidate_by_origin.get(origin))

        family_queues = {
            reason: [item for item in candidates if reason in item["reasons"]]
            for reason in reason_order
        }
        family_indexes = {reason: 0 for reason in reason_order}
        limit = title_probe_limit or len(candidates)
        while len(ordered) < limit:
            progress = False
            for reason in reason_order:
                queue = family_queues[reason]
                index = family_indexes[reason]
                while index < len(queue) and queue[index]["origin"] in selected_origins:
                    index += 1
                family_indexes[reason] = index
                if index >= len(queue):
                    continue
                family_indexes[reason] = index + 1
                progress = append_candidate(queue[index]) or progress
                if len(ordered) >= limit:
                    break
            if not progress:
                break
        if len(ordered) < limit:
            for item in candidates:
                append_candidate(item)
                if len(ordered) >= limit:
                    break

        ordered = ordered[:limit]
        targets = [item["target"] for item in ordered]
        runtime_reason_counts = {}
        for item in ordered:
            for reason in item["reasons"]:
                runtime_reason_counts[reason] = (
                    runtime_reason_counts.get(reason, 0) + 1)
        selection_meta.update({
            "runtime_title_candidate_count": len(candidates),
            "runtime_title_selected_count": len(targets),
            "runtime_title_reason_counts": runtime_reason_counts,
            "runtime_title_selection_strategy": (
                "required_artifact_and_sso_then_reason_round_robin"
            ),
            "runtime_title_target_reasons": {
                item["origin"]: item["reasons"] for item in ordered
            },
            "runtime_title_target_urls": {
                item["origin"]: item["target"] for item in ordered
            },
        })
        return targets

    def build_runtime_artifact_full_targets(self, selection_meta):
        """Choose the small, heavy JS archive subset independently."""
        selection_meta = selection_meta or {}
        target_urls = selection_meta.get("target_urls", {}) or {}
        target_reasons = selection_meta.get("target_reasons", {}) or {}
        reason_order = (
            "source_map_seed", "spa_framework", "webpack_vite_chunks", "low_yield_js",
            "login_admin_api_docs", "cross_origin_sso",
            "untitled_html_shell", "untitled_html_title_probe",
            "in_scope_redirect", "restricted_browser",
        )
        ordered_origins = []
        for reason in reason_order:
            ordered_origins.extend(
                origin for origin in target_urls
                if origin not in ordered_origins and
                reason in (target_reasons.get(origin) or [])
            )
        ordered_origins.extend(
            origin for origin in target_urls if origin not in ordered_origins)
        try:
            artifact_limit = max(int(getattr(
                Config, "RUNTIME_ARTIFACT_MAX_TARGETS", 8) or 0), 0)
        except (TypeError, ValueError):
            artifact_limit = 8
        targets = []
        seen = set()
        selected_origins = []
        for origin in ordered_origins:
            target = self._runtime_navigation_target(
                origin, target_urls.get(origin) or origin)
            if not target or target in seen:
                continue
            seen.add(target)
            targets.append(target)
            selected_origins.append(origin)
            if artifact_limit and len(targets) >= artifact_limit:
                break
        selection_meta.update({
            "runtime_artifact_selected_count": len(targets),
            "runtime_artifact_target_origins": selected_origins,
            "runtime_artifact_target_reasons": {
                origin: list(target_reasons.get(origin) or [])
                for origin in selected_origins
            },
        })
        return targets

    def persist_dynamic_browser_site_signals(self, selection_meta):
        """Expose dynamic browser selection hints on site rows for operators."""
        selection_meta = selection_meta or {}
        target_reasons = selection_meta.get("target_reasons", {}) or {}
        target_urls = selection_meta.get("target_urls", {}) or {}
        if not target_reasons:
            return 0

        spa_reasons = {
            "source_map_seed",
            "spa_framework",
            "webpack_vite_chunks",
            "low_yield_js",
            "untitled_html_shell",
        }
        operations = []
        now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        for origin, raw_reasons in target_reasons.items():
            origin = self.canonical_origin(origin)
            if not origin:
                continue
            reasons = list(dict.fromkeys(
                str(value or "").strip()
                for value in (raw_reasons or [])
                if str(value or "").strip()
            ))
            if not reasons:
                continue
            update_doc = {
                "$set": {
                    "dynamic_browser_selected": True,
                    "dynamic_browser_reasons": reasons,
                    "dynamic_browser_updated_at": now,
                }
            }
            spa_signals = [
                "selection_{}".format(reason)
                for reason in reasons if reason in spa_reasons
            ]
            if spa_signals:
                update_doc["$set"]["browser_spa_detected"] = True
                update_doc["$addToSet"] = {
                    "spa_signals": {"$each": spa_signals}
                }
            if "cross_origin_sso" in reasons:
                target_url = str(target_urls.get(origin) or "").strip()
                update_doc["$set"]["browser_cross_origin_redirect"] = True
                if target_url:
                    update_doc["$set"]["browser_final_url"] = target_url
            operations.append(UpdateOne(
                {
                    "task_id": self.task_id,
                    "$or": [
                        {"canonical_site": origin},
                        {"site": origin},
                    ],
                },
                update_doc,
                upsert=False,
            ))
        if not operations:
            return 0
        try:
            result = utils.conn_db("site").bulk_write(
                operations, ordered=False)
            return int(result.modified_count or 0)
        except Exception as exc:
            logger.warning(
                "persist dynamic browser site signals failed task_id:{} error:{}".format(
                    self.task_id, exc))
            return 0

    def fetch_site_target_allowed(self, origin, quality_map, site_identify=False):
        item = quality_map.get(origin) or {}
        status = item.get("status")
        if status in self.TRANSIENT_FETCH_STATUS_CODES:
            return True, "transient_status"
        if not item.get("fetch_site_complete"):
            return True, "fetch_incomplete"
        if (
            site_identify and
            not item.get("observer_ward_complete") and
            status not in self.OBSERVER_TERMINAL_SKIP_STATUS_CODES
        ):
            return True, "fingerprint_incomplete"
        return self.site_spider_target_allowed(origin, quality_map)

    def wih_site_origin(self, value):
        origin = self.canonical_origin(value)
        if not origin:
            return ""
        parsed = urlparse(origin)
        host = (parsed.hostname or "").strip(".").lower()
        if not host or not wih_ip_target_allowed(host):
            return ""
        if self.scope_domain and not domain_in_scope_domain(host, self.scope_domain):
            try:
                ipaddress.ip_address(host.strip("[]"))
            except ValueError:
                return ""
        if self.should_skip_web_discovery_site(origin):
            return ""
        return origin

    def build_wih_site_targets(self, raw_sites, named_only=False):
        quality_map = self.load_site_spider_quality()
        max_targets = int(getattr(
            Config, "WIH_SITE_FALLBACK_MAX_TARGETS", 400) or 0)
        targets = []
        seen = set()
        reasons = {}
        candidate_count = 0
        allowed_named_edge_count = 0

        def filtered(reason):
            reasons[reason] = reasons.get(reason, 0) + 1

        for value in raw_sites or []:
            origin = self.canonical_origin(value)
            if not origin or origin in seen:
                filtered("invalid_or_duplicate")
                continue
            seen.add(origin)
            candidate_count += 1
            parsed = urlparse(origin)
            host = (parsed.hostname or "").strip(".").lower()
            try:
                ipaddress.ip_address(host.strip("[]"))
                is_ip = True
            except ValueError:
                is_ip = False
            if named_only and is_ip:
                filtered("bare_ip")
                continue
            if not is_ip and self.scope_domain and not domain_in_scope_domain(
                    host, self.scope_domain):
                filtered("out_of_scope")
                continue

            edge_detected = self.is_edge_site(origin)
            if edge_detected and self.should_skip_web_discovery_site(origin):
                filtered("shared_edge")
                continue
            if edge_detected:
                allowed_named_edge_count += 1

            if origin not in quality_map:
                filtered("missing_quality")
                continue
            allowed, reason = self.site_spider_target_allowed(origin, quality_map)
            if not allowed:
                filtered(reason or "low_quality")
                continue

            targets.append(origin)
            if max_targets > 0 and len(targets) >= max_targets:
                break

        self.wih_target_selection_meta = {
            "fallback_candidate_count": candidate_count,
            "fallback_selected_count": len(targets),
            "fallback_filtered_count": sum(reasons.values()),
            "fallback_filter_reasons": reasons,
            "fallback_named_edge_allowed_count": allowed_named_edge_count,
            "fallback_limit": max_targets,
        }
        return targets

    def build_wih_targets_from_katana(self, crawl_result):
        max_targets = int(getattr(Config, "WIH_KATANA_MAX_TARGETS", 1200) or 0)
        values = []
        if getattr(Config, "WIH_INCLUDE_KATANA_ENTRY_URLS", False):
            values.extend((value, "entry_origin") for value in (crawl_result.get("urls", []) or []))
        if getattr(Config, "WIH_INCLUDE_KATANA_RESOURCE_URLS", True):
            resource_values = list(crawl_result.get("crawler_urls", []) or [])
            resource_values.extend(crawl_result.get("all_urls", []) or [])
            values.extend((value, "resource_origin") for value in resource_values)

        targets = []
        seen = set()
        entry_target_count = 0
        resource_target_count = 0
        for value, target_type in values:
            value = str(value or "").strip()
            if not value:
                continue
            if target_type == "resource_origin":
                path = urlparse(value).path or ""
                if os.path.splitext(path.lower())[1] not in WIH_SCRIPT_RESOURCE_EXTENSIONS:
                    continue
            origin = self.wih_site_origin(value)
            if not origin or origin in seen:
                continue
            seen.add(origin)
            targets.append(origin)
            if target_type == "entry_origin":
                entry_target_count += 1
            else:
                resource_target_count += 1
            if max_targets > 0 and len(targets) >= max_targets:
                break

        self.site_spider_wih_targets = targets
        self.site_spider_wih_entry_target_count = entry_target_count
        self.site_spider_wih_resource_target_count = resource_target_count
        return targets

    def site_screenshot(self):
        # ***站点截图***
        capture_save_dir = Config.SCREENSHOT_DIR + "/" + self.task_id
        summary = services.site_screenshot(
            sorted(self.active_poc_sites),
            concurrency=6,
            capture_dir=capture_save_dir,
        ) or {}
        failed_count = int(summary.get("failed_count", 0) or 0)
        output_count = int(summary.get("output_count", 0) or 0)
        if failed_count:
            summary["warning"] = "{} screenshot(s) failed".format(failed_count)
            if output_count:
                summary["_stage_status"] = "done_with_warnings"
                summary["completion_state"] = "done_with_warnings"
            else:
                summary["_stage_status"] = "partial"
                summary["partial_reason"] = "all_screenshots_failed"
        return summary

    def site_spider(self, stage_name=WebSiteFetchStatus.SITE_SPIDER):
        self.entry_tracker.snapshot_prior_assets()
        quality_cluster_summary = {}
        try:
            quality_cluster_summary = refresh_site_quality_clusters(self.task_id)
        except Exception as exc:
            logger.warning(
                "site quality cluster refresh failed task_id:{} error:{}".format(
                    self.task_id, exc))
        configured_engine = str(getattr(Config, "SITE_SPIDER_ENGINE", "katana") or "katana").lower()
        if configured_engine != "katana":
            logger.warning("SITE_SPIDER_ENGINE={} ignored; legacy site spider is disabled".format(configured_engine))
        engine = "katana"
        entry_urls_list = []  # 是一个二维数组
        restricted_entry_urls_list = []
        skipped_edge_sites = 0
        skipped_low_quality_sites = 0
        skipped_duplicate_sites = 0
        skipped_quality_reasons = {}
        quality_map = self.load_site_spider_quality()
        seen_origins = set()
        for site in self.available_sites:
            origin = self.canonical_origin(site)
            if not origin:
                skipped_low_quality_sites += 1
                skipped_quality_reasons["invalid_url"] = skipped_quality_reasons.get("invalid_url", 0) + 1
                continue
            if origin in seen_origins:
                skipped_duplicate_sites += 1
                continue
            seen_origins.add(origin)
            if self.should_skip_web_discovery_site(origin):
                skipped_edge_sites += 1
                continue
            allowed, skip_reason = self.site_spider_target_allowed(origin, quality_map)
            if not allowed:
                skipped_low_quality_sites += 1
                skipped_quality_reasons[skip_reason] = skipped_quality_reasons.get(skip_reason, 0) + 1
                continue

            entry_urls = [origin]
            entry_urls.extend(
                (quality_map.get(origin) or {}).get(
                    "route_confirmed_urls", [])[:5])
            entry_urls.extend(self.search_engines_result.get(site, []))
            if skip_reason == "restricted":
                restricted_entry_urls_list.append(entry_urls)
            else:
                entry_urls_list.append(entry_urls)

        spider_urls = []
        crawler_error = ""
        crawl_meta = {}
        entry_url_sources = {}
        dynamic_selection_meta = {
            "candidate_count": 0,
            "selected_count": 0,
            "selected_source_count": 0,
            "unique_target_count": 0,
            "selected_named_count": 0,
            "selected_ip_count": 0,
            "selected_restricted_count": 0,
            "sso_candidate_count": 0,
            "sso_selected_count": 0,
            "sso_target_limit": 0,
            "sso_rejected_non_public_count": 0,
            "sso_redirect_hosts": [],
            "ip_target_limit": 0,
            "reason_counts": {},
            "selection_strategy": "reason_round_robin",
            "target_reasons": {},
            "target_urls": {},
        }
        dynamic_result_meta = {}
        dynamic_error = ""
        dynamic_warning = ""
        probe_summary = {
            "initial_probe_error_count": 0,
            "retry_probe_count": 0,
            "retry_recovered_count": 0,
            "probe_error_count": 0,
            "retry_deferred_count": 0,
            "external_redirect_count": 0,
        }

        def dynamic_stage_fields():
            return {
                "dynamic_candidate_count": dynamic_selection_meta.get(
                    "candidate_count", 0),
                "dynamic_candidate_reason_counts": dynamic_selection_meta.get(
                    "candidate_reason_counts", {}),
                "dynamic_unselected_reason_counts": dynamic_selection_meta.get(
                    "unselected_reason_counts", {}),
                "dynamic_target_count": dynamic_selection_meta.get(
                    "selected_count", 0),
                "dynamic_selected_source_count": dynamic_selection_meta.get(
                    "selected_source_count", 0),
                "dynamic_unique_target_count": dynamic_selection_meta.get(
                    "unique_target_count", 0),
                "dynamic_named_target_count": dynamic_selection_meta.get(
                    "selected_named_count", 0),
                "dynamic_ip_target_count": dynamic_selection_meta.get(
                    "selected_ip_count", 0),
                "dynamic_restricted_target_count": dynamic_selection_meta.get(
                    "selected_restricted_count", 0),
                "dynamic_sso_candidate_count": dynamic_selection_meta.get(
                    "sso_candidate_count", 0),
                "dynamic_sso_selected_count": dynamic_selection_meta.get(
                    "sso_selected_count", 0),
                "dynamic_sso_target_limit": dynamic_selection_meta.get(
                    "sso_target_limit", 0),
                "dynamic_sso_rejected_non_public_count": dynamic_selection_meta.get(
                    "sso_rejected_non_public_count", 0),
                "dynamic_sso_redirect_hosts": dynamic_selection_meta.get(
                    "sso_redirect_hosts", []),
                "dynamic_ip_target_limit": dynamic_selection_meta.get(
                    "ip_target_limit", 0),
                "dynamic_reason_counts": dynamic_selection_meta.get("reason_counts", {}),
                "dynamic_selection_strategy": dynamic_selection_meta.get(
                    "selection_strategy", "reason_round_robin"),
                "dynamic_target_reasons": dynamic_selection_meta.get("target_reasons", {}),
                "dynamic_target_urls": dynamic_selection_meta.get("target_urls", {}),
                "runtime_title_candidate_count": dynamic_selection_meta.get(
                    "runtime_title_candidate_count", 0),
                "runtime_title_target_count": dynamic_selection_meta.get(
                    "runtime_title_selected_count", 0),
                "runtime_title_reason_counts": dynamic_selection_meta.get(
                    "runtime_title_reason_counts", {}),
                "runtime_title_selection_strategy": dynamic_selection_meta.get(
                    "runtime_title_selection_strategy", ""),
                "runtime_artifact_target_count": dynamic_selection_meta.get(
                    "runtime_artifact_selected_count", 0),
                "dynamic_site_signal_count": dynamic_selection_meta.get(
                    "site_signal_count", 0),
                "dynamic_raw_output_count": int(
                    dynamic_result_meta.get("raw_output_count", 0) or 0),
                "dynamic_all_url_count": int(
                    dynamic_result_meta.get("all_url_count", 0) or 0),
                "dynamic_unique_all_url_count": int(
                    dynamic_result_meta.get("unique_all_url_count", 0) or 0),
                "dynamic_domain_count": int(
                    dynamic_result_meta.get("domain_count", 0) or 0),
                "dynamic_unique_domain_count": int(
                    dynamic_result_meta.get("unique_domain_count", 0) or 0),
                "dynamic_entry_url_count": int(
                    dynamic_result_meta.get("entry_url_count", 0) or 0),
                "dynamic_xhr_url_count": int(
                    dynamic_result_meta.get("browser_xhr_url_count", 0) or 0),
                "dynamic_network_url_count": int(
                    dynamic_result_meta.get("browser_network_url_count", 0) or 0),
                "dynamic_script_url_count": int(
                    dynamic_result_meta.get("browser_script_url_count", 0) or 0),
                "dynamic_external_network_filtered_count": int(
                    dynamic_result_meta.get("external_network_filtered_count", 0) or 0),
                "dynamic_unique_entry_url_count": int(
                    dynamic_result_meta.get("unique_entry_url_count", 0) or 0),
                "dynamic_batch_total": int(
                    dynamic_result_meta.get("crawl_batch_total", 0) or 0),
                "dynamic_actual_batch_count": int(
                    dynamic_result_meta.get("crawl_batch_total", 0) or 0),
                "dynamic_batch_attempted": int(
                    dynamic_result_meta.get("crawl_batch_attempted", 0) or 0),
                "dynamic_batch_completed": int(
                    dynamic_result_meta.get("crawl_batch_completed", 0) or 0),
                "dynamic_batch_succeeded": int(
                    dynamic_result_meta.get("crawl_batch_succeeded", 0) or 0),
                "dynamic_batch_timed_out": int(
                    dynamic_result_meta.get("crawl_batch_timed_out", 0) or 0),
                "dynamic_batch_failed": int(
                    dynamic_result_meta.get("crawl_batch_failed", 0) or 0),
                "dynamic_warning_count": max(
                    int(dynamic_result_meta.get("warning_count", 0) or 0),
                    int(bool(dynamic_warning)),
                ),
                "dynamic_target_metrics": list(
                    dynamic_result_meta.get("crawl_target_metrics", []) or []),
                "dynamic_browser_path": str(
                    dynamic_result_meta.get("browser_path", "") or ""),
                "dynamic_browser_version": str(
                    dynamic_result_meta.get("browser_version", "") or ""),
                "dynamic_warning": dynamic_warning,
            }
        if engine == "katana":
            try:
                crawl_results = []
                if entry_urls_list:
                    crawl_results.append(services.katana_spider(
                        entry_urls_list,
                        scope_domains=self.scope_domain,
                        task_id=self.task_id,
                        evidence_callback=self.save_site_spider_all_url_callback,
                        domain_callback=self.save_site_spider_domain_evidence,
                        entry_callback=self.save_site_spider_entry_candidate,
                        crawl_profile="normal",
                        stage_name=stage_name,
                    ))
                if restricted_entry_urls_list:
                    crawl_results.append(services.katana_spider(
                        restricted_entry_urls_list,
                        scope_domains=self.scope_domain,
                        task_id=self.task_id,
                        evidence_callback=self.save_site_spider_all_url_callback,
                        domain_callback=self.save_site_spider_domain_evidence,
                        entry_callback=self.save_site_spider_entry_candidate,
                        crawl_profile="restricted",
                        stage_name=stage_name,
                    ))
                base_crawl_result = self.merge_crawl_results(crawl_results)
                self.runtime_artifact_seed_urls.update(
                    runtime_artifact_script_seed_urls(base_crawl_result))
                self.runtime_artifact_seed_map_urls.update(
                    runtime_artifact_map_seed_urls(base_crawl_result))
                dynamic_source_groups = entry_urls_list + restricted_entry_urls_list
                if dynamic_source_groups and getattr(
                    Config, "KATANA_DYNAMIC_BROWSER_ENABLE", True
                ):
                    restricted_origins = {
                        self.canonical_origin(group[0])
                        for group in restricted_entry_urls_list if group
                    }
                    dynamic_targets, dynamic_selection_meta = (
                        self.build_dynamic_spider_targets(
                            dynamic_source_groups,
                            quality_map,
                            base_crawl_result,
                            restricted_origins=restricted_origins,
                        )
                    )
                    self.runtime_artifact_full_targets = (
                        self.build_runtime_artifact_full_targets(
                            dynamic_selection_meta)
                    )
                    self.runtime_artifact_targets = (
                        self.build_runtime_artifact_targets(dynamic_selection_meta)
                    )
                    self.runtime_artifact_target_reasons = dict(
                        dynamic_selection_meta.get(
                            "runtime_title_target_reasons", {}) or
                        dynamic_selection_meta.get("target_reasons", {}) or {})
                    dynamic_selection_meta["site_signal_count"] = (
                        self.persist_dynamic_browser_site_signals(
                            dynamic_selection_meta)
                    )
                    if dynamic_targets:
                        dynamic_before_all_url_count = len(self.site_spider_all_url_set)
                        dynamic_before_domain_count = len(self.site_spider_domain_set)
                        base_entry_urls = set(base_crawl_result.get("urls", []) or [])
                        try:
                            dynamic_result = services.katana_spider(
                                dynamic_targets,
                                scope_domains=self.scope_domain,
                                task_id=self.task_id,
                                evidence_callback=self.save_site_spider_all_url_callback,
                                domain_callback=self.save_site_spider_domain_evidence,
                                entry_callback=self.save_site_spider_entry_candidate,
                                crawl_profile="dynamic",
                                stage_name=stage_name,
                            )
                            dynamic_result_meta = dict(
                                dynamic_result.get("meta", {}) or {})
                            self.runtime_artifact_seed_urls.update(
                                runtime_artifact_script_seed_urls(dynamic_result))
                            self.runtime_artifact_seed_map_urls.update(
                                runtime_artifact_map_seed_urls(dynamic_result))
                            dynamic_result_meta.update({
                                "unique_all_url_count": max(
                                    len(self.site_spider_all_url_set) -
                                    dynamic_before_all_url_count,
                                    0,
                                ),
                                "unique_domain_count": max(
                                    len(self.site_spider_domain_set) -
                                    dynamic_before_domain_count,
                                    0,
                                ),
                                "unique_entry_url_count": len(
                                    set(dynamic_result.get("urls", []) or []) -
                                    base_entry_urls
                                ),
                            })
                            dynamic_warning = "; ".join(dict.fromkeys(
                                str(value).strip()
                                for value in dynamic_result_meta.get("warnings", []) or []
                                if str(value).strip()
                            ))
                            crawl_results.append(dynamic_result)
                        except Exception as e:
                            dynamic_error = str(e)
                            dynamic_warning = dynamic_error
                            logger.warning(
                                "katana dynamic browser failed task_id:{} error:{}".format(
                                    self.task_id, e))
                            logger.exception(e)
                crawl_result = self.merge_crawl_results(crawl_results)
                crawl_meta = crawl_result.get("meta", {}) or {}
                crawl_meta.update(dynamic_stage_fields())
                if crawl_meta.get("partial_error"):
                    crawler_error = str(crawl_meta.get("partial_error"))
                wih_targets = self.build_wih_targets_from_katana(crawl_result)
                domain_sources = crawl_result.get("domain_sources", {}) or {}
                domain_entry_urls = crawl_result.get("domain_entry_urls", {}) or {}
                url_sources = crawl_result.get("url_sources", {}) or {}
                entry_url_sources = crawl_result.get("entry_url_sources", {}) or {}
                all_url_count = 0
                for absolute_url in crawl_result.get("all_urls", []):
                    if self.save_site_spider_all_url_evidence(
                        absolute_url,
                        source_url=url_sources.get(absolute_url, ""),
                    ):
                        all_url_count += 1

                for domain in crawl_result.get("domains", []):
                    self.save_site_spider_domain_evidence(
                        domain,
                        source_url=domain_sources.get(domain, ""),
                        discovered_url=domain_entry_urls.get(domain, ""),
                    )
                    self.site_spider_domain_set.add(domain)
                    if domain_entry_urls.get(domain):
                        self.site_spider_domain_url_map[domain] = domain_entry_urls[domain]

                for url in crawl_result.get("urls", []):
                    sources = entry_url_sources.get(url, [])
                    self.entry_tracker.register_url(
                        url,
                        source_urls=sources,
                        collector="katana",
                    )
                    if url in self.page_url_set:
                        continue
                    spider_urls.append(url)
                    self.page_url_set.add(url)
                self.base_update_task.update_stage_progress(
                    stage_name,
                    {
                        "input_count": len(entry_urls_list) + len(restricted_entry_urls_list),
                        "output_count": len(spider_urls),
                        "new_domain_count": len(self.site_spider_domain_set),
                        "discovered_domain_count": len(self.site_spider_domain_set),
                        "all_url_count": len(self.site_spider_all_url_set),
                        "wih_target_count": len(wih_targets),
                        "wih_entry_target_count": self.site_spider_wih_entry_target_count,
                        "wih_resource_target_count": self.site_spider_wih_resource_target_count,
                        "skipped_edge": skipped_edge_sites,
                        "skipped_low_quality": skipped_low_quality_sites,
                        "skipped_duplicate": skipped_duplicate_sites,
                        "skipped_quality_reasons": skipped_quality_reasons,
                        "crawler_engine": "katana",
                        "restricted_target_count": len(restricted_entry_urls_list),
                        **dynamic_stage_fields(),
                    },
                )
            except Exception as e:
                crawler_error = str(e)
                logger.warning("katana spider failed, skip legacy spider fallback: {}".format(e))
                logger.exception(e)

        if len(spider_urls) > 0:
            logger.info("spider_urls {} task_id:{}".format(len(spider_urls), self.task_id))
            probe_summary = self.probe_entry_urls(
                spider_urls,
                source_map=entry_url_sources,
                collector="katana",
                discovery_source="katana_all_url",
                url_type="js_web_entry",
            )
            risky_url_count = probe_summary.get("risky_url_count", 0)
            if risky_url_count:
                logger.info("skip risky crawler urls:{} task_id:{}".format(risky_url_count, self.task_id))

        if len(str(self.task_id)) == 24:
            CommonTask(self.task_id).insert_task_stat()
        entry_counts = self.entry_tracker.counts()
        summary = {
            "input_count": len(entry_urls_list) + len(restricted_entry_urls_list),
            "output_count": len(spider_urls),
            "skipped_edge": skipped_edge_sites,
            "skipped_low_quality": skipped_low_quality_sites,
            "skipped_duplicate": skipped_duplicate_sites,
            "skipped_quality_reasons": skipped_quality_reasons,
            "risky_url_count": risky_url_count if len(spider_urls) > 0 else 0,
            "entry_initial_probe_error_count": probe_summary.get(
                "initial_probe_error_count", 0),
            "entry_retry_probe_count": probe_summary.get(
                "retry_probe_count", 0),
            "entry_retry_recovered_count": probe_summary.get(
                "retry_recovered_count", 0),
            "entry_probe_error_count": probe_summary.get(
                "probe_error_count", 0),
            "entry_retry_deferred_count": probe_summary.get(
                "retry_deferred_count", 0),
            "entry_external_redirect_count": probe_summary.get(
                "external_redirect_count", 0),
            "new_domain_count": len(self.site_spider_domain_set),
            "discovered_domain_count": len(self.site_spider_domain_set),
            "all_url_count": len(self.site_spider_all_url_set),
            "wih_target_count": len(self.site_spider_wih_targets),
            "wih_entry_target_count": self.site_spider_wih_entry_target_count,
            "wih_resource_target_count": self.site_spider_wih_resource_target_count,
            "crawler_engine": "katana" if engine == "katana" else "legacy",
            "restricted_target_count": len(restricted_entry_urls_list),
            "quality_cluster_count": int(
                quality_cluster_summary.get("cluster_count", 0) or 0),
            "quality_collapsed_count": int(
                quality_cluster_summary.get("collapsed_count", 0) or 0),
            **dynamic_stage_fields(),
            "crawler_error": crawler_error,
        }
        summary.update(crawl_meta)
        if crawler_error:
            summary.update({
                "_stage_status": "partial",
                "error": crawler_error,
                "error_count": 1,
                "partial_reason": "katana_failed",
            })
        elif dynamic_warning:
            summary.update({
                "_stage_status": "done_with_warnings",
                "completion_state": "done_with_warnings",
                "warning": dynamic_warning,
            })
        summary.update({
            "entry_candidate_count": entry_counts.get("candidate_count", 0),
            "entry_alive_count": entry_counts.get("alive_count", 0),
            "entry_pending_count": entry_counts.get("pending_count", 0),
            "entry_external_redirect_total": entry_counts.get(
                "external_redirect_count", 0),
        })
        return summary

    def runtime_artifact_ready(self):
        return bool(
            getattr(Config, "RUNTIME_ARTIFACT_ENABLE", False) and
            getattr(self, "runtime_artifact_targets", [])
        )

    def run_runtime_artifact(self, stage_name=WebSiteFetchStatus.RUNTIME_ARTIFACT):
        targets = list(dict.fromkeys(getattr(
            self, "runtime_artifact_targets", []) or []))
        if not getattr(Config, "RUNTIME_ARTIFACT_ENABLE", False):
            return {
                "input_count": len(targets),
                "output_count": 0,
                "skip_reason": "runtime_artifact_disabled",
            }
        if not targets:
            return {
                "input_count": 0,
                "output_count": 0,
                "skip_reason": "no_dynamic_targets",
            }
        artifact_targets = list(dict.fromkeys(getattr(
            self, "runtime_artifact_full_targets", []) or []))
        try:
            return services.runtime_artifact_collect(
                task_id=self.task_id,
                targets=targets,
                artifact_targets=artifact_targets,
                seed_js_urls=sorted(getattr(
                    self, "runtime_artifact_seed_urls", set()) or set()),
                seed_map_urls=sorted(getattr(
                    self, "runtime_artifact_seed_map_urls", set()) or set()),
                target_reasons=dict(getattr(
                    self, "runtime_artifact_target_reasons", {}) or {}),
                stage_name=stage_name,
            )
        except Exception as exc:
            logger.warning(
                "runtime artifact collection failed task_id:{} error:{}".format(
                    self.task_id, exc))
            logger.exception(exc)
            return {
                "input_count": len(targets),
                "output_count": 0,
                "_stage_status": "done_with_warnings",
                "completion_state": "done_with_warnings",
                "warning": str(exc),
                "warning_count": 1,
                "matching_pipeline_unchanged": True,
            }

    def fetch_site(self):
        # ***站点信息获取***
        site_identify = bool(self.options.get(WebSiteFetchOption.SITE_IDENTIFY))
        quality_map = self.load_site_spider_quality()
        fetch_targets = []
        seen_targets = set()
        self.fetch_site_skipped_low_quality = 0
        self.fetch_site_skipped_duplicate = 0
        for raw_site in self.sites:
            raw_site = str(raw_site or "").strip()
            if not raw_site:
                continue
            try:
                normalized = utils.normal_url(raw_site) or raw_site
                parsed = urlparse(normalized)
            except (TypeError, ValueError):
                self.fetch_site_skipped_low_quality += 1
                continue
            origin = self.canonical_origin(normalized)
            allowed, _ = self.fetch_site_target_allowed(
                origin, quality_map, site_identify=site_identify)
            is_root_target = parsed.path in ("", "/") and not parsed.query
            if not allowed and is_root_target:
                self.fetch_site_skipped_low_quality += 1
                continue
            target = origin if is_root_target else normalized
            if target in seen_targets:
                self.fetch_site_skipped_duplicate += 1
                continue
            seen_targets.add(target)
            fetch_targets.append(target)

        self.site_info_list = services.fetch_site(
            fetch_targets,
            observer_ward_enable=site_identify,
            task_id=self.task_id,
            on_batch=self.save_site_info_batch,
        )
        self.fetch_site_meta = dict(getattr(self.site_info_list, "meta", {}) or {})
        fetched_sites = set()
        seen_available_sites = set(self.available_sites)
        for site_info in self.site_info_list:
            curr_site = site_info["site"]
            if curr_site and curr_site not in seen_available_sites:
                self.available_sites.append(curr_site)
                seen_available_sites.add(curr_site)
            if curr_site:
                fetched_sites.add(curr_site)

        # find_site/asset_seed_probe already confirmed these URLs with httpx and
        # saved them to site/asset_seed_alive. Do not let the older FetchSite
        # request path become the only gate for katana/ffuf/WIH.
        for curr_site in fetch_targets:
            curr_site = str(curr_site or "").strip()
            if curr_site and curr_site not in seen_available_sites:
                self.available_sites.append(curr_site)
                seen_available_sites.add(curr_site)
        summary = {
            "input_count": len(self.sites),
            "output_count": len(self.available_sites),
            "probe_input_count": len(fetch_targets),
            "skipped_low_quality": self.fetch_site_skipped_low_quality,
            "skipped_duplicate": self.fetch_site_skipped_duplicate,
            "fetch_site_count": len(fetched_sites),
            "prefilled_site_count": max(0, len(self.available_sites) - len(fetched_sites)),
        }
        summary.update(self.fetch_site_meta)
        summary["input_count"] = len(self.sites)
        summary["output_count"] = len(self.available_sites)
        return summary

    def post_route_enrichment(self, route_urls):
        summary = {
            "enabled": bool(getattr(
                Config, "POST_ROUTE_ENRICHMENT_ENABLE", True)),
            "candidate_count": len(set(route_urls or [])),
            "crawl_target_count": 0,
            "crawl_url_count": 0,
            "wih_target_count": 0,
            "wih_record_count": 0,
            "error_count": 0,
            "warnings": [],
        }
        if not summary["enabled"] or not route_urls:
            return summary
        if not self.options.get(WebSiteFetchOption.SITE_SPIDER):
            return summary

        crawl_limit = max(int(getattr(
            Config, "POST_ROUTE_CRAWL_MAX_TARGETS", 24) or 0), 0)
        targets = []
        seen = set()
        for value in route_urls:
            value = utils.normal_url(str(value or "").strip())
            if not value or value in seen:
                continue
            parsed = urlparse(value)
            host = (parsed.hostname or "").strip(".").lower()
            if not host or parsed.scheme not in ("http", "https"):
                continue
            try:
                address = ipaddress.ip_address(host.strip("[]"))
                if not address.is_global:
                    continue
            except ValueError:
                if self.scope_domain and not domain_in_scope_domain(
                        host, self.scope_domain):
                    continue
            seen.add(value)
            targets.append(value)
            if crawl_limit and len(targets) >= crawl_limit:
                break

        summary["crawl_target_count"] = len(targets)
        if not targets:
            return summary

        crawl_result = {}
        try:
            crawl_result = services.katana_spider(
                [[value] for value in targets],
                scope_domains=self.scope_domain,
                task_id=self.task_id,
                evidence_callback=self.save_site_spider_all_url_callback,
                domain_callback=self.save_site_spider_domain_evidence,
                entry_callback=self.save_site_spider_entry_candidate,
                crawl_profile="normal",
                stage_name=WebSiteFetchStatus.FILE_LEAK,
            ) or {}
            summary["crawl_url_count"] = len(set(
                list(crawl_result.get("urls", []) or []) +
                list(crawl_result.get("all_urls", []) or [])
            ))
            crawl_meta = dict(crawl_result.get("meta", {}) or {})
            for warning in crawl_meta.get("warnings", []) or []:
                warning = str(warning or "").strip()
                if warning:
                    summary["warnings"].append(warning)
        except Exception as e:
            summary["error_count"] += 1
            summary["warnings"].append("post-route katana: {}".format(e))

        if not self.options.get(WebSiteFetchOption.Info_Hunter):
            return summary

        wih_limit = max(int(getattr(
            Config, "POST_ROUTE_WIH_MAX_TARGETS", 60) or 0), 0)
        wih_targets = []
        seen_wih_targets = set()

        def add_wih_target(value):
            value = utils.normal_url(str(value or "").strip())
            if not value or value in seen_wih_targets:
                return
            parsed = urlparse(value)
            host = (parsed.hostname or "").strip(".").lower()
            if not host or parsed.scheme not in ("http", "https"):
                return
            try:
                address = ipaddress.ip_address(host.strip("[]"))
                if not address.is_global:
                    return
            except ValueError:
                if self.scope_domain and not domain_in_scope_domain(
                        host, self.scope_domain):
                    return
            seen_wih_targets.add(value)
            wih_targets.append(value)

        for value in targets:
            add_wih_target(value)
        for value in crawl_result.get("urls", []) or []:
            add_wih_target(value)
        for value in (
                list(crawl_result.get("crawler_urls", []) or []) +
                list(crawl_result.get("all_urls", []) or [])):
            path = urlparse(str(value or "")).path.lower()
            if os.path.splitext(path)[1] in WIH_SCRIPT_RESOURCE_EXTENSIONS:
                add_wih_target(value)
        if wih_limit:
            wih_targets = wih_targets[:wih_limit]
        summary["wih_target_count"] = len(wih_targets)

        batch_size = max(1, int(getattr(Config, "WIH_BATCH_SIZE", 50) or 50))
        for start in range(0, len(wih_targets), batch_size):
            if self.base_update_task.is_terminal():
                summary["warnings"].append("post-route WIH stopped with task")
                break
            try:
                records = services.run_wih(
                    wih_targets[start:start + batch_size], task_id=self.task_id)
                inserted, _ = self.save_wih_records(
                    records,
                    extra_fields={"wih_target_source": "ffuf_route"},
                )
                summary["wih_record_count"] += inserted
                result_meta = dict(getattr(records, "meta", {}) or {})
                if result_meta.get("error"):
                    summary["error_count"] += 1
                    summary["warnings"].append(str(result_meta["error"]))
            except Exception as e:
                summary["error_count"] += 1
                summary["warnings"].append("post-route WIH: {}".format(e))
        summary["warnings"] = list(dict.fromkeys(summary["warnings"]))[:5]
        return summary

    def file_leak(self):
        # Freeze the pre-scan asset set before fileleak rows are streamed in.
        # Confirmed paths can then be classified as genuinely new entries.
        self.entry_tracker.snapshot_prior_assets()
        saved_urls = {
            item.get("url")
            for item in utils.conn_db("fileleak").find(
                {"task_id": self.task_id}, {"_id": 0, "url": 1})
            if item.get("url")
        }

        def promote_route_sites(pages):
            route_urls = {}
            for page in pages or []:
                item = page.dump_json()
                if not item.get("route_promotion_eligible"):
                    continue
                origin = utils.canonical_site_url(
                    item.get("site") or getattr(page, "site", ""))
                url = str(item.get("url") or "").strip()
                if not origin or not url:
                    continue
                route_urls.setdefault(origin, set()).add(url)

            if not route_urls:
                return 0, []

            collection = utils.conn_db("site")
            origins = sorted(route_urls)
            existing_by_origin = {}
            existing_query = formal_site_query({
                "task_id": self.task_id,
                "$or": [
                    {"canonical_site": {"$in": origins}},
                    {"site": {"$in": origins}},
                ],
            })
            for existing in collection.find(existing_query, {
                "_id": 1,
                "site": 1,
                "canonical_site": 1,
                "route_confirmed_urls": 1,
                "asset_score": 1,
            }):
                existing_origin = (
                    existing.get("canonical_site") or
                    utils.canonical_site_url(existing.get("site"))
                )
                if existing_origin:
                    existing_by_origin[existing_origin] = existing

            operations = []
            enrichment_urls = set()
            for origin, urls in route_urls.items():
                existing = existing_by_origin.get(origin)
                if not existing:
                    continue
                enrichment_urls.update(urls)
                merged_urls = list(dict.fromkeys(
                    list(existing.get("route_confirmed_urls") or []) + sorted(urls)
                ))[:20]
                score = max(int(existing.get("asset_score") or 0), 40)
                operations.append(UpdateOne(
                    {"_id": existing["_id"]},
                    {
                        "$set": {
                            "quality_state": "route_confirmed",
                            "display_eligible": True,
                            "pipeline_mode": "full",
                            "quality_reason": "route_discovery_confirmed",
                            "quality_evidence": ["independent_route_response"],
                            "quality_version": SITE_QUALITY_VERSION,
                            "route_discovery_status": "confirmed",
                            "route_confirmed_urls": merged_urls,
                            "route_hit_count": len(merged_urls),
                            "asset_score": score,
                            "asset_level": "high" if score >= 70 else "medium",
                        },
                        "$addToSet": {"asset_reasons": "route_confirmed"},
                    },
                ))
            if not operations:
                return 0, sorted(enrichment_urls)
            result = collection.bulk_write(operations, ordered=False)
            return int(result.modified_count or 0), sorted(enrichment_urls)

        def save_pages(pages):
            hit_count = 0
            for page in pages:
                item = page.dump_json()
                item["task_id"] = self.task_id
                if not item.get("site"):
                    item["site"] = getattr(page, "site", "")
                if not item.get("url"):
                    continue
                query = {"task_id": self.task_id, "url": item.get("url")}
                utils.conn_db('fileleak').update_one(query, {"$set": item}, upsert=True)
                saved_urls.add(item["url"])
                hit_count += 1
            self.base_update_task.update_stage_progress(
                WebSiteFetchStatus.FILE_LEAK,
                {
                    "input_count": len(sites),
                    "output_count": len(saved_urls),
                },
            )
            self.base_update_task.update_task_field(
                "statistic.fileleak_cnt", len(saved_urls))
            return hit_count

        sites = self.file_leak_sites()
        pages = services.file_leak(
            sites,
            utils.load_file(Config.FILE_LEAK_TOP_2k),
            gen_dict=Config.FILE_LEAK_GEN_DYNAMIC,
            task_id=self.task_id,
            on_result=save_pages,
            target_profiles=self.file_leak_target_profiles,
            target_route_keys=self.file_leak_target_route_keys,
        )
        ffuf_meta = dict(getattr(pages, "meta", {}) or {})
        removed_urls = list(getattr(pages, "removed_urls", []) or [])
        if removed_urls:
            for start in range(0, len(removed_urls), 500):
                batch = removed_urls[start:start + 500]
                utils.conn_db('fileleak').delete_many({
                    "task_id": self.task_id,
                    "url": {"$in": batch},
                })
            saved_urls.difference_update(removed_urls)

        # Re-upsert the final kept rows so template annotations survive the
        # task-level de-duplication pass.
        save_pages(pages)
        route_promoted_site_count, promoted_route_urls = promote_route_sites(pages)
        route_enrichment = self.post_route_enrichment(promoted_route_urls)
        entry_registered_count = 0
        if getattr(Config, "FFUF_PROMOTE_TO_ENTRY", False):
            for page in pages:
                item = page.dump_json()
                if not item.get("entry_eligible"):
                    continue
                entry = self.entry_tracker.register_path_entry(
                    item, collector="ffuf")
                if entry.get("_ffuf_registered_new"):
                    entry_registered_count += 1
        filtered_count = int(ffuf_meta.get("site_filtered_count", 0) or 0)
        filtered_count += int(ffuf_meta.get("task_filtered_count", 0) or 0)
        filtered_count += int(ffuf_meta.get("baseline_filtered_count", 0) or 0)
        timeout_count = int(ffuf_meta.get("timeout_count", 0) or 0)
        failure_count = int(ffuf_meta.get("failure_count", 0) or 0)
        exhausted_site_count = int(
            ffuf_meta.get("exhausted_site_count", 0) or 0)
        retryable_failure_site_count = int(
            ffuf_meta.get("retryable_failure_site_count", 0) or 0)
        transient_verify_count = int(
            ffuf_meta.get("transient_verify_count", 0) or 0)
        redirect_template_count = int(
            ffuf_meta.get("redirect_template_count", 0) or 0)
        redirect_resolved_count = int(
            ffuf_meta.get("redirect_resolved_count", 0) or 0)
        warnings = list(ffuf_meta.get("warnings", []) or [])
        summary = {
            "input_count": len(sites),
            "output_count": len(saved_urls),
            "filtered_count": filtered_count,
            "error_count": (
                timeout_count + failure_count + transient_verify_count +
                exhausted_site_count),
            "completed_site_count": int(ffuf_meta.get("completed_site_count", 0) or 0),
            "skipped_completed_site_count": int(
                ffuf_meta.get("skipped_completed_site_count", 0) or 0),
            "timeout_count": timeout_count,
            "failure_count": failure_count,
            "exhausted_site_count": exhausted_site_count,
            "retryable_failure_site_count": retryable_failure_site_count,
            "stopped_count": int(ffuf_meta.get("stopped_count", 0) or 0),
            "site_filtered_count": int(ffuf_meta.get("site_filtered_count", 0) or 0),
            "task_filtered_count": int(ffuf_meta.get("task_filtered_count", 0) or 0),
            "baseline_filtered_count": int(
                ffuf_meta.get("baseline_filtered_count", 0) or 0),
            "dynamic_word_count": int(ffuf_meta.get("dynamic_word_count", 0) or 0),
            "dynamic_rejected_count": int(
                ffuf_meta.get("dynamic_rejected_count", 0) or 0),
            "site_scoped_candidate_target_count": int(
                ffuf_meta.get("site_scoped_candidate_target_count", 0) or 0),
            "site_scoped_candidate_word_count": int(
                ffuf_meta.get("site_scoped_candidate_word_count", 0) or 0),
            "task_wide_domain_word_removed_count": int(
                ffuf_meta.get("task_wide_domain_word_removed_count", 0) or 0),
            "site_scoped_target_count": int(
                ffuf_meta.get("site_scoped_target_count", 0) or 0),
            "site_scoped_scan_word_count": int(
                ffuf_meta.get("site_scoped_scan_word_count", 0) or 0),
            "site_scoped_result_count": int(
                ffuf_meta.get("site_scoped_result_count", 0) or 0),
            "site_scoped_meaningful_result_count": int(
                ffuf_meta.get("site_scoped_meaningful_result_count", 0) or 0),
            "normal_target_count": int(ffuf_meta.get("normal_target_count", 0) or 0),
            "low_info_target_count": int(
                ffuf_meta.get("low_info_target_count", 0) or 0),
            "edge_limited_target_count": int(
                ffuf_meta.get("edge_limited_target_count", 0) or 0),
            "restricted_target_count": int(
                ffuf_meta.get("restricted_target_count", 0) or 0),
            "priority_scan_word_count": int(
                ffuf_meta.get("priority_scan_word_count", 0) or 0),
            "priority_result_count": int(
                ffuf_meta.get("priority_result_count", 0) or 0),
            "priority_meaningful_result_count": int(
                ffuf_meta.get("priority_meaningful_result_count", 0) or 0),
            "low_info_short_scan_count": int(
                ffuf_meta.get("low_info_short_scan_count", 0) or 0),
            "low_info_escalated_count": int(
                ffuf_meta.get("low_info_escalated_count", 0) or 0),
            "low_info_skipped_full_word_count": int(
                ffuf_meta.get("low_info_skipped_full_word_count", 0) or 0),
            "edge_limited_short_scan_count": int(
                ffuf_meta.get("edge_limited_short_scan_count", 0) or 0),
            "edge_limited_escalated_count": int(
                ffuf_meta.get("edge_limited_escalated_count", 0) or 0),
            "edge_limited_skipped_full_word_count": int(
                ffuf_meta.get("edge_limited_skipped_full_word_count", 0) or 0),
            "restricted_short_scan_count": int(
                ffuf_meta.get("restricted_short_scan_count", 0) or 0),
            "restricted_escalated_count": int(
                ffuf_meta.get("restricted_escalated_count", 0) or 0),
            "restricted_skipped_full_word_count": int(
                ffuf_meta.get("restricted_skipped_full_word_count", 0) or 0),
            "pending_site_count": int(
                ffuf_meta.get("pending_site_count", 0) or 0),
            "slice_site_count": int(
                ffuf_meta.get("slice_site_count", 0) or 0),
            "deferred_site_count": int(
                ffuf_meta.get("deferred_site_count", 0) or 0),
            "continuation_required": bool(
                ffuf_meta.get("continuation_required")),
            "route_candidate_target_count": int(
                ffuf_meta.get("route_candidate_target_count", 0) or 0),
            "route_cluster_count": int(
                ffuf_meta.get("route_cluster_count", 0) or 0),
            "route_cluster_target_count": int(
                ffuf_meta.get("route_cluster_target_count", 0) or 0),
            "route_sample_target_count": int(
                ffuf_meta.get("route_sample_target_count", 0) or 0),
            "route_dedupe_reused_target_count": int(
                ffuf_meta.get("route_dedupe_reused_target_count", 0) or 0),
            "route_dedupe_saved_word_count": int(
                ffuf_meta.get("route_dedupe_saved_word_count", 0) or 0),
            "route_dedupe_split_cluster_count": int(
                ffuf_meta.get("route_dedupe_split_cluster_count", 0) or 0),
            "route_dedupe_fallback_target_count": int(
                ffuf_meta.get("route_dedupe_fallback_target_count", 0) or 0),
            "verified_result_count": int(
                ffuf_meta.get("verified_result_count", 0) or 0),
            "unverified_result_count": int(
                ffuf_meta.get("unverified_result_count", 0) or 0),
            "sso_protected_count": int(
                ffuf_meta.get("sso_protected_count", 0) or 0),
            "protected_result_count": int(
                ffuf_meta.get("protected_result_count", 0) or 0),
            "entry_candidate_count": int(
                ffuf_meta.get("entry_candidate_count", 0) or 0),
            "resource_clue_count": int(
                ffuf_meta.get("resource_clue_count", 0) or 0),
            "non_entry_result_count": int(
                ffuf_meta.get("non_entry_result_count", 0) or 0),
            "stale_result_count": int(
                ffuf_meta.get("stale_result_count", 0) or 0),
            "transient_verify_count": transient_verify_count,
            "second_level_input_count": int(
                ffuf_meta.get("second_level_input_count", 0) or 0),
            "second_level_result_count": int(
                ffuf_meta.get("second_level_result_count", 0) or 0),
            "entry_registered_count": entry_registered_count,
            "route_promoted_site_count": route_promoted_site_count,
            "route_enrichment_candidate_count": route_enrichment["candidate_count"],
            "route_enrichment_crawl_target_count": route_enrichment["crawl_target_count"],
            "route_enrichment_crawl_url_count": route_enrichment["crawl_url_count"],
            "route_enrichment_wih_target_count": route_enrichment["wih_target_count"],
            "route_enrichment_wih_record_count": route_enrichment["wih_record_count"],
            "route_enrichment_error_count": route_enrichment["error_count"],
            "entry_promotion_enabled": bool(getattr(
                Config, "FFUF_PROMOTE_TO_ENTRY", False)),
            "redirect_template_count": redirect_template_count,
            "redirect_group_count": int(
                ffuf_meta.get("redirect_group_count", 0) or 0),
            "redirect_resolved_count": redirect_resolved_count,
            "redirect_resolution_error_count": int(
                ffuf_meta.get("redirect_resolution_error_count", 0) or 0),
        }
        if (
            timeout_count or failure_count or transient_verify_count or
            exhausted_site_count
        ):
            summary.update({
                "_stage_status": "partial",
                "partial_reason": "ffuf_partial_failure",
                "warning": "; ".join(warnings[:5]) or (
                    "ffuf had incomplete site scans or transient verification responses"),
            })
        elif summary["continuation_required"]:
            summary.update({
                "_stage_status": "deferred",
                "completion_state": "deferred",
            })
        elif route_enrichment["error_count"]:
            summary.update({
                "_stage_status": "done_with_warnings",
                "completion_state": "done_with_warnings",
                "warning": "; ".join(route_enrichment["warnings"]),
            })
        return summary

    @property
    def poc_sites(self):
        if self._poc_sites is None:
            self._poc_sites = set()
            for x in self.available_sites:
                cut_target = utils.url.cut_filename(x)
                if cut_target:
                    self._poc_sites.add(cut_target)

        return self._poc_sites

    @property
    def active_poc_sites(self):
        visible = set()
        for item in utils.conn_db("site").find(
                visible_site_query({"task_id": self.task_id}), {
                    "site": 1,
                    "quality_state": 1,
                    "route_confirmed_urls": 1,
                }):
            target = utils.url.cut_filename(item.get("site", ""))
            if target:
                visible.add(target)
            if item.get("quality_state") == "route_confirmed":
                for route_url in (item.get("route_confirmed_urls") or [])[:3]:
                    normalized = utils.normal_url(route_url)
                    if normalized:
                        visible.add(normalized)
        return visible

    def file_leak_sites(self):
        poc_sites = set(self.poc_sites)
        site_docs = list(utils.conn_db("site").find(
            formal_site_query({"task_id": self.task_id}),
            {
                "site": 1, "tag": 1, "cdn": 1, "is_cdn": 1, "waf": 1,
                "waf_name": 1, "waf_strength": 1, "is_waf": 1,
                "edge": 1, "edge_name": 1, "webserver": 1, "cname": 1,
                "canonical_site": 1, "ip": 1, "resolved_ips": 1, "headers": 1,
                "http_server": 1, "body_hash": 1, "content_type": 1,
                "location": 1, "favicon": 1,
                "status": 1, "status_code": 1, "title": 1,
                "body_length": 1, "content_length": 1,
                "finger": 1, "tech": 1,
                "quality_state": 1, "display_eligible": 1,
                "pipeline_mode": 1, "quality_reason": 1,
            }
        ))

        # A resumed fetch_site stage can skip roots whose HTTP/fingerprint
        # evidence is already complete. Rebuild the FFUF baseline from stored
        # formal evidence so low-information roots still receive their bounded
        # route probe instead of disappearing with the in-memory target list.
        for item in site_docs:
            site = utils.url.cut_filename(item.get("site", ""))
            if site:
                poc_sites.add(site)
        if not poc_sites:
            return []

        docs_by_site = {}
        for item in site_docs:
            site = utils.url.cut_filename(item.get("site", ""))
            if site and site in poc_sites:
                docs_by_site.setdefault(site, []).append(item)

        allowed = []
        self.file_leak_target_profiles = {}
        self.file_leak_target_route_keys = {}
        skipped_cdn_waf = 0
        profile_counts = {
            "normal": 0,
            "low_info": 0,
            "edge_limited": 0,
            "restricted": 0,
        }
        missing_doc_count = 0
        for site in sorted(poc_sites):
            docs = docs_by_site.get(site) or []
            if not docs:
                # available_sites only contains origins already confirmed by
                # the HTTP probe. Keep legacy rows whose details were not saved.
                profile = "normal"
                missing_doc_count += 1
            else:
                profile = merge_directory_scan_profiles(docs)
            if profile is None:
                skipped_cdn_waf += 1
                continue
            allowed.append(site)
            site_key = site.rstrip("/")
            self.file_leak_target_profiles[site_key] = profile
            route_key = merge_directory_scan_route_keys(docs)
            if route_key:
                self.file_leak_target_route_keys[site_key] = route_key
            profile_counts[profile] += 1

        logger.info(
            "file_leak target filter task_id:{} poc:{} allowed:{} normal:{} low_info:{} edge_limited:{} restricted:{} route_candidates:{} route_clusters:{} missing_doc:{} skip_edge:{}".format(
                self.task_id,
                len(poc_sites),
                len(allowed),
                profile_counts["normal"],
                profile_counts["low_info"],
                profile_counts["edge_limited"],
                profile_counts["restricted"],
                len(self.file_leak_target_route_keys),
                len(set(self.file_leak_target_route_keys.values())),
                missing_doc_count,
                skipped_cdn_waf,
            )
        )
        return allowed

    def risk_cruising(self, npoc_service_target_set: set):
        # *** 运行PoC任务, 需要自己在外层手动调用
        poc_config = self.options.get("poc_config", [])
        plugins = []
        for info in poc_config:
            if not info.get("enable"):
                continue
            plugins.append(info["plugin_name"])

        poc_targets = self.active_poc_sites

        if npoc_service_target_set is not None:
            poc_targets = self.active_poc_sites | npoc_service_target_set

        result = run_risk_cruising(plugins=plugins, targets=poc_targets)
        for item in result:
            item["task_id"] = self.task_id
            item["save_date"] = utils.curr_date()
            utils.conn_db('vuln').insert_one(item)

    def nuclei_scan(self):
        if not is_nuclei_scan_enabled(self.options):
            logger.warning("skip nuclei_scan because explicit confirmation is missing, task_id:{}".format(
                self.task_id))
            return {
                "input_count": 0,
                "output_count": 0,
                "skipped": True,
                "skip_reason": "missing_explicit_confirm",
            }
        targets = self.active_poc_sites
        logger.info("start nuclei_scan， poc_sites:{}".format(len(targets)))
        scan_results = nuclei_scan(list(targets))
        for item in scan_results:
            item["task_id"] = self.task_id
            item["save_date"] = utils.curr_date()
            utils.conn_db('nuclei_result').insert_one(item)

        logger.info("end nuclei_scan， result:{}".format(len(scan_results)))
        return {
            "input_count": len(targets),
            "output_count": len(scan_results),
        }

    def run_func(self, name: str, func: callable):
        logger.info("start run {}, {}".format(name, self.__str__()))
        self.base_update_task.update_task_field("status", name)
        if not self.base_update_task.start_stage(name):
            logger.warning("skip run {} because task is terminal, task_id:{}".format(name, self.task_id))
            return {}

        t1 = time.time()
        summary = None
        try:
            summary = func()
        except Exception as e:
            elapse = time.time() - t1
            self.base_update_task.fail_stage(name, e, elapsed=elapse)
            raise
        elapse = time.time() - t1
        summary, stage_status = split_stage_summary(summary)
        self.base_update_task.update_services(
            name, elapse, summary=summary, status=stage_status)

        logger.info("end run {} ({:.2f}s), {}".format(name, elapse, self.__str__()))
        return summary or {}

    def update_page_url_set(self):
        from app.helpers import get_url_by_task_id
        # page_url_set 从数据库读取搜索引擎爬取到的URL
        urls = get_url_by_task_id(self.task_id)
        self.page_url_set |= set(urls)

        for u in self.page_url_set:
            o = urlparse(u)
            ret_url = "{}://{}".format(o.scheme, o.netloc)
            entry_urls = self.search_engines_result.get(ret_url, [])
            entry_urls.append(u)
            self.search_engines_result[ret_url] = entry_urls

    def normalize_wih_domain(self, content):
        domain = str(content or "").strip()
        if " (" in domain:
            domain = domain.split(" (", 1)[0].strip()

        domain = domain.strip(".").lower()
        return domain

    def is_wih_record_allowed(self, record):
        if record.recordType == "all_url":
            entry_url, _ = normalize_entry_candidate(
                record.content,
                self.scope_domain,
                literal_all_url=True,
            )
            if not entry_url:
                return False
            record.content = entry_url
            return True

        if record.recordType != "domain":
            return True

        if not self.scope_domain:
            return True

        domain = self.normalize_wih_domain(record.content)
        if not domain:
            return False

        if not domain_in_scope_domain(domain, self.scope_domain):
            return False

        if utils.check_domain_black(domain):
            return False

        record.content = domain
        return True

    def add_wih_domain_set(self, record):
        if record.recordType != "domain":
            return

        domain = self.normalize_wih_domain(record.content)
        if not domain:
            return

        if domain in self.wih_domain_set:
            return

        self.wih_domain_set.add(domain)

    def add_wih_all_url_entry(self, record):
        if record.recordType != "all_url":
            return False
        entry_url, host = normalize_entry_candidate(
            record.content,
            self.scope_domain,
            literal_all_url=True,
        )
        if not entry_url or not host:
            return False

        source_values = []
        for value in (getattr(record, "source", ""), getattr(record, "site", "")):
            value = str(value or "").strip()
            if value and value not in source_values:
                source_values.append(value)
        status = "pending"
        try:
            address = ipaddress.ip_address(host.strip("[]"))
            if not address.is_global:
                status = "skipped_non_global"
        except ValueError:
            if self.scope_domain and domain_in_scope_domain(host, self.scope_domain):
                self.wih_domain_set.add(host)
                self.entry_tracker.register_domain(
                    host,
                    source_url=source_values[0] if source_values else "",
                    discovered_url=entry_url,
                    collector="wih",
                )

        self.entry_tracker.register_url(
            entry_url,
            source_urls=source_values,
            collector="wih",
            status=status,
        )
        self.wih_entry_url_set.add(entry_url)
        current = self.wih_entry_url_sources.setdefault(entry_url, [])
        for value in source_values:
            if value not in current:
                current.append(value)
        record.content = entry_url
        return True

    def wih_record_quality(self, record):
        quality = {
            "relation_level": "strong",
            "confidence": "medium",
            "quality_reasons": [],
        }
        source = str(getattr(record, "source", "") or "").strip()
        source_host = ""
        if source.startswith(("http://", "https://")):
            source_host = (urlparse(source).hostname or "").strip(".").lower()
        if source_host and self.scope_domain and not domain_in_scope_domain(source_host, self.scope_domain):
            quality["relation_level"] = "weak"
            quality["confidence"] = "low"
            quality["quality_reasons"].append("external_resource_source")

        content = str(getattr(record, "content", "") or "").strip().lower()
        placeholder_tokens = (
            'password":"senha',
            'password":"parola',
            "notcheckcurrentpassword",
            'password":"password',
        )
        if record.recordType != "domain" and any(token in content for token in placeholder_tokens):
            quality["confidence"] = "low"
            quality["quality_reasons"].append("placeholder_or_translation")
        return quality

    def save_wih_records(self, records, extra_fields=None):
        extra_fields = extra_fields or {}
        filtered_domain_count = 0
        insert_count = 0
        for record in records or []:
            if not self.is_wih_record_allowed(record):
                filtered_domain_count += 1
                continue

            canonical_hash = wih_content_hash(self.task_id, record.recordType, record.content)
            is_new = canonical_hash not in self.wih_record_set

            self.add_wih_domain_set(record)

            if record.recordType == "domain":
                self.entry_tracker.register_domain(
                    record.content,
                    source_url=getattr(record, "site", ""),
                    discovered_url=getattr(record, "source", ""),
                    collector="wih",
                )
            elif record.recordType == "all_url":
                self.add_wih_all_url_entry(record)

            item = record.dump_json()
            item["task_id"] = self.task_id
            item.update(extra_fields)
            item.update(self.wih_record_quality(record))
            item["collector"] = "wih"
            item["fnv_hash"] = canonical_hash
            self.upsert_wih_item(item)
            self.wih_record_set.add(canonical_hash)
            if is_new:
                insert_count += 1

        return insert_count, filtered_domain_count

    def select_wih_targets(self):
        source_mode = str(getattr(Config, "WIH_TARGET_SOURCE", "katana") or "katana").lower()
        fallback_enabled = bool(getattr(Config, "WIH_FALLBACK_TO_SITE_LIST", True))
        self.wih_target_selection_meta = {}
        if source_mode in ("katana", "auto"):
            if self.site_spider_wih_targets:
                self.wih_target_selection_meta = {
                    "fallback_candidate_count": 0,
                    "fallback_selected_count": 0,
                    "fallback_filtered_count": 0,
                    "fallback_filter_reasons": {},
                    "fallback_named_edge_allowed_count": 0,
                }
                return list(self.site_spider_wih_targets), "katana"
            if self.options.get(WebSiteFetchOption.SITE_SPIDER) and not fallback_enabled:
                return [], "katana_empty"

        if source_mode == "site" or fallback_enabled:
            raw_sites = list(self.available_sites or self.sites)
            is_katana_fallback = (
                source_mode in ("katana", "auto") and
                bool(self.options.get(WebSiteFetchOption.SITE_SPIDER))
            )
            sites = self.build_wih_site_targets(
                raw_sites,
                named_only=is_katana_fallback,
            )
            return sites, "site_fallback" if is_katana_fallback else "site"

        return [], "none"

    def run_web_info_hunter(self, stage_name=WebSiteFetchStatus.Info_Hunter):
        batch_size = max(1, int(getattr(Config, "WIH_BATCH_SIZE", 50) or 50))
        filtered_domain_count = 0
        insert_count = 0
        raw_sites = list(self.available_sites or self.sites)
        targets, target_source = self.select_wih_targets()
        skipped_edge = 0
        if target_source in ("site", "site_fallback"):
            skipped_edge = int(
                (self.wih_target_selection_meta.get("fallback_filter_reasons") or {})
                .get("shared_edge", 0)
            )
        error_count = 0
        all_url_alive_total = 0
        all_url_probe_total = 0
        all_url_initial_error_total = 0
        all_url_retry_total = 0
        all_url_recovered_total = 0
        all_url_probe_error_total = 0
        warnings = []
        logger.info("webInfoHunter target_source:{} targets:{} task_id:{}".format(
            target_source, len(targets), self.task_id))

        for start in range(0, len(targets), batch_size):
            if self.base_update_task.is_terminal():
                logger.warning("stop webInfoHunter early on terminal task status, task_id:{}".format(self.task_id))
                break

            batch = targets[start:start + batch_size]
            records = services.run_wih(batch, task_id=self.task_id)
            result_meta = dict(getattr(records, "meta", {}) or {})
            if result_meta.get("error"):
                error_count += 1
                warnings.append(str(result_meta.get("error")))
            batch_insert_count, batch_filtered_count = self.save_wih_records(
                records,
                extra_fields={"wih_target_source": target_source},
            )
            insert_count += batch_insert_count
            filtered_domain_count += batch_filtered_count
            batch_entry_probe = self.probe_entry_urls(
                sorted(self.wih_entry_url_set),
                source_map=self.wih_entry_url_sources,
                collector="wih",
                discovery_source="wih_all_url",
                url_type="js_web_entry",
            )
            all_url_alive_total += int(batch_entry_probe.get("output_count", 0) or 0)
            all_url_probe_total += int(batch_entry_probe.get("probe_count", 0) or 0)
            all_url_initial_error_total += int(
                batch_entry_probe.get("initial_probe_error_count", 0) or 0)
            all_url_retry_total += int(
                batch_entry_probe.get("retry_probe_count", 0) or 0)
            all_url_recovered_total += int(
                batch_entry_probe.get("retry_recovered_count", 0) or 0)
            all_url_probe_error_total += int(
                batch_entry_probe.get("probe_error_count", 0) or 0)
            self.base_update_task.update_stage_progress(
                stage_name,
                {
                    "input_count": len(targets),
                    "output_count": insert_count,
                    "filtered_count": filtered_domain_count,
                    "error_count": error_count,
                    "processed_site_count": min(start + len(batch), len(targets)),
                    "skipped_edge": skipped_edge,
                    "new_domain_count": len(self.wih_domain_set),
                    "all_url_entry_count": len(self.wih_entry_url_set),
                    "all_url_alive_count": all_url_alive_total,
                    "all_url_probe_count": all_url_probe_total,
                    "all_url_initial_probe_error_count": all_url_initial_error_total,
                    "all_url_retry_probe_count": all_url_retry_total,
                    "all_url_retry_recovered_count": all_url_recovered_total,
                    "all_url_probe_error_count": all_url_probe_error_total,
                    "target_source": target_source,
                    **self.wih_target_selection_meta,
                },
            )
            logger.info("webInfoHunter batch {}/{} insert:{} filtered:{} task_id:{}".format(
                start // batch_size + 1,
                (len(targets) + batch_size - 1) // batch_size,
                batch_insert_count,
                batch_filtered_count,
                self.task_id,
            ))

        entry_probe_summary = self.probe_entry_urls(
            sorted(self.wih_entry_url_set),
            source_map=self.wih_entry_url_sources,
            collector="wih",
            discovery_source="wih_all_url",
            url_type="js_web_entry",
        )
        all_url_alive_total += int(entry_probe_summary.get("output_count", 0) or 0)
        all_url_probe_total += int(entry_probe_summary.get("probe_count", 0) or 0)
        all_url_initial_error_total += int(
            entry_probe_summary.get("initial_probe_error_count", 0) or 0)
        all_url_retry_total += int(
            entry_probe_summary.get("retry_probe_count", 0) or 0)
        all_url_recovered_total += int(
            entry_probe_summary.get("retry_recovered_count", 0) or 0)
        all_url_probe_error_total += int(
            entry_probe_summary.get("probe_error_count", 0) or 0)

        if filtered_domain_count:
            logger.info("filter out-scope wih domains: {}, task_id:{}".format(
                filtered_domain_count, self.task_id))
        summary = {
            "input_count": len(targets),
            "output_count": insert_count,
            "filtered_count": filtered_domain_count,
            "error_count": error_count,
            "skipped_edge": skipped_edge,
            "new_domain_count": len(self.wih_domain_set),
            "target_source": target_source,
            "katana_entry_target_count": self.site_spider_wih_entry_target_count,
            "katana_resource_target_count": self.site_spider_wih_resource_target_count,
            "all_url_entry_count": len(self.wih_entry_url_set),
            "all_url_alive_count": all_url_alive_total,
            "all_url_probe_count": all_url_probe_total,
            "all_url_initial_probe_error_count": all_url_initial_error_total,
            "all_url_retry_probe_count": all_url_retry_total,
            "all_url_retry_recovered_count": all_url_recovered_total,
            "all_url_probe_error_count": all_url_probe_error_total,
            **self.wih_target_selection_meta,
        }
        if error_count:
            summary.update({
                "_stage_status": "partial",
                "partial_reason": "wih_partial_failure",
                "warning": "; ".join(warnings[:5]),
            })
        return summary

    def run_discovery(self):
        # *** 对站点进行基本信息的获取
        self.run_func(WebSiteFetchStatus.FETCH_SITE, self.fetch_site)

        """ *** 保存站点信息到数据库 """
        self.save_site_info()

        # 清空，节省内存
        self.site_info_list = []

        if self.base_update_task.is_terminal():
            logger.warning("stop WebSiteFetch after fetch_site, task_id:{}".format(self.task_id))
            return

        """ *** 站点截图 """
        if self.options.get(WebSiteFetchOption.SITE_CAPTURE):
            self.run_func(WebSiteFetchStatus.SITE_CAPTURE, self.site_screenshot)
            if self.base_update_task.is_terminal():
                return

        """ ***调用站点爬虫发现URL """
        if self.options.get(WebSiteFetchOption.SITE_SPIDER):
            self.update_page_url_set()
            self.run_func(WebSiteFetchStatus.SITE_SPIDER, self.site_spider)
            if self.base_update_task.is_terminal():
                return

            if self.runtime_artifact_ready():
                self.run_func(
                    WebSiteFetchStatus.RUNTIME_ARTIFACT,
                    lambda: self.run_runtime_artifact(
                        stage_name=WebSiteFetchStatus.RUNTIME_ARTIFACT),
                )
                if self.base_update_task.is_terminal():
                    return

        """ *** 对站点调用 WebInfoHunter """
        if self.options.get(WebSiteFetchOption.Info_Hunter):
            self.run_func(WebSiteFetchStatus.Info_Hunter, self.run_web_info_hunter)

    def run_post_discovery(self):
        summaries = {}
        if self.base_update_task.is_terminal():
            return summaries

        def stage_done(stage_name):
            item = utils.conn_db("task_stage").find_one(
                {"task_id": self.task_id, "stage": stage_name},
                {"_id": 0, "status": 1},
            )
            return bool(item and item.get("status") in ("done", "done_with_warnings"))

        """ *** 对站点进行文件目录爆破 """
        if self.options.get(WebSiteFetchOption.FILE_LEAK) and not stage_done(
                WebSiteFetchStatus.FILE_LEAK):
            summaries[WebSiteFetchStatus.FILE_LEAK] = self.run_func(
                WebSiteFetchStatus.FILE_LEAK, self.file_leak) or {}
            if self.base_update_task.is_terminal():
                return summaries
            if summaries[WebSiteFetchStatus.FILE_LEAK].get("continuation_required"):
                return summaries

        """ *** 对站点运行 nuclei """
        if is_nuclei_scan_enabled(self.options) and not stage_done(
                WebSiteFetchStatus.NUCLEI_SCAN):
            summaries[WebSiteFetchStatus.NUCLEI_SCAN] = self.run_func(
                WebSiteFetchStatus.NUCLEI_SCAN, self.nuclei_scan)
            if self.base_update_task.is_terminal():
                return summaries
        return summaries

    def run(self):
        self.run_discovery()
        self.run_post_discovery()


def domain_in_scope_domain(domain: str, scope_domain: list):
    domain = str(domain or "").strip(".").lower()
    for scope in scope_domain:
        scope = str(scope or "").strip(".").lower()
        if not scope:
            continue
        if domain == scope or domain.endswith("." + scope):
            return True
    return False
