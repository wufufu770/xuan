import time
from urllib.parse import urlparse
from bson import ObjectId
from app import services
from app.config import Config
from app.services.buildDomainInfo import build_domain_info
from app.services.assetSeedProbe import httpx_probe_urls
from app.services.fetchSite import fetch_site
from app.services.baseUpdateTask import BaseUpdateTask
from app.services.entryAsset import EntryAssetTracker
from app.services.storage import save_domain_documents, save_site_documents, save_url_page_map
from app.services.assetPolicy import (
    merge_directory_scan_profiles,
    merge_directory_scan_route_keys,
)
from app.utils.site_scope import formal_domain_query, formal_site_query

from app import utils


logger = utils.get_logger()


class DomainSiteUpdate(object):
    def __init__(
        self,
        task_id: str,
        domains: list,
        source: str,
        url_evidence=None,
        reprobe_existing_without_site=False,
        run_file_leak=True,
    ):
        self.task_id = task_id
        self.domains = domains
        self.source = source
        self.url_evidence = self._normalize_url_evidence(url_evidence or {})
        self.reprobe_existing_without_site = bool(reprobe_existing_without_site)
        self.run_file_leak_enabled = bool(run_file_leak)
        self.domain_info_list = []
        self.available_sites = []
        self.new_domain_count = 0
        self.reprobe_domain_count = 0
        self.existing_domain_docs = {}
        self.base_update_task = BaseUpdateTask(self.task_id)
        self.task_options = self._load_task_options()
        self.site_identify_enabled = bool(self.task_options.get("site_identify"))
        self.file_leak_target_profiles = {}
        self.file_leak_target_route_keys = {}
        self.entry_tracker = EntryAssetTracker(self.task_id)

    @staticmethod
    def _normalize_url_evidence(url_evidence):
        result = {}
        for raw_domain, values in (url_evidence or {}).items():
            domain = str(raw_domain or "").strip(".").lower()
            if not domain:
                continue
            if isinstance(values, str):
                values = [values]
            for value in values or []:
                value = str(value or "").strip()
                try:
                    parsed = urlparse(value)
                except (TypeError, ValueError):
                    continue
                host = (parsed.hostname or "").strip(".").lower()
                if parsed.scheme not in ("http", "https") or host != domain:
                    continue
                result.setdefault(domain, [])
                if value not in result[domain]:
                    result[domain].append(value)
        return result

    def _load_task_options(self):
        try:
            task = utils.conn_db("task").find_one({"_id": ObjectId(self.task_id)}, {"options": 1})
        except Exception:
            task = None

        return (task or {}).get("options", {}) or {}

    def save_domain_info(self):
        domain_info_list = build_domain_info(self.domains)
        save_domain_documents(self.task_id, domain_info_list, self.source)
        resolved_domains = {item.domain for item in domain_info_list}
        unresolved_docs = []
        for domain in self.domains:
            domain = str(domain or "").strip(".").lower()
            if not domain or domain in resolved_domains:
                continue
            if not utils.is_valid_domain(domain) or utils.check_domain_black(domain):
                continue
            existing = self.existing_domain_docs.get(domain) or {}
            if existing.get("ips"):
                # A transient DNS failure during feedback must not erase a
                # previously confirmed resolution.
                continue
            unresolved_docs.append({
                "domain": domain,
                "type": "UNKNOWN",
                "record": [],
                "ips": [],
                "resolve_status": "unresolved",
            })
        if unresolved_docs:
            save_domain_documents(self.task_id, unresolved_docs, self.source)
        self.domain_info_list = domain_info_list
        return {
            "output_count": len(domain_info_list) + len(unresolved_docs),
            "resolved_count": len(domain_info_list),
            "unresolved_count": len(unresolved_docs),
        }

    def probe_sites(self):
        targets = []
        for domain_info_obj in self.domain_info_list:
            domain = domain_info_obj.domain
            targets.extend(self.url_evidence.get(domain, []))
            targets.append("https://{}".format(domain))
            targets.append("http://{}".format(domain))

        ordered_targets = []
        seen_targets = set()
        for target in targets:
            target = str(target or "").strip()
            if not target or target in seen_targets:
                continue
            seen_targets.add(target)
            ordered_targets.append(target)

        alive_urls = httpx_probe_urls(
            ordered_targets, task_id=self.task_id,
            base_domain="",
            source="{}_domain_update".format(self.source),
            accepted_status_ranges=[(200, 399), (401, 401), (403, 403)],
        )

        raw_feedback_ports = str(getattr(
            Config,
            "DOMAIN_FEEDBACK_WEB_PORTS",
            getattr(Config, "ASSET_SEED_WEB_PORTS", "80,443,8080,8443"),
        ) or "")
        feedback_ports = []
        for value in raw_feedback_ports.split(","):
            value = value.strip()
            if not value or value in ("80", "443"):
                continue
            try:
                port = int(value)
            except ValueError:
                continue
            if 0 < port <= 65535 and str(port) not in feedback_ports:
                feedback_ports.append(str(port))

        max_feedback_domains = max(int(getattr(
            Config, "DOMAIN_FEEDBACK_MAX_DOMAINS", 500) or 500), 0)
        feedback_domains = list(self.domains)
        if max_feedback_domains:
            feedback_domains = feedback_domains[:max_feedback_domains]

        common_port_alive = []
        if feedback_domains and feedback_ports:
            common_port_alive = httpx_probe_urls(
                feedback_domains,
                task_id=self.task_id,
                base_domain="",
                source="{}_domain_update_ports".format(self.source),
                accepted_status_ranges=[(200, 399), (401, 401), (403, 403)],
                ports=",".join(feedback_ports),
            )
            alive_urls = list(set(alive_urls + common_port_alive))

        alive_set = set(alive_urls)
        available_sites = []
        for url in alive_urls:
            if url.startswith("https://"):
                available_sites.append(url)
            elif url.startswith("http://"):
                https_url = "https://" + url[7:]
                if https_url not in alive_set:
                    available_sites.append(url)

        self.available_sites = list(set(available_sites))
        return {
            "input_count": len(ordered_targets),
            "output_count": len(self.available_sites),
            "evidence_url_count": sum(len(x) for x in self.url_evidence.values()),
            "common_port_domain_count": len(feedback_domains),
            "common_port_alive_count": len(common_port_alive),
            "common_port_skipped_domain_count": max(0, len(self.domains) - len(feedback_domains)),
        }

    def save_site_info(self):
        def _save_batch(site_info_list, progress):
            for item in site_info_list:
                item["source"] = self.source
            page_map = self.build_entry_page_map(site_info_list)
            save_site_documents(self.task_id, site_info_list)
            if page_map:
                save_url_page_map(
                    self.task_id,
                    page_map,
                    self.source,
                    url_type="discovered_entry",
                    extra_fields={"feedback_stage": "{}_domain_update".format(self.source)},
                )
            if self.site_identify_enabled:
                self.refresh_finger_stat()
            self.base_update_task.update_stage_progress(
                "{}_domain_update".format(self.source),
                {
                    "output_count": progress.get("output_count", 0),
                    "batch_index": progress.get("batch_index", 0),
                    "total_batches": progress.get("total_batches", 0),
                    "reused_site_count": progress.get("reused_site_count", 0),
                    "reused_probe_count": progress.get("reused_probe_count", 0),
                    "probed_target_count": progress.get("probed_target_count", 0),
                },
            )

        site_info_list = fetch_site(
            self.available_sites,
            observer_ward_enable=self.site_identify_enabled,
            task_id=self.task_id,
            on_batch=_save_batch,
        )
        for item in site_info_list:
            item["source"] = self.source
        page_map = self.build_entry_page_map(site_info_list)
        save_site_documents(self.task_id, site_info_list)
        if page_map:
            save_url_page_map(
                self.task_id,
                page_map,
                self.source,
                url_type="discovered_entry",
                extra_fields={"feedback_stage": "{}_domain_update".format(self.source)},
            )
        if self.site_identify_enabled:
            self.refresh_finger_stat()
        summary = {
            "input_count": len(self.available_sites),
            "output_count": len(site_info_list),
            "entry_url_count": len(page_map),
        }
        fetch_meta = dict(getattr(site_info_list, "meta", {}) or {})
        summary.update(fetch_meta)
        summary["input_count"] = len(self.available_sites)
        summary["output_count"] = len(site_info_list)
        return summary

    @staticmethod
    def build_entry_page_map(site_info_list):
        page_map = {}
        for item in site_info_list or []:
            site = str(item.get("site") or "").strip()
            try:
                parsed = urlparse(site)
            except (TypeError, ValueError):
                continue
            if parsed.path and parsed.path != "/":
                page_map[site] = {
                    "title": item.get("title", ""),
                    "status_code": item.get("status"),
                    "content_length": item.get("body_length", 0),
                }
        return page_map

    def refresh_finger_stat(self):
        finger_stat_map = utils.arl.gen_stat_finger_map(self.task_id)
        utils.conn_db("stat_finger").delete_many({"task_id": self.task_id})
        for key in finger_stat_map:
            data = finger_stat_map[key].copy()
            data["task_id"] = self.task_id
            query = {"task_id": self.task_id, "name": data.get("name")}
            utils.conn_db("stat_finger").update_one(query, {"$set": data}, upsert=True)

    def file_leak_sites(self):
        if not self.available_sites:
            return []

        raw_sites = set()
        for site in self.available_sites:
            cut_target = utils.url.cut_filename(site)
            if cut_target:
                raw_sites.add(cut_target)

        if not raw_sites:
            return []

        lookup_sites = set(raw_sites)
        lookup_sites.update(site.rstrip("/") + "/" for site in raw_sites)
        lookup_sites.update(str(site or "").strip() for site in self.available_sites)
        site_docs = list(utils.conn_db("site").find(
            formal_site_query({
                "task_id": self.task_id,
                "site": {"$in": list(lookup_sites)},
            }),
            {"site": 1, "tag": 1, "cdn": 1, "is_cdn": 1, "waf": 1,
             "waf_name": 1, "waf_strength": 1, "is_waf": 1, "edge": 1,
             "edge_name": 1, "webserver": 1, "cname": 1, "status": 1,
             "canonical_site": 1, "ip": 1, "resolved_ips": 1, "headers": 1,
             "http_server": 1, "body_hash": 1, "content_type": 1,
             "location": 1, "favicon": 1,
             "status_code": 1, "title": 1, "body_length": 1,
             "content_length": 1, "finger": 1,
             "tech": 1}
        ))
        docs_by_site = {}
        for item in site_docs:
            site = utils.url.cut_filename(item.get("site", ""))
            if site and site in raw_sites:
                docs_by_site.setdefault(site, []).append(item)

        allowed = []
        self.file_leak_target_profiles = {}
        self.file_leak_target_route_keys = {}
        for site in sorted(raw_sites):
            docs = docs_by_site.get(site) or []
            profile = merge_directory_scan_profiles(docs)
            if profile is None:
                continue
            allowed.append(site)
            site_key = site.rstrip("/")
            self.file_leak_target_profiles[site_key] = profile
            route_key = merge_directory_scan_route_keys(docs)
            if route_key:
                self.file_leak_target_route_keys[site_key] = route_key
        return allowed

    def run_file_leak(self):
        if not self.run_file_leak_enabled or not self.task_options.get("file_leak"):
            return {"input_count": 0, "output_count": 0}

        self.entry_tracker.snapshot_prior_assets()
        sites = self.file_leak_sites()
        saved_urls = set()

        def save_pages(pages):
            for page in pages:
                item = page.dump_json()
                item["task_id"] = self.task_id
                if not item.get("site"):
                    item["site"] = getattr(page, "site", "")
                if not item.get("url"):
                    continue
                query = {"task_id": self.task_id, "url": item.get("url")}
                utils.conn_db("fileleak").update_one(query, {"$set": item}, upsert=True)
                saved_urls.add(item["url"])

        pages = services.file_leak(
            sites,
            utils.load_file(Config.FILE_LEAK_TOP_2k),
            gen_dict=Config.FILE_LEAK_GEN_DYNAMIC,
            task_id=self.task_id,
            on_result=save_pages,
            target_profiles=self.file_leak_target_profiles,
            target_route_keys=getattr(self, "file_leak_target_route_keys", {}),
        )
        ffuf_meta = dict(getattr(pages, "meta", {}) or {})
        removed_urls = list(getattr(pages, "removed_urls", []) or [])
        if removed_urls:
            utils.conn_db("fileleak").delete_many({
                "task_id": self.task_id,
                "url": {"$in": removed_urls},
            })
            saved_urls.difference_update(removed_urls)
        save_pages(pages)

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

        return {
            "input_count": len(sites),
            "output_count": len(saved_urls),
            "entry_registered_count": entry_registered_count,
            "entry_promotion_enabled": bool(getattr(
                Config, "FFUF_PROMOTE_TO_ENTRY", False)),
            "baseline_filtered_count": int(
                ffuf_meta.get("baseline_filtered_count", 0) or 0),
            "dynamic_word_count": int(
                ffuf_meta.get("dynamic_word_count", 0) or 0),
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
            "edge_limited_short_scan_count": int(
                ffuf_meta.get("edge_limited_short_scan_count", 0) or 0),
            "edge_limited_escalated_count": int(
                ffuf_meta.get("edge_limited_escalated_count", 0) or 0),
            "edge_limited_skipped_full_word_count": int(
                ffuf_meta.get("edge_limited_skipped_full_word_count", 0) or 0),
            "priority_result_count": int(
                ffuf_meta.get("priority_result_count", 0) or 0),
            "entry_candidate_count": int(
                ffuf_meta.get("entry_candidate_count", 0) or 0),
            "resource_clue_count": int(
                ffuf_meta.get("resource_clue_count", 0) or 0),
            "route_cluster_count": int(
                ffuf_meta.get("route_cluster_count", 0) or 0),
            "route_dedupe_reused_target_count": int(
                ffuf_meta.get("route_dedupe_reused_target_count", 0) or 0),
            "route_dedupe_saved_word_count": int(
                ffuf_meta.get("route_dedupe_saved_word_count", 0) or 0),
            "route_dedupe_split_cluster_count": int(
                ffuf_meta.get("route_dedupe_split_cluster_count", 0) or 0),
            "route_dedupe_fallback_target_count": int(
                ffuf_meta.get("route_dedupe_fallback_target_count", 0) or 0),
        }

    # 对域名进行检查，如果域名不在任务范围内，就不进行更新
    def set_and_check_domains(self):
        valid_domains = []
        for domain in self.domains:
            domain = str(domain or "").strip(".").lower()
            if not domain:
                continue
            if not utils.is_valid_domain(domain) or utils.check_domain_black(domain):
                continue
            if domain not in valid_domains:
                valid_domains.append(domain)

        self.existing_domain_docs = {
            item.get("domain"): item
            for item in utils.conn_db("domain").find(
                formal_domain_query({"task_id": self.task_id}),
                {"_id": 0, "domain": 1, "ips": 1, "resolve_status": 1},
            )
            if item.get("domain")
        }
        task_domains = set(self.existing_domain_docs)
        try:
            wildcard_candidates = set(utils.conn_db(
                "asset_seed_candidate").distinct(
                    "domain",
                    {
                        "task_id": self.task_id,
                        "domain": {"$in": valid_domains},
                        "candidate_type": "wildcard_dns",
                        "pipeline_eligible": False,
                    },
                ))
        except (KeyError, AttributeError):
            wildcard_candidates = set()
        valid_domains = [
            domain for domain in valid_domains
            if domain in task_domains or domain not in wildcard_candidates
        ]
        if self.source:
            for domain in valid_domains:
                if domain not in task_domains:
                    continue
                utils.conn_db("domain").update_one(
                    {"task_id": self.task_id, "domain": domain},
                    {"$addToSet": {"sources": self.source}}
                )

        site_hosts = set()
        if self.reprobe_existing_without_site:
            for item in utils.conn_db("site").find(
                formal_site_query({"task_id": self.task_id}),
                {"_id": 0, "site": 1}
            ):
                try:
                    host = (urlparse(item.get("site", "")).hostname or "").strip(".").lower()
                except (TypeError, ValueError):
                    host = ""
                if host:
                    site_hosts.add(host)

        selected = []
        for domain in valid_domains:
            if domain not in task_domains:
                self.new_domain_count += 1
                selected.append(domain)
                continue
            if self.reprobe_existing_without_site and domain not in site_hosts:
                self.reprobe_domain_count += 1
                selected.append(domain)
        self.domains = selected

    def finish_terminal_stage(self, status_name, started_at, checkpoint):
        if not self.base_update_task.is_terminal():
            return False

        elapsed = time.time() - started_at
        self.base_update_task.update_services(status_name, elapsed, summary={
            "input_count": len(self.domains),
            "output_count": len(self.available_sites),
            "checkpoint": checkpoint,
            "partial_reason": "task_terminal",
        })
        logger.warning(
            "stop domain site update at {} task_id:{}".format(
                checkpoint, self.task_id))
        return True

    def run(self):
        status_name = f"{self.source}_domain_update"
        raw_input_count = len(self.domains)
        self.base_update_task.update_task_field("status", status_name)
        if not self.base_update_task.start_stage(status_name, input_count=raw_input_count):
            logger.warning("skip domain site update because task is terminal, task_id:{}".format(self.task_id))
            return {}

        t1 = time.time()
        try:
            self.set_and_check_domains()
            logger.info(
                "start domain site update task_id:{}, raw:{}, selected:{}, source:{}".format(
                    self.task_id, raw_input_count, len(self.domains), self.source))
            self.base_update_task.update_stage_progress(status_name, {
                "input_count": len(self.domains),
                "raw_input_count": raw_input_count,
                "new_domain_count": self.new_domain_count,
                "reprobe_domain_count": self.reprobe_domain_count,
            })

            if self.finish_terminal_stage(status_name, t1, "domain_selection"):
                return {}

            domain_summary = self.save_domain_info()
            if self.finish_terminal_stage(status_name, t1, "save_domain_info"):
                return {}

            probe_summary = self.probe_sites()
            if self.finish_terminal_stage(status_name, t1, "probe_sites"):
                return {}

            site_summary = self.save_site_info()
            if self.finish_terminal_stage(status_name, t1, "save_site_info"):
                return {}

            file_leak_summary = self.run_file_leak()
            elapse = time.time() - t1
            summary = {
                "input_count": len(self.domains),
                "raw_input_count": raw_input_count,
                "output_count": len(self.available_sites),
                "new_domain_count": self.new_domain_count,
                "reprobe_domain_count": self.reprobe_domain_count,
                "evidence_url_count": sum(len(x) for x in self.url_evidence.values()),
                "domain_count": domain_summary.get("output_count", 0),
                "resolved_count": domain_summary.get("resolved_count", 0),
                "unresolved_count": domain_summary.get("unresolved_count", 0),
                "probe_alive_count": probe_summary.get("output_count", 0),
                "common_port_domain_count": probe_summary.get("common_port_domain_count", 0),
                "common_port_alive_count": probe_summary.get("common_port_alive_count", 0),
                "common_port_skipped_domain_count": probe_summary.get("common_port_skipped_domain_count", 0),
                "site_count": site_summary.get("output_count", 0),
                "fileleak_count": file_leak_summary.get("output_count", 0),
            }
            for key in (
                "_stage_status", "error_count", "warning", "partial_reason",
                "observer_ward_input_count", "observer_ward_failed_site_count",
            ):
                if site_summary.get(key) is not None:
                    summary[key] = site_summary.get(key)
            stage_status = site_summary.get("_stage_status", "done")
            summary.pop("_stage_status", None)
            self.base_update_task.update_services(
                status_name, elapse, summary=summary, status=stage_status)
            logger.info("end domain site update elapse {}".format(elapse))
            return summary
        except Exception as e:
            elapse = time.time() - t1
            try:
                self.base_update_task.fail_stage(status_name, e, elapsed=elapse, summary={
                    "input_count": len(self.domains),
                    "raw_input_count": raw_input_count,
                    "output_count": len(self.available_sites),
                })
            except Exception as stage_error:
                logger.warning(
                    "mark domain site update stage failed task_id:{} error:{}".format(
                        self.task_id, stage_error))
            raise


# 将域名直接加到任务数据中，只加到域名和站点表中，
# 没有检验添加的域名是否在任务范围中
# 会检验域名是否已经存在任务中
def domain_site_update(
    task_id: str,
    domains: list,
    source: str,
    url_evidence=None,
    reprobe_existing_without_site=False,
    run_file_leak=True,
):
    return DomainSiteUpdate(
        task_id,
        domains,
        source,
        url_evidence=url_evidence,
        reprobe_existing_without_site=reprobe_existing_without_site,
        run_file_leak=run_file_leak,
    ).run()
