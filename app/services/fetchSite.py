import json
import os
import signal
import subprocess
import time
from pyquery import PyQuery as pq
import binascii
from urllib.parse import urljoin, urlparse
import mmh3
from app import utils
from app.config import Config
from .baseThread import BaseThread

logger = utils.get_logger()
from .autoTag import auto_tag
from app.utils import http_req, normal_url
from .observerWard import observer_ward_fingerprint_batch
from .resourceBudget import acquire as acquire_resource_budget
from .baseUpdateTask import BaseUpdateTask
from .assetPolicy import http_access_profile
from app.utils.site_scope import formal_pipeline_query, formal_site_query


class FetchSiteResult(list):
    def __init__(self, values=None, meta=None):
        super().__init__(values or [])
        self.meta = dict(meta or {})


class FetchSite(BaseThread):
    TRANSIENT_HTTP_STATUS_CODES = {
        408, 418, 425, 429, 500, 501, 502, 503, 504,
    }
    OBSERVER_TERMINAL_SKIP_STATUS_CODES = {400, 404, 405, 410}

    def __init__(
        self,
        sites,
        concurrency=6,
        http_timeout=None,
        observer_ward_enable=None,
        task_id="",
        on_batch=None,
    ):
        normalized_sites = self.normalize_sites(sites)
        if concurrency is None:
            concurrency = getattr(Config, "FETCH_SITE_CONCURRENCY", 10)
        super().__init__(normalized_sites, concurrency)
        self.task_id = task_id
        self.base_update_task = BaseUpdateTask(task_id) if task_id else None
        self.site_info_list = []
        self.http_timeout = http_timeout
        self.observer_ward_enable = observer_ward_enable
        self.on_batch = on_batch
        self.meta = {
            "input_count": len(normalized_sites),
            "reused_site_count": 0,
            "reused_probe_count": 0,
            "probed_target_count": 0,
            "output_count": 0,
        }
        if self.observer_ward_enable is None:
            self.observer_ward_enable = getattr(Config, "OBSERVER_WARD_ENABLE", False)
        if http_timeout is None:
            self.http_timeout = int(getattr(
                Config,
                "FETCH_SITE_HTTPX_TIMEOUT",
                getattr(Config, "ASSET_SEED_HTTPX_TIMEOUT", 8),
            ) or 8)

    def task_stopped(self):
        if not self.base_update_task:
            return False
        if len(str(self.task_id)) != 24:
            return False
        try:
            return self.base_update_task.is_terminal()
        except Exception as e:
            logger.warning("fetch_site task status check failed: {}".format(e))
            return False

    @staticmethod
    def normalize_sites(sites):
        ordered = []
        seen = set()
        for site in sites or []:
            site = str(site or "").strip()
            if not site or site in seen:
                continue
            seen.add(site)
            ordered.append(site)
        return ordered

    def httpx_timeout(self):
        if isinstance(self.http_timeout, (tuple, list)) and self.http_timeout:
            try:
                return max(int(max(self.http_timeout)), 1)
            except Exception:
                pass
        try:
            return max(int(getattr(Config, "ASSET_SEED_HTTPX_TIMEOUT", 8)), 1)
        except Exception:
            return 8

    def httpx_threads(self):
        try:
            return max(int(getattr(Config, "FETCH_SITE_CONCURRENCY", self.concurrency)), 1)
        except Exception:
            return max(int(self.concurrency or 1), 1)

    def httpx_rate_limit(self):
        try:
            return max(int(getattr(Config, "ASSET_SEED_HTTPX_RATE_LIMIT", 150)), 1)
        except Exception:
            return 150

    def httpx_batch_size(self):
        try:
            return max(int(getattr(Config, "ASSET_SEED_HTTPX_BATCH_SIZE", 500)), 1)
        except Exception:
            return 500

    @staticmethod
    def chunked(items, size):
        size = max(int(size or 1), 1)
        for index in range(0, len(items), size):
            yield items[index:index + size]

    def build_httpx_command(self):
        return [
            getattr(Config, "HTTPX_BIN", "/usr/local/bin/httpx"),
            "-json", "-silent", "-title", "-status-code", "-content-length",
            "-content-type", "-location", "-hash", "sha256",
            "-web-server", "-tech-detect", "-favicon", "-cdn", "-ip", "-cname",
            "-follow-host-redirects", "-include-response-header",
            "-threads", str(self.httpx_threads()),
            "-rate-limit", str(self.httpx_rate_limit()),
            "-timeout", str(self.httpx_timeout()),
        ]

    def run_httpx_batch(self, sites):
        if not sites:
            return []

        input_text = "\n".join(sites) + "\n"
        estimated_timeout = max(
            60,
            self.httpx_timeout() * max(len(sites), 1) // self.httpx_threads() + 60,
        )
        timeout = min(
            estimated_timeout,
            max(int(getattr(Config, "FETCH_SITE_BATCH_TIMEOUT", 300) or 300), 60),
        )
        command = self.build_httpx_command()
        logger.info("fetch_site httpx batch sites:{} timeout:{}".format(len(sites), timeout))

        proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            text=True,
        )
        timed_out = False
        try:
            stdout, stderr = proc.communicate(input=input_text, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                stdout, stderr = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                stdout, stderr = proc.communicate()
            logger.warning("fetch_site httpx timeout after {}s sites:{}".format(timeout, len(sites)))
            self.meta["_stage_status"] = "partial"
            self.meta["partial_reason"] = "fetch_site_httpx_timeout"
            self.meta["error_count"] = int(self.meta.get("error_count", 0) or 0) + 1
            self.meta["warning"] = "fetch_site httpx timeout after {}s".format(timeout)

        if proc.returncode not in (0, None) and not timed_out:
            logger.warning("fetch_site httpx exit {} stderr:{}".format(
                proc.returncode, (stderr or "").strip()[-500:]))
            self.meta["_stage_status"] = "partial"
            self.meta["partial_reason"] = "fetch_site_httpx_failure"
            self.meta["error_count"] = int(self.meta.get("error_count", 0) or 0) + 1
            self.meta["warning"] = "fetch_site httpx exit {}".format(proc.returncode)

        results = []
        for line in (stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except ValueError:
                logger.debug("fetch_site httpx bad json: {}".format(line[:200]))
        return results

    def header_text(self, header):
        if isinstance(header, str):
            return header
        if not isinstance(header, dict):
            return ""

        lines = []
        for key, value in header.items():
            key = str(key or "").replace("_", "-")
            if not key:
                continue
            header_name = "-".join([part[:1].upper() + part[1:] for part in key.split("-")])
            lines.append("{}: {}".format(header_name, value))
        return "\n".join(lines)

    def first_ip(self, item):
        ip = item.get("host_ip") or item.get("ip")
        if isinstance(ip, list):
            ip = ip[0] if ip else ""
        if ip:
            return str(ip).strip()

        a_records = item.get("a") or []
        if isinstance(a_records, list) and a_records:
            return str(a_records[0]).strip()
        return ""

    def resolved_ips(self, item):
        values = item.get("a") or []
        if not isinstance(values, list):
            values = [values]
        first = self.first_ip(item)
        if first:
            values.append(first)
        return sorted(set(str(value).strip() for value in values if str(value or "").strip()))

    def favicon_from_httpx(self, site, item):
        favicon_hash = item.get("favicon")
        if favicon_hash in (None, ""):
            return {}
        try:
            favicon_hash = int(favicon_hash)
        except Exception:
            pass
        return {
            "hash": favicon_hash,
            "url": urljoin(site, "/favicon.ico"),
        }

    @staticmethod
    def response_hashes_from_httpx(item):
        hashes = item.get("hash") or item.get("hashes") or {}
        if not isinstance(hashes, dict):
            hashes = {}
        return {
            "body_hash": str(hashes.get("body_sha256") or "").strip().lower(),
            "header_hash": str(hashes.get("header_sha256") or "").strip().lower(),
        }

    def build_site_info_from_httpx(self, item):
        raw_site = item.get("url") or item.get("input") or ""
        site = normal_url(raw_site) or raw_site
        if not site:
            return None

        parsed = urlparse(site)
        hostname = (item.get("host") or parsed.hostname or "").strip(".")
        if not hostname:
            return None

        headers = self.header_text(
            item.get("header") or item.get("response_header") or item.get("headers") or {})
        http_server = item.get("webserver") or ""
        if not http_server and isinstance(item.get("header"), dict):
            http_server = item.get("header", {}).get("server", "")

        body_length = item.get("content_length")
        if body_length is None:
            body_length = item.get("body_length") or item.get("content-length") or 0
        try:
            body_length = int(body_length or 0)
        except Exception:
            body_length = 0

        status = item.get("status_code")
        try:
            status = int(status) if status is not None else None
        except Exception:
            pass

        site_info = {
            "site": site[:200],
            "hostname": hostname,
            "ip": self.first_ip(item),
            "resolved_ips": self.resolved_ips(item),
            "title": item.get("title", "") or "",
            "status": status,
            "headers": headers,
            "http_server": http_server,
            "body_length": body_length,
            "content_type": item.get("content_type") or "",
            "location": item.get("location") or "",
            "finger": [],
            "favicon": self.favicon_from_httpx(site, item),
            "tech": item.get("tech") or [],
            "cdn": bool(item.get("cdn")),
            "cdn_name": item.get("cdn_name") or item.get("cdn_type") or "",
            "cname": item.get("cname") or "",
            "waf": bool(item.get("waf")),
            "waf_name": item.get("waf_name") or "",
            "edge": bool(item.get("edge")),
            "edge_name": item.get("edge_name") or "",
            "edge_reasons": item.get("edge_reasons") or [],
            "tag": item.get("tag") or [],
        }
        site_info.update(self.response_hashes_from_httpx(item))

        domain_parsed = utils.domain_parsed(hostname)
        if domain_parsed:
            site_info["fld"] = domain_parsed["fld"]
            if not site_info["ip"]:
                ips = utils.get_ip(hostname)
                if ips:
                    site_info["ip"] = ips[0]
        elif not site_info["ip"]:
            site_info["ip"] = hostname

        return site_info

    @staticmethod
    def site_key(site):
        site = str(site or "").strip()
        if not site:
            return ""
        try:
            normalized = normal_url(site) or site
            parsed = urlparse(normalized)
        except (TypeError, ValueError):
            return ""
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return ""
        if parsed.path in ("", "/") and not parsed.query and not parsed.fragment:
            return "{}://{}".format(parsed.scheme, parsed.netloc.lower())
        return normalized

    @staticmethod
    def item_status(item):
        status = item.get("status")
        if status is None:
            status = item.get("status_code")
        try:
            return int(status) if status is not None else None
        except (TypeError, ValueError):
            return None

    def is_reusable_http_result(self, item):
        status = self.item_status(item)
        return status is not None and status not in self.TRANSIENT_HTTP_STATUS_CODES

    def load_reusable_site_map(self):
        if not self.task_id:
            return {}

        target_keys = {self.site_key(site) for site in self.targets}
        target_keys.discard("")
        if not target_keys:
            return {}

        reusable = {}
        projection = {
            "_id": 0, "site": 1, "hostname": 1, "ip": 1, "title": 1,
            "status": 1, "headers": 1, "http_server": 1, "body_length": 1,
            "body_hash": 1, "header_hash": 1, "content_type": 1, "location": 1,
            "resolved_ips": 1,
            "finger": 1, "favicon": 1, "tech": 1, "cdn": 1,
            "cdn_name": 1, "cname": 1, "waf": 1, "waf_name": 1,
            "edge": 1, "edge_name": 1, "edge_reasons": 1, "tag": 1,
            "fld": 1, "fetch_site_complete": 1, "observer_ward_complete": 1,
        }
        for item in utils.conn_db("site").find(
            formal_site_query({
                "task_id": self.task_id,
                "fetch_site_complete": True,
            }), projection
        ):
            key = self.site_key(item.get("site"))
            if key not in target_keys or not self.is_reusable_http_result(item):
                continue
            item = dict(item)
            item["_reuse_kind"] = "site"
            reusable[key] = item

        probe_projection = {
            "_id": 0, "url": 1, "host": 1, "ip": 1, "title": 1,
            "status_code": 1, "header": 1, "headers": 1,
            "response_header": 1, "webserver": 1, "body_length": 1,
            "content_length": 1, "favicon": 1, "tech": 1, "cdn": 1,
            "body_hash": 1, "header_hash": 1, "content_type": 1, "location": 1,
            "resolved_ips": 1, "a": 1,
            "cdn_name": 1, "cname": 1, "waf": 1, "waf_name": 1,
            "edge": 1, "edge_name": 1, "edge_reasons": 1, "tag": 1,
        }
        cursor = utils.conn_db("asset_seed_alive").find(
            formal_pipeline_query({
                "task_id": self.task_id,
                "status_code": {"$ne": None},
            }),
            probe_projection,
        ).sort("save_date", -1)
        for item in cursor:
            key = self.site_key(item.get("url"))
            if (
                key not in target_keys or key in reusable or
                not self.is_reusable_http_result(item)
            ):
                continue
            item = dict(item)
            item["_reuse_kind"] = "probe"
            reusable[key] = item
        return reusable

    def process_site_info_batch(self, site_info_list, batch_index, total_batches):
        if not site_info_list:
            return []

        for item in site_info_list:
            item.setdefault("finger", [])
            item.setdefault("tag", [])
        observer_completed_keys = self.merge_observer_ward_fingerprints(site_info_list)
        auto_tag(site_info_list)
        for item in site_info_list:
            item["fetch_site_complete"] = self.is_reusable_http_result(item)
            if self.observer_ward_enable:
                item["observer_ward_complete"] = (
                    self.site_key(item.get("site")) in observer_completed_keys
                )

        self.site_info_list.extend(site_info_list)
        self.meta["output_count"] = len(self.site_info_list)
        if self.on_batch:
            self.on_batch(site_info_list, {
                **self.meta,
                "batch_index": batch_index,
                "total_batches": total_batches,
                "batch_output_count": len(site_info_list),
            })
        return site_info_list

    def fetch_site_with_httpx(self):
        self.site_info_list = []
        targets = list(self.targets)
        if not targets:
            return []

        reusable = self.load_reusable_site_map()
        batch_size = self.httpx_batch_size()
        total_batches = (len(targets) + batch_size - 1) // batch_size
        for batch_index, batch in enumerate(self.chunked(targets, batch_size), 1):
            if self.task_stopped():
                self.meta["_stage_status"] = "partial"
                self.meta["partial_reason"] = "task_terminal"
                self.meta["warning"] = "fetch_site stopped before batch completion"
                self.meta["stopped"] = True
                break
            logger.info("fetch_site httpx batch {}/{} sites:{} task_id:{}".format(
                batch_index, total_batches, len(batch), self.task_id))

            batch_site_info = []
            probe_targets = []
            for target in batch:
                cached = reusable.get(self.site_key(target))
                if not cached:
                    probe_targets.append(target)
                    continue

                reuse_kind = cached.get("_reuse_kind")
                cached = dict(cached)
                cached.pop("_reuse_kind", None)
                if reuse_kind == "site":
                    cached["site"] = normal_url(cached.get("site")) or cached.get("site")
                    batch_site_info.append(cached)
                    self.meta["reused_site_count"] += 1
                else:
                    site_info = self.build_site_info_from_httpx(cached)
                    if site_info:
                        batch_site_info.append(site_info)
                        self.meta["reused_probe_count"] += 1

            results = []
            if probe_targets:
                with acquire_resource_budget("tool:httpx", task_id=self.task_id, stage="fetch_site"):
                    results = self.run_httpx_batch(probe_targets)
                self.meta["probed_target_count"] += len(probe_targets)
            for result in results:
                site_info = self.build_site_info_from_httpx(result)
                if site_info:
                    batch_site_info.append(site_info)

            deduped = {}
            for item in batch_site_info:
                key = self.site_key(item.get("site"))
                if key:
                    deduped[key] = item
            self.process_site_info_batch(list(deduped.values()), batch_index, total_batches)

        return self.site_info_list

    def build_observer_ward_fingerprint(self, name):
        return {
            "icon": "default.png",
            "name": name,
            "confidence": "85",
            "version": "",
            "website": "https://github.com/emo-crab/observer_ward",
            "categories": ["observer_ward"]
        }

    def site_match_keys(self, site):
        keys = set()
        site = str(site or "").strip()
        if not site:
            return keys

        keys.add(site.rstrip("/"))
        keys.add(site.rstrip("/") + "/")
        return keys

    def should_observer_ward_scan(self, item):
        skip_raw = str(getattr(
            Config,
            "OBSERVER_WARD_SKIP_STATUS_CODES",
            "400,404,405,410,418,429,500,501,502,503,504",
        ) or "")
        skip_codes = set()
        for value in skip_raw.split(","):
            value = value.strip()
            if not value:
                continue
            try:
                skip_codes.add(int(value))
            except ValueError:
                continue

        status = self.item_status(item)
        if status in skip_codes:
            return False

        if (
            getattr(Config, "RESTRICTED_HTTP_DISCOVERY", True) and
            http_access_profile(status) == "restricted"
        ):
            return True

        return status is not None

    def observer_terminal_skip(self, item):
        return self.item_status(item) in self.OBSERVER_TERMINAL_SKIP_STATUS_CODES

    def merge_observer_ward_fingerprints(self, site_info_list=None):
        site_info_list = self.site_info_list if site_info_list is None else site_info_list
        if not self.observer_ward_enable:
            return set()

        if not site_info_list:
            return set()

        site_list = []
        completed_keys = set()
        skipped_count = 0
        for item in site_info_list:
            if not item.get("site"):
                continue
            if item.get("observer_ward_complete"):
                completed_keys.add(self.site_key(item.get("site")))
                continue
            if not self.should_observer_ward_scan(item):
                skipped_count += 1
                if self.observer_terminal_skip(item):
                    completed_keys.add(self.site_key(item.get("site")))
                continue
            site_list.append(item["site"])

        if skipped_count:
            logger.info("observer_ward skip low value sites:{} task_id:{}".format(
                skipped_count, getattr(self, "task_id", "")))

        if not site_list:
            return completed_keys

        observer_map = observer_ward_fingerprint_batch(
            site_list,
            enabled=self.observer_ward_enable,
            task_id=getattr(self, "task_id", ""),
        )
        observer_meta = dict(getattr(observer_map, "meta", {}) or {})
        self.meta["observer_ward_input_count"] = (
            self.meta.get("observer_ward_input_count", 0) + len(site_list))
        self.meta["observer_ward_failed_site_count"] = (
            self.meta.get("observer_ward_failed_site_count", 0) +
            int(observer_meta.get("failed_site_count", 0) or 0)
        )
        if observer_meta.get("partial"):
            self.meta["_stage_status"] = "partial"
            self.meta["partial_reason"] = "observer_ward_partial_failure"
            self.meta["error_count"] = (
                int(self.meta.get("error_count", 0) or 0) +
                int(observer_meta.get("error_count", 1) or 1)
            )
            self.meta["warning"] = observer_meta.get("error") or "observer_ward incomplete"

        if not observer_meta.get("partial"):
            completed_keys.update(self.site_key(site) for site in site_list)

        if not observer_map:
            logger.info("observer_ward batch no fingerprint result")
            return completed_keys

        matched_site_count = 0
        matched_finger_count = 0
        for item in site_info_list:
            names = []
            for key in self.site_match_keys(item.get("site")):
                names = observer_map.get(key, [])
                if names:
                    break

            if not names:
                continue

            known_finger_set = set()
            for finger_item in item.get("finger", []):
                name = finger_item.get("name", "").strip()
                if name:
                    known_finger_set.add(name.lower())

            added = 0
            for name in names:
                name = name.strip()
                if not name:
                    continue

                name_key = name.lower()
                if name_key in known_finger_set:
                    continue

                item["finger"].append(self.build_observer_ward_fingerprint(name))
                known_finger_set.add(name_key)
                added += 1

            if added:
                matched_site_count += 1
                matched_finger_count += added

        logger.info("observer_ward batch merged sites:{} fingers:{}".format(matched_site_count, matched_finger_count))
        return completed_keys

    def run(self):
        t1 = time.time()
        logger.info("start fetch site httpx {}".format(len(self.targets)))
        self.fetch_site_with_httpx()
        elapse = time.time() - t1
        logger.info("end fetch site httpx result:{} elapse {}".format(len(self.site_info_list), elapse))

        return FetchSiteResult(self.site_info_list, meta=self.meta)


def fetch_favicon(url):
    f = FetchFavicon(url)
    return f.run()


def fetch_site(
    sites,
    concurrency=None,
    http_timeout=None,
    observer_ward_enable=None,
    task_id="",
    on_batch=None,
):
    f = FetchSite(
        sites,
        concurrency=concurrency,
        http_timeout=http_timeout,
        observer_ward_enable=observer_ward_enable,
        task_id=task_id,
        on_batch=on_batch,
    )
    return f.run()


class FetchFavicon(object):
    def __init__(self, url):
        self.url = url
        self.favicon_url = None
        pass

    def build_result(self, data):
        result = {
            "data": data,
            "url": self.favicon_url,
            "hash": mmh3.hash(data)
        }
        return result

    def run(self):
        result = {}
        try:
            favicon_url = urljoin(self.url, "/favicon.ico")
            data = self.get_favicon_data(favicon_url)
            if data:
                self.favicon_url = favicon_url
                return self.build_result(data)

            favicon_url = self.find_icon_url_from_html()
            if not favicon_url:
                return result
            data = self.get_favicon_data(favicon_url)
            if data:
                self.favicon_url = favicon_url
                return self.build_result(data)

        except Exception as e:
            logger.warning("error on {} {}".format(self.url, e))

        return result

    def get_favicon_data(self, favicon_url):
        parsed = urlparse(favicon_url or "")
        if parsed.scheme not in ("http", "https"):
            return

        conn = http_req(favicon_url)
        if conn.status_code != 200:
            return

        if len(conn.content) <= 80:
            logger.debug("favicon content len lt 100")
            return

        if "image" in conn.headers.get("Content-Type", ""):
            data = self.encode_bas64_lines(conn.content)
            return data

    def encode_bas64_lines(self, s):
        """Encode a string into multiple lines of base-64 data."""
        MAXLINESIZE = 76  # Excluding the CRLF
        MAXBINSIZE = (MAXLINESIZE // 4) * 3
        pieces = []
        for i in range(0, len(s), MAXBINSIZE):
            chunk = s[i: i + MAXBINSIZE]
            pieces.append(bytes.decode(binascii.b2a_base64(chunk)))
        return "".join(pieces)

    def find_icon_url_from_html(self):
        conn = http_req(self.url)
        if b"<link" not in conn.content:
            return
        d = pq(conn.content)
        links = d('link').items()
        icon_link_list = []
        for link in links:
            if link.attr("href") and 'icon' in link.attr("rel"):
                icon_link_list.append(link)

        for link in icon_link_list:
            if "shortcut" in link:
                return self.normalize_icon_url(link.attr('href'))

        if icon_link_list:
            return self.normalize_icon_url(icon_link_list[0].attr('href'))

    def normalize_icon_url(self, href):
        icon_url = urljoin(self.url, href or "")
        parsed = urlparse(icon_url or "")
        if parsed.scheme not in ("http", "https"):
            return
        return icon_url
