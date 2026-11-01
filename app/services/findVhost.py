import json
import difflib
import os
import re
import subprocess
import threading

from app.utils import get_title, http_req, get_logger
from app.config import Config
from .baseThread import BaseThread, thread_map
from requests.exceptions import ConnectTimeout, ReadTimeout

logger = get_logger()

bool_ratio = 0.9
REDIRECT_STATUS_CODES = {301, 302, 307, 308}
GENERIC_TITLES = {
    "301 moved permanently",
    "302 found",
    "302 moved temporarily",
    "403 forbidden",
    "404 not found",
    "502 bad gateway",
    "503 service unavailable",
    "access denied",
    "forbidden",
    "error",
}
PARKING_TITLE_PATTERNS = (
    re.compile(r"^domena\s+.+\s+jest\s+utrzymywana\s+na\s+serwerach\s+nazwa\.pl$", re.I),
    re.compile(r"\b(?:domain|domena)\b.*\b(?:parked|parking|for sale)\b", re.I),
    re.compile(r"\bthis domain (?:has been registered|is registered)\b", re.I),
)


class Page(object):
    def __init__(self, url, domain, content, status_code, content_type, headers=None):
        self.url = url
        self.domain = domain
        self.content = content or b""
        self.body_length = len(self.content)
        self.status_code = status_code
        self.title = get_title(self.content)
        self.content_type = (content_type or "").lower()
        self.headers = headers or {}
        self.redirect_location = self.headers.get("Location", "") if hasattr(self.headers, "get") else ""
        self.confidence = "strict"

    def normalized_title(self):
        title = str(self.title or "").strip().lower()
        domain = str(self.domain or "").strip().lower()
        if domain:
            title = re.sub(re.escape(domain), "{host}", title, flags=re.I)
        return re.sub(r"\s+", " ", title)

    def __eq__(self, other):
        if isinstance(other, Page):
            if self.status_code != other.status_code:
                return False

            if self.content_type != other.content_type:
                return False

            if abs(self.body_length - other.body_length) > 20:
                return False

            self_title = self.normalized_title()
            other_title = other.normalized_title()
            if abs(len(self_title) - len(other_title)) >= 3:
                return False

            if self.status_code == 200 and abs(self.body_length - other.body_length) <= 3:
                return True

            quick_ratio = difflib.SequenceMatcher(None, self.content, other.content).quick_ratio()
            return quick_ratio > bool_ratio
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return "<Page>{}-----{}".format(self.url, self.domain)

    def __hash__(self):
        return hash(self.url)

    def dump_json(self):
        return json.dumps(self.dump_json_obj(), ensure_ascii=False)

    def dump_json_obj(self):
        item = {
            "url": self.url,
            "domain": self.domain,
            "body_length": self.body_length,
            "title": self.title,
            "status_code": self.status_code,
            "redirect_location": self.redirect_location,
            "confidence": self.confidence,
        }
        return item


def _is_text_like(page):
    content_type = page.content_type or ""
    if any(x in content_type for x in ["text", "html", "json", "xml"]):
        return True
    prefix = page.content[:500].lower()
    return b"<html" in prefix or b"<!doctype" in prefix or b"{" in prefix


def _is_generic_title(title):
    title = (title or "").strip().lower()
    if not title:
        return False
    if title in GENERIC_TITLES:
        return True
    generic_fragments = [
        "access denied", "forbidden", "not found", "bad gateway",
        "service unavailable", "moved permanently", "moved temporarily",
        "安全防护", "访问被拒绝", "请求拦截", "waf",
    ]
    return any(x in title for x in generic_fragments)


def _is_parking_page(page):
    title = str(page.title or "").strip()
    if any(pattern.search(title) for pattern in PARKING_TITLE_PATTERNS):
        return True
    content = page.content[:8192].decode("utf-8", errors="ignore").lower()
    parking_markers = (
        "serwerach nazwa.pl",
        "domain parking",
        "domain is parked",
        "buy this domain",
        "this domain is for sale",
    )
    return any(marker in content for marker in parking_markers)


class BruteVhost(BaseThread):
    def __init__(self, ip, domains, scheme, concurrency=6):
        super(BruteVhost, self).__init__(targets=domains, concurrency=concurrency)
        self.ip = ip
        self.scheme = scheme
        self.url_ip = "{}://{}".format(self.scheme, self.ip)
        self.domains = domains
        self.not_found_set = set()
        self.success_set = set()
        self.cnt = 0
        self.total_cnt = len(self.domains)
        self.error_cnt = 0
        self.print_skip_warning_flag = False

    def brute_domain(self, domain):
        try:
            headers = {
                "Host": "{}".format(domain)
            }
            res = http_req(self.url_ip, headers=headers, timeout=(3, 6))
            content = res.content.replace(domain.encode(), b"")
            res_type = res.headers.get("Content-Type", "")
            page = Page(url=self.url_ip, domain=domain, content=content,
                        status_code=res.status_code, content_type=res_type,
                        headers=res.headers)
            return page
        except Exception as e:
            logger.debug("{} {} {}".format(self.url_ip, domain, str(e)))
            if isinstance(e, (ConnectTimeout, ReadTimeout)):
                self.error_cnt += 1

    def _is_baseline_page(self, page):
        for not_found_page in self.not_found_set:
            if page == not_found_page:
                return True
        return False

    def _is_valid_success(self, page):
        if '百度一下' in page.title:
            return False

        allow_redirect = bool(getattr(Config, "HOST_COLLISION_ACCEPT_REDIRECT", False))
        if page.status_code in REDIRECT_STATUS_CODES:
            if not allow_redirect:
                return False
            location = (page.redirect_location or "").lower()
            if page.domain.lower() not in location:
                return False
            page.confidence = "redirect"
            return not self._is_baseline_page(page)

        if page.status_code != 200:
            return False

        if not _is_text_like(page):
            return False

        min_body_length = int(getattr(Config, "HOST_COLLISION_MIN_BODY_LENGTH", 300) or 300)
        if page.body_length < min_body_length:
            return False

        if ("json" not in page.content_type) and (b"<" not in page.content):
            return False

        if _is_generic_title(page.title):
            return False

        if _is_parking_page(page):
            return False

        if self._is_baseline_page(page):
            return False

        page.confidence = "strict_200"
        return True

    def work(self, domain):
        if self.error_cnt >= 10:
            if not self.print_skip_warning_flag:
                logger.warning("skip {}".format(self.url_ip))

            self.print_skip_warning_flag = True
            return

        self.cnt += 1
        if self.cnt % 20 == 1:
            logger.debug("[{}/{}] >>> {} {}".format(
                self.cnt, self.total_cnt,
                self.url_ip, domain))

        page = self.brute_domain(domain)
        if not page:
            return

        if not self._is_valid_success(page):
            return

        if page not in self.success_set:
            success = page.dump_json()
            logger.success("found {}".format(success))
            self.success_set.add(page)

    def run(self):
        if not self.domains:
            return self.success_set
        domain_404_list = [self.ip, "not123abc" + self.domains[0], "wfaz.zljhaz.com", "n0ta." + self.domains[0]]
        logger.debug(">> build 404 page {}://{}".format(self.scheme, self.ip))
        for item in domain_404_list:
            page = self.brute_domain(item)
            if page:
                self.not_found_set.add(page)
        self._run()

        if len(self.success_set) > 0:
            logger.info("found {} {}".format(self.url_ip, len(self.success_set)))

        return self.success_set


def brute_vhost(ip, args):
    domains, scheme = args
    logger.info("brute_vhost >>> ip: {}, domain: {}, scheme: {}".format(ip, len(domains), scheme))
    brute = BruteVhost(ip=ip, domains=domains, scheme=scheme,
                       concurrency=max(int(getattr(
                           Config, "HOST_COLLISION_HOST_CONCURRENCY", 8) or 1), 1))
    return brute.run()


def _find_vhost_python(ips, domains, on_progress=None):
    target_scheme = ["http", "https"]
    results = []
    same_set = set()
    completed_targets = 0
    total_targets = len(ips) * len(target_scheme)

    for scheme in target_scheme:
        scheme_completed = 0

        def completed(_ip, _result):
            nonlocal completed_targets, scheme_completed
            completed_targets += 1
            scheme_completed += 1
            if on_progress:
                on_progress({
                    "scheme": scheme,
                    "scheme_completed": scheme_completed,
                    "scheme_total": len(ips),
                    "completed_targets": completed_targets,
                    "total_targets": total_targets,
                })

        result_map = thread_map(
            brute_vhost,
            items=ips,
            arg=(domains, scheme),
            concurrency=max(int(getattr(
                Config, "HOST_COLLISION_TARGET_CONCURRENCY", 3) or 1), 1),
            on_complete=completed,
        )
        for ip in result_map:
            page_set = result_map[ip]
            for page in page_set:
                key = "{}-{}-{}-{}-{}".format(
                    page.url, page.domain, page.title, page.status_code, page.body_length)
                if key in same_set:
                    continue

                same_set.add(key)
                results.append(page.dump_json_obj())

    return results


def _normalize_endpoint(value):
    if isinstance(value, str):
        parsed = None
        if "://" in value:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(value)
            except (TypeError, ValueError):
                parsed = None
        if parsed and parsed.hostname:
            scheme = str(parsed.scheme or "http").lower()
            port = parsed.port or (443 if scheme == "https" else 80)
            return {
                "scheme": scheme,
                "ip": parsed.hostname,
                "port": port,
                "sources": [],
                "domains": [],
            }
        return None

    if not isinstance(value, dict):
        return None
    scheme = str(value.get("scheme") or "").strip().lower()
    ip = str(value.get("ip") or "").strip().strip("[]")
    try:
        port = int(value.get("port") or 0)
    except (TypeError, ValueError):
        return None
    if scheme not in ("http", "https") or not ip or port <= 0 or port > 65535:
        return None
    return {
        "scheme": scheme,
        "ip": ip,
        "port": port,
        "sources": sorted(set(value.get("sources") or [])),
        "domains": sorted(set(value.get("domains") or [])),
    }


def _legacy_endpoints(ips):
    endpoints = []
    for ip in ips or []:
        ip = str(ip or "").strip()
        if not ip:
            continue
        endpoints.extend([
            {"scheme": "http", "ip": ip, "port": 80, "sources": ["legacy_default"]},
            {"scheme": "https", "ip": ip, "port": 443, "sources": ["legacy_default"]},
        ])
    return endpoints


def _dedupe_endpoints(values):
    merged = {}
    for raw in values or []:
        item = _normalize_endpoint(raw)
        if not item:
            continue
        key = (item["scheme"], item["ip"], item["port"])
        current = merged.setdefault(key, {
            "scheme": item["scheme"],
            "ip": item["ip"],
            "port": item["port"],
            "sources": set(),
            "domains": set(),
        })
        current["sources"].update(item.get("sources") or [])
        current["domains"].update(item.get("domains") or [])
    output = []
    for key in sorted(merged):
        item = merged[key]
        item["sources"] = sorted(item["sources"])
        item["domains"] = sorted(item["domains"])
        output.append(item)
    return output


def _find_vhost_python_endpoints(endpoints, domains, on_progress=None, on_result=None):
    results = []
    completed_targets = 0
    total_targets = len(endpoints)
    for endpoint in endpoints:
        target = endpoint["ip"]
        default_port = (
            endpoint["scheme"] == "http" and endpoint["port"] == 80
        ) or (
            endpoint["scheme"] == "https" and endpoint["port"] == 443
        )
        if not default_port:
            target = "{}:{}".format(target, endpoint["port"])
        endpoint_domains = sorted(set(domains) | set(endpoint.get("domains") or []))
        page_set = brute_vhost(target, (endpoint_domains, endpoint["scheme"])) or []
        for page in page_set:
            item = page.dump_json_obj()
            item.update({
                "ip": endpoint["ip"],
                "port": endpoint["port"],
                "scheme": endpoint["scheme"],
                "path": "/",
                "sni": "",
                "endpoint_sources": endpoint.get("sources") or [],
            })
            results.append(item)
            if on_result:
                on_result(item)
        completed_targets += 1
        if on_progress:
            on_progress({
                "endpoint_key": "{}://{}:{}".format(
                    endpoint["scheme"], endpoint["ip"], endpoint["port"]),
                "completed_targets": completed_targets,
                "total_targets": total_targets,
                "engine": "python_fallback",
            })
    return results


def _drain_stderr(stream, output):
    try:
        for line in iter(stream.readline, ""):
            line = line.strip()
            if line:
                output.append(line)
    finally:
        stream.close()


def _find_vhost_go(
        endpoints, domains, paths=None, on_progress=None, on_result=None,
        base_domain=""):
    engine_path = str(getattr(Config, "HOST_COLLISION_ENGINE_PATH", "") or "")
    payload = {
        "endpoints": endpoints,
        "domains": sorted(set(domains or [])),
        "base_domain": str(base_domain or "").strip().strip("*.").lower(),
        "paths": paths or {},
        "concurrency": max(int(getattr(
            Config, "HOST_COLLISION_GLOBAL_CONCURRENCY", 128) or 1), 1),
        "endpoint_concurrency": max(int(getattr(
            Config, "HOST_COLLISION_TARGET_CONCURRENCY", 8) or 1), 1),
        "host_concurrency": max(int(getattr(
            Config, "HOST_COLLISION_HOST_CONCURRENCY", 16) or 1), 1),
        "connect_timeout_ms": max(int(getattr(
            Config, "HOST_COLLISION_CONNECT_TIMEOUT_MS", 1800) or 1), 250),
        "request_timeout_ms": max(int(getattr(
            Config, "HOST_COLLISION_REQUEST_TIMEOUT_MS", 6000) or 1), 500),
        "max_body_bytes": max(int(getattr(
            Config, "HOST_COLLISION_MAX_BODY_BYTES", 131072) or 1), 4096),
        "min_body_length": max(int(getattr(
            Config, "HOST_COLLISION_MIN_BODY_LENGTH", 300) or 1), 1),
        "accept_redirect": bool(getattr(
            Config, "HOST_COLLISION_ACCEPT_REDIRECT", False)),
        "path_limit": max(int(getattr(
            Config, "HOST_COLLISION_PATH_LIMIT", 3) or 0), 0),
        "retries": max(int(getattr(
            Config, "HOST_COLLISION_RETRIES", 1) or 0), 0),
    }
    proc = subprocess.Popen(
        [engine_path],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    stderr_lines = []
    stderr_thread = threading.Thread(
        target=_drain_stderr,
        args=(proc.stderr, stderr_lines),
        daemon=True,
    )
    stderr_thread.start()
    results = []
    completed_endpoint_keys = set()
    try:
        json.dump(payload, proc.stdin, ensure_ascii=True)
        proc.stdin.close()
        for raw_line in proc.stdout:
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                message = json.loads(raw_line)
            except ValueError:
                logger.warning("host collision engine invalid output: {}".format(
                    raw_line[:500]))
                continue
            event_type = message.get("type")
            if event_type == "result" and isinstance(message.get("result"), dict):
                item = message["result"]
                results.append(item)
                if on_result:
                    on_result(item)
            elif event_type == "start" and on_progress:
                progress = dict(message)
                progress["completed_targets"] = int(
                    progress.get("completed_endpoints", 0) or 0)
                progress["total_targets"] = int(
                    progress.get("total_endpoints", len(endpoints)) or len(endpoints))
                progress["engine"] = "go"
                on_progress(progress)
            elif event_type == "progress" and on_progress:
                progress = dict(message)
                endpoint_key = str(progress.get("endpoint_key") or "")
                if endpoint_key:
                    completed_endpoint_keys.add(endpoint_key)
                progress["completed_targets"] = int(
                    progress.get("completed_endpoints", 0) or 0)
                progress["total_targets"] = int(
                    progress.get("total_endpoints", len(endpoints)) or len(endpoints))
                progress["engine"] = "go"
                on_progress(progress)
            elif event_type == "progress":
                endpoint_key = str(message.get("endpoint_key") or "")
                if endpoint_key:
                    completed_endpoint_keys.add(endpoint_key)
            elif event_type == "summary" and on_progress:
                progress = dict(message)
                progress["completed_targets"] = int(
                    progress.get("completed_endpoints", 0) or 0)
                progress["total_targets"] = int(
                    progress.get("total_endpoints", len(endpoints)) or len(endpoints))
                progress["engine"] = "go"
                progress["summary"] = True
                on_progress(progress)
        return_code = proc.wait()
        stderr_thread.join(timeout=2)
        if return_code:
            raise RuntimeError(
                "host collision engine exited {}: {}".format(
                    return_code, "; ".join(stderr_lines[-10:])))
        expected_endpoint_keys = {
            "{}://{}:{}".format(
                endpoint.get("scheme"), endpoint.get("ip"), endpoint.get("port"))
            for endpoint in endpoints
        }
        missing_endpoint_keys = expected_endpoint_keys - completed_endpoint_keys
        if missing_endpoint_keys:
            raise RuntimeError(
                "host collision engine ended before completing {} endpoints".format(
                    len(missing_endpoint_keys)))
    except BaseException:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
        raise
    finally:
        if proc.stdin and not proc.stdin.closed:
            proc.stdin.close()
        if proc.stdout:
            proc.stdout.close()
        stderr_thread.join(timeout=2)
    return results


def find_vhost(
        ips=None, domains=None, on_progress=None, endpoints=None,
        paths=None, on_result=None, base_domain=""):
    domains = sorted(set(domains or []))
    normalized_endpoints = _dedupe_endpoints(
        endpoints if endpoints is not None else _legacy_endpoints(ips))
    targeted_domain_count = sum(
        len(endpoint.get("domains") or []) for endpoint in normalized_endpoints)
    if not normalized_endpoints or (not domains and not targeted_domain_count):
        return []

    engine_path = str(getattr(Config, "HOST_COLLISION_ENGINE_PATH", "") or "")
    engine_enabled = bool(getattr(Config, "HOST_COLLISION_GO_ENGINE", True))
    if engine_enabled and engine_path and os.path.isfile(engine_path) and os.access(engine_path, os.X_OK):
        try:
            return _find_vhost_go(
                normalized_endpoints,
                domains,
                paths=paths,
                on_progress=on_progress,
                on_result=on_result,
                base_domain=base_domain,
            )
        except Exception:
            logger.exception(
                "host collision Go engine failed after launch; abort the stage "
                "instead of silently rerunning with the weaker Python engine")
            raise
    else:
        logger.warning("host collision Go engine unavailable, use Python fallback")
    return _find_vhost_python_endpoints(
        normalized_endpoints,
        domains,
        on_progress=on_progress,
        on_result=on_result,
    )
