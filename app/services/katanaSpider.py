import html
import ipaddress
import json
import os
import re
import select
import signal
import shutil
import subprocess
import tempfile
import time
from urllib.parse import parse_qsl, unquote, urlparse

from app import utils
from app.config import Config
from .baseUpdateTask import BaseUpdateTask
from app.services.resourceBudget import acquire as acquire_resource_budget

logger = utils.get_logger()

STATIC_EXTENSIONS = {
    ".7z", ".avi", ".bz2", ".css", ".csv", ".doc", ".docx", ".eot", ".gif",
    ".gz", ".ico", ".jpeg", ".jpg", ".js", ".json", ".map", ".mov", ".mp3",
    ".mp4", ".otf", ".pdf", ".png", ".ppt", ".pptx", ".rar", ".svg", ".tar",
    ".tgz", ".ts", ".ttf", ".txt", ".wav", ".woff", ".woff2", ".xls", ".xlsx",
    ".xml", ".zip",
}

BROWSER_SCRIPT_EXTENSIONS = {".js", ".mjs", ".map"}

BROWSER_NETWORK_STATIC_EXTENSIONS = {
    ".7z", ".avi", ".bz2", ".css", ".csv", ".doc", ".docx", ".eot",
    ".gif", ".gz", ".ico", ".jpeg", ".jpg", ".js", ".map", ".mov",
    ".mp3", ".mp4", ".mjs", ".otf", ".pdf", ".png", ".ppt", ".pptx",
    ".rar", ".svg", ".tar", ".tgz", ".ts", ".ttf", ".wav", ".woff",
    ".woff2", ".xls", ".xlsx", ".zip",
}

GENERIC_STATIC_SEGMENTS = {
    "assets", "css", "fonts", "images", "img", "js", "media", "static",
}

BUILD_ARTIFACT_SEGMENTS = {
    ".pnpm", "_next", "__webpack_hmr", "chunks", "clientlibs", "dist",
    "node_modules", "runtime", "webpack",
}

BUILD_ARTIFACT_PREFIXES = (
    "/_next/static/",
    "/assets/",
    "/static/",
    "/node_modules/",
)

API_PATTERNS = [
    r"^/api(?:/|$)",
    r"/api(?:/|$)",
    r"^/rest(?:/|$)",
    r"/graphql(?:/|$)",
    r"/openapi(?:/|$)",
    r"/swagger(?:/|$)",
    r"/v\d+/(?:api|openapi)(?:/|$)",
]

API_SEGMENTS = {
    "ajax", "api", "apis", "graphql", "jsonrpc", "openapi", "rest", "rpc",
    "service", "services", "servlet",
}

API_ENDPOINT_EXTENSIONS = {
    ".action", ".asmx", ".ashx", ".do", ".json", ".jsonp", ".svc",
}

ENTRY_TERMINAL_SEGMENTS = {
    "admin", "backend", "cloud", "console", "dashboard", "explore", "home",
    "index", "login", "manager", "packages", "portal", "sqllab", "superset",
    "welcome", "workspace",
}

API_ACTION_WORDS = {
    "add", "authorize", "callback", "change", "check", "config", "create",
    "data", "delete", "detail", "download", "edit", "export", "generate",
    "get", "import", "info", "list", "login", "logout", "profile", "query",
    "refresh", "remove", "reset", "save", "search", "self", "send", "set",
    "status", "submit", "toggle", "token", "update", "upload", "validate",
    "view",
}

DANGEROUS_QUERY_WORDS = {
    "cancel", "clear", "confirm", "del", "delete", "disable", "drop",
    "edit", "enable", "logout", "modify", "pay", "refund", "remove",
    "reset", "restart", "save", "start", "stop", "submit", "truncate",
    "update",
}

HAE_ALL_URL_RE = re.compile(
    r"https?://[-A-Za-z0-9+&@#/%?=~_|!:,.;\u4E00-\u9FFF]+[-A-Za-z0-9+&@#/%=~_|]"
)


def _normalize_domain(domain):
    return str(domain or "").strip().strip(".").lower()


def _domain_in_scope(domain, scope_domains):
    domain = _normalize_domain(domain)
    for scope in scope_domains or []:
        scope = _normalize_domain(scope)
        if not scope:
            continue
        if domain == scope or domain.endswith("." + scope):
            return True
    return False


def _ip_address(hostname):
    try:
        return ipaddress.ip_address(str(hostname or "").strip("[]"))
    except ValueError:
        return None


def _is_ip_host(hostname):
    return _ip_address(hostname) is not None


def _ip_url_scope(hostname):
    ip = _ip_address(hostname)
    if not ip:
        return ""

    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_global:
        return "public"
    if ip.is_private:
        return "private"
    try:
        if ip in ipaddress.ip_network("100.64.0.0/10"):
            return "shared"
    except ValueError:
        pass
    return "reserved"


def _is_allowed_ip_host(hostname):
    ip = _ip_address(hostname)
    if not ip:
        return False

    if not getattr(Config, "KATANA_ALLOW_IP_URLS", True):
        return False

    scope = _ip_url_scope(hostname)
    if scope in ("link_local", "multicast", "unspecified"):
        return False

    if scope == "loopback":
        return bool(getattr(Config, "KATANA_ALLOW_LOOPBACK_IP_URLS", True))

    if scope == "public":
        return True

    if scope == "private" and getattr(Config, "KATANA_ALLOW_PRIVATE_IP_URLS", True):
        return True

    if scope == "shared" and getattr(Config, "KATANA_ALLOW_SHARED_IP_URLS", True):
        return True

    if scope == "reserved" and getattr(Config, "KATANA_ALLOW_RESERVED_IP_URLS", True):
        return True

    return False


def _should_fetch_ip_url(hostname):
    scope = _ip_url_scope(hostname)
    if scope == "public":
        return True
    return bool(getattr(Config, "KATANA_FETCH_NON_GLOBAL_IP_URLS", False))


def _is_static_path(path):
    ext = os.path.splitext(str(path or "").lower())[1]
    return ext in STATIC_EXTENSIONS


def _is_api_hostname(hostname):
    labels = [x for x in str(hostname or "").lower().split(".") if x]
    if not labels:
        return False

    first_label = labels[0]
    return (
        first_label == "api" or
        first_label.startswith("api-") or
        first_label.endswith("-api") or
        bool(re.match(r"^api\d+$", first_label)) or
        "-api-" in first_label
    )


def _is_build_artifact_path(path):
    path = unquote(str(path or "")).strip()
    if not path:
        return False

    lower_path = path.lower()
    if any(lower_path.startswith(prefix) for prefix in BUILD_ARTIFACT_PREFIXES):
        return True

    segments = [x for x in lower_path.strip("/").split("/") if x]
    if any(segment in BUILD_ARTIFACT_SEGMENTS for segment in segments):
        return True

    if "static/chunks" in lower_path or "/assets/" in lower_path:
        return True

    return False


def _has_dirty_entry_chars(value):
    value = unquote(str(value or ""))
    dirty_chars = ("\\", "<", ">", "`", "\"", "'", "{", "}", "|")
    return any(ch in value for ch in dirty_chars)


def _segment_words(segment):
    segment = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(segment or ""))
    return [x for x in re.split(r"[^A-Za-z0-9]+", segment.lower()) if x]


def _is_action_segment(segment):
    segment = str(segment or "").strip()
    if not segment:
        return False

    lower_segment = segment.lower()
    if lower_segment in ENTRY_TERMINAL_SEGMENTS:
        return False

    words = _segment_words(segment)
    if any(word in API_SEGMENTS for word in words):
        return True

    if any(word in API_ACTION_WORDS for word in words):
        return True

    for action in API_ACTION_WORDS:
        if lower_segment.startswith(action) and len(lower_segment) > len(action) + 2:
            return True
        if lower_segment.endswith(action) and len(lower_segment) > len(action) + 2:
            return True

    return False


def _is_api_path(path):
    raw_path = str(path or "").strip()
    if not raw_path:
        return False

    path = raw_path.lower()
    for pattern in API_PATTERNS:
        if re.search(pattern, path):
            return True

    segments = [x for x in raw_path.strip("/").split("/") if x]
    lower_segments = [x.lower() for x in segments]
    if any(segment in API_SEGMENTS for segment in lower_segments):
        return True

    if os.path.splitext(path)[1].lower() in API_ENDPOINT_EXTENSIONS:
        return True

    return any(_is_action_segment(segment) for segment in segments)


def _has_dangerous_query(query):
    for key, value in parse_qsl(str(query or ""), keep_blank_values=True):
        words = _segment_words(key) + _segment_words(value)
        if any(word in DANGEROUS_QUERY_WORDS for word in words):
            return True
    return False


def _has_entry_path(parsed, literal_all_url=False):
    if parsed.scheme not in ("http", "https"):
        return False

    hostname = _normalize_domain(parsed.hostname)
    if (
        not literal_all_url and
        getattr(Config, "KATANA_FILTER_API", True) and
        _is_api_hostname(hostname)
    ):
        return False

    path = unquote(parsed.path or "")
    fragment = unquote(parsed.fragment or "")
    if path in ("", "/") and fragment:
        if fragment.startswith("!/"):
            path = fragment[1:]
        elif fragment.startswith("/"):
            path = fragment
    if not path or path == "/":
        return False

    if _has_dirty_entry_chars(path) or "@" in path:
        return False

    if _is_static_path(path):
        return False

    if _is_build_artifact_path(path):
        return False

    if (
        not literal_all_url and
        getattr(Config, "KATANA_FILTER_API", True) and
        _is_api_path(path)
    ):
        return False

    if _has_dangerous_query(parsed.query):
        return False

    segments = [x for x in path.lower().strip("/").split("/") if x]
    if segments and segments[0] in GENERIC_STATIC_SEGMENTS:
        return False

    return True


def normalize_entry_candidate(raw_url, scope_domains=None, literal_all_url=False):
    try:
        url = utils.normal_url(raw_url)
    except (TypeError, ValueError):
        return "", ""
    if not url:
        return "", ""

    try:
        raw_fragment = urlparse(str(raw_url or "")).fragment
    except (TypeError, ValueError):
        raw_fragment = ""
    if raw_fragment:
        url = "{}#{}".format(url, raw_fragment)

    try:
        parsed = urlparse(url)
        hostname = _normalize_domain(parsed.hostname)
    except (TypeError, ValueError):
        return "", ""
    if not hostname:
        return "", ""

    is_ip_host = _is_ip_host(hostname)
    normalized_scope = [_normalize_domain(value) for value in (scope_domains or []) if _normalize_domain(value)]
    if normalized_scope and not _domain_in_scope(hostname, normalized_scope):
        if not (is_ip_host and _is_allowed_ip_host(hostname)):
            return "", ""
    if is_ip_host and not _is_allowed_ip_host(hostname):
        return "", ""
    if not is_ip_host and utils.check_domain_black(hostname):
        return "", ""
    if not _has_entry_path(parsed, literal_all_url=literal_all_url):
        return "", hostname
    if _has_dirty_entry_chars(unquote(url)):
        return "", hostname
    return url, hostname


class KatanaSpider(object):
    def __init__(
        self,
        entry_urls_list,
        scope_domains=None,
        task_id="",
        evidence_callback=None,
        domain_callback=None,
        entry_callback=None,
        crawl_profile="normal",
        stage_name="site_spider",
    ):
        self.task_id = task_id or ""
        self.scope_domains = [_normalize_domain(x) for x in (scope_domains or []) if _normalize_domain(x)]
        self.base_update_task = BaseUpdateTask(self.task_id) if self.task_id else None
        self.incremental_url_set = set()
        self.incremental_url_list = []
        self.incremental_domain_set = set()
        self.incremental_ip_url_host_set = set()
        self.incremental_all_url_set = set()
        self.incremental_all_url_list = []
        self.evidence_pair_set = set()
        self.domain_evidence_pair_set = set()
        self.domain_entry_url_map = {}
        self.entry_host_count = {}
        self.entry_cap_logged = False
        self.host_cap_logged = set()
        self.entry_cap_reached = False
        self.raw_output_count = 0
        self.stop_reason = ""
        self.partial_error = ""
        self.warnings = []
        self.last_progress_update = 0
        self.crawl_batch_total = 0
        self.crawl_batch_completed = 0
        self.crawl_batch_attempted = 0
        self.crawl_batch_succeeded = 0
        self.crawl_batch_timed_out = 0
        self.crawl_batch_failed = 0
        self.crawl_target_metrics = []
        self.last_crawl_meta = {}
        self.url_source_map = {}
        self.entry_url_sources_map = {}
        self.domain_source_map = {}
        self.crawler_url_sources_map = {}
        self.seed_endpoint_set = set()
        self.crawler_endpoint_set = set()
        self.body_all_url_set = set()
        self.browser_xhr_url_set = set()
        self.browser_network_url_set = set()
        self.browser_script_url_set = set()
        self.external_network_url_set = set()
        self.evidence_callback = evidence_callback
        self.domain_callback = domain_callback
        self.entry_callback = entry_callback
        self.crawl_profile = str(crawl_profile or "normal").strip().lower()
        self.stage_name = str(stage_name or "site_spider")
        self.entry_urls = []
        seen = set()
        for item in entry_urls_list or []:
            if isinstance(item, str):
                values = [item]
            else:
                values = list(item or [])
            for url in values:
                url = str(url or "").strip()
                if not url:
                    continue
                try:
                    normalized = utils.normal_url(url)
                except (TypeError, ValueError):
                    normalized = ""
                normalized = normalized or url
                if normalized in seen:
                    continue
                seen.add(normalized)
                self.entry_urls.append(normalized)
                self.seed_endpoint_set.add(normalized)

    def _task_stopped(self):
        if not self.base_update_task:
            return False
        try:
            return self.base_update_task.is_terminal()
        except Exception as e:
            logger.warning("katana check task status failed: {}".format(e))
            return False

    def _max_entry_urls(self):
        if self.crawl_profile == "dynamic":
            return int(getattr(Config, "KATANA_DYNAMIC_MAX_ENTRY_URLS", 1000) or 0)
        if self.crawl_profile == "restricted":
            return int(getattr(Config, "KATANA_RESTRICTED_MAX_ENTRY_URLS", 300) or 0)
        return int(getattr(Config, "KATANA_MAX_ENTRY_URLS", 1000) or 0)

    def _max_entry_urls_per_host(self):
        if self.crawl_profile == "dynamic":
            return int(getattr(
                Config, "KATANA_DYNAMIC_MAX_ENTRY_URLS_PER_HOST", 80) or 0)
        if self.crawl_profile == "restricted":
            return int(getattr(Config, "KATANA_RESTRICTED_MAX_ENTRY_URLS_PER_HOST", 30) or 0)
        return int(getattr(Config, "KATANA_MAX_ENTRY_URLS_PER_HOST", 0) or 0)

    def _max_raw_outputs(self):
        if self.crawl_profile == "dynamic":
            return int(getattr(Config, "KATANA_DYNAMIC_MAX_RAW_OUTPUTS", 15000) or 0)
        return int(getattr(Config, "KATANA_MAX_RAW_OUTPUTS", 50000) or 0)

    def _profile_value(self, normal_name, restricted_name, dynamic_name=None):
        if self.crawl_profile == "dynamic" and dynamic_name:
            return getattr(Config, dynamic_name, getattr(Config, normal_name))
        if self.crawl_profile == "restricted":
            return getattr(Config, restricted_name, getattr(Config, normal_name))
        return getattr(Config, normal_name)

    def _update_progress(self, force=False):
        if not self.base_update_task:
            return

        interval = int(getattr(Config, "KATANA_PROGRESS_INTERVAL", 10) or 10)
        now = time.time()
        if not force and now - self.last_progress_update < interval:
            return

        self.last_progress_update = now
        try:
            self.base_update_task.update_stage_progress(
                self.stage_name,
                {
                    "input_count": len(self.entry_urls),
                    "output_count": len(self.incremental_url_set),
                    "raw_output_count": self.raw_output_count,
                    "domain_count": len(self.incremental_domain_set),
                    "ip_url_host_count": len(self.incremental_ip_url_host_set),
                    "all_url_count": len(self.incremental_all_url_set),
                    "seed_endpoint_count": len(self.seed_endpoint_set),
                    "crawler_endpoint_count": len(self.crawler_endpoint_set),
                    "body_all_url_count": len(self.body_all_url_set),
                    "browser_xhr_url_count": len(self.browser_xhr_url_set),
                    "browser_network_url_count": len(
                        self.browser_network_url_set),
                    "browser_script_url_count": len(self.browser_script_url_set),
                    "external_network_filtered_count": len(
                        self.external_network_url_set),
                    "entry_cap_reached": self.entry_cap_reached,
                    "max_entry_urls": self._max_entry_urls(),
                    "max_entry_urls_per_host": self._max_entry_urls_per_host(),
                    "crawler_engine": "katana",
                    "crawl_profile": self.crawl_profile,
                    "crawl_batch_total": self.crawl_batch_total,
                    "crawl_batch_completed": self.crawl_batch_completed,
                    "crawl_batch_attempted": self.crawl_batch_attempted,
                    "crawl_batch_succeeded": self.crawl_batch_succeeded,
                    "crawl_batch_timed_out": self.crawl_batch_timed_out,
                    "crawl_batch_failed": self.crawl_batch_failed,
                    "crawl_warning_count": len(self.warnings),
                },
            )
        except Exception as e:
            logger.warning("katana update stage progress failed task_id:{} error:{}".format(self.task_id, e))

    def _build_command(self, input_path):
        command = [
            Config.KATANA_BIN,
            "-list", input_path,
            "-silent",
            "-j",
            "-or",
            "-d", str(self._profile_value(
                "KATANA_DEPTH", "KATANA_RESTRICTED_DEPTH", "KATANA_DYNAMIC_DEPTH")),
            "-c", str(self._profile_value(
                "KATANA_CONCURRENCY", "KATANA_RESTRICTED_CONCURRENCY",
                "KATANA_DYNAMIC_CONCURRENCY")),
            "-p", str(self._profile_value(
                "KATANA_PARALLELISM", "KATANA_RESTRICTED_PARALLELISM",
                "KATANA_DYNAMIC_PARALLELISM")),
            "-rl", str(self._profile_value(
                "KATANA_RATE_LIMIT", "KATANA_RESTRICTED_RATE_LIMIT",
                "KATANA_DYNAMIC_RATE_LIMIT")),
            "-timeout", str(self._profile_value(
                "KATANA_TIMEOUT", "KATANA_RESTRICTED_TIMEOUT",
                "KATANA_DYNAMIC_TIMEOUT")),
            "-iqp",
            "-fsu",
            "-fs", "rdn",
        ]

        if getattr(Config, "KATANA_JS_CRAWL", True):
            command.append("-jc")

        if self.crawl_profile == "dynamic":
            command.extend([
                # The normal pass already ran. Hybrid mode repeats that pass and
                # can consume the page/time budget before Chrome contributes.
                "-hl",
                "-xhr",
                "-nos",
                "-pls", "domcontentloaded",
                "-dwt", str(max(int(getattr(
                    Config, "KATANA_DYNAMIC_DOM_WAIT", 3) or 0), 0)),
                "-time-stable", str(max(int(getattr(
                    Config, "KATANA_DYNAMIC_TIME_STABLE", 2) or 0), 0)),
            ])
            chrome_path = str(getattr(
                Config, "KATANA_CHROME_PATH", "") or "").strip()
            if chrome_path:
                command.extend(["-scp", chrome_path])
            if getattr(Config, "KATANA_DYNAMIC_JSLUICE", True):
                command.append("-jsl")
            crawl_duration = int(getattr(
                Config, "KATANA_DYNAMIC_CRAWL_DURATION", 25) or 0)
            if crawl_duration > 0:
                command.extend([
                    # Katana applies -ct to every target, not to the whole list.
                    "-ct", "{}s".format(crawl_duration),
                ])
            max_domain_pages = int(getattr(
                Config, "KATANA_DYNAMIC_MAX_DOMAIN_PAGES", 30) or 0)
            if max_domain_pages > 0:
                command.extend(["-mdp", str(max_domain_pages)])

        known_files = str(getattr(Config, "KATANA_KNOWN_FILES", "") or "").strip()
        if known_files and self.crawl_profile != "dynamic":
            for item in known_files.split(","):
                item = item.strip()
                if item:
                    command.extend(["-kf", item])

        if self.crawl_profile == "dynamic":
            nice_value = max(min(int(getattr(
                Config, "KATANA_DYNAMIC_NICE", 10) or 0), 19), 0)
            nice_bin = shutil.which("nice")
            if nice_value and nice_bin:
                command = [nice_bin, "-n", str(nice_value)] + command
            cpuset = str(getattr(
                Config, "KATANA_DYNAMIC_CPUSET", "") or "").strip()
            taskset_bin = shutil.which("taskset")
            if cpuset and taskset_bin:
                command = [taskset_bin, "-c", cpuset] + command

        return command

    def _add_warning(self, message):
        message = str(message or "").strip()
        if message and message not in self.warnings:
            self.warnings.append(message)

    @staticmethod
    def _extract_request_field(data, field):
        if not isinstance(data, dict):
            return ""

        request = data.get("request")
        if isinstance(request, dict):
            value = request.get(field)
            if value:
                return str(value).strip()

        value = data.get(field)
        if value:
            return str(value).strip()

        return ""

    def _normalize_entry_url(self, raw_url, literal_all_url=False):
        return normalize_entry_candidate(
            raw_url,
            self.scope_domains,
            literal_all_url=literal_all_url,
        )

    @staticmethod
    def _decode_all_url_text(item):
        text = html.unescape(str(item or ""))
        replacements = (
            (r"\\+u003[aA]", ":"),
            (r"\\+x3[aA]", ":"),
            (r"\\+u002[fF]", "/"),
            (r"\\+x2[fF]", "/"),
            (r"\\+/", "/"),
        )
        for pattern, replacement in replacements:
            text = re.sub(pattern, replacement, text)
        return text

    def _extract_absolute_urls(self, item):
        urls = []
        seen = set()
        decoded = self._decode_all_url_text(item)
        for match in HAE_ALL_URL_RE.findall(decoded):
            url = match.strip()
            if url in seen:
                continue
            seen.add(url)
            urls.append(url)
        return urls

    def _extract_discoveries(self, item):
        item = str(item or "").strip()
        if not item:
            return []

        try:
            data = json.loads(item)
        except ValueError:
            return [
                {
                    "url": url,
                    "source": "",
                    "tag": "",
                    "attribute": "",
                    "kind": "plain_all_url",
                }
                for url in self._extract_absolute_urls(item)
                if not self._is_seed_endpoint(url)
            ]
        if not isinstance(data, dict):
            return [
                {
                    "url": url,
                    "source": "",
                    "tag": "",
                    "attribute": "",
                    "kind": "plain_all_url",
                }
                for url in self._extract_absolute_urls(item)
                if not self._is_seed_endpoint(url)
            ]

        endpoint = self._extract_request_field(data, "endpoint") or self._extract_request_field(data, "url")
        source = self._extract_request_field(data, "source")
        request = data.get("request") if isinstance(data.get("request"), dict) else {}
        request_headers = self._normalized_headers(request.get("headers"))
        if not source:
            source = request_headers.get("referer", "")
        discoveries = []
        if endpoint and not self._is_seed_endpoint(endpoint):
            self.crawler_endpoint_set.add(endpoint)
            self._remember_source(self.crawler_url_sources_map, endpoint, source)
            if self.crawl_profile == "dynamic" and self._is_browser_script_url(endpoint):
                discoveries.append({
                    "url": endpoint,
                    "source": source,
                    "tag": "request",
                    "attribute": "endpoint",
                    "kind": "browser_script",
                })

        response = data.get("response")
        response = response if isinstance(response, dict) else {}
        xhr_requests = []
        for values in (
            data.get("xhr_requests", []),
            response.get("xhr_requests", []),
        ):
            if isinstance(values, dict):
                values = [values]
            if isinstance(values, (list, tuple)):
                xhr_requests.extend(values)

        explicit_xhr_endpoints = set()
        for xhr_request in xhr_requests:
            if not isinstance(xhr_request, dict):
                continue
            xhr_endpoint = str(
                xhr_request.get("endpoint") or xhr_request.get("url") or ""
            ).strip()
            if not xhr_endpoint or self._is_seed_endpoint(xhr_endpoint):
                continue
            explicit_xhr_endpoints.add(xhr_endpoint)
            self.crawler_endpoint_set.add(xhr_endpoint)
            self._remember_source(
                self.crawler_url_sources_map, xhr_endpoint, endpoint or source)
            if self.crawl_profile == "dynamic":
                discoveries.append({
                    "url": xhr_endpoint,
                    "source": endpoint or source,
                    "tag": "xhr",
                    "attribute": str(xhr_request.get("method") or "").upper(),
                    "kind": "browser_xhr",
                })

        if (
            self.crawl_profile == "dynamic" and
            endpoint and
            endpoint not in explicit_xhr_endpoints and
            not self._is_seed_endpoint(endpoint) and
            self._looks_like_browser_network_request(data)
        ):
            discoveries.append({
                "url": endpoint,
                "source": source,
                "tag": "browser_network",
                "attribute": str(request.get("method") or "GET").upper(),
                "kind": "browser_network",
            })

        body = response.get("body", "")
        for url in self._extract_absolute_urls(body):
            discoveries.append({
                "url": url,
                "source": endpoint or source,
                "tag": "body",
                "attribute": "",
                "kind": "body_all_url",
            })

        return discoveries

    @staticmethod
    def _normalized_headers(value):
        if not isinstance(value, dict):
            return {}
        return {
            str(name or "").strip().lower(): str(header or "").strip()
            for name, header in value.items()
            if str(name or "").strip()
        }

    @classmethod
    def _looks_like_browser_network_request(cls, data):
        if not isinstance(data, dict):
            return False
        request = data.get("request")
        if not isinstance(request, dict):
            request = {}
        endpoint = str(
            request.get("endpoint") or request.get("url") or
            data.get("endpoint") or data.get("url") or ""
        ).strip()
        try:
            parsed = urlparse(endpoint)
        except (TypeError, ValueError):
            return False
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return False
        if os.path.splitext((parsed.path or "").lower())[1] in BROWSER_NETWORK_STATIC_EXTENSIONS:
            return False

        method = str(request.get("method") or data.get("method") or "GET").upper()
        request_headers = cls._normalized_headers(request.get("headers"))
        response = data.get("response")
        response = response if isinstance(response, dict) else {}
        response_headers = cls._normalized_headers(response.get("headers"))
        content_type = str(
            response_headers.get("content-type") or
            response.get("content_type") or ""
        ).lower().split(";", 1)[0].strip()

        if method not in ("GET", "HEAD", "OPTIONS"):
            return True
        if (
            content_type in {
                "application/graphql", "application/json", "application/xml",
                "text/event-stream", "text/json", "text/xml",
            } or
            content_type.endswith("+json") or
            content_type.endswith("+xml")
        ):
            return True
        if _is_api_path(parsed.path):
            return True
        if "html" in content_type or "xhtml" in content_type:
            return False
        return bool(
            request_headers.get("referer") and
            "*/*" in request_headers.get("accept", "")
        )

    @staticmethod
    def _is_browser_script_url(url):
        try:
            path = urlparse(str(url or "")).path.lower()
        except (TypeError, ValueError):
            return False
        return os.path.splitext(path)[1] in BROWSER_SCRIPT_EXTENSIONS

    def _remember_external_network_url(self, url):
        try:
            parsed = urlparse(str(url or "").strip())
        except (TypeError, ValueError):
            return
        hostname = _normalize_domain(parsed.hostname)
        if (
            parsed.scheme in ("http", "https") and
            hostname and
            not _is_ip_host(hostname) and
            self.scope_domains and
            not _domain_in_scope(hostname, self.scope_domains)
        ):
            self.external_network_url_set.add(str(url).strip())

    def _is_seed_endpoint(self, url):
        try:
            normalized = utils.normal_url(str(url or "").strip())
        except (TypeError, ValueError):
            normalized = ""
        return bool(normalized and normalized in self.seed_endpoint_set)

    @staticmethod
    def _remember_source(source_map, key, source):
        key = str(key or "").strip()
        source = str(source or "").strip()
        if not key or not source:
            return

        if not source_map.get(key):
            source_map[key] = source

    def _save_incremental_entry_url(
        self,
        raw_url,
        source_url="",
        literal_all_url=False,
    ):
        entry_url, hostname = self._normalize_entry_url(
            raw_url,
            literal_all_url=literal_all_url,
        )
        if not entry_url:
            return "skip"

        source_url = str(source_url or "").strip()
        if _is_ip_host(hostname) and not _should_fetch_ip_url(hostname):
            self._run_callback(
                self.entry_callback, entry_url, source_url, "skipped_non_global")
            return "skip"

        if source_url:
            self.entry_url_sources_map.setdefault(entry_url, set()).add(source_url)

        if entry_url in self.incremental_url_set:
            self._run_callback(self.entry_callback, entry_url, source_url, "pending")
            return "duplicate"

        max_entry_urls = self._max_entry_urls()
        if max_entry_urls > 0 and len(self.incremental_url_set) >= max_entry_urls:
            if not self.entry_cap_logged:
                logger.warning("katana incremental entry urls capped at {} task_id:{}".format(
                    max_entry_urls, self.task_id))
                self.entry_cap_logged = True
            self.entry_cap_reached = True
            return "entry_cap"

        max_entry_urls_per_host = self._max_entry_urls_per_host()
        if max_entry_urls_per_host > 0 and self.entry_host_count.get(hostname, 0) >= max_entry_urls_per_host:
            if hostname not in self.host_cap_logged:
                logger.info("katana host entry urls capped host:{} cap:{} task_id:{}".format(
                    hostname, max_entry_urls_per_host, self.task_id))
                self.host_cap_logged.add(hostname)
            return "host_cap"

        self.incremental_url_set.add(entry_url)
        self.incremental_url_list.append(entry_url)
        self.entry_host_count[hostname] = self.entry_host_count.get(hostname, 0) + 1
        self._run_callback(self.entry_callback, entry_url, source_url, "pending")

        # Do not write crawler candidates to url here. The URL collection is for
        # fetched entry results; raw All URL hits are stored as WIH evidence by
        # commonTask.site_spider.
        return "tracked"

    def _run_callback(self, callback, *args):
        if not callback:
            return
        try:
            callback(*args)
        except Exception as e:
            logger.warning("katana incremental callback failed task_id:{} error:{}".format(
                self.task_id, e))
            if not self.partial_error:
                self.partial_error = "katana incremental storage failed: {}".format(e)

    def _record_evidence(self, absolute_url, source_url, kind, entry_url, hostname, max_raw_outputs):
        absolute_url = str(absolute_url or "").strip()
        source_url = str(source_url or "").strip()
        if not absolute_url or not hostname:
            return True

        if max_raw_outputs > 0 and absolute_url not in self.incremental_all_url_set \
                and len(self.incremental_all_url_set) >= max_raw_outputs:
            self.stop_reason = "all url output capped at {}".format(max_raw_outputs)
            return False

        if absolute_url not in self.incremental_all_url_set:
            self.incremental_all_url_set.add(absolute_url)
            self.incremental_all_url_list.append(absolute_url)

        if kind in ("body_all_url", "plain_all_url"):
            self.body_all_url_set.add(absolute_url)
        else:
            self.crawler_endpoint_set.add(absolute_url)
        if kind == "browser_xhr":
            self.browser_xhr_url_set.add(absolute_url)
        elif kind == "browser_network":
            self.browser_network_url_set.add(absolute_url)
        elif kind == "browser_script":
            self.browser_script_url_set.add(absolute_url)

        self._remember_source(self.url_source_map, absolute_url, source_url)
        evidence_pair = (absolute_url, source_url)
        if evidence_pair not in self.evidence_pair_set:
            self.evidence_pair_set.add(evidence_pair)
            self._run_callback(self.evidence_callback, absolute_url, source_url, kind)

        if _is_ip_host(hostname):
            self.incremental_ip_url_host_set.add(hostname)
            return True

        self.incremental_domain_set.add(hostname)
        self._remember_source(self.domain_source_map, hostname, source_url)
        if entry_url and hostname not in self.domain_entry_url_map:
            self.domain_entry_url_map[hostname] = entry_url

        domain_pair = (hostname, source_url)
        if domain_pair not in self.domain_evidence_pair_set:
            self.domain_evidence_pair_set.add(domain_pair)
            self._run_callback(self.domain_callback, hostname, source_url, absolute_url)
        return True

    def _append_output(self, stdout_lines, item, max_raw_outputs):
        item = str(item or "").strip()
        if not item:
            return True

        self.raw_output_count += 1
        discoveries = self._extract_discoveries(item)
        if not discoveries:
            self._update_progress()
            return True

        for discovery in discoveries:
            absolute_url = discovery.get("url", "")
            source_url = discovery.get("source", "")
            kind = discovery.get("kind", "crawler_endpoint")
            is_all_url = kind in {
                "body_all_url", "plain_all_url", "browser_xhr",
                "browser_network", "browser_script",
            }
            is_entry_candidate = kind in ("body_all_url", "plain_all_url")
            entry_url, hostname = self._normalize_entry_url(
                absolute_url,
                literal_all_url=is_all_url,
            )
            if not hostname:
                if self.crawl_profile == "dynamic" and is_all_url:
                    self._remember_external_network_url(absolute_url)
                continue

            save_status = "skip"
            is_seed = self._is_seed_endpoint(absolute_url)
            if is_entry_candidate and not is_seed and entry_url:
                save_status = self._save_incremental_entry_url(
                    absolute_url,
                    source_url=source_url,
                    literal_all_url=True,
                )

            is_evidence = is_all_url and not is_seed
            if is_evidence:
                if not self._record_evidence(
                    absolute_url, source_url, kind, entry_url, hostname, max_raw_outputs
                ):
                    return False

            self._update_progress()
            if save_status == "entry_cap":
                # Entry display is capped independently. Continue crawling so
                # domain and All URL discovery are not truncated by a UI limit.
                continue

        return True

    @staticmethod
    def _signal_process_group(proc, sig):
        try:
            os.killpg(proc.pid, sig)
            return True
        except ProcessLookupError:
            return False
        except OSError as e:
            logger.warning("katana signal process group failed pid:{} signal:{} error:{}".format(
                proc.pid, sig, e))
            return False

    def _terminate_process_group(self, proc, reason, grace_seconds=3):
        if proc is None:
            return

        started = time.monotonic()
        if proc.poll() is None:
            self._signal_process_group(proc, signal.SIGTERM)
            try:
                proc.wait(timeout=max(float(grace_seconds), 0.1))
            except subprocess.TimeoutExpired:
                pass

        # The Katana parent can exit before Chrome descendants. The process
        # group is dedicated to this crawl, so always clear any survivors.
        self._signal_process_group(proc, signal.SIGKILL)
        if proc.poll() is None:
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                logger.error("katana process group did not exit pid:{} reason:{}".format(
                    proc.pid, reason))

        logger.info(
            "katana process cleanup pid:{} reason:{} returncode:{} elapsed:{:.2f}s".format(
                proc.pid, reason, proc.poll(), time.monotonic() - started))

    @staticmethod
    def _stderr_tail(stderr_file, limit=1000):
        if stderr_file is None:
            return ""
        try:
            stderr_file.flush()
            stderr_file.seek(0, os.SEEK_END)
            size = stderr_file.tell()
            stderr_file.seek(max(size - max(int(limit), 1) * 4, 0))
            return (stderr_file.read() or "")[-limit:]
        except (OSError, ValueError):
            return ""

    @staticmethod
    def _drain_stdout(stream):
        if stream is None:
            return ""
        try:
            os.set_blocking(stream.fileno(), False)
            return stream.read() or ""
        except (BlockingIOError, OSError, TypeError, ValueError):
            return ""

    def _crawl(self, entry_urls=None, timeout_limit=None):
        urls = list(dict.fromkeys(
            self.entry_urls if entry_urls is None else entry_urls))
        if not urls:
            return []

        if not shutil.which(Config.KATANA_BIN) and not os.path.exists(Config.KATANA_BIN):
            raise RuntimeError("katana binary not found: {}".format(Config.KATANA_BIN))
        if self.crawl_profile == "dynamic":
            chrome_path = str(getattr(
                Config, "KATANA_CHROME_PATH", "") or "").strip()
            if chrome_path and not (
                os.path.isfile(chrome_path) and os.access(chrome_path, os.X_OK)
            ):
                raise RuntimeError(
                    "pinned chrome binary is not executable: {}".format(chrome_path))

        fd, input_path = tempfile.mkstemp(prefix="arl_katana_", suffix=".txt", dir=Config.TMP_PATH)
        os.close(fd)
        with open(input_path, "w", encoding="utf-8") as f:
            f.write("\n".join(urls) + "\n")

        command = self._build_command(input_path)
        request_timeout = int(self._profile_value(
            "KATANA_TIMEOUT", "KATANA_RESTRICTED_TIMEOUT", "KATANA_DYNAMIC_TIMEOUT"))
        depth = int(self._profile_value(
            "KATANA_DEPTH", "KATANA_RESTRICTED_DEPTH", "KATANA_DYNAMIC_DEPTH"))
        if self.crawl_profile == "dynamic":
            crawl_duration = int(getattr(
                Config, "KATANA_DYNAMIC_CRAWL_DURATION", 25) or 25)
            parallelism = max(int(getattr(
                Config, "KATANA_DYNAMIC_PARALLELISM", 1) or 1), 1)
            target_batches = (max(len(urls), 1) + parallelism - 1) // parallelism
            configured_target_timeout = max(int(getattr(
                Config, "KATANA_DYNAMIC_TARGET_TIMEOUT", 45) or 0), 1)
            target_timeout = max(
                configured_target_timeout,
                crawl_duration + 10,
                request_timeout + 5,
            )
            timeout = target_timeout * target_batches
        else:
            timeout = max(60, request_timeout * max(len(urls), 1) * 3)
        if timeout_limit is not None:
            timeout = max(min(timeout, float(timeout_limit)), 1)
        target_log = " targets:{}".format(urls) if self.crawl_profile == "dynamic" else ""
        logger.info("start katana crawl inputs:{} scope:{} depth:{} profile:{}{}".format(
            len(urls), len(self.scope_domains), depth, self.crawl_profile, target_log))
        self._update_progress(force=True)

        proc = None
        stderr_file = None
        stdout_lines = []
        stderr_text = ""
        max_raw_outputs = self._max_raw_outputs()
        cleanup_reason = "completed"
        cleanup_done = False
        crawl_started = time.monotonic()
        outcome = "completed"
        raw_before = self.raw_output_count
        all_url_before = len(self.incremental_all_url_set)
        crawler_before = len(self.crawler_endpoint_set)
        try:
            stderr_file = tempfile.TemporaryFile(
                mode="w+t", encoding="utf-8", errors="replace")
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=stderr_file,
                text=True,
                start_new_session=True,
            )

            start_time = time.time()
            while True:
                if self._task_stopped():
                    logger.warning("katana terminated by task stop")
                    cleanup_reason = "task_stop"
                    outcome = "task_stop"
                    self._terminate_process_group(proc, cleanup_reason)
                    cleanup_done = True
                    break

                if time.time() - start_time > timeout:
                    message = "katana timeout target:{} after {:.1f}s".format(
                        urls[0] if len(urls) == 1 else len(urls), float(timeout))
                    logger.warning(message)
                    if self.crawl_profile == "dynamic":
                        self._add_warning(message)
                    else:
                        self.partial_error = message
                    cleanup_reason = "timeout"
                    outcome = "timeout"
                    self._terminate_process_group(proc, cleanup_reason)
                    cleanup_done = True
                    stderr_text = self._stderr_tail(stderr_file)
                    break

                if proc.poll() is not None:
                    rest = self._drain_stdout(proc.stdout)
                    if rest:
                        for item in rest.splitlines():
                            if not self._append_output(stdout_lines, item, max_raw_outputs):
                                break
                    stderr_text = self._stderr_tail(stderr_file)
                    break

                ready, _, _ = select.select([proc.stdout], [], [], 1)
                if ready:
                    line = proc.stdout.readline()
                    if line:
                        if not self._append_output(stdout_lines, line, max_raw_outputs):
                            logger.warning("katana {}, terminate early".format(
                                self.stop_reason or "output capped"))
                            cleanup_reason = self.stop_reason or "output_cap"
                            outcome = "output_cap"
                            self._terminate_process_group(proc, cleanup_reason)
                            cleanup_done = True
                            stderr_text = self._stderr_tail(stderr_file)
                            break

            if proc and proc.returncode not in (0, None):
                logger.warning("katana exit {} stderr:{}".format(
                    proc.returncode, stderr_text.strip()[-1000:]))
                if (
                    outcome == "completed" and
                    not self.partial_error and
                    not self.stop_reason and
                    not self._task_stopped()
                ):
                    message = "katana exit {}: {}".format(
                        proc.returncode, stderr_text.strip()[-500:])
                    if self.crawl_profile == "dynamic":
                        self._add_warning(message)
                    else:
                        self.partial_error = message
                    outcome = "exit_error"
        finally:
            if proc is not None and not cleanup_done:
                self._terminate_process_group(proc, cleanup_reason)
            if proc is not None:
                for stream in (proc.stdout,):
                    try:
                        stream.close()
                    except (AttributeError, OSError):
                        pass
            if stderr_file is not None:
                try:
                    stderr_file.close()
                except OSError:
                    pass
            try:
                os.remove(input_path)
            except OSError:
                pass

        self.last_crawl_meta = {
            "targets": list(urls),
            "outcome": outcome,
            "elapsed_seconds": round(time.monotonic() - crawl_started, 2),
            "raw_output_count": max(self.raw_output_count - raw_before, 0),
            "all_url_count": max(len(self.incremental_all_url_set) - all_url_before, 0),
            "crawler_endpoint_count": max(
                len(self.crawler_endpoint_set) - crawler_before, 0),
        }

        self._update_progress(force=True)
        logger.info("end katana crawl evidence:{} raw_lines:{}".format(
            len(self.incremental_all_url_list), self.raw_output_count))
        return list(self.incremental_all_url_list)

    def _crawl_dynamic_batches(self):
        urls = list(dict.fromkeys(self.entry_urls))
        batch_size = max(int(getattr(
            Config, "KATANA_DYNAMIC_BATCH_SIZE", 1) or 1), 1)
        batches = [
            urls[index:index + batch_size]
            for index in range(0, len(urls), batch_size)
        ]
        total_timeout = max(int(getattr(
            Config, "KATANA_DYNAMIC_TOTAL_TIMEOUT", 480) or 0), 0)
        deadline = time.monotonic() + total_timeout if total_timeout else None
        self.crawl_batch_total = len(batches)
        self.crawl_batch_completed = 0
        self.crawl_batch_attempted = 0
        self.crawl_batch_succeeded = 0
        self.crawl_batch_timed_out = 0
        self.crawl_batch_failed = 0
        self.crawl_target_metrics = []
        self._update_progress(force=True)

        consecutive_timeouts = 0
        max_consecutive_timeouts = max(int(getattr(
            Config, "KATANA_DYNAMIC_MAX_CONSECUTIVE_TIMEOUTS", 3) or 0), 0)

        for index, batch in enumerate(batches, 1):
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                message = "katana dynamic total timeout after {}s batches:{}/{}".format(
                    total_timeout, self.crawl_batch_completed, self.crawl_batch_total)
                self._add_warning(message)
                logger.warning(message)
                break

            logger.info("katana dynamic batch {}/{} inputs:{}".format(
                index, self.crawl_batch_total, len(batch)))
            self.crawl_batch_attempted += 1
            self._crawl(batch, timeout_limit=remaining)
            self.crawl_batch_completed = index
            target_meta = dict(self.last_crawl_meta or {})
            target_meta["batch"] = index
            self.crawl_target_metrics.append(target_meta)
            outcome = target_meta.get("outcome")
            if outcome == "timeout":
                self.crawl_batch_timed_out += 1
                consecutive_timeouts += 1
            elif outcome == "exit_error":
                self.crawl_batch_failed += 1
                consecutive_timeouts = 0
            elif outcome in ("completed", "output_cap"):
                self.crawl_batch_succeeded += 1
                consecutive_timeouts = 0
            self._update_progress(force=True)
            if self.stop_reason:
                break
            if (
                max_consecutive_timeouts > 0 and
                consecutive_timeouts >= max_consecutive_timeouts
            ):
                message = "katana dynamic circuit breaker after {} consecutive timeouts".format(
                    consecutive_timeouts)
                self._add_warning(message)
                logger.warning(message)
                break

        return list(self.incremental_all_url_list)

    def run(self):
        if self.crawl_profile == "dynamic":
            with acquire_resource_budget(
                "tool:katana:dynamic", task_id=self.task_id,
                stage=self.stage_name, max_concurrency=1,
            ):
                with acquire_resource_budget(
                    "tool:katana", task_id=self.task_id, stage=self.stage_name,
                ):
                    raw_urls = self._crawl_dynamic_batches()
        else:
            with acquire_resource_budget(
                "tool:katana", task_id=self.task_id, stage=self.stage_name,
            ):
                raw_urls = self._crawl()
        domain_set = set(self.incremental_domain_set)
        entry_urls = list(self.incremental_url_list)
        max_entry_urls = self._max_entry_urls()
        max_entry_urls_per_host = self._max_entry_urls_per_host()

        logger.info(
            "katana result summary task_id:{} raw_lines:{} evidence:{} domains:{} entry_urls:{} seeds:{}".format(
                self.task_id,
                self.raw_output_count,
                len(raw_urls),
                len(domain_set),
                len(entry_urls),
                len(self.seed_endpoint_set),
            )
        )

        self._update_progress(force=True)
        return {
            "domains": sorted(domain_set),
            "urls": entry_urls,
            "all_urls": raw_urls,
            "crawler_urls": sorted(self.crawler_endpoint_set),
            "crawler_url_sources": {
                url: self.crawler_url_sources_map.get(url, "")
                for url in sorted(self.crawler_endpoint_set)
            },
            "domain_entry_urls": dict(self.domain_entry_url_map),
            "domain_sources": {
                domain: self.domain_source_map.get(domain, "")
                for domain in sorted(domain_set)
            },
            "url_sources": {
                url: self.url_source_map.get(url, "")
                for url in sorted(set(raw_urls))
            },
            "entry_url_sources": {
                url: sorted(self.entry_url_sources_map.get(url, set()))
                for url in entry_urls
            },
            "meta": {
                "raw_output_count": self.raw_output_count,
                "all_url_count": len(raw_urls),
                "domain_count": len(domain_set),
                "ip_url_host_count": len(self.incremental_ip_url_host_set),
                "entry_url_count": len(entry_urls),
                "seed_endpoint_count": len(self.seed_endpoint_set),
                "crawler_endpoint_count": len(self.crawler_endpoint_set),
                "body_all_url_count": len(self.body_all_url_set),
                "browser_xhr_url_count": len(self.browser_xhr_url_set),
                "browser_network_url_count": len(
                    self.browser_network_url_set),
                "browser_script_url_count": len(self.browser_script_url_set),
                "external_network_filtered_count": len(
                    self.external_network_url_set),
                "entry_cap_reached": self.entry_cap_reached,
                "max_entry_urls": max_entry_urls,
                "max_entry_urls_per_host": max_entry_urls_per_host,
                "stop_reason": self.stop_reason,
                "partial_error": self.partial_error,
                "warnings": list(self.warnings),
                "warning_count": len(self.warnings),
                "crawl_profile": self.crawl_profile,
                "crawl_batch_total": self.crawl_batch_total,
                "crawl_batch_completed": self.crawl_batch_completed,
                "crawl_batch_attempted": self.crawl_batch_attempted,
                "crawl_batch_succeeded": self.crawl_batch_succeeded,
                "crawl_batch_timed_out": self.crawl_batch_timed_out,
                "crawl_batch_failed": self.crawl_batch_failed,
                "crawl_target_metrics": list(self.crawl_target_metrics),
                "browser_path": (
                    str(getattr(Config, "KATANA_CHROME_PATH", "") or "").strip()
                    if self.crawl_profile == "dynamic" else ""
                ),
                "browser_version": (
                    str(getattr(Config, "KATANA_CHROME_VERSION", "") or "").strip()
                    if self.crawl_profile == "dynamic" else ""
                ),
            },
        }


def katana_spider(
    entry_urls_list,
    scope_domains=None,
    task_id="",
    evidence_callback=None,
    domain_callback=None,
    entry_callback=None,
    crawl_profile="normal",
    stage_name="site_spider",
):
    spider = KatanaSpider(
        entry_urls_list=entry_urls_list,
        scope_domains=scope_domains,
        task_id=task_id,
        evidence_callback=evidence_callback,
        domain_callback=domain_callback,
        entry_callback=entry_callback,
        crawl_profile=crawl_profile,
        stage_name=stage_name,
    )
    return spider.run()
