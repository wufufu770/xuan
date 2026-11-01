import hashlib
import ipaddress
import json
import re
from urllib.parse import urlsplit

from app.modules import SiteAutoTag
from app.services.edgeAsset import classify_edge_infrastructure, is_edge_tagged


STRONG_WAF_RULES = (
    ("cloudwaf", r"cloudwaf|cloud.?waf"),
    ("cloudflare", r"\bcloudflare\b|cf-ray|cf-cache-status"),
    ("aliyun_yundun", r"yundun|云盾|aliyunwaf|aliyun.?waf|x-aliyun"),
    ("tencent_edgeone", r"edgeone|tencentwaf|腾讯云.?waf|x-tencent"),
    ("baidu_yunjiasu", r"yunjiasu|百度云加速|baidu.?waf"),
    ("qianxin", r"qianxin|奇安信|360.?waf|360.?webscan"),
    ("wangsu", r"wangsu|网宿|wscdn"),
    ("safedog", r"safedog|安全狗"),
    ("yunsuo", r"yunsuo|云锁"),
    ("mod_security", r"mod_security|modsecurity"),
    ("imperva", r"imperva|incapsula"),
    ("akamai", r"akamai"),
    ("f5", r"big-ip|\bf5\b"),
    ("aws_waf", r"aws.?waf|awselb|cloudfront"),
    ("barracuda", r"barracuda"),
    ("sucuri", r"sucuri"),
    ("openresty_waf", r"openresty.*waf|waf.*openresty"),
)

WEAK_WAF_TITLE_RULES = (
    ("generic_waf", r"\bwaf\b|web application firewall"),
    ("generic_block", r"access denied|blocked by|访问被拒绝|请求拦截|forbidden"),
)

LOW_INFORMATION_TITLE_MARKERS = (
    "welcome to nginx",
    "welcome to openresty",
    "welcome to centos",
    "apache http server test page",
    "test page for the nginx http",
    "apache tomcat",
    "500 internal server error",
    "error 404--not found",
    "404 not found",
    "page not found",
    "页面不存在",
    "没有找到站点",
)

TRANSIENT_BLOCK_STATUS_CODES = {418, 429}

TRANSIENT_BLOCK_TITLE_MARKERS = (
    "waf拦截",
    "waf 拦截",
    "blocked by waf",
    "web application firewall",
    "安全拦截",
    "风控拦截",
    "访问被拒绝",
    "访问被拦截",
    "访问拦截",
    "请求被拦截",
    "请求过于频繁",
    "too many requests",
    "rate limit",
)

STATIC_EDGE_HOST_WORDS = {
    "asset", "assets", "cdn", "css", "file", "files", "font", "fonts",
    "image", "images", "img", "js", "media", "resource", "resources",
    "static",
}

STATIC_EDGE_CONTENT_TYPES = (
    "application/font", "application/javascript", "application/octet-stream",
    "application/wasm", "font/", "image/", "text/css", "text/javascript",
    "video/",
)

GENERIC_EDGE_TITLES = {
    "301 moved permanently", "302 found", "302 moved temporarily",
    "400 bad request", "401 unauthorized", "403 forbidden", "404 not found",
    "405 method not allowed", "500 internal server error", "502 bad gateway",
    "503 service unavailable", "access denied", "forbidden", "not found",
}

DIRECTORY_ROUTE_KEY_VERSION = "route-v3"
DIRECTORY_ROUTE_STABLE_STATUS_CODES = {
    200, 204, 301, 302, 303, 307, 308, 401, 403, 404, 405, 410,
}
DIRECTORY_ROUTE_HEADER_FIELDS = {
    "content-type", "server", "x-powered-by", "x-server", "x-server-by",
}


def _item_text(item, keys, include_tech=False):
    values = []
    for key in keys:
        value = (item or {}).get(key)
        if isinstance(value, list):
            value = " ".join(str(item) for item in value)
        if value:
            values.append(str(value))

    if include_tech:
        tech = (item or {}).get("tech") or (item or {}).get("technologies") or []
        if isinstance(tech, list):
            values.extend(str(value) for value in tech if value)
        elif tech:
            values.append(str(tech))
    return " ".join(values).lower()


def classify_waf_evidence(item):
    """Return WAF evidence without promoting generic block pages to strong infrastructure."""
    strong_text = _item_text(
        item,
        ["cdn_name", "cdn_type", "webserver", "cname", "header", "response_header"],
        include_tech=True,
    )
    for name, pattern in STRONG_WAF_RULES:
        if re.search(pattern, strong_text, re.I):
            return {
                "detected": True,
                "strength": "strong",
                "name": name,
                "reason": "infrastructure_or_header",
            }

    title = _item_text(item, ["title"])
    for name, pattern in WEAK_WAF_TITLE_RULES:
        if re.search(pattern, title, re.I):
            return {
                "detected": True,
                "strength": "weak",
                "name": name,
                "reason": "generic_title",
            }

    return {
        "detected": False,
        "strength": "none",
        "name": "",
        "reason": "",
    }


def has_strong_edge_marker(item):
    """Only strong CDN/WAF/edge evidence may suppress active scanning."""
    item = item or {}
    if (
        item.get("cdn") or item.get("is_cdn") or item.get("cdn_name") or
        item.get("edge") or item.get("edge_name") or is_edge_tagged(item)
    ):
        return True

    infrastructure = classify_edge_infrastructure(" ".join([
        str(item.get("webserver") or ""),
        " ".join(item.get("cname") or []) if isinstance(item.get("cname"), list)
        else str(item.get("cname") or ""),
        str(item.get("cdn_name") or ""),
        str(item.get("waf_name") or ""),
    ]))
    if infrastructure:
        return True

    waf_strength = str(item.get("waf_strength") or "").strip().lower()
    if item.get("waf") or item.get("is_waf") or item.get("waf_name"):
        # Legacy rows did not have waf_strength. Preserve their old behavior;
        # new generic block-page matches are explicitly stored as weak.
        return waf_strength != "weak"
    return False


def http_access_profile(status_code):
    try:
        status_code = int(status_code)
    except (TypeError, ValueError):
        return "normal"
    if status_code in (401, 403):
        return "restricted"
    return "normal"


def is_transient_block_page(item):
    """Return whether a response is a temporary block/rate-limit page.

    These responses remain useful evidence and should stay retryable, but
    active crawling or directory scanning only reinforces the block.
    """
    item = item or {}
    status = item.get("status")
    if status is None:
        status = item.get("status_code")
    try:
        status = int(status) if status is not None else None
    except (TypeError, ValueError):
        status = None
    if status in TRANSIENT_BLOCK_STATUS_CODES:
        return True

    title = str(item.get("title") or "").strip().lower()
    return any(marker in title for marker in TRANSIENT_BLOCK_TITLE_MARKERS)


def _directory_status(item):
    status = (item or {}).get("status")
    if status is None:
        status = (item or {}).get("status_code")
    try:
        return int(status) if status is not None else None
    except (TypeError, ValueError):
        return None


def _directory_site_host(item):
    site = str((item or {}).get("canonical_site") or (item or {}).get(
        "site") or "").strip()
    try:
        return str(urlsplit(site).hostname or "").strip(".").lower()
    except (TypeError, ValueError):
        return ""


def _directory_body_length(item):
    value = (item or {}).get("body_length")
    if value is None:
        value = (item or {}).get("content_length")
    try:
        return max(int(value or 0), 0)
    except (TypeError, ValueError):
        return 0


def _directory_content_type(item):
    headers = _route_header_map(item)
    return str((item or {}).get("content_type") or headers.get(
        "content-type") or "").split(";", 1)[0].strip().lower()


def _meaningful_business_title(item):
    title = str((item or {}).get("title") or "").strip().lower()
    if not title or title in GENERIC_EDGE_TITLES:
        return False
    if any(marker in title for marker in LOW_INFORMATION_TITLE_MARKERS):
        return False
    if any(marker in title for marker in TRANSIENT_BLOCK_TITLE_MARKERS):
        return False
    return not bool(re.fullmatch(
        r"(?:http\s+)?[1-5]\d\d(?:\s+\w+){0,3}", title, re.I))


def _has_application_evidence(item):
    if _meaningful_business_title(item):
        return True
    if (item or {}).get("finger") or (item or {}).get("tech"):
        return True
    content_type = _directory_content_type(item)
    body_length = _directory_body_length(item)
    return bool(
        body_length >= 256 and (
            content_type in ("application/json", "application/xml") or
            content_type.endswith("+json") or
            content_type.startswith("text/html") or
            content_type.startswith("application/xhtml")
        )
    )


def _is_static_edge_site(item):
    content_type = _directory_content_type(item)
    if any(content_type.startswith(prefix) for prefix in STATIC_EDGE_CONTENT_TYPES):
        return True

    host = _directory_site_host(item)
    labels = set(filter(None, re.split(r"[.\-_]+", host)))
    if not labels.intersection(STATIC_EDGE_HOST_WORDS):
        return False
    return not _has_application_evidence(item)


def directory_scan_decision(item):
    """Return a scan profile and explainable evidence for one HTTP origin."""
    item = item or {}
    if is_transient_block_page(item):
        return {
            "profile": None,
            "scan_policy": "inventory_only",
            "reason": "transient_block",
            "evidence": ["rate_limit_or_transient_block"],
        }

    status = _directory_status(item)
    if item.get("quality_state") == "route_confirmed":
        return {
            "profile": "normal",
            "scan_policy": "active",
            "reason": "route_discovery_confirmed",
            "evidence": ["independent_route_response"],
        }
    if (
        item.get("quality_state") != "route_confirmed" and
        item.get("pipeline_mode") == "route_probe_only"
    ):
        return {
            "profile": "low_info",
            "scan_policy": "limited_active",
            "reason": item.get("quality_reason") or "low_information_root",
            "evidence": [
                "quality_{}".format(item.get("quality_state") or "hidden"),
                "route_probe_only",
            ],
        }
    strong_edge = has_strong_edge_marker(item)
    host = _directory_site_host(item)
    host_is_ip = False
    if host:
        try:
            ipaddress.ip_address(host)
            host_is_ip = True
        except ValueError:
            pass

    if strong_edge:
        evidence = ["strong_edge"]
        if not host:
            return {
                "profile": None,
                "scan_policy": "inventory_only",
                "reason": "edge_unknown_origin",
                "evidence": evidence + ["missing_origin"],
            }
        if host_is_ip:
            return {
                "profile": None,
                "scan_policy": "inventory_only",
                "reason": "direct_edge_ip",
                "evidence": evidence + ["ip_origin"],
            }
        if _is_static_edge_site(item):
            return {
                "profile": None,
                "scan_policy": "inventory_only",
                "reason": "static_edge",
                "evidence": evidence + ["static_content_or_host"],
            }
        if status in (401, 403):
            return {
                "profile": "restricted",
                "scan_policy": "limited_active",
                "reason": "edge_restricted",
                "evidence": evidence + ["named_origin", "restricted_status"],
            }
        if (
            _has_application_evidence(item) or
            (status is not None and 300 <= status < 400) or
            status in DIRECTORY_ROUTE_STABLE_STATUS_CODES
        ):
            business_evidence = []
            if _meaningful_business_title(item):
                business_evidence.append("business_title")
            if item.get("finger") or item.get("tech"):
                business_evidence.append("application_fingerprint")
            if _directory_content_type(item):
                business_evidence.append("response_content_type")
            if status is not None and 300 <= status < 400:
                business_evidence.append("redirect_response")
            return {
                "profile": "edge_limited",
                "scan_policy": "limited_active",
                "reason": "edge_business_origin",
                "evidence": evidence + business_evidence + ["named_origin"],
            }
        return {
            "profile": None,
            "scan_policy": "inventory_only",
            "reason": "edge_without_application_evidence",
            "evidence": evidence + ["named_origin"],
        }

    if status in (401, 403, 429):
        return {
            "profile": "restricted",
            "scan_policy": "limited_active",
            "reason": "restricted_status",
            "evidence": ["restricted_status"],
        }

    tags = item.get("tag") or []
    if isinstance(tags, str):
        tags = [tags]
    if SiteAutoTag.INVALID in tags:
        return {
            "profile": "low_info",
            "scan_policy": "limited_active",
            "reason": "invalid_or_default_page",
            "evidence": ["invalid_tag"],
        }

    title = str(item.get("title") or "").strip().lower()
    if any(marker in title for marker in LOW_INFORMATION_TITLE_MARKERS):
        return {
            "profile": "low_info",
            "scan_policy": "limited_active",
            "reason": "low_information_title",
            "evidence": ["default_or_error_title"],
        }

    body_length = _directory_body_length(item)

    if status is not None and status >= 400:
        return {
            "profile": "low_info",
            "scan_policy": "limited_active",
            "reason": "low_information_status",
            "evidence": ["http_error_status"],
        }
    if status == 200 and not title and body_length <= 300:
        return {
            "profile": "low_info",
            "scan_policy": "limited_active",
            "reason": "small_untitled_response",
            "evidence": ["small_body", "missing_title"],
        }
    return {
        "profile": "normal",
        "scan_policy": "active",
        "reason": "application_origin",
        "evidence": ["http_responsive"],
    }


def directory_scan_target_profile(item):
    """Return the backward-compatible FFUF profile for one HTTP origin."""
    return directory_scan_decision(item)["profile"]


def _route_values(value):
    if value in (None, ""):
        return []
    if isinstance(value, (list, tuple, set)):
        values = value
    else:
        values = [value]
    return [str(item).strip() for item in values if str(item or "").strip()]


def _route_header_map(item):
    raw = (
        (item or {}).get("header") or
        (item or {}).get("response_header") or
        (item or {}).get("headers") or
        {}
    )
    headers = {}
    if isinstance(raw, dict):
        pairs = raw.items()
    else:
        pairs = []
        for line in str(raw or "").splitlines():
            if ":" not in line:
                continue
            pairs.append(line.split(":", 1))
    for key, value in pairs:
        name = str(key or "").strip().lower().replace("_", "-")
        if name not in DIRECTORY_ROUTE_HEADER_FIELDS:
            continue
        headers[name] = str(value or "").strip().lower()
    return headers


def _route_body_hash(item):
    value = str((item or {}).get("body_hash") or "").strip().lower()
    if not value:
        hashes = (item or {}).get("hash") or (item or {}).get("hashes") or {}
        if isinstance(hashes, dict):
            value = str(hashes.get("body_sha256") or "").strip().lower()
    if re.fullmatch(r"[0-9a-f]{64}", value):
        return value
    return ""


def _route_redirect_location(item):
    value = str((item or {}).get("location") or (item or {}).get(
        "redirect_location") or "").strip()
    if not value:
        return ""
    try:
        parsed = urlsplit(value)
    except (TypeError, ValueError):
        return value
    if not parsed.scheme or not parsed.netloc:
        return value
    host = str(parsed.hostname or "").strip(".").lower()
    if not host:
        return value
    try:
        port = parsed.port
    except ValueError:
        return value
    scheme = parsed.scheme.lower()
    default_port = (scheme == "http" and port == 80) or (
        scheme == "https" and port == 443)
    authority = host if not port or default_port else "{}:{}".format(host, port)
    return "{}://{}{}{}".format(
        scheme,
        authority,
        parsed.path or "/",
        "?" + parsed.query if parsed.query else "",
    )


def directory_scan_route_key(item):
    """Build a conservative candidate key for response-template sampling.

    This key only selects hosts for online baseline comparison. It is never
    sufficient by itself to reuse or suppress a scan.
    """
    item = item or {}
    if directory_scan_target_profile(item) not in (
        "normal", "low_info", "edge_limited", "restricted"
    ):
        return ""

    status = item.get("status")
    if status is None:
        status = item.get("status_code")
    try:
        status = int(status)
    except (TypeError, ValueError):
        return ""
    if status not in DIRECTORY_ROUTE_STABLE_STATUS_CODES:
        return ""

    site = str(item.get("canonical_site") or item.get("site") or "").strip()
    try:
        parsed = urlsplit(site)
        host = str(parsed.hostname or "").strip(".").lower()
    except (TypeError, ValueError):
        return ""
    scheme = str(parsed.scheme or "").lower()
    if scheme not in ("http", "https") or not host:
        return ""

    ips = []
    for value in _route_values(item.get("resolved_ips") or item.get("ip")):
        try:
            normalized = str(ipaddress.ip_address(value))
        except ValueError:
            continue
        if normalized not in ips:
            ips.append(normalized)
    if not ips:
        return ""

    body_length = item.get("body_length")
    if body_length is None:
        body_length = item.get("content_length")
    try:
        body_length = int(body_length or 0)
    except (TypeError, ValueError):
        return ""
    if body_length <= 0:
        return ""

    headers = _route_header_map(item)
    content_type = str(item.get("content_type") or headers.get(
        "content-type") or "").split(";", 1)[0].strip().lower()
    server_values = sorted(set(filter(None, (
        str(item.get("http_server") or item.get("webserver") or "").strip().lower(),
        headers.get("server", ""),
        headers.get("x-server", ""),
        headers.get("x-server-by", ""),
        headers.get("x-powered-by", ""),
    ))))
    favicon = item.get("favicon") or {}
    favicon_hash = favicon.get("hash") if isinstance(favicon, dict) else ""
    body_hash = _route_body_hash(item)
    redirect_location = _route_redirect_location(item)
    response_discriminator = bool(
        body_hash or
        (300 <= status < 400 and redirect_location) or
        (
            status in (401, 403, 404, 405, 410) and
            (server_values or content_type or str(item.get("title") or "").strip())
        )
    )
    if not response_discriminator:
        return ""

    payload = {
        "version": DIRECTORY_ROUTE_KEY_VERSION,
        "status": status,
        "body_length": body_length,
        "body_hash": body_hash,
        "content_type": content_type,
        "location": redirect_location,
        "title": str(item.get("title") or "").strip().lower(),
        "servers": server_values,
        "favicon_hash": str(favicon_hash or ""),
    }
    serialized = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "{}:{}".format(
        DIRECTORY_ROUTE_KEY_VERSION,
        hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
    )


def merge_directory_scan_profiles(items):
    """Return one conservative but non-binary profile for duplicate origins."""
    profiles = []
    for item in items or []:
        profile = directory_scan_target_profile(item)
        profiles.append(profile)
    active_profiles = [profile for profile in profiles if profile is not None]
    if not active_profiles:
        return None
    if "restricted" in profiles:
        return "restricted"
    if "edge_limited" in profiles or len(active_profiles) != len(profiles):
        return "edge_limited"
    if "low_info" in profiles:
        return "low_info"
    return "normal"


def merge_directory_scan_route_keys(items):
    keys = [directory_scan_route_key(item) for item in items or []]
    if not keys or any(not key for key in keys):
        return ""
    unique = set(keys)
    return keys[0] if len(unique) == 1 else ""
