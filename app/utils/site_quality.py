import hashlib
import re
from urllib.parse import urljoin, urlsplit


SITE_QUALITY_VERSION = "site-quality-v3"

SOFT_404_TITLE_MARKERS = (
    "页面不存在",
    "访问的页面不存在",
    "没有找到站点",
    "page not found",
    "404 not found",
    "error 404--not found",
    "error 404 not found",
    "http status 404",
    "not found",
    "未找到",
    "出错了-404",
)

SOFT_404_TITLE_PATTERNS = (
    re.compile(r"访问的页面不存在", re.IGNORECASE),
    re.compile(r"(?:页面|网页|资源).{0,16}(?:不存在|未找到)", re.IGNORECASE),
    re.compile(r"(?:page|resource).{0,16}(?:not\s+found|missing)", re.IGNORECASE),
    re.compile(r"\bnot[\s_-]*found\b", re.IGNORECASE),
)

PLACEHOLDER_TITLE_MARKERS = (
    "welcome to nginx",
    "welcome to openresty",
    "welcome to tengine",
    "welcome to centos",
    "apache http server test page",
    "test page for the nginx http",
)

GENERIC_REDIRECT_TITLES = {
    "301 moved permanently",
    "302 found",
    "302 moved temporarily",
    "303 see other",
    "307 temporary redirect",
    "308 permanent redirect",
}

TRANSIENT_STATUS_CODES = {408, 418, 425, 429, 500, 501, 502, 503, 504}
RESTRICTED_STATUS_CODES = {401, 403}
NOT_FOUND_STATUS_CODES = {404, 410}
PROTOCOL_ERROR_STATUS_CODES = {400, 405, 411, 413, 414, 415, 421}
RESTRICTED_TITLE_MARKERS = ("401 unauthorized", "403 forbidden")
TRANSIENT_TITLE_MARKERS = (
    "500 internal server error", "502 bad gateway", "503 service unavailable",
    "503 service temporarily unavailable", "504 gateway time-out",
)
PROTOCOL_ERROR_TITLE_MARKERS = (
    "400 bad request", "405 method not allowed",
    "400 the plain http request was sent to https port",
    "400 no required ssl certificate was sent",
)

AUTH_REDIRECT_MARKERS = (
    "/auth", "/cas", "/login", "/oauth", "/saml", "/signin", "/sso",
)
AUTH_REDIRECT_HOST_LABELS = {
    "account", "accounts", "auth", "cas", "id", "login", "oauth",
    "passport", "signin", "sso",
}

NOTFOUND_REDIRECT_MARKERS = (
    "/notfound", "notfound.", "not-found", "not_found",
    "/404", "404.", "error404", "page-not-found", "page_not_found",
)

TEMPLATE_TITLE_PATTERNS = (
    (
        re.compile(r"^【[^】]{1,80}旅游线路】.+旅游攻略[，,].+旅游景点大全[-|].+"),
        "travel_line_page",
    ),
)

HIDDEN_SITE_QUALITY_STATES = {
    "evidence_only",
    "placeholder",
    "redirect_alias",
    "soft_404",
    "protocol_error",
}

VISIBLE_SITE_QUALITY_STATES = {
    "active",
    "restricted",
    "route_confirmed",
    "transient_block",
    "spa_shell",
    "template_content",
}

SPA_MARKERS = (
    "vue", "react", "angular", "next.js", "nextjs", "nuxt", "svelte",
    "webpack", "vite", "__next", "__nuxt", "chunk", "javascript",
)

GENERIC_TITLE_MARKERS = GENERIC_REDIRECT_TITLES | {
    "403 forbidden", "401 unauthorized", "404 not found", "405 method not allowed",
    "400 bad request", "500 internal server error", "502 bad gateway",
    "503 service unavailable", "504 gateway time-out", "not found",
    "loading", "loading...", "please wait", "please wait...",
    "redirecting", "redirecting...", "加载中", "加载中...",
    "页面加载中", "正在加载", "跳转中",
}

BROWSER_REPLACEABLE_TITLE_MARKERS = (
    set(GENERIC_TITLE_MARKERS) |
    set(SOFT_404_TITLE_MARKERS) |
    set(PLACEHOLDER_TITLE_MARKERS) |
    set(RESTRICTED_TITLE_MARKERS) |
    set(TRANSIENT_TITLE_MARKERS) |
    set(PROTOCOL_ERROR_TITLE_MARKERS)
)

UNTITLED_HTML_BROWSER_MAX_BYTES = 64 * 1024
# Keep title-only browser probes bounded. A large response can be a download
# or an error page and should not consume the SPA browser budget.
BROWSER_TITLE_PROBE_MAX_BYTES = 4 * 1024 * 1024

# Conservative fallback for historical rows that have not been backfilled yet.
# Keep the raw expression available for Mongo queries and API serialization.
LEGACY_HIDDEN_TITLE_REGEX = (
    r"^\s*(?:"
    r".*访问的页面不存在.*|"
    r".*页面.{0,16}(?:不存在|未找到).*|"
    r"没有找到站点(?:\s*[|_-].*)?|"
    r"page not found(?:\s*[|_-].*)?|"
    r"404 not found(?:\s*[|_-].*)?|http status 404(?:\s*[|_-].*)?|"
    r"not found(?:\s*[|_-].*)?|未找到(?:\s*[|_-].*)?|"
    r"error 404(?:--|\s+)not found(?:\s*[|_-].*)?|"
    r"welcome to (?:nginx|openresty|centos|tengine)!?|"
    r"apache http server test page(?:\s*[|_-].*)?|"
    r"test page for the nginx http(?:\s*[|_-].*)?|"
    r"301 moved permanently|302 found|302 moved temporarily|"
    r"303 see other|307 temporary redirect|308 permanent redirect"
    r")\s*$"
)
LEGACY_HIDDEN_TITLE_PATTERN = re.compile(
    LEGACY_HIDDEN_TITLE_REGEX, re.IGNORECASE)


def _status_code(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _positive_int(value):
    try:
        return max(int(value or 0), 0)
    except (TypeError, ValueError):
        return 0


def _is_true(value):
    if isinstance(value, str):
        return value.strip().lower() not in {"", "0", "false", "no", "off", "none", "null"}
    return bool(value)


def _body_length(item):
    value = (item or {}).get("body_length")
    if value is None:
        value = (item or {}).get("content_length")
    try:
        return max(int(value or 0), 0)
    except (TypeError, ValueError):
        return 0


def preferred_site_title(item):
    """Return the title a tester should see for a site row.

    Browser titles only replace a missing or known placeholder HTTP title.
    A meaningful server-rendered HTTP title remains authoritative, which
    avoids hiding useful origin-specific labels behind a later browser visit.
    """
    item = item or {}
    title = str(item.get("title") or "").strip()
    browser_title = str(item.get("browser_title") or "").strip()
    if browser_title and (
        not title or
        _contains_marker(title.lower(), BROWSER_REPLACEABLE_TITLE_MARKERS)
    ):
        return browser_title
    return title


def _title(item):
    return preferred_site_title(item).lower()


def _text_values(value):
    if isinstance(value, dict):
        value = value.get("name") or value.get("technology") or ""
    if isinstance(value, (list, tuple, set)):
        return [str(item or "") for item in value if item]
    return [str(value or "")]


def site_has_spa_evidence(item):
    """Return true for a shell that deserves browser enrichment.

    HTTPX often has no title for a JS shell. Technology/script evidence must
    outrank the small-body heuristic so route discovery can still happen.
    """
    item = item or {}
    if _positive_int(item.get("spa_score")) >= 45:
        return True
    spa_profile = item.get("spa_profile")
    if isinstance(spa_profile, dict) and _positive_int(spa_profile.get("score")) >= 45:
        return True
    if _is_true(item.get("browser_spa_detected")) or _positive_int(item.get("runtime_script_count")):
        return True
    values = []
    for field in (
            "tech", "finger", "spa_signals", "browser_title_source",
            "spa_framework", "spa_confidence", "spa_render_mode",
            "spa_route_mode"):
        values.extend(_text_values(item.get(field)))
    text = " ".join(values).lower()
    return any(marker in text for marker in SPA_MARKERS)


def site_has_browser_redirect_evidence(item):
    item = item or {}
    return bool(
        _is_true(item.get("browser_cross_origin_redirect")) or
        str(item.get("browser_final_title") or "").strip() or
        str(item.get("browser_final_url") or "").strip()
    )


def site_needs_browser_title(item):
    """Return true when the HTTP probe has no trustworthy HTML title.

    This is broader than SPA detection because HTTPX can miss a title on a
    server-rendered page or before a JS shell updates the DOM. Callers use it
    only to schedule a bounded browser title probe; URL/WIH matching is not
    changed by this signal.
    """
    item = item or {}
    status = _status_code(
        item.get("status") if item.get("status") is not None
        else item.get("status_code")
    )
    if status != 200:
        return False
    content_type = str(item.get("content_type") or "").lower()
    if content_type and "html" not in content_type and "xhtml" not in content_type:
        return False
    if _body_length(item) > BROWSER_TITLE_PROBE_MAX_BYTES:
        return False
    title = _title(item)
    return not title or _contains_marker(title, GENERIC_TITLE_MARKERS)


def _quality_cluster_key(item, state):
    if state in {"active", "route_confirmed", "spa_shell"}:
        return ""
    item = item or {}
    status = _status_code(item.get("status") if item.get("status") is not None else item.get("status_code"))
    body_hash = str(item.get("body_hash") or "").strip().lower()
    header_hash = str(item.get("header_hash") or "").strip().lower()
    title = re.sub(r"\s+", " ", _title(item)).strip()
    server = str(item.get("http_server") or item.get("webserver") or "").strip().lower()
    length = _body_length(item)
    template_signature = _template_title_signature(title)
    if state == "template_content" and template_signature:
        raw = "|".join((
            str(status or ""),
            "template",
            _site_host_family(item),
            template_signature,
        ))
        return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:24]
    if not any((body_hash, header_hash, title, server, length)):
        return ""
    if body_hash:
        raw = "{}|body:{}".format(status or "", body_hash)
    else:
        raw = "|".join((str(status or ""), header_hash, title, server, str(length)))
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:24]


def _evidence_sources(item, evidence):
    values = []
    for raw in (item.get("sources"), item.get("source"), evidence):
        if isinstance(raw, (list, tuple, set)):
            values.extend(str(value or "").strip() for value in raw)
        elif raw:
            values.append(str(raw).strip())
    return list(dict.fromkeys(value for value in values if value))


def _contains_marker(title, markers):
    for marker in markers:
        if title == marker:
            return True
        if not title.startswith(marker):
            continue
        suffix = title[len(marker):].lstrip()
        if not suffix or suffix[0] in "|_-:([{!":
            return True
    return False


def _looks_like_soft_404_title(title):
    title = re.sub(r"\s+", " ", str(title or "").strip().lower())
    if not title:
        return False
    if _contains_marker(title, SOFT_404_TITLE_MARKERS):
        return True
    return any(pattern.search(title) for pattern in SOFT_404_TITLE_PATTERNS)


def _redirect_location(item):
    return str(
        (item or {}).get("location") or
        (item or {}).get("redirect_location") or ""
    ).strip()


def _split_redirect(item):
    location = _redirect_location(item)
    site = str((item or {}).get("site") or (item or {}).get("canonical_site") or "").strip()
    if not location or not site:
        return location, site, None, ""
    try:
        destination = urlsplit(urljoin(site, location))
    except ValueError:
        return location, site, None, ""
    destination_text = "{}?{}".format(
        destination.path or "", destination.query or "").lower()
    return location, site, destination, destination_text


def _is_auth_redirect(item):
    """Return true only for a redirect that looks like an auth gateway."""
    item = item or {}
    _location, _site, destination, destination_text = _split_redirect(item)
    if not destination:
        return False
    destination_labels = set(
        str(destination.hostname or "").lower().split("."))
    return bool(
        any(marker in destination_text for marker in AUTH_REDIRECT_MARKERS) or
        destination_labels.intersection(AUTH_REDIRECT_HOST_LABELS)
    )


def _is_notfound_redirect(item, status):
    if status is None or not 300 <= status < 400:
        return False
    if _is_auth_redirect(item):
        return False
    _location, _site, destination, destination_text = _split_redirect(item)
    if not destination_text:
        return False
    return any(marker in destination_text for marker in NOTFOUND_REDIRECT_MARKERS)


def _is_incomplete_redirect(item, status, title):
    if status is None or not 300 <= status < 400:
        return False
    if title or _redirect_location(item):
        return False
    if site_has_spa_evidence(item) or site_has_browser_redirect_evidence(item):
        return False
    return True


def _is_root_redirect_alias(item, status, title):
    if status is None or not 300 <= status < 400:
        return False

    location, site, destination, _destination_text = _split_redirect(item)
    if _is_auth_redirect(item):
        return False
    if not location or not site:
        return title in GENERIC_REDIRECT_TITLES
    if not destination:
        return False
    if destination.path not in ("", "/") or destination.query:
        return False
    try:
        source = urlsplit(site)
    except ValueError:
        return False
    if title in GENERIC_REDIRECT_TITLES:
        return True
    return bool(
        destination.hostname and source.hostname and
        (
            destination.hostname.lower() != source.hostname.lower() or
            destination.scheme != source.scheme
        )
    )


def _site_host_family(item):
    site = str((item or {}).get("site") or (item or {}).get("canonical_site") or "").strip()
    try:
        host = (urlsplit(site).hostname or "").lower()
    except ValueError:
        host = ""
    labels = [label for label in host.split(".") if label]
    if len(labels) >= 3:
        return ".".join(labels[-3:])
    return host


def _template_title_signature(title):
    title = re.sub(r"\s+", " ", str(title or "").strip())
    if not title:
        return ""
    for pattern, signature in TEMPLATE_TITLE_PATTERNS:
        if pattern.search(title):
            return signature
    return ""


def _quality_result(state, visible, pipeline_mode, reason, evidence, item=None, score=0, verification_status="needs_review"):
    item = item or {}
    quality = "primary" if visible and state not in {"restricted", "transient_block"} else (
        "review" if visible else "hidden_noise"
    )
    noise_reasons = [] if quality == "primary" else [str(reason or "unspecified")]
    result = {
        "quality_state": state,
        "display_eligible": bool(visible),
        "pipeline_mode": pipeline_mode,
        "quality_reason": reason,
        "quality_evidence": list(evidence or []),
        "quality_version": SITE_QUALITY_VERSION,
        "asset_quality": quality,
        "asset_visibility": "visible" if visible else "hidden_noise",
        "quality_score": max(0, min(int(score or 0), 100)),
        "noise_reasons": noise_reasons,
        "evidence_sources": _evidence_sources(item, evidence),
        "verification_status": verification_status,
        "policy_version": SITE_QUALITY_VERSION,
    }
    result["quality_cluster_key"] = _quality_cluster_key(item, state)
    return result


def classify_site_quality(item):
    """Classify one observed origin without deleting its supporting evidence.

    Low-information roots remain route-probe eligible so a valid application
    mounted below / can still be discovered by the short directory profile.
    """
    item = item or {}
    def result(state, visible, pipeline_mode, reason, evidence, score=0, verification_status="needs_review"):
        return _quality_result(
            state, visible, pipeline_mode, reason, evidence,
            item=item, score=score, verification_status=verification_status,
        )

    if site_has_confirmed_route(item):
        return result(
            "route_confirmed", True, "full", "route_discovery_confirmed",
            ["independent_route_response"], 98, "confirmed",
        )

    status = _status_code(
        item.get("status") if item.get("status") is not None
        else item.get("status_code")
    )
    title = _title(item)

    if status in RESTRICTED_STATUS_CODES:
        return result(
            "restricted", True, "restricted", "restricted_http_response",
            ["http_status_{}".format(status)], 58, "needs_review",
        )

    if status in TRANSIENT_STATUS_CODES:
        return result(
            "transient_block", True, "retry_only", "transient_http_response",
            ["http_status_{}".format(status)], 35, "needs_review",
        )

    if status in NOT_FOUND_STATUS_CODES:
        return result(
            "soft_404", False, "route_probe_only", "not_found_http_response",
            ["http_status_{}".format(status)], 5, "evidence_only",
        )

    if status in PROTOCOL_ERROR_STATUS_CODES:
        return result(
            "protocol_error", False, "route_probe_only", "protocol_error_response",
            ["http_status_{}".format(status)], 8, "evidence_only",
        )

    if status in (204, 205):
        return result(
            "placeholder", False, "route_probe_only", "empty_http_response",
            ["http_status_{}".format(status), "missing_response_body"], 5, "evidence_only",
        )

    if _looks_like_soft_404_title(title):
        return result(
            "soft_404", False, "route_probe_only", "soft_404_title",
            ["low_information_title"], 5, "evidence_only",
        )

    if _contains_marker(title, RESTRICTED_TITLE_MARKERS):
        return result(
            "restricted", True, "restricted", "restricted_response_title",
            ["generic_restricted_title"], 50, "needs_review",
        )

    if _contains_marker(title, TRANSIENT_TITLE_MARKERS):
        return result(
            "transient_block", True, "retry_only", "transient_response_title",
            ["generic_transient_title"], 30, "needs_review",
        )

    if _contains_marker(title, PROTOCOL_ERROR_TITLE_MARKERS):
        return result(
            "protocol_error", False, "route_probe_only", "protocol_error_title",
            ["generic_protocol_error_title"], 8, "evidence_only",
        )

    if _contains_marker(title, PLACEHOLDER_TITLE_MARKERS) and not (
        site_has_spa_evidence(item) and str(item.get("browser_title") or "").strip()
    ):
        return result(
            "placeholder", False, "route_probe_only", "default_server_page",
            ["default_page_title"], 5, "evidence_only",
        )

    if _is_notfound_redirect(item, status):
        return result(
            "soft_404", False, "route_probe_only", "notfound_redirect",
            ["notfound_redirect_location", "http_status_{}".format(status)],
            5, "evidence_only",
        )

    if _is_incomplete_redirect(item, status, title):
        return result(
            "redirect_alias", False, "route_probe_only",
            "missing_redirect_location",
            ["missing_title", "missing_redirect_location", "http_status_{}".format(status)],
            8, "evidence_only",
        )

    if _is_root_redirect_alias(item, status, title):
        return result(
            "redirect_alias", False, "route_probe_only", "generic_redirect_page",
            ["generic_redirect_title", "http_status_{}".format(status)], 8, "evidence_only",
        )

    if (
        status is not None and 300 <= status < 400 and
        not title and _is_auth_redirect(item)
    ):
        return result(
            "active", True, "browser_enrich", "actionable_redirect",
            ["missing_title", "auth_redirect_location"],
            68, "needs_browser_title",
        )

    if title in GENERIC_REDIRECT_TITLES:
        # A generic 302 page can still point at the real application route or
        # an SSO gateway. _is_root_redirect_alias() already removed plain
        # scheme/host aliases, so a remaining 3xx Location deserves crawling
        # and browser title enrichment instead of being hidden as noise.
        location = str(
            item.get("location") or item.get("redirect_location") or ""
        ).strip()
        if (
            status is not None and 300 <= status < 400 and
            location and _is_auth_redirect(item)
        ):
            return result(
                "active", True, "browser_enrich", "actionable_redirect",
                ["generic_redirect_title", "non_alias_location"],
                68, "needs_browser_title",
            )
        return result(
            "redirect_alias", False, "route_probe_only", "generic_redirect_title",
            ["generic_redirect_title"], 8, "evidence_only",
        )

    content_type = str(item.get("content_type") or "").lower()
    if status == 200 and not title and _body_length(item) <= 300:
        if site_has_spa_evidence(item):
            return result(
                "spa_shell", True, "browser_enrich", "spa_runtime_candidate",
                ["small_body", "missing_title", "spa_evidence"], 76, "needs_browser_title",
            )
        if content_type and "html" not in content_type and "xhtml" not in content_type:
            return result(
                "evidence_only", False, "route_probe_only",
                "small_non_html_response",
                ["small_body", "missing_title", "non_html_response"],
                18, "evidence_only",
            )
        return result(
            "placeholder", False, "route_probe_only", "small_untitled_page",
            ["small_body", "missing_title"], 10, "evidence_only",
        )

    # Client-rendered shells can be larger than the tiny bootstrap threshold
    # because they contain inline config, preload tags, or serialized state.
    # Keep reasonably small HTML shells visible and browser-enrichable.
    if (
        status == 200 and not title and
        _body_length(item) <= UNTITLED_HTML_BROWSER_MAX_BYTES and
        (not content_type or "html" in content_type or "xhtml" in content_type) and
        not site_has_spa_evidence(item)
    ):
        return result(
            "active", True, "browser_enrich", "untitled_html_page",
            ["missing_title", "html_shell"], 66, "needs_browser_title",
        )

    if site_has_spa_evidence(item):
        return result(
            "spa_shell", True, "browser_enrich", "spa_runtime_evidence",
            ["spa_evidence"], 82, "needs_browser_title",
        )

    if status == 200 and _template_title_signature(title):
        return result(
            "template_content", True, "route_probe_only",
            "repeated_content_template",
            ["template_title_pattern"], 62, "confirmed",
        )

    return result(
        "active", True, "full", "application_response",
        ["independent_http_response"], 82 if status and 200 <= status < 300 else 70, "confirmed",
    )


def apply_site_quality(item, previous=None):
    """Classify a site write while preserving prior route confirmation.

    Project assets can be refreshed from a root response that contains less
    context than the original task row. A confirmed independent route remains
    meaningful even when that root later looks like a placeholder or soft 404.
    """
    item = item if item is not None else {}
    context = dict(previous or {})
    context.update(item)
    if (previous or {}).get("quality_state") == "route_confirmed":
        context["quality_state"] = "route_confirmed"
    quality = classify_site_quality(context)
    # A repeated low-information response stays suppressed when it is copied
    # into a project or refreshed by a later generic HTTP observation. A real
    # application/route result has no cluster key and automatically lifts the
    # suppression.
    if (
        context.get("quality_cluster_representative") is False and
        quality.get("quality_cluster_key")
    ):
        quality["display_eligible"] = False
        quality["asset_visibility"] = "hidden_noise"
        reasons = list(quality.get("noise_reasons") or [])
        quality["noise_reasons"] = list(dict.fromkeys(
            reasons + ["repeated_response_template"]
        ))
    elif (
        context.get("quality_cluster_representative") is False and
        not quality.get("quality_cluster_key")
    ):
        quality["quality_cluster_representative"] = True
        quality["quality_cluster_size"] = 1
    item.update(quality)
    return item


def site_has_confirmed_route(item):
    item = item or {}
    try:
        route_hit_count = int(item.get("route_hit_count") or 0)
    except (TypeError, ValueError):
        route_hit_count = 0
    return bool(
        item.get("route_discovery_status") == "confirmed" or
        route_hit_count > 0 or
        item.get("quality_state") == "route_confirmed"
    )


def site_is_display_eligible(item):
    if not item:
        return False
    if item.get("quality_cluster_representative") is False:
        return False
    if str(item.get("asset_visibility") or "").strip().lower() == "hidden_noise":
        return False
    if item.get("display_eligible") is False:
        return False
    state = str(item.get("quality_state") or "").strip().lower()
    if state:
        return state in VISIBLE_SITE_QUALITY_STATES
    if item.get("display_eligible") is not None:
        return bool(item.get("display_eligible"))
    return not bool(LEGACY_HIDDEN_TITLE_PATTERN.search(preferred_site_title(item)))
