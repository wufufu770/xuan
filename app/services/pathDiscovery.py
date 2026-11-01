import hashlib
import html
import ipaddress
import re
import secrets
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from difflib import SequenceMatcher
from html.parser import HTMLParser
from urllib.parse import parse_qsl, quote, unquote, urlencode, urljoin, urlsplit, urlunsplit

from bson import ObjectId

from app import utils
from app.config import Config


logger = utils.get_logger()


REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}
STATIC_ASSET_EXTENSIONS = {
    ".7z", ".avi", ".bmp", ".css", ".csv", ".doc", ".docx", ".eot",
    ".flv", ".gif", ".gz", ".ico", ".jpeg", ".jpg", ".js", ".json",
    ".map", ".mkv", ".mov", ".mp3", ".mp4", ".mpeg", ".pdf", ".png",
    ".ppt", ".pptx", ".rar", ".svg", ".tar", ".tgz", ".tif", ".tiff",
    ".ttf", ".txt", ".wav", ".webp", ".woff", ".woff2", ".xls",
    ".xlsx", ".xml", ".xz", ".yaml", ".yml", ".zip",
}
API_PATH_SEGMENTS = {
    "api", "api-gateway", "api_gateway", "apigw", "gateway-api", "graphql",
    "fapi", "open-api", "open_api", "openapi", "rest", "rpc", "web-api",
    "web_api", "webapi", "ws", "v1", "v2", "v3",
}
RESOURCE_PATH_SEGMENTS = {
    "_app", "_next", "_nuxt", "asset", "assets", "css", "dist", "font",
    "fonts", "image", "images", "img", "javascript", "js", "layui", "lib",
    "libs", "media", "node_modules", "public", "res", "resource",
    "resources", "src", "static", "vendor", "vendors",
}
IGNORED_DOMAIN_LABELS = {
    "assets", "cdn", "css", "download", "file", "files", "img", "images",
    "js", "openapi", "static", "upload", "uploads", "www",
}
VOLATILE_QUERY_KEYS = {
    "_", "authcode", "callback", "checksum", "cksum", "code", "code_challenge",
    "encquery", "expires", "nonce", "random", "requestid", "request_id", "rnd",
    "session", "sessionid", "signature", "state", "ticket", "timestamp", "token",
    "ts",
}
RETURN_QUERY_KEYS = {
    "backurl", "continue", "destination", "from", "goto", "next", "relaystate",
    "redirect", "redirect_uri", "redirecturl", "return", "return_url", "returnurl",
    "service", "target", "url",
}
SSO_PATTERN = re.compile(
    r"(?:^|[./?&=_-])(?:account|auth|cas|federation|identity|idp|login|oauth2?|"
    r"oidc|passport|saml2?|signin|sso)(?:$|[./?&=_-])",
    re.I,
)
SECOND_LEVEL_DEFAULT_WORDS = (
    "login", "index", "admin", "manage", "manager", "console", "portal",
    "workspace", "home", "main", "system", "dashboard", "web", "app",
)
PRODUCT_PATH_HINTS = {
    "apollo": ("apollo", "apollo-portal"),
    "cas": ("cas", "cas/login"),
    "druid": ("druid", "druid/index.html"),
    "eureka": ("eureka", "eureka/apps"),
    "gitea": ("gitea", "gitea/user/login"),
    "gitlab": ("gitlab", "gitlab/users/sign_in"),
    "grafana": ("grafana", "grafana/login"),
    "harbor": ("harbor",),
    "jeecg": ("jeecg-boot", "jeecg-boot/sys/login"),
    "jenkins": ("jenkins", "jenkins/login"),
    "jupyter": ("jupyter", "jupyter/tree"),
    "keycloak": ("keycloak", "keycloak/admin", "realms"),
    "kibana": ("kibana",),
    "metabase": ("metabase",),
    "nacos": ("nacos",),
    "ruoyi": ("ruoyi", "ruoyi/login"),
    "seeyon": ("seeyon", "seeyon/login"),
    "spring boot admin": ("spring-boot-admin",),
    "superset": ("superset",),
    "swagger": ("swagger-ui.html", "swagger-ui/index.html"),
    "tongda": ("tongda", "tongdaoa", "tongdaoa/login"),
    "weaver": ("weaver", "weaver/login"),
    "xxl-job": ("xxl-job-admin", "xxl-job-admin/toLogin"),
}
PRODUCT_PATH_WORDS = {
    str(word or "").strip("/").lower()
    for words in PRODUCT_PATH_HINTS.values()
    for word in words
    if str(word or "").strip("/")
}
HIGH_VALUE_PATH_TOKENS = {
    "account", "admin", "auth", "backend", "backstage", "cas", "console",
    "control", "dashboard", "home", "iam", "idaas", "identity", "idp",
    "index", "login", "manage", "manager", "oauth", "oauth2", "oidc",
    "operation", "portal", "saml", "saml2", "signin", "sso", "sys",
    "sysadmin", "system", "tenant", "workspace",
}
DYNAMIC_REJECTED_SEGMENTS = {
    "[object object]", "__webpack_hmr", "_vba_project_cur", "babel-loader",
    "cache-loader", "css-loader", "file-loader", "html-webpack-plugin",
    "mini-css-extract-plugin", "source-map-loader", "style-loader",
    "url-loader", "vue-cli-plugin-uni", "webpack", "webpack-dev-server",
}
RESOURCE_CLUE_FILENAMES = {
    "asset-manifest.json", "manifest.json", "manifest.webmanifest",
    "precache-manifest.json", "robots.txt", "service-worker.js",
    "sitemap.xml", "sitemap.xml.gz", "sw.js",
}
RESOURCE_CONTENT_TYPE_MARKERS = (
    "javascript", "ecmascript", "text/css", "image/", "font/",
    "application/font", "application/octet-stream", "application/pdf",
    "application/wasm",
)


def ordered_unique(values):
    result = []
    seen = set()
    for value in values or []:
        value = str(value or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def browser_request_headers():
    return {
        "User-Agent": str(getattr(
            Config,
            "FFUF_USER_AGENT",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        )),
        "Accept": str(getattr(
            Config,
            "FFUF_ACCEPT",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        )),
        "Accept-Language": str(getattr(
            Config, "FFUF_ACCEPT_LANGUAGE", "zh-CN,zh;q=0.9,en;q=0.8")),
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Upgrade-Insecure-Requests": "1",
    }


def normalize_path_word(value):
    value = unquote(str(value or "").strip()).replace("\\", "/")
    if not value or value.startswith("#"):
        return ""
    if len(value) > 256 or any(ord(char) < 32 for char in value):
        return ""
    if value.startswith(("http://", "https://")):
        try:
            value = urlsplit(value).path
        except ValueError:
            return ""
    value = re.sub(r"/{2,}", "/", value).strip("/")
    if not value or value in (".", "..") or "\x00" in value:
        return ""
    if any(part in (".", "..") for part in value.split("/")):
        return ""
    return value


def is_high_value_path(value):
    value = normalize_path_word(value)
    if not value:
        return False
    lowered = value.lower()
    if SSO_PATTERN.search(lowered):
        return True
    tokens = set(filter(None, re.split(r"[/_.-]+", lowered)))
    if tokens & HIGH_VALUE_PATH_TOKENS:
        return True
    return any(
        lowered == product or lowered.startswith(product + "/")
        for product in PRODUCT_PATH_WORDS
    )


def _looks_random_label(value):
    value = str(value or "").strip().lower()
    if not value or len(value) > 32:
        return True
    if re.fullmatch(r"[a-f0-9]{12,}", value):
        return True
    if re.fullmatch(r"[a-z0-9]{18,}", value):
        digit_count = sum(char.isdigit() for char in value)
        vowel_count = sum(char in "aeiou" for char in value)
        return digit_count >= 4 or vowel_count <= 2
    return False


def dynamic_path_word_is_usable(value, source="url"):
    value = normalize_path_word(value)
    if not value or len(value) > 96:
        return False
    if re.search(r"[\s\[\]{}<>\"'`@;$]", value):
        return False

    parts = [part for part in value.split("/") if part]
    if not parts or len(parts) > 3:
        return False
    for part in parts:
        lowered = part.lower()
        if len(part) > 48 or lowered in DYNAMIC_REJECTED_SEGMENTS:
            return False
        if lowered.startswith(("_vba_", "webpack-", "webpack_")):
            return False
        if source == "domain" and part.isdigit():
            return False
    return True


def _path_has_static_extension(path):
    path = str(path or "").split("?", 1)[0].lower().rstrip("/")
    if not path:
        return False
    tail = path.rsplit("/", 1)[-1]
    if "." not in tail:
        return False
    extension = "." + tail.rsplit(".", 1)[-1]
    return extension in STATIC_ASSET_EXTENSIONS


def path_words_from_url(value, max_depth=2):
    try:
        parsed = urlsplit(str(value or "").strip())
    except ValueError:
        return []
    if parsed.scheme and parsed.scheme not in ("http", "https"):
        return []

    path = unquote(parsed.path or "")
    parts = [part for part in path.split("/") if part and part not in (".", "..")]
    if not parts:
        return []

    result = []
    prefix = []
    for part in parts[:max(max_depth, 1)]:
        lowered = part.lower()
        if (
            lowered in API_PATH_SEGMENTS
            or lowered in RESOURCE_PATH_SEGMENTS
            or _path_has_static_extension(part)
            or not dynamic_path_word_is_usable(part)
        ):
            break
        prefix.append(part)
        candidate = normalize_path_word("/".join(prefix))
        if candidate:
            result.append(candidate)
    return ordered_unique(result)


def domain_label_words(host, base_domain=""):
    host = str(host or "").strip(".").lower()
    base_domain = str(base_domain or "").strip(".").lower()
    if not host:
        return []
    if base_domain and (host == base_domain or host.endswith("." + base_domain)):
        prefix = host[:-len(base_domain)].rstrip(".")
        labels = [value for value in prefix.split(".") if value]
    else:
        labels = host.split(".")[:-2]

    result = []
    for label in reversed(labels):
        if label.isdigit() or label in IGNORED_DOMAIN_LABELS or _looks_random_label(label):
            continue
        if 1 < len(label) <= 32:
            result.append(label)
        for token in re.split(r"[-_]", label):
            if (
                1 < len(token) <= 24
                and not token.isdigit()
                and token not in IGNORED_DOMAIN_LABELS
                and not _looks_random_label(token)
            ):
                result.append(token)
    return ordered_unique(result)


def site_scoped_domain_path_words(target, base_domain=""):
    """Build path words that belong only to the target HTTP origin.

    A hostname label is useful as a directory clue, but it must not become a
    task-wide word.  Keep both slash forms because some reverse proxies only
    route the canonical ``/label/`` form and do not redirect ``/label``.
    """
    try:
        host = str(urlsplit(str(target or "").strip()).hostname or "")
    except ValueError:
        return []
    if not host:
        return []
    try:
        ipaddress.ip_address(host)
        return []
    except ValueError:
        pass

    result = []
    for label in domain_label_words(host, base_domain=base_domain):
        word = normalize_path_word(label)
        if not dynamic_path_word_is_usable(word, source="domain"):
            continue
        result.extend((word, word + "/"))
    return ordered_unique(result)


def select_dynamic_path_words(candidate_groups, limit=300):
    """Score candidates while reserving capacity for each evidence source."""
    limit = max(int(limit or 0), 0)
    if limit == 0:
        return [], {"dynamic_rejected_count": 0}

    source_bases = {
        "product": 400,
        "high_url": 320,
        "domain": 240,
        "url": 120,
    }
    records = {}
    rejected_count = 0
    for source in ("product", "url", "domain"):
        for raw_value in (candidate_groups or {}).get(source, []) or []:
            value = normalize_path_word(raw_value)
            if not dynamic_path_word_is_usable(value, source=source):
                rejected_count += 1
                continue
            group = "high_url" if source == "url" and is_high_value_path(value) else source
            score = source_bases[group]
            if is_high_value_path(value):
                score += 40
            if "/" not in value:
                score += 12
            current = records.get(value)
            if current is None:
                records[value] = {
                    "word": value,
                    "group": group,
                    "score": score,
                    "frequency": 1,
                    "sources": {group},
                }
            else:
                current["frequency"] += 1
                current["sources"].add(group)
                if score > current["score"]:
                    current["group"] = group
                    current["score"] = score

    def record_rank(record):
        return (
            -(record["score"] + min(record["frequency"], 10) * 2),
            len(record["word"].split("/")),
            record["word"].lower(),
        )

    grouped = {name: [] for name in source_bases}
    for record in records.values():
        grouped[record["group"]].append(record)
    for values in grouped.values():
        values.sort(key=record_rank)

    quotas = {
        "product": int(limit * 0.20),
        "high_url": int(limit * 0.35),
        "domain": int(limit * 0.25),
    }
    quotas["url"] = max(limit - sum(quotas.values()), 0)

    selected = []
    selected_words = set()
    for group in ("product", "high_url", "domain", "url"):
        for record in grouped[group][:quotas[group]]:
            selected.append(record)
            selected_words.add(record["word"])

    if len(selected) < limit:
        remaining = sorted(
            (record for record in records.values() if record["word"] not in selected_words),
            key=record_rank,
        )
        for record in remaining[:limit - len(selected)]:
            selected.append(record)
            selected_words.add(record["word"])

    selected.sort(key=record_rank)
    selected = selected[:limit]
    selected_counts = Counter(record["group"] for record in selected)
    return [record["word"] for record in selected], {
        "dynamic_rejected_count": rejected_count,
        "dynamic_selected_product_count": selected_counts["product"],
        "dynamic_selected_high_url_count": selected_counts["high_url"],
        "dynamic_selected_domain_count": selected_counts["domain"],
        "dynamic_selected_url_count": selected_counts["url"],
        "dynamic_selected_domain_words": [
            record["word"] for record in selected
            if record["sources"] == {"domain"}
        ],
    }


def split_priority_words(words, max_words=240):
    words = ordered_unique(normalize_path_word(value) for value in words or [])
    priority = [value for value in words if is_high_value_path(value)]
    max_words = max(int(max_words or 0), 0)
    selected = priority[:max_words] if max_words else []
    selected_set = set(selected)
    remainder = [value for value in priority[max_words:] if value not in selected_set]
    remainder.extend(
        value for value in words
        if value not in selected_set and value not in remainder
    )
    return selected, remainder


def _task_target(task_id):
    if not task_id:
        return ""
    try:
        task = utils.conn_db("task").find_one(
            {"_id": ObjectId(str(task_id))}, {"_id": 0, "target": 1}
        )
    except Exception:
        task = None
    return str((task or {}).get("target") or "").strip(".").lower()


def _limited_find(collection, query, projection, limit):
    try:
        cursor = utils.conn_db(collection).find(query, projection)
        if hasattr(cursor, "limit"):
            cursor = cursor.limit(limit)
        return list(cursor)
    except Exception as exc:
        logger.warning("dynamic path source {} failed: {}".format(collection, exc))
        return []


def build_dynamic_path_words(task_id, targets, limit=300, source_limit=5000):
    limit = max(int(limit or 0), 0)
    source_limit = max(int(source_limit or 0), 1)
    if not task_id or limit == 0:
        return [], {"dynamic_word_count": 0}

    base_domain = _task_target(task_id)
    path_values = []
    domain_values = []
    product_values = []
    query = {"task_id": str(task_id)}

    for target in targets or []:
        try:
            parsed = urlsplit(str(target or "").strip())
        except ValueError:
            continue
        if parsed.hostname:
            domain_values.append(parsed.hostname)
        path_values.append(target)

    for item in _limited_find("domain", query, {"_id": 0, "domain": 1}, source_limit):
        domain_values.append(item.get("domain"))

    for collection, fields in (
        ("site", ("site",)),
        ("url", ("url", "discovered_from")),
        ("entry_asset", ("seed", "final_url", "alive_url")),
    ):
        projection = {"_id": 0}
        projection.update({field: 1 for field in fields})
        for item in _limited_find(collection, query, projection, source_limit):
            for field in fields:
                path_values.append(item.get(field))

    wih_query = {
        "task_id": str(task_id),
        "$or": [
            {"record_type": "all_url"},
            {"evidence_type": "hae_all_url"},
        ],
    }
    for item in _limited_find("wih", wih_query, {"_id": 0, "content": 1}, source_limit):
        path_values.append(item.get("content"))

    site_fields = {"_id": 0, "title": 1, "finger": 1}
    for item in _limited_find("site", query, site_fields, source_limit):
        text_values = [item.get("title")]
        for finger in item.get("finger") or []:
            if isinstance(finger, dict):
                text_values.append(finger.get("name"))
            else:
                text_values.append(finger)
        searchable = " ".join(str(value or "") for value in text_values).lower()
        for marker, words in PRODUCT_PATH_HINTS.items():
            if re.search(r"\b{}\b".format(re.escape(marker)), searchable):
                product_values.extend(words)

    url_words = []
    product_words = []
    domain_words = []
    source_counts = {"url": 0, "product": 0, "domain": 0}
    for value in path_values:
        words = path_words_from_url(value)
        url_words.extend(words)
        source_counts["url"] += len(words)
    product_words.extend(product_values)
    source_counts["product"] = len(product_values)
    for value in domain_values:
        words = domain_label_words(value, base_domain=base_domain)
        domain_words.extend(words)
        source_counts["domain"] += len(words)

    words, selection_meta = select_dynamic_path_words(
        {
            "product": product_words,
            "url": url_words,
            "domain": domain_words,
        },
        limit=limit,
    )
    return words, {
        "dynamic_word_count": len(words),
        "dynamic_source_url_count": source_counts["url"],
        "dynamic_source_product_count": source_counts["product"],
        "dynamic_source_domain_count": source_counts["domain"],
        **selection_meta,
    }


class _EntryHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.values = []

    def handle_starttag(self, tag, attrs):
        attrs = {str(key or "").lower(): value for key, value in attrs}
        if tag.lower() == "form" and attrs.get("action"):
            self.values.append(attrs["action"])
        if tag.lower() == "meta" and str(attrs.get("http-equiv") or "").lower() == "refresh":
            content = str(attrs.get("content") or "")
            match = re.search(r"url\s*=\s*['\"]?([^'\";]+)", content, re.I)
            if match:
                self.values.append(match.group(1).strip())


def _normalize_body(body, request_url):
    if isinstance(body, bytes):
        text = body[:256 * 1024].decode("utf-8", errors="ignore")
    else:
        text = str(body or "")[:256 * 1024]
    text = html.unescape(text).lower()
    try:
        parsed = urlsplit(request_url)
        decoded_path = unquote(parsed.path or "")
        bare_path = decoded_path.strip("/")
        path_tail = bare_path.rsplit("/", 1)[-1]
        replacements = [
            request_url,
            parsed.path,
            decoded_path,
            quote(parsed.path or ""),
            quote(request_url, safe=""),
        ]
        bare_values = [bare_path, path_tail]
    except ValueError:
        replacements = [request_url]
        bare_values = []
    for value in sorted(set(replacements), key=lambda item: len(str(item or "")), reverse=True):
        value = str(value or "").lower()
        if value and value != "/":
            text = text.replace(value, "{request_path}")
    echo_prefix = (
        r"(?:cannot\s+get|missing|no\s+route(?:\s+for)?|not\s+found|path|"
        r"request(?:ed)?|resource|route|uri|url)\s*[:=]?\s+"
    )
    echo_suffix = r"\s+(?:does\s+not\s+exist|not\s+found|was\s+not\s+found)"
    for value in sorted(set(bare_values), key=len, reverse=True):
        value = str(value or "").lower()
        if not value or value == "/":
            continue
        escaped = re.escape(value)
        text = re.sub(
            r"({}){}(?=$|[\s<>'\".,;:!?])".format(echo_prefix, escaped),
            r"\1{request_path}",
            text,
        )
        text = re.sub(
            r"(?<![a-z0-9]){}({})".format(escaped, echo_suffix),
            r"{request_path}\1",
            text,
        )
    text = re.sub(r"[0-9a-f]{8}-[0-9a-f-]{27,}", "{uuid}", text)
    text = re.sub(r"\b[0-9a-f]{16,}\b", "{token}", text)
    text = re.sub(r"\b\d{6,}\b", "{number}", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:32768]


def _parse_redirect_query(query_text):
    standard = parse_qsl(query_text, keep_blank_values=True)
    if "%3d" not in str(query_text or "").lower():
        return standard

    decoded = unquote(str(query_text or ""))
    matches = list(re.finditer(
        r"(?:^|[&;\s]+)([a-zA-Z0-9_.-]+)=",
        decoded,
    ))
    if len(matches) < 2:
        return standard

    relaxed = []
    for index, match in enumerate(matches):
        value_end = matches[index + 1].start() if index + 1 < len(matches) else len(decoded)
        value = decoded[match.end():value_end].strip(" \t\r\n&;")
        relaxed.append((match.group(1), value))

    encoded_blob = len(standard) <= 1 or any("=" in key for key, _value in standard)
    return relaxed if encoded_blob else standard


def normalize_redirect_location(location, request_url=""):
    location = str(location or "").strip()
    if not location:
        return ""
    try:
        absolute = urljoin(request_url, location)
        parsed = urlsplit(absolute)
    except ValueError:
        return location.lower()

    normalized_path = parsed.path or "/"
    try:
        request_path = unquote(urlsplit(request_url).path or "").strip("/")
    except ValueError:
        request_path = ""
    if request_path:
        normalized_path = unquote(normalized_path)
        normalized_path = re.sub(
            r"/{}(?=/|$)".format(re.escape(request_path)),
            "/{request_path}",
            normalized_path,
        )

    query = []
    for key, value in _parse_redirect_query(parsed.query):
        lowered = key.lower()
        if lowered in VOLATILE_QUERY_KEYS:
            normalized_value = "{volatile}"
        elif lowered in RETURN_QUERY_KEYS:
            normalized_value = "{return_target}"
        else:
            normalized_value = value
        query.append((lowered, normalized_value))
    query.sort()
    host = (parsed.hostname or "").lower()
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port:
        host = "{}:{}".format(host, port)

    try:
        request_parsed = urlsplit(request_url)
        request_host = (request_parsed.hostname or "").lower()
        request_port = request_parsed.port
    except (TypeError, ValueError):
        request_host = ""
        request_port = None
    if request_port:
        request_host = "{}:{}".format(request_host, request_port)
    if request_host and host == request_host:
        host = "{self}"
    return urlunsplit((parsed.scheme.lower(), host, normalized_path, urlencode(query), ""))


def resolve_redirect_location(location, request_url=""):
    location = str(location or "").strip()
    if not location:
        return ""
    try:
        absolute = urljoin(request_url, location)
        parsed = urlsplit(absolute)
    except (TypeError, ValueError):
        return ""
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        return ""
    return urlunsplit((
        parsed.scheme.lower(),
        parsed.netloc,
        parsed.path or "/",
        parsed.query,
        "",
    ))


def redirect_destination_metadata(location, request_url=""):
    absolute = resolve_redirect_location(location, request_url)
    if not absolute:
        return {
            "redirect_url": "",
            "redirect_host": "",
            "redirect_path": "",
            "redirect_type": "",
        }

    parsed = urlsplit(absolute)
    try:
        request_parsed = urlsplit(request_url)
    except (TypeError, ValueError):
        request_parsed = None
    same_origin = bool(
        request_parsed
        and request_parsed.scheme.lower() == parsed.scheme.lower()
        and request_parsed.netloc.lower() == parsed.netloc.lower()
    )
    redirect_type = "same_origin" if same_origin else "cross_origin"
    if is_sso_redirect(absolute):
        redirect_type = "sso"
    return {
        "redirect_url": absolute,
        "redirect_host": (parsed.hostname or "").lower(),
        "redirect_path": parsed.path or "/",
        "redirect_type": redirect_type,
    }


def is_sso_redirect(location):
    value = unquote(str(location or "")).lower()
    if not value:
        return False
    return bool(SSO_PATTERN.search(value))


def is_resource_clue_response(signature):
    if not signature:
        return False
    try:
        path = unquote(urlsplit(signature.request_url).path or "").lower().rstrip("/")
    except ValueError:
        path = ""
    filename = path.rsplit("/", 1)[-1]
    if filename in RESOURCE_CLUE_FILENAMES or _path_has_static_extension(path):
        return True
    content_type = str(signature.content_type or "").lower()
    return any(marker in content_type for marker in RESOURCE_CONTENT_TYPE_MARKERS)


def is_html_response(signature):
    if not signature:
        return False
    content_type = str(signature.content_type or "").lower()
    if "html" in content_type or "xhtml" in content_type:
        return True
    if signature.title:
        return True
    body = signature.normalized_body[:4096]
    return any(marker in body for marker in (
        "<!doctype html", "<html", "<head", "<body", "<form", "<title",
    ))


class ResponseSignature(object):
    def __init__(
        self,
        request_url="",
        status_code=None,
        body=b"",
        content_type="",
        location="",
        title="",
        cookie_names=None,
    ):
        self.request_url = str(request_url or "")
        try:
            self.status_code = int(status_code) if status_code is not None else None
        except (TypeError, ValueError):
            self.status_code = None
        raw_body = body or b""
        self.content_length = len(raw_body)
        if isinstance(raw_body, bytes):
            self.body = raw_body[:64 * 1024]
        else:
            self.body = str(raw_body)[:64 * 1024]
        self.content_type = str(content_type or "").split(";", 1)[0].strip().lower()
        self.location = str(location or "").strip()
        self.normalized_location = normalize_redirect_location(self.location, self.request_url)
        self.title = str(title or "").strip()
        self.cookie_names = tuple(sorted(set(cookie_names or [])))
        self.normalized_body = _normalize_body(self.body, self.request_url)
        self.body_hash = hashlib.sha256(self.normalized_body.encode("utf-8")).hexdigest()
        self.word_count = len(self.normalized_body.split())
        if isinstance(self.body, bytes):
            self.line_count = max(self.body.count(b"\n") + 1, 1)
        else:
            self.line_count = max(str(self.body).count("\n") + 1, 1)


class SiteBaseline(object):
    def __init__(self, target):
        self.target = target
        self.random_signatures = []
        self.root_signature = None
        self.dynamic_words = []
        self.request_count = 0
        self.error_count = 0
        self.stopped = False


class ParentBaselineMap(dict):
    def __init__(self):
        super().__init__()
        self.request_count = 0
        self.error_count = 0
        self.stopped = False


def probe_response_signature(url, timeout=5):
    conn = None
    try:
        conn = utils.http_req(
            url,
            "get",
            timeout=(3, max(int(timeout or 5), 1)),
            allow_redirects=False,
            headers=browser_request_headers(),
        )
        cookies = []
        try:
            cookies = list(conn.cookies.keys())
        except Exception:
            pass
        return ResponseSignature(
            request_url=url,
            status_code=conn.status_code,
            body=conn.content,
            content_type=conn.headers.get("Content-Type", ""),
            location=conn.headers.get("Location", ""),
            title=utils.get_title(conn.content).strip(),
            cookie_names=cookies,
        )
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def _entry_words_from_root(target, signature):
    values = []
    if signature.location:
        values.append(signature.location)
    if signature.body:
        parser = _EntryHTMLParser()
        try:
            parser.feed(signature.body[:256 * 1024].decode("utf-8", errors="ignore"))
            values.extend(parser.values)
        except Exception:
            pass

    try:
        target_host = (urlsplit(target).netloc or "").lower()
    except ValueError:
        target_host = ""
    words = []
    for value in values:
        try:
            absolute = urljoin(target, str(value or "").strip())
            parsed = urlsplit(absolute)
        except ValueError:
            continue
        if (parsed.netloc or "").lower() != target_host:
            continue
        words.extend(path_words_from_url(absolute))
    return ordered_unique(words)


def build_site_baseline(target, request_count=3, timeout=5, should_stop=None):
    baseline = SiteBaseline(target)
    if should_stop and should_stop():
        baseline.stopped = True
        return baseline
    try:
        baseline.root_signature = probe_response_signature(target, timeout=timeout)
        baseline.request_count += 1
        baseline.dynamic_words = _entry_words_from_root(target, baseline.root_signature)
    except Exception as exc:
        baseline.error_count += 1
        logger.debug("ffuf root baseline failed {} {}".format(target, exc))

    for _ in range(max(int(request_count or 0), 0)):
        if should_stop and should_stop():
            baseline.stopped = True
            break
        random_word = "arl-not-found-{}".format(secrets.token_hex(10))
        random_url = target.rstrip("/") + "/" + random_word
        try:
            baseline.random_signatures.append(
                probe_response_signature(random_url, timeout=timeout)
            )
            baseline.request_count += 1
        except Exception as exc:
            baseline.error_count += 1
            logger.debug("ffuf random baseline failed {} {}".format(random_url, exc))
    return baseline


def build_parent_baselines(
    target,
    parent_words,
    timeout=5,
    should_stop=None,
    concurrency=4,
):
    result = ParentBaselineMap()
    parents = ordered_unique(normalize_path_word(value) for value in parent_words)
    if not parents:
        return result

    def probe_parent(parent):
        parent_url = target.rstrip("/") + "/" + parent.lstrip("/")
        if should_stop and should_stop():
            return parent_url, None, "task_stopped"
        random_url = parent_url.rstrip("/") + "/arl-not-found-{}".format(
            secrets.token_hex(10))
        try:
            signature = probe_response_signature(random_url, timeout=timeout)
            return parent_url, signature, ""
        except Exception as exc:
            logger.debug("ffuf parent baseline failed {} {}".format(random_url, exc))
            return parent_url, None, "probe_failed"

    workers = min(max(int(concurrency or 1), 1), len(parents))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(probe_parent, parent) for parent in parents]
        for future in as_completed(futures):
            parent_url, signature, reason = future.result()
            if reason == "task_stopped":
                result.stopped = True
                continue
            if signature is not None:
                baseline = SiteBaseline(parent_url)
                baseline.random_signatures.append(
                    signature
                )
                baseline.request_count = 1
                result.request_count += 1
                result[parent_url.rstrip("/")] = baseline
            else:
                result.error_count += 1
    return result


def signatures_match(candidate, baseline, length_tolerance=128, similarity=0.985):
    if not candidate or not baseline:
        return False
    if candidate.status_code != baseline.status_code:
        return False

    if candidate.status_code in REDIRECT_STATUS_CODES:
        if candidate.normalized_location and (
            candidate.normalized_location == baseline.normalized_location
        ):
            return True

    if candidate.body_hash and candidate.body_hash == baseline.body_hash:
        return True

    length_delta = abs(candidate.content_length - baseline.content_length)
    length_limit = max(int(length_tolerance or 0), int(max(
        candidate.content_length, baseline.content_length, 1
    ) * 0.02))
    if length_delta > length_limit:
        return False
    if candidate.content_type and baseline.content_type and (
        candidate.content_type != baseline.content_type
    ):
        return False
    if candidate.title and baseline.title and candidate.title != baseline.title:
        return False
    if not candidate.normalized_body or not baseline.normalized_body:
        return candidate.title == baseline.title and length_delta <= length_limit

    ratio = SequenceMatcher(
        None,
        candidate.normalized_body[:4096],
        baseline.normalized_body[:4096],
        autojunk=False,
    ).ratio()
    return ratio >= float(similarity or 0.985)


def classify_response(candidate, baseline, length_tolerance=128, similarity=0.985):
    if candidate is None:
        return "unverified_path", False, "probe_failed"
    for random_signature in baseline.random_signatures or []:
        if signatures_match(
            candidate,
            random_signature,
            length_tolerance=length_tolerance,
            similarity=similarity,
        ):
            return "template_suspect", True, "random_baseline_match"

    if candidate.status_code in REDIRECT_STATUS_CODES and is_sso_redirect(candidate.location):
        return "sso_protected", False, "distinct_sso_redirect"
    if (
        candidate.status_code is not None
        and 500 <= candidate.status_code < 600
    ):
        return "non_entry_response", False, "server_error_response"
    if is_resource_clue_response(candidate):
        return "resource_clue", False, "static_or_build_resource"
    if candidate.status_code in (401, 403):
        return "protected_401_403", False, "distinct_protected_response"
    if (
        candidate.status_code is not None
        and 200 <= candidate.status_code < 300
        and is_html_response(candidate)
    ):
        return "path_entry", False, "distinct_html_response"
    if candidate.status_code in REDIRECT_STATUS_CODES:
        return "redirect_clue", False, "distinct_non_sso_redirect"
    return "non_entry_response", False, "non_html_or_error_response"


def build_secondary_words(pages, child_words=None, max_roots=10, max_words=140):
    children = ordered_unique(
        normalize_path_word(value)
        for value in (child_words or SECOND_LEVEL_DEFAULT_WORDS)
    )
    roots = []
    parent_map = {}
    for page in pages or []:
        if getattr(page, "entry_type", "") not in {
            "path_entry", "protected_401_403", "sso_protected",
        }:
            continue
        try:
            path = urlsplit(page.url).path or ""
        except ValueError:
            continue
        root = normalize_path_word(path)
        if not root or _path_has_static_extension(root):
            continue
        if len(root.split("/")) > 3 or root in roots:
            continue
        roots.append(root)
        if len(roots) >= max(int(max_roots or 0), 0):
            break

    result = []
    for root in roots:
        root_tail = root.rstrip("/").rsplit("/", 1)[-1].lower()
        for child in children:
            if child.lower() == root_tail:
                continue
            word = normalize_path_word("{}/{}".format(root, child))
            if not word or word == root or word in parent_map:
                continue
            parent_map[word] = root
            result.append(word)
            if len(result) >= max(int(max_words or 0), 0):
                return result, parent_map
    return result, parent_map
