import concurrent.futures
import re
from urllib.parse import urljoin, urlparse

from app import utils
from app.config import Config

logger = utils.get_logger()

JS_URL_QUERY_LIMIT = 3000
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)

# webpack 产物特征
WEBPACK_CONTENT_MARKERS = (
    "webpackChunk", "__webpack_require__", "webpackJsonp",
    "self.webpackChunk", "window.webpackJsonp",
)
CHUNK_NAME_RE = re.compile(r"(?:chunk|bundle|vendor|app|main)[\w.\-]*\.js", re.I)

# 从 JS 内容中提取同源 JS 引用
SAME_ORIGIN_JS_RE = re.compile(
    r"[\"']([^\"']{1,300}?\.js)(?:\?[^\"']{0,200})?[\"']", re.I)

STATIC_SKIP_RE = re.compile(
    r"\.(jpg|jpeg|png|gif|css|ico|svg|woff2?|ttf|eot|map)(\?|$)", re.I)

# 内置敏感信息规则（WIH 之外的兜底层）
SENSITIVE_RULES = [
    ("access_key", re.compile(
        r"(?:LTAI[\w]{10,30}|AKID[\w]{10,40}|AKIA[0-9A-Z]{16})")),
    ("api_key", re.compile(
        r"(?:api[_-]?key|apikey|app[_-]?key|appkey|secret[_-]?key)"
        r"[\"']?\s*[:=]\s*[\"']([\w\-]{16,64})[\"']", re.I)),
    ("secret", re.compile(
        r"(?:secret|token|passwd|password)[\"']?\s*[:=]\s*[\"']"
        r"([^\"'\s]{8,64})[\"']", re.I)),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}")),
    ("internal_url", re.compile(
        r"https?://(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])"
        r"\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|"
        r"[\w\-]+\.(?:internal|local|intranet|corp|lan))(?::\d+)?[^\s\"'<>]*")),
    ("internal_ip", re.compile(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])"
        r"\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b")),
    ("db_conn", re.compile(
        r"(?:jdbc:[\w]+://[^\s\"'<>]{5,120}|"
        r"(?:mongodb|redis|mysql|postgres|amqp)://[^\s\"'<>@]{3,60}"
        r":?[^\s\"'<>@]{0,60}@[^\s\"'<>]{3,100})")),
]


def is_webpack_bundle(content):
    return any(marker in content for marker in WEBPACK_CONTENT_MARKERS)


def extract_same_origin_js(page_url, content, base_domain):
    refs = set()
    for ref in SAME_ORIGIN_JS_RE.findall(content or ""):
        ref = ref.strip()
        if not ref or ref.startswith(("data:", "blob:")):
            continue
        absolute = urljoin(page_url, ref)
        try:
            host = (urlparse(absolute).hostname or "").lower()
        except ValueError:
            continue
        if not host:
            continue
        if host != base_domain and not host.endswith("." + base_domain):
            continue
        if STATIC_SKIP_RE.search(absolute):
            continue
        refs.add(absolute)
    return refs


def _download_js(url):
    try:
        response = utils.http_req(
            url, timeout=(6, 12), headers={"User-Agent": USER_AGENT})
        content = response.content
        if len(content) > int(getattr(Config, "JS_DEEP_MAX_FILE_BYTES", 2097152)):
            content = content[:int(
                getattr(Config, "JS_DEEP_MAX_FILE_BYTES", 2097152))]
        return url, content.decode("utf-8", errors="replace")
    except Exception:
        return url, ""


def collect_js_urls(task_id, base_domain, max_files=None):
    """从 url 集合收集目标域 JS 资源。"""
    max_files = max_files or int(
        getattr(Config, "JS_DEEP_MAX_FILES", 150) or 150)
    pattern = re.compile(r"\.js(\?|$)", re.I)

    urls = []
    suffix = "." + base_domain
    cursor = utils.conn_db("url").find(
        {"task_id": task_id, "url": {"$regex": r"\.js(\?|$)"}},
        {"_id": 0, "url": 1},
    ).limit(JS_URL_QUERY_LIMIT)
    for item in cursor:
        url = str(item.get("url") or "")
        if not url or STATIC_SKIP_RE.search(url):
            continue
        try:
            host = (urlparse(url).hostname or "").lower()
        except ValueError:
            continue
        if host and (host == base_domain or host.endswith(suffix)):
            urls.append(url)

    # 去重 + 排序保证断点重跑稳定
    urls = sorted(set(urls))
    return urls[:max_files]


def run_js_deep(task_id, base_domain, ai_enabled_fn=None):
    """JS 深度分析：
    1) 收集已发现的 JS URL 并下载
    2) webpack chunk 识别 → 递归拉取同源 chunk 引用
    3) 规则提取敏感信息 → wih 集合（source=js_deep）
    4) AI 兜底提取（可选，依赖 AI 配置）
    """
    recursion_depth = max(int(
        getattr(Config, "JS_DEEP_CHUNK_RECURSION", 1) or 1), 0)
    concurrency = max(int(
        getattr(Config, "JS_DEEP_CONCURRENCY", 8) or 8), 1)
    ai_max_files = int(getattr(Config, "JS_DEEP_AI_MAX_FILES", 10) or 10)

    visited = set()
    pending = collect_js_urls(task_id, base_domain)
    input_count = len(pending)
    webpack_count = 0
    findings = []
    analyzed_files = []

    for depth in range(recursion_depth + 1):
        if not pending:
            break
        batch = [url for url in pending if url not in visited][:200]
        for url in batch:
            visited.add(url)
        if not batch:
            break

        with concurrent.futures.ThreadPoolExecutor(
                max_workers=concurrency) as executor:
            for url, content in executor.map(_download_js, batch):
                if not content:
                    continue
                analyzed_files.append(url)
                if is_webpack_bundle(content):
                    webpack_count += 1

                for record_type, match in extract_sensitive(content):
                    findings.append(_build_record(
                        task_id, base_domain, url, record_type, match))

                if depth < recursion_depth:
                    refs = extract_same_origin_js(url, content, base_domain)
                    pending.extend(
                        ref for ref in refs if ref not in visited)

        pending = [url for url in pending if url not in visited]

    # AI 兜底：优先分析命中规则的文件，其次抽样
    ai_findings = []
    if ai_enabled_fn and ai_enabled_fn() and analyzed_files:
        content_cache = {}
        priority_urls = sorted({
            record["source_url"] for record in findings
            if record.get("source_url")
        })[:ai_max_files]
        if len(priority_urls) < ai_max_files:
            for url in analyzed_files:
                if len(priority_urls) >= ai_max_files:
                    break
                if url not in priority_urls:
                    priority_urls.append(url)

        for url in priority_urls:
            _, content = _download_js(url)
            if not content or len(content) < 200:
                continue
            content_cache[url] = content
        if content_cache:
            from app.services.ai_judge import ai_extract_sensitive

            for url, content in content_cache.items():
                for record in ai_extract_sensitive(content, source=url):
                    findings.append(_build_record(
                        task_id, base_domain, url,
                        record["record_type"], record["content"],
                        extractor="ai"))

    saved_count = save_js_findings(task_id, findings)

    summary = {
        "input_count": input_count,
        "analyzed_file_count": len(analyzed_files),
        "webpack_bundle_count": webpack_count,
        "finding_count": len(findings),
        "saved_count": saved_count,
        "analyzed_urls": analyzed_files[:30],
    }
    logger.info("js deep {} analyzed:{} webpack:{} findings:{} saved:{}".format(
        base_domain, len(analyzed_files), webpack_count, len(findings),
        saved_count))
    return summary


def extract_sensitive(content):
    results = []
    seen = set()
    for record_type, pattern in SENSITIVE_RULES:
        for match in pattern.finditer(content or ""):
            value = (match.group(1) if match.groups() else match.group(0))
            value = str(value or "").strip()
            if not value or len(value) < 6:
                continue
            dedupe_key = (record_type, value)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            results.append((record_type, value))
            if len(results) >= 100:
                return results
    return results


def _build_record(task_id, base_domain, url, record_type, content,
                  extractor="rule"):
    import hashlib

    fnv_hash = hashlib.md5(
        "{}|{}|{}".format(task_id, record_type, content).encode("utf-8")
    ).hexdigest()
    return {
        "task_id": task_id,
        "record_type": record_type,
        "content": str(content)[:500],
        "site": url,
        "source": "js_deep",
        "source_url": url,
        "extractor": extractor,
        "base_domain": base_domain,
        "fnv_hash": str(fnv_hash),
        "collector": "js_deep",
    }


def save_js_findings(task_id, findings):
    if not findings:
        return 0

    conn = utils.conn_db("wih")
    existing = {
        str(item.get("fnv_hash"))
        for item in conn.find(
            {"task_id": task_id, "source": "js_deep"},
            {"_id": 0, "fnv_hash": 1})
        if item.get("fnv_hash")
    }
    now = utils.curr_date()
    docs = []
    seen = set()
    for record in findings:
        fnv = str(record.get("fnv_hash") or "")
        if fnv in existing or fnv in seen:
            continue
        seen.add(fnv)
        doc = dict(record)
        doc["save_date"] = now
        doc["update_date"] = now
        docs.append(doc)

    if docs:
        conn.insert_many(docs)
    return len(docs)
