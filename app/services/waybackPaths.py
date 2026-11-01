import re
from urllib.parse import urlparse

from app import utils
from app.config import Config

logger = utils.get_logger()

CDX_BASE_URL = "http://web.archive.org/cdx/search/cdx"

DEFAULT_TIMEOUT = 30
DEFAULT_MAX_RESULTS = 5000
DEFAULT_MAX_PATHS = 500

# 历史快照里的静态资源对资产面没有价值，直接过滤
STATIC_EXTENSIONS = (
    ".jpg", ".jpeg", ".png", ".gif", ".css", ".ico", ".svg", ".woff",
    ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".avi", ".wmv", ".flv",
    ".js.map", ".pdf", ".zip", ".rar", ".gz", ".7z", ".exe", ".dmg",
    ".bmp", ".webp", ".tiff", ".xls", ".xlsx", ".doc", ".docx", ".ppt",
)

WAYBACK_HOST_COLLECTION = "wayback_host"


def _fetch_cdx_urls(host_pattern, timeout, max_results):
    url = (
        "{base}?url={pattern}&output=json&fl=original,timestamp,statuscode"
        "&collapse=urlkey&limit={limit}".format(
            base=CDX_BASE_URL, pattern=host_pattern, limit=max(max_results, 1))
    )
    try:
        response = utils.http_req(url, timeout=(timeout, timeout + 20))
        rows = response.json()
    except Exception as e:
        logger.warning("wayback cdx request failed {}: {}".format(
            host_pattern, e))
        return []

    if not isinstance(rows, list) or len(rows) < 2:
        return []

    entries = []
    for row in rows[1:]:
        if not isinstance(row, (list, tuple)) or not row:
            continue
        entries.append({
            "url": str(row[0] or ""),
            "timestamp": str(row[1] if len(row) > 1 else ""),
            "statuscode": str(row[2] if len(row) > 2 else ""),
        })
    return entries


def _is_static_path(path):
    lower = path.lower()
    return any(lower.endswith(ext) for ext in STATIC_EXTENSIONS)


def normalize_history_url(raw_url, base_domain):
    """校验 URL 属于目标域并拆出 host/path，非目标域返回 None。"""
    raw_url = str(raw_url or "").strip()
    if not raw_url:
        return None
    if "://" not in raw_url:
        raw_url = "http://" + raw_url

    parsed = urlparse(raw_url)
    host = (parsed.hostname or "").strip(".").lower()
    if not host:
        return None
    if host != base_domain and not host.endswith("." + base_domain):
        return None

    path = parsed.path or "/"
    if parsed.query:
        path = path + "?" + parsed.query
    return {"host": host, "path": path, "url": raw_url}


def collect_wayback_paths(task_id, base_domain, max_results=None,
                          max_paths=None, timeout=None):
    """拉取目标根域的历史 URL，写入 fileleak(source=wayback) 与 wayback_host。

    返回 summary dict 供 task_stage 使用。
    """
    timeout = timeout or DEFAULT_TIMEOUT
    max_results = max_results or DEFAULT_MAX_RESULTS
    max_paths = max_paths or DEFAULT_MAX_PATHS

    entries = _fetch_cdx_urls("*." + base_domain, timeout, max_results)

    host_history = {}
    path_records = {}
    for entry in entries:
        normalized = normalize_history_url(entry["url"], base_domain)
        if not normalized:
            continue
        host_history.setdefault(normalized["host"], 0)
        host_history[normalized["host"]] += 1

        path = normalized["path"]
        if path in ("/", "") or _is_static_path(path):
            continue

        dedupe_key = normalized["host"] + path
        if dedupe_key in path_records:
            continue
        path_records[dedupe_key] = {
            "host": normalized["host"],
            "path": path.split("?")[0],
            "url": normalized["url"],
            "timestamp": entry["timestamp"],
            "statuscode": entry["statuscode"],
        }

        if len(path_records) >= max_paths:
            break

    now = utils.curr_date()
    saved_path_count = _save_path_records(task_id, base_domain, path_records, now)
    host_count = _save_host_history(task_id, base_domain, host_history, now)

    summary = {
        "input_count": len(entries),
        "history_host_count": len(host_history),
        "history_path_count": len(path_records),
        "saved_path_count": saved_path_count,
        "saved_host_count": host_count,
    }
    logger.info("wayback backtrack {} entries:{} hosts:{} paths:{} saved:{}".format(
        base_domain, len(entries), len(host_history), len(path_records),
        saved_path_count))
    return summary


def _save_path_records(task_id, base_domain, path_records, now):
    if not path_records:
        return 0

    conn = utils.conn_db("fileleak")
    existing = set()
    for item in conn.find(
        {"task_id": task_id, "scanner": "wayback"},
        {"_id": 0, "url": 1},
    ):
        if item.get("url"):
            existing.add(item["url"])

    operations = []
    for record in path_records.values():
        if record["url"] in existing:
            continue
        operations.append({
            "task_id": task_id,
            "site": record["host"],
            "url": record["url"],
            "path": record["path"],
            "title": "",
            "status_code": 0,
            "content_length": 0,
            "content_type": "",
            "scanner": "wayback",
            "source": "wayback",
            "sources": ["wayback"],
            "wayback_timestamp": record["timestamp"],
            "wayback_statuscode": record["statuscode"],
            "base_domain": base_domain,
            "save_date": now,
            "update_date": now,
        })

    if operations:
        conn.insert_many(operations)
    return len(operations)


def _save_host_history(task_id, base_domain, host_history, now):
    if not host_history:
        return 0

    conn = utils.conn_db(WAYBACK_HOST_COLLECTION)
    existing = {
        item.get("host")
        for item in conn.find(
            {"task_id": task_id}, {"_id": 0, "host": 1})
        if item.get("host")
    }
    operations = []
    for host, url_count in host_history.items():
        if host in existing:
            continue
        operations.append({
            "task_id": task_id,
            "base_domain": base_domain,
            "host": host,
            "history_url_count": url_count,
            "source": "wayback",
            "save_date": now,
        })
    if operations:
        conn.insert_many(operations)
    return len(operations)


def wayback_documented_hosts(task_id):
    """返回该任务中有 wayback 历史记录的主机集合（影子资产判定用）。"""
    return {
        item.get("host")
        for item in utils.conn_db(WAYBACK_HOST_COLLECTION).find(
            {"task_id": task_id}, {"_id": 0, "host": 1})
        if item.get("host")
    }
