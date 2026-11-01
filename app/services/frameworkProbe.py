import json
import os
import concurrent.futures
from urllib.parse import urljoin, urlparse

from app import utils
from app.config import Config, basedir

logger = utils.get_logger()

FRAMEWORK_PATHS_FILE = os.path.join(basedir, 'dicts/framework_paths.json')

DEFAULT_SITE_LIMIT = 200
DEFAULT_PATHS_PER_SITE = 14
PROBE_CONCURRENCY = 20
PROBE_TIMEOUT = (5, 8)
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)


def load_framework_map():
    try:
        with open(FRAMEWORK_PATHS_FILE) as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except (OSError, ValueError) as e:
        logger.warning("load framework_paths.json failed: {}".format(e))
    return {}


def match_frameworks(finger_names, framework_map):
    """指纹名 → 命中的探测路径集合。"""
    lower_names = [str(name or "").lower() for name in finger_names]
    paths = set()
    matched_keys = []
    for key, rule in framework_map.items():
        keywords = [str(k).lower() for k in rule.get("finger_keywords") or []]
        if not keywords:
            continue
        if any(keyword in name for name in lower_names for keyword in keywords):
            matched_keys.append(key)
            for path in rule.get("paths") or []:
                paths.add(str(path))
    return sorted(matched_keys), sorted(paths)


def probe_site_paths(site, paths):
    """对单站点探测框架定向路径，返回命中列表。"""
    hits = []
    for path in paths:
        url = urljoin(site if site.endswith("/") else site + "/", path.lstrip("/"))
        try:
            response = utils.http_req(
                url, timeout=PROBE_TIMEOUT, headers={"User-Agent": UA},
                allow_redirects=False)
        except Exception:
            continue
        status = getattr(response, "status_code", 0)
        if status in (0, 404, 410):
            continue
        # 401/403 说明路径存在但需鉴权，同样是有效暴露证据
        title = ""
        try:
            from pyquery import PyQuery as pq
            if "html" in str(response.headers.get("Content-Type", "")):
                title = pq(response.content)("title").text()[:100]
        except Exception:
            pass
        hits.append({
            "url": url,
            "path": path,
            "status_code": status,
            "title": title,
            "content_length": len(response.content or b""),
        })
    return hits


def run_framework_probe(task_id, max_sites=None):
    """框架驱动目录探测：observer_ward 指纹 → 定向路径验证 → fileleak。"""
    framework_map = load_framework_map()
    if not framework_map:
        return {"input_count": 0, "probed_site_count": 0,
                "hit_count": 0, "saved_count": 0}

    max_sites = max_sites or DEFAULT_SITE_LIMIT

    sites = []
    for item in utils.conn_db("site").find(
        {"task_id": task_id, "status": {"$gt": 0}},
        {"_id": 0, "site": 1, "finger": 1},
    ).limit(max_sites * 3):
        site = str(item.get("site") or "")
        finger_names = [
            finger.get("name") if isinstance(finger, dict) else str(finger)
            for finger in (item.get("finger") or [])
            if (finger.get("name") if isinstance(finger, dict) else finger)
        ]
        if site and finger_names:
            sites.append((site, finger_names))
        if len(sites) >= max_sites:
            break

    site_paths = []
    for site, finger_names in sites:
        matched_keys, paths = match_frameworks(finger_names, framework_map)
        if paths:
            site_paths.append((site, matched_keys, paths[:DEFAULT_PATHS_PER_SITE]))

    all_hits = []
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=PROBE_CONCURRENCY) as executor:
        futures = {
            executor.submit(probe_site_paths, site, paths): (site, keys)
            for site, keys, paths in site_paths
        }
        for future in concurrent.futures.as_completed(futures):
            site, keys = futures[future]
            try:
                hits = future.result()
            except Exception:
                continue
            for hit in hits:
                hit["site"] = site
                hit["frameworks"] = keys
                all_hits.append(hit)

    saved_count = save_probe_hits(task_id, all_hits)

    summary = {
        "input_count": len(sites),
        "probed_site_count": len(site_paths),
        "hit_count": len(all_hits),
        "saved_count": saved_count,
        "framework_hits": sorted({
            key
            for hit in all_hits
            for key in (hit.get("frameworks") or [])
        }),
    }
    logger.info("framework probe task:{} sites:{} probed:{} hits:{} saved:{}".format(
        task_id, len(sites), len(site_paths), len(all_hits), saved_count))
    return summary


def save_probe_hits(task_id, hits):
    if not hits:
        return 0

    conn = utils.conn_db("fileleak")
    existing = {
        item.get("url")
        for item in conn.find(
            {"task_id": task_id, "scanner": "framework_probe"},
            {"_id": 0, "url": 1})
        if item.get("url")
    }
    now = utils.curr_date()
    docs = []
    for hit in hits:
        if hit["url"] in existing:
            continue
        docs.append({
            "task_id": task_id,
            "site": hit.get("site") or "",
            "url": hit["url"],
            "path": hit.get("path") or "",
            "title": hit.get("title") or "",
            "status_code": hit.get("status_code") or 0,
            "content_length": hit.get("content_length") or 0,
            "content_type": "",
            "scanner": "framework_probe",
            "source": "framework_probe",
            "sources": ["framework_probe"],
            "frameworks": hit.get("frameworks") or [],
            "save_date": now,
            "update_date": now,
        })
    if docs:
        conn.insert_many(docs)
    return len(docs)
