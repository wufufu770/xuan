# -*- coding:UTF-8 -*-
"""APP 商店链接解析与 APK 本地下载（应用宝 + iTunes，2026-10-28 实测链路）。

Android 链路（全部实测可用）：
  名称搜索   GET https://sj.qq.com/search?q=<kw>（SSR 页含 appdetail/<pkg> 链接）
  详情+直链  GET https://a.app.qq.com/o/simple.jsp?pkgname=<pkg>（必须移动 UA）
             页面 JSON appDetail 含 developer/appName/versionName/apkUrl/apkUrl64/
             fileSize/apkMd5；developer 与凤鸟公司名比对 = 防假冒核心校验
  APK 下载   apkUrl 302 -> 腾讯 CDN，application/vnd.android.package-archive

iOS 链路：
  GET https://itunes.apple.com/search?term=<kw>&country=cn&entity=software&limit=5
  官方 API；sellerName 多为英文，改用 bundleId 与 Android 包名厂商前缀交叉印证。

缓存：app_store_cache 集合（TTL 7 天，按 appname+ent_name 键）。
限速：商店请求间隔 >=0.6s，单次解析最多探测 6 个候选包。
可信度：confirmed（开发商匹配）/ high（名称精确）/ suspected（名称包含）/ none。
"""
import hashlib
import json
import os
import re
import time

import requests

from app import utils

logger = utils.get_logger()

UA_DESKTOP = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
UA_MOBILE = ("Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36")

QQ_SEARCH = "https://sj.qq.com/search?q={}"
QQ_DETAIL = "https://a.app.qq.com/o/simple.jsp?pkgname={}"
QQ_WEB = "https://sj.qq.com/appdetail/{}"
ITUNES_SEARCH = ("https://itunes.apple.com/search?term={}&country=cn"
                 "&entity=software&limit={}")

CACHE_COLLECTION = "app_store_cache"
CACHE_TTL_SECONDS = 7 * 86400
MAX_CANDIDATES = 4
REQUEST_INTERVAL = 0.6
REQUEST_TIMEOUT = 30

APK_DIR = "/opt/ARL/data/app_download"
MAX_FILE_MB = 600
TOTAL_QUOTA_GB = 20

_last_request = [0.0]


def _throttle():
    now = time.time()
    wait = REQUEST_INTERVAL - (now - _last_request[0])
    if wait > 0:
        time.sleep(wait)
    _last_request[0] = time.time()


def _http_get(url, mobile=False, **kwargs):
    _throttle()
    headers = kwargs.pop("headers", {})
    headers["User-Agent"] = UA_MOBILE if mobile else UA_DESKTOP
    return requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT, **kwargs)


def _vendor_prefix(pkg):
    parts = [p for p in str(pkg or "").split(".") if p]
    return ".".join(parts[:2]) if len(parts) >= 2 else str(pkg or "")


def _norm_name(name):
    """去掉营销名里的分隔符尾巴，用于宽松比对。"""
    text = str(name or "").strip().lower()
    return re.split(r"[-–—|·\s]+", text)[0] if text else ""


# ---------------------------------------------------------------- cache ----
def _cache_get(app_name, ent_name):
    doc = utils.conn_db(CACHE_COLLECTION).find_one({
        "app_name": str(app_name), "ent_name": str(ent_name or "")})
    if not doc:
        return None
    if time.time() - float(doc.get("ts") or 0) > CACHE_TTL_SECONDS:
        return None
    return doc.get("result")


def _cache_put(app_name, ent_name, result):
    utils.conn_db(CACHE_COLLECTION).update_one(
        {"app_name": str(app_name), "ent_name": str(ent_name or "")},
        {"$set": {"result": result, "ts": time.time(),
                  "save_date": utils.curr_date()}},
        upsert=True)


# ---------------------------------------------------------------- android --
def qq_search(app_name):
    """应用宝搜索页 -> [(pkg, 页面内展示名)]，按页面出现顺序（相关性优先）。"""
    try:
        resp = _http_get(QQ_SEARCH.format(requests.utils.quote(app_name)))
        if resp.status_code != 200:
            return []
        pkgs, seen = [], set()
        for pkg in re.findall(r"appdetail/([a-zA-Z0-9._]+)", resp.text):
            if pkg not in seen:
                seen.add(pkg)
                pkgs.append(pkg)
        return pkgs
    except Exception as exc:
        logger.warning("appdl qq_search failed: %s", exc)
        return []


def qq_detail(pkg):
    """移动 UA 中转页 -> appDetail JSON（含 apkUrl/developer/versionName/fileSize/md5）。"""
    try:
        resp = _http_get(QQ_DETAIL.format(pkg), mobile=True)
        if resp.status_code != 200:
            return None
        m = re.search(r'"appDetail"\s*:\s*(\{.*?"flag"\s*:\s*\{.*?\}.*?\})\s*[,}]',
                      resp.text, re.S)
        raw = None
        if m:
            try:
                raw = json.loads(m.group(1))
            except ValueError:
                raw = None
        if not raw:
            i = resp.text.find('"appDetail"')
            j = resp.text.find('"apkUrl"', i)
            if i != -1 and j != -1:
                seg = resp.text[i:j + 400]
                apk = re.search(r'"apkUrl"\s*:\s*"([^"]+)"', seg)
                apk64 = re.search(r'"apkUrl64"\s*:\s*"([^"]+)"', seg)
                name = re.search(r'"appName"\s*:\s*"([^"]+)"', seg)
                dev = re.search(r'"developer"\s*:\s*"([^"]+)"', seg)
                if apk:
                    return {"packageName": pkg, "appName": name and name.group(1),
                            "developer": dev and dev.group(1),
                            "apkUrl": apk.group(1),
                            "apkUrl64": apk64 and apk64.group(1)}
        return raw
    except Exception as exc:
        logger.warning("appdl qq_detail %s failed: %s", pkg, exc)
        return None


def _score_android(detail, app_name, company_names):
    """给候选包打分：开发商匹配 > 名称精确 > 名称包含。返回 (score, reason)。"""
    name = str(detail.get("appName") or "")
    dev = str(detail.get("developer") or "")
    author = str(detail.get("author") or "")
    target = str(app_name or "").strip()
    if dev and dev in company_names:
        return 100, "developer:" + dev
    if author and author in company_names:
        return 95, "author:" + author
    if name == target:
        return 80, "name_exact"
    if _norm_name(name) == _norm_name(target):
        return 70, "name_norm"
    if target and (target in name or name in target):
        return 40, "name_contains"
    return 0, ""


def resolve_android(app_name, company_names):
    """名称 -> 应用宝包。返回 {pkg, detail_url, apk_url, ...} 或 None。"""
    pkgs = qq_search(app_name)
    best, best_score, best_reason = None, 0, ""
    for pkg in pkgs[:MAX_CANDIDATES]:
        detail = qq_detail(pkg)
        if not detail or not detail.get("apkUrl"):
            continue
        score, reason = _score_android(detail, app_name, company_names)
        if score > best_score:
            best, best_score, best_reason = detail, score, reason
        if score >= 95:
            break
    if not best:
        return None
    size_info = best.get("fileSize") or {}
    return {
        "pkg": best.get("packageName"),
        "detail_url": QQ_WEB.format(best.get("packageName")),
        "apk_url": best.get("apkUrl"),
        "apk_url64": best.get("apkUrl64") or best.get("apkUrl"),
        "version": best.get("versionName", ""),
        "size_bytes": int(size_info.get("bytes") or 0),
        "size_text": size_info.get("desc", ""),
        "developer": best.get("developer", ""),
        "md5": str(best.get("apkMd5") or "").lower(),
        "score": best_score,
        "matched_by": best_reason,
    }


# -------------------------------------------------------------------- ios --
def itunes_search(app_name, limit=5):
    try:
        resp = _http_get(ITUNES_SEARCH.format(requests.utils.quote(app_name), limit))
        if resp.status_code != 200:
            return []
        return resp.json().get("results") or []
    except Exception as exc:
        logger.warning("appdl itunes failed: %s", exc)
        return []


def resolve_ios(app_name, android_pkg=None):
    """名称 -> App Store 条目；android_pkg 厂商前缀一致则升为确认。"""
    results = itunes_search(app_name)
    if not results:
        return None
    target = str(app_name or "").strip()
    scored = []
    for r in results:
        track = str(r.get("trackName") or "")
        score = 0
        if track == target:
            score = 80
        elif _norm_name(track) == _norm_name(target):
            score = 70
        elif target and (target in track or track in target):
            score = 40
        if android_pkg and _vendor_prefix(r.get("bundleId")) == _vendor_prefix(android_pkg):
            score += 30
        scored.append((score, r))
    scored.sort(key=lambda x: -x[0])
    score, best = scored[0]
    if score <= 0:
        return None
    return {
        "track_url": best.get("trackViewUrl", ""),
        "bundle_id": best.get("bundleId", ""),
        "track_name": best.get("trackName", ""),
        "seller": best.get("sellerName", ""),
        "version": best.get("version", ""),
        "score": score,
    }


# ----------------------------------------------------------------- enrich --
def _confidence(android, ios):
    score = max((android or {}).get("score") or 0, (ios or {}).get("score") or 0)
    if score >= 95:
        return "confirmed"
    if score >= 70:
        return "high"
    if score >= 40:
        return "suspected"
    return "none"


def enrich_app(app_row, ent_name, group_companies=None):
    """单个 app 的完整解析（带缓存）。app_row 是 fengniao_intel.app 数组元素。"""
    app_name = str(app_row.get("appname") or app_row.get("name") or "").strip()
    if not app_name:
        return {"confidence": "none", "reason": "empty_name"}
    cached = _cache_get(app_name, ent_name)
    if cached:
        return cached

    company_names = {str(ent_name or "")}
    for name in (group_companies or []):
        if name:
            company_names.add(str(name))

    android = resolve_android(app_name, company_names)
    ios = resolve_ios(app_name, android_pkg=(android or {}).get("pkg"))
    result = {
        "android": android,
        "ios": ios,
        "confidence": _confidence(android, ios),
        "checked_date": utils.curr_date(),
    }
    _cache_put(app_name, ent_name, result)
    return result


# --------------------------------------------------------------- download --
def _dir_size_mb(path):
    total = 0
    for root, _, files in os.walk(path):
        for fn in files:
            try:
                total += os.path.getsize(os.path.join(root, fn))
            except OSError:
                pass
    return total / 1048576.0


def download_apk(apk_url, dest_path, expected_md5="", max_mb=MAX_FILE_MB,
                 on_progress=None):
    """流式下载 APK 到 dest_path，校验大小与 MD5。返回 metadata dict 或抛异常。

    MD5 优先取 URL 文件名内嵌的哈希（应用宝 CDN 命名即 <md5>.apk，
    对应所下载文件本身；接口的 apkMd5 字段只随 32 位包）。
    """
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    tmp_path = dest_path + ".part"
    m = re.search(r"/([0-9a-fA-F]{32})\.apk", apk_url)
    verify_md5 = m.group(1).lower() if m else (expected_md5 or "").lower()
    _throttle()
    resp = requests.get(apk_url, headers={"User-Agent": UA_MOBILE},
                        timeout=(20, 120), stream=True)
    if resp.status_code not in (200, 206):
        raise RuntimeError("APK 下载 HTTP {}".format(resp.status_code))

    total = int(resp.headers.get("Content-Length") or 0)
    if total and total > max_mb * 1048576:
        raise RuntimeError("APK 超过大小上限 {}MB（实际 {:.0f}MB）".format(
            max_mb, total / 1048576.0))

    md5 = hashlib.md5()
    done = 0
    with open(tmp_path, "wb") as f:
        for chunk in resp.iter_content(chunk_size=262144):
            if not chunk:
                continue
            f.write(chunk)
            md5.update(chunk)
            done += len(chunk)
            if done > max_mb * 1048576:
                f.close()
                os.remove(tmp_path)
                raise RuntimeError("APK 超过大小上限 {}MB".format(max_mb))
            if on_progress and total:
                try:
                    on_progress(done, total)
                except Exception:
                    pass
    digest = md5.hexdigest()
    # MD5 校验必须在落盘（os.replace）之前：不匹配即删除临时文件，
    # 避免坏文件残留在目标路径被当作有效下载
    if verify_md5 and verify_md5 != digest:
        os.remove(tmp_path)
        raise RuntimeError("MD5 校验失败：期望 {} 实际 {}".format(verify_md5, digest))
    os.replace(tmp_path, dest_path)
    return {"size": done, "md5": digest, "md5_verified": bool(verify_md5)}
