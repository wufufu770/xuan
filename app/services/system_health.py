"""平台自身健康指标（可观测性最小版）。

供 stats/summary 的 health 段消费：近期任务成败、活跃 token 数、
凤鸟 token 剩余有效期。所有子查询独立容错，单项失败不影响整体。
"""

import time

from app import utils

RECENT_TASK_SAMPLE = 500


def collect_health():
    conn = utils.conn_db
    health = {}

    # 近期任务成败（按 _id 倒序取样，ObjectId 自带时间序）
    try:
        rows = list(conn("task").aggregate([
            {"$sort": {"_id": -1}}, {"$limit": RECENT_TASK_SAMPLE},
            {"$group": {"_id": {"$ifNull": ["$status", "unknown"]},
                        "n": {"$sum": 1}}}]))
        counts = {r["_id"]: r["n"] for r in rows}
        done = counts.get("done", 0)
        error = counts.get("error", 0)
        settled = done + error
        health["tasks_recent"] = {
            "sample": sum(counts.values()),
            "done": done,
            "error": error,
            "success_rate": round(done / settled, 4) if settled else None,
        }
    except Exception:
        health["tasks_recent"] = {}

    # 活跃登录 token 数
    try:
        health["api_token_active"] = conn("api_token").count_documents(
            {"revoked": {"$ne": True}, "expires_ts": {"$gt": time.time()}})
    except Exception:
        health["api_token_active"] = None

    # 凤鸟 token 剩余有效期（负数=已过期）
    feng = {"configured": False, "expires_ts": 0, "expires_in_hours": None}
    try:
        from app.routes.fengniao import _token_from_yaml
        from app.services.fengniao import token_expire_time
        token = _token_from_yaml()
        feng["configured"] = bool(token)
        expires = token_expire_time(token) if token else 0
        feng["expires_ts"] = expires
        if expires:
            feng["expires_in_hours"] = round((expires - time.time()) / 3600.0, 1)
    except Exception:
        pass
    health["fengniao_token"] = feng

    # 漏洞严重度分布（vulnerability + nuclei_vul 聚合，权威口径）
    sev = {}
    try:
        for coll in ("vulnerability", "nuclei_vul"):
            for row in conn(coll).aggregate([
                    {"$group": {"_id": {"$toLower": {"$ifNull": ["$severity", "unknown"]}},
                                "n": {"$sum": 1}}}]):
                sev[row["_id"]] = sev.get(row["_id"], 0) + row["n"]
    except Exception:
        pass
    health["vuln_by_severity"] = sev

    return health
