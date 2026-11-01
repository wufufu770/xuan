"""报告中心：资产组风险报告（xlsx + 可选 LLM 执行摘要）。

- xlsx：域名/IP/站点/漏洞四个 sheet（openpyxl，复用既有依赖）
- LLM 摘要：复用 ai_judge 多供应商通道；未启用或失败时报告照常产出
- 异步 job：report_job 集合记录进度（与 fengniao collect 同模式），
  规避 gunicorn sync worker 30s 超时
- 落盘：Config.REPORT_ROOT（默认 /opt/ARL/data/reports）
"""

import os
import threading
import time

from threading import BoundedSemaphore

from app import utils
from app.config import Config

logger = utils.get_logger()

JOB_COLLECTION = "report_job"
REPORT_COLLECTION = "report"
REPORT_SEMAPHORE = BoundedSemaphore(2)

_SHEET_MAX_ROWS = 20000


def report_root():
    return str(getattr(Config, "REPORT_ROOT", "") or "/opt/ARL/data/reports")


def _safe_name(text):
    return "".join(c for c in str(text or "report") if c.isalnum() or c in "-_")[:64] or "report"


def collect_scope_data(scope_id):
    """聚合资产组四类数据（各 sheet 上限 _SHEET_MAX_ROWS）。"""
    conn = utils.conn_db
    task_ids = []
    for item in conn("task").find({"scope_id": scope_id}, {"_id": 1}):
        task_ids.append(str(item["_id"]))

    def _query(task_field):
        if task_ids:
            return {"$or": [{"scope_id": scope_id}, {task_field: {"$in": task_ids}}]}
        return {"scope_id": scope_id}

    domains = list(conn("domain").find(
        _query("task_id"), {"domain": 1, "resolve_status": 1, "source": 1}
    ).limit(_SHEET_MAX_ROWS))
    ips = list(conn("ip").find(
        _query("task_id"), {"ip": 1, "port_info": 1, "os": 1}
    ).limit(_SHEET_MAX_ROWS))
    sites = list(conn("site").find(
        _query("task_id"),
        {"site": 1, "title": 1, "status": 1, "finger": 1}
    ).limit(_SHEET_MAX_ROWS))
    vulns = list(conn("vulnerability").find(
        _query("task_id"), {"vul_name": 1, "severity": 1, "url": 1, "detail": 1}
    ).limit(_SHEET_MAX_ROWS))
    nuclei_vulns = list(conn("nuclei_vul").find(
        _query("task_id"), {"vul_name": 1, "severity": 1, "url": 1}
    ).limit(_SHEET_MAX_ROWS))
    vulns.extend(nuclei_vulns)
    return {"domains": domains, "ips": ips, "sites": sites, "vulns": vulns}


def build_xlsx(data, path):
    """生成 xlsx 报告文件；返回行数统计 dict。"""
    from openpyxl import Workbook

    wb = Workbook()
    counts = {}

    def _fill(ws_title, headers, rows):
        ws = wb.create_sheet(ws_title)
        ws.append(headers)
        for row in rows[:_SHEET_MAX_ROWS]:
            ws.append([str(item) if item is not None else "" for item in row])
        counts[ws_title] = min(len(rows), _SHEET_MAX_ROWS)

    _fill("域名", ["域名", "解析状态", "来源"],
          [[d.get("domain"), d.get("resolve_status", ""), d.get("source", "")]
           for d in data["domains"]])
    _fill("IP", ["IP", "端口", "系统"],
          [[i.get("ip"),
            ",".join(str(p.get("port_id")) for p in i.get("port_info") or []),
            i.get("os", "")] for i in data["ips"]])
    _fill("站点", ["站点", "标题", "状态码", "指纹"],
          [[s.get("site"), s.get("title", ""), s.get("status", ""),
            ",".join(f.get("name", "") if isinstance(f, dict) else str(f)
                     for f in s.get("finger") or [])] for s in data["sites"]])
    _fill("漏洞", ["漏洞名", "严重程度", "URL"],
          [[v.get("vul_name"), v.get("severity", ""), v.get("url", "")]
           for v in data["vulns"]])

    del wb["Sheet"]
    os.makedirs(os.path.dirname(path), exist_ok=True)
    wb.save(path)
    return counts


def build_summary_stats(data):
    """给 LLM 的结构化统计（不含明细，控 token）。"""
    severities = {}
    for v in data["vulns"]:
        sev = str(v.get("severity") or "unknown")
        severities[sev] = severities.get(sev, 0) + 1
    fingers = {}
    for s in data["sites"]:
        for f in s.get("finger") or []:
            name = f.get("name") if isinstance(f, dict) else str(f)
            if name:
                fingers[name] = fingers.get(name, 0) + 1
    top_fingers = sorted(fingers.items(), key=lambda x: -x[1])[:15]
    return {
        "domains": len(data["domains"]),
        "ips": len(data["ips"]),
        "sites": len(data["sites"]),
        "vulns": len(data["vulns"]),
        "vuln_by_severity": severities,
        "top_fingerprints": top_fingers,
    }


def llm_summary(stats):
    """LLM 执行摘要；未启用/失败返回空串（不阻塞报告）。"""
    try:
        from app.services.ai_judge import ai_enabled, ai_chat
        if not ai_enabled():
            return ""
        import json
        prompt = (
            "以下是资产测绘任务的统计 JSON，请用中文写 200 字以内的执行摘要，"
            "先总体规模，再按严重程度概括风险，最后给 3 条处置建议：\n"
            + json.dumps(stats, ensure_ascii=False))
        return (ai_chat(prompt) or "").strip()
    except Exception as exc:
        logger.warning("report llm summary failed: %s", exc)
        return ""


def _set_job(job_id, **values):
    values["update_time"] = utils.curr_date()
    utils.conn_db(JOB_COLLECTION).update_one(
        {"_id": job_id}, {"$set": values}, upsert=True)


def run_report_job(job_id, scope_id, scope_name, use_llm=False):
    """线程内执行：聚合 → xlsx → 摘要 → 落 report 集合。"""
    try:
        _set_job(job_id, status="running", progress_done=10,
                 current="collect")
        data = collect_scope_data(scope_id)

        _set_job(job_id, progress_done=40, current="xlsx")
        filename = "{}_{}.xlsx".format(
            _safe_name(scope_name or scope_id),
            time.strftime("%Y%m%d_%H%M%S"))
        path = os.path.join(report_root(), filename)
        counts = build_xlsx(data, path)

        summary_md = ""
        if use_llm:
            _set_job(job_id, progress_done=70, current="llm_summary")
            summary_md = llm_summary(build_summary_stats(data))

        report_doc = {
            "scope_id": scope_id,
            "scope_name": scope_name or scope_id,
            "filename": filename,
            "path": path,
            "size": os.path.getsize(path),
            "counts": counts,
            "summary": summary_md,
            "llm_used": bool(summary_md),
            "create_date": utils.curr_date(),
            "create_ts": time.time(),
        }
        report_id = utils.conn_db(REPORT_COLLECTION).insert_one(report_doc).inserted_id
        _set_job(job_id, status="done", progress_done=100,
                 report_id=str(report_id), current="done")
        logger.info("report done scope={} file={}".format(scope_id, filename))
    except Exception as exc:
        logger.exception(exc)
        _set_job(job_id, status="error", error=str(exc), current="error")


_jobs_sem = REPORT_SEMAPHORE


def submit_report_job(scope_id, scope_name="", use_llm=False):
    """投递报告生成 job，返回 job_id。"""
    from bson import ObjectId
    job_id = ObjectId()
    utils.conn_db(JOB_COLLECTION).insert_one({
        "_id": job_id, "scope_id": scope_id, "scope_name": scope_name or scope_id,
        "use_llm": bool(use_llm), "status": "waiting",
        "progress_done": 0, "current": "waiting",
        "create_time": utils.curr_date(),
    })

    def worker():
        with _jobs_sem:
            run_report_job(job_id, scope_id, scope_name, use_llm)

    threading.Thread(target=worker, daemon=True).start()
    return str(job_id)


def get_job(job_id):
    from bson import ObjectId
    try:
        return utils.conn_db(JOB_COLLECTION).find_one({"_id": ObjectId(job_id)})
    except Exception:
        return None


def get_report(report_id):
    from bson import ObjectId
    try:
        return utils.conn_db(REPORT_COLLECTION).find_one({"_id": ObjectId(report_id)})
    except Exception:
        return None
