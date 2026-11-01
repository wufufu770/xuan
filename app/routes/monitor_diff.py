"""监控资产 diff 历史查询：列表（含计数摘要）与详情。"""

from bson import ObjectId
from flask import request
from flask_restx import Namespace

from app import utils
from app.utils import auth
from . import ARLResource

ns = Namespace('monitor_diff', description="监控资产变化历史")

DIFF_STORE_ITEMS = 200


def _summarize(doc):
    """diff 文档 -> 列表摘要（只保留计数与截断明细）。"""
    diff = doc.get("diff") or {}
    summary = {}
    for key in ("domains", "ports", "sites", "titles", "certs", "apps"):
        section = diff.get(key) or {}
        summary[key] = {
            "added_total": section.get("added_total", 0),
            "removed_total": section.get("removed_total", 0),
            "changed_total": section.get("changed_total", 0),
        }
        if key == "certs":
            summary[key]["expiring_total"] = section.get("expiring_total", 0)
    return {
        "_id": str(doc["_id"]),
        "job_id": doc.get("job_id"),
        "scope_id": doc.get("scope_id"),
        "source": doc.get("source"),
        "target": doc.get("target"),
        "run_date": doc.get("run_date"),
        "run_number": doc.get("run_number"),
        "summary": summary,
    }


@ns.route('/list/')
class MonitorDiffList(ARLResource):
    @auth
    def get(self):
        """变化历史列表（?job_id= / ?scope_id= / ?limit=，默认 50 上限 200）"""
        query = {}
        job_id = str(request.args.get("job_id") or "").strip()
        scope_id = str(request.args.get("scope_id") or "").strip()
        if job_id:
            query["job_id"] = job_id
        if scope_id:
            query["scope_id"] = scope_id
        try:
            limit = min(max(int(request.args.get("limit") or 50), 1), 200)
        except (TypeError, ValueError):
            limit = 50

        items = []
        for doc in utils.conn_db("monitor_diff").find(query).sort("_id", -1).limit(limit):
            items.append(_summarize(doc))
        return {"code": 200, "message": "success",
                "data": {"items": items, "total": len(items)}}


@ns.route('/detail/')
class MonitorDiffDetail(ARLResource):
    @auth
    def get(self):
        """单条变化明细（?diff_id=，含截断后的增删清单）"""
        diff_id = str(request.args.get("diff_id") or "").strip()
        if not diff_id or not ObjectId.is_valid(diff_id):
            return {"code": 400, "message": "diff_id 非法", "data": {}}
        doc = utils.conn_db("monitor_diff").find_one({"_id": ObjectId(diff_id)})
        if not doc:
            return {"code": 404, "message": "未找到", "data": {}}
        doc["_id"] = str(doc["_id"])
        return {"code": 200, "message": "success", "data": {"diff": doc}}
