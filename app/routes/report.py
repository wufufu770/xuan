"""报告中心 REST：生成（异步 job）/ 进度 / 下载 / 历史列表。"""

import os

from flask import send_file
from flask_restx import fields, Namespace

from app import utils
from app.utils import get_logger, auth
from app.utils.audit import audit
from . import ARLResource
from app.services import report_center

ns = Namespace('report', description="报告中心")

logger = get_logger()


def _ret(data=None, message="success", code=200):
    return {"code": code, "message": message, "data": data or {}}


generate_fields = ns.model('ReportGenerate', {
    'scope_id': fields.String(required=True, description="资产组 ID"),
    'scope_name': fields.String(required=False, description="资产组名"),
    'use_llm': fields.Boolean(default=False, description="生成 LLM 执行摘要"),
})


@ns.route('/generate/')
class ReportGenerate(ARLResource):
    @auth
    @ns.expect(generate_fields)
    def post(self):
        """投递报告生成任务（异步，GET /job/ 轮询进度）"""
        args = self.parse_args(generate_fields)
        scope_id = str(args.get("scope_id") or "").strip()
        if not scope_id:
            return _ret({"error": "scope_id 不能为空"}, message="参数缺失", code=400)
        job_id = report_center.submit_report_job(
            scope_id,
            scope_name=str(args.get("scope_name") or "").strip(),
            use_llm=bool(args.get("use_llm")))
        audit("report_generate", detail={"scope_id": scope_id, "use_llm": bool(args.get("use_llm"))})
        return _ret({"job_id": job_id})


@ns.route('/job/')
class ReportJob(ARLResource):
    @auth
    def get(self):
        """报告生成进度（?job_id=）"""
        from flask import request
        job_id = str(request.args.get("job_id") or "").strip()
        if not job_id:
            return _ret({"error": "job_id 不能为空"}, message="参数缺失", code=400)
        job = report_center.get_job(job_id)
        if not job:
            return _ret({"error": "job 不存在"}, message="未找到", code=404)
        job.pop("_id", None)
        return _ret({"job": job})


@ns.route('/download/')
class ReportDownload(ARLResource):
    @auth
    def get(self):
        """下载报告文件（?report_id=）"""
        from flask import request
        report_id = str(request.args.get("report_id") or "").strip()
        if not report_id:
            return _ret({"error": "report_id 不能为空"}, message="参数缺失", code=400)
        doc = report_center.get_report(report_id)
        if not doc:
            return _ret({"error": "报告不存在"}, message="未找到", code=404)
        path = doc.get("path") or ""
        if not path.startswith(report_center.report_root()) or not os.path.exists(path):
            return _ret({"error": "报告文件缺失"}, message="文件缺失", code=404)
        return send_file(path, as_attachment=True,
                         download_name=doc.get("filename") or "report.xlsx")


@ns.route('/list/')
class ReportList(ARLResource):
    @auth
    def get(self):
        """报告历史列表（?scope_id= 可选）"""
        from flask import request
        scope_id = str(request.args.get("scope_id") or "").strip()
        query = {"scope_id": scope_id} if scope_id else {}
        items = []
        for doc in report_center.utils.conn_db(
                report_center.REPORT_COLLECTION).find(
                query, {"path": 0}).limit(50):
            doc["_id"] = str(doc["_id"])
            items.append(doc)
        return _ret({"items": items})
