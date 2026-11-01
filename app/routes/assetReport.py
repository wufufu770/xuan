from flask import make_response
from flask_restx import Namespace, fields
from urllib.parse import quote

from app.services.assetReport import (
    build_asset_report,
    render_asset_report,
    safe_filename,
)
from app.utils import auth
from . import ARLResource, get_arl_parser


ns = Namespace("asset_report", description="HTML asset report export")

task_report_fields = ns.model("AssetReportTasks", {
    "task_id": fields.List(
        fields.String(description="Task ID"), required=True,
    ),
})
project_report_fields = {
    "name": fields.String(required=True, description="Project name"),
}


def _download_response(report):
    html = render_asset_report(report)
    filename = safe_filename(report["meta"].get("title"))
    response = make_response(html)
    response.headers["Content-Type"] = "text/html; charset=utf-8"
    response.headers["Content-Disposition"] = (
        "attachment; filename=asset-report.html; filename*=UTF-8''{}".format(
            quote(filename)
        )
    )
    response.headers["Access-Control-Expose-Headers"] = "Content-Disposition"
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@ns.route("/tasks/")
class ARLTaskAssetReport(ARLResource):
    @auth
    @ns.expect(task_report_fields)
    def post(self):
        args = self.parse_args(task_report_fields)
        task_ids = args.get("task_id") or []
        if not task_ids:
            return {"code": 400, "message": "请选择至少一个任务"}, 400
        try:
            report = build_asset_report(task_ids=task_ids)
        except ValueError:
            return {"code": 404, "message": "未找到所选任务"}, 404
        return _download_response(report)


@ns.route("/project/")
class ARLProjectAssetReport(ARLResource):
    parser = get_arl_parser(project_report_fields, location="args")

    @auth
    @ns.expect(parser)
    def get(self):
        args = self.parser.parse_args()
        project_name = str(args.get("name") or "").strip()
        if not project_name:
            return {"code": 400, "message": "请选择项目"}, 400
        try:
            report = build_asset_report(project_name=project_name)
        except ValueError:
            return {"code": 404, "message": "项目不存在或暂无任务"}, 404
        return _download_response(report)
