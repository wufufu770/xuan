import re
import time

from bson import ObjectId
from flask import make_response
from flask_restx import Namespace, fields

from app import utils
from app.modules import ErrorMsg
from app.services.hostCollisionExport import (
    host_collision_page,
    host_collision_rows,
    hosts_file_lines,
)
from app.utils import auth
from . import ARLResource, base_query_fields, get_arl_parser


ns = Namespace("host_collision", description="Host 碰撞结果")


search_fields = {
    "task_id": fields.String(required=False, description="任务 ID"),
    "project_name": fields.String(required=False, description="项目名/任务名"),
    "q": fields.String(required=False, description="关键词"),
    "ip": fields.String(required=False, description="IP"),
    "host": fields.String(required=False, description="Host"),
}
search_fields.update(base_query_fields)


def _selected_task_ids(task_id="", project_name=""):
    task_id = str(task_id or "").strip()
    project_name = str(project_name or "").strip()
    if task_id:
        if not re.match(r"^[a-fA-F0-9]{24}$", task_id):
            return None, utils.build_ret(ErrorMsg.Error, {"error": "invalid task_id"})
        if not utils.conn_db("task").find_one({"_id": ObjectId(task_id)}, {"_id": 1}):
            return None, utils.build_ret(ErrorMsg.NotFoundTask, {"task_id": task_id})
        return [task_id], None

    if project_name:
        return [
            str(item.get("_id"))
            for item in utils.conn_db("task").find({"name": project_name}, {"_id": 1})
        ], None

    return None, utils.build_ret(
        ErrorMsg.Error, {"error": "task_id or project_name is required"})


def _query_rows(args):
    task_ids, error = _selected_task_ids(
        task_id=args.get("task_id"), project_name=args.get("project_name"))
    if error:
        return None, error
    return host_collision_rows(
        task_ids,
        keyword=args.get("q"),
        ip=args.get("ip"),
        host=args.get("host"),
        order=args.get("order") or "ip,host",
    ), None


@ns.route("/")
class ARLHostCollision(ARLResource):
    parser = get_arl_parser(search_fields, location="args")

    @auth
    @ns.expect(parser)
    def get(self):
        args = self.parser.parse_args()
        requested_order = args.get("order") or "ip,host"
        task_ids, error = _selected_task_ids(
            task_id=args.get("task_id"), project_name=args.get("project_name"))
        if error:
            return error

        default_field = self.get_default_field(args)
        page = default_field.get("page", 1)
        size = default_field.get("size", 10)
        data = host_collision_page(
            task_ids,
            keyword=args.get("q"),
            ip=args.get("ip"),
            host=args.get("host"),
            order=requested_order,
            page=page,
            size=size,
        )
        data["code"] = 200
        return data


@ns.route("/export/")
class ARLHostCollisionExport(ARLResource):
    parser = get_arl_parser(search_fields, location="args")

    @auth
    @ns.expect(parser)
    def get(self):
        args = self.parser.parse_args()
        rows, error = _query_rows(args)
        if error:
            return error

        lines = hosts_file_lines(rows)
        response = make_response("\n".join(lines) + ("\n" if lines else ""))
        filename = "host_collision_hosts_{}_{}.txt".format(
            len(lines), int(time.time()))
        response.headers["Content-Type"] = "text/plain; charset=utf-8"
        response.headers["Access-Control-Expose-Headers"] = "Content-Disposition"
        response.headers["Content-Disposition"] = "attachment; filename={}".format(filename)
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response
