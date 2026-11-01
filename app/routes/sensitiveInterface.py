import csv
import hashlib
import io
from datetime import datetime
from urllib.parse import quote

from bson import ObjectId
from bson.errors import InvalidId
from pymongo.errors import DuplicateKeyError
from flask import make_response
from flask_restx import Namespace, Resource, fields, reqparse

from app import utils
from app.services.sensitiveInterface import (
    TAG_CATALOG,
    load_custom_rules,
    normalize_custom_rule,
    query_sensitive_interfaces,
    validate_custom_rule,
)
from app.utils import auth, user_login_header


ns = Namespace("sensitive_interface", description="敏感接口聚合与关键词规则")


query_parser = reqparse.RequestParser(bundle_errors=True)
query_parser.add_argument("task_id", type=str, location="args")
query_parser.add_argument("project_name", type=str, location="args")
query_parser.add_argument("scope_id", type=str, location="args")
query_parser.add_argument("page", type=int, default=1, location="args")
query_parser.add_argument("size", type=int, default=20, location="args")
query_parser.add_argument("q", type=str, default="", location="args")
query_parser.add_argument("tag", type=str, default="", location="args")
query_parser.add_argument("source", type=str, default="", location="args")
query_parser.add_argument("confidence", type=str, default="", location="args")
query_parser.add_argument("order", type=str, default="-score", location="args")


rule_model = ns.model("SensitiveInterfaceRule", {
    "keyword": fields.String(required=True, description="关键词"),
    "tag_code": fields.String(required=True, description="标签编码"),
    "location": fields.String(required=True, description="匹配位置"),
    "mode": fields.String(required=True, description="匹配方式"),
    "weight": fields.Integer(required=True, description="权重"),
    "enabled": fields.Boolean(required=False, description="是否启用"),
})


def _error(message, code=400):
    return {"message": message, "code": code, "data": {}}, code


def _run_query(args, export=False):
    return query_sensitive_interfaces(
        task_id=args.get("task_id"),
        project_name=args.get("project_name"),
        scope_id=args.get("scope_id"),
        page=1 if export else args.get("page"),
        size=100000 if export else args.get("size"),
        query=args.get("q"),
        tag_code=args.get("tag"),
        source=args.get("source"),
        confidence=args.get("confidence"),
        order=args.get("order"),
        max_size=100000 if export else 500,
    )


def _rule_object_id(rule):
    identity = "\x1f".join(str(rule[field]) for field in ("keyword", "tag_code", "location", "mode"))
    return ObjectId(hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24])


def _csv_cell(value):
    text = str(value if value is not None else "")
    if text.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


@ns.route("/")
class SensitiveInterfaceList(Resource):
    @auth
    @ns.expect(query_parser)
    def get(self):
        """查询任务或项目的敏感接口候选，历史数据即时生效。"""
        args = query_parser.parse_args()
        try:
            return _run_query(args)
        except (ValueError, InvalidId) as exc:
            return _error(str(exc), 400)
        except LookupError as exc:
            return _error(str(exc), 404)


@ns.route("/export/")
class SensitiveInterfaceExport(Resource):
    @auth
    @ns.expect(query_parser)
    def get(self):
        """导出当前筛选条件下的敏感接口 CSV。"""
        args = query_parser.parse_args()
        try:
            data = _run_query(args, export=True)
        except (ValueError, InvalidId) as exc:
            return _error(str(exc), 400)
        except LookupError as exc:
            return _error(str(exc), 404)

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "风险分", "置信度", "标签", "URL", "方法", "HTTP状态",
            "验证状态", "响应标题", "参数", "来源", "任务ID", "证据", "发现时间",
        ])
        for item in data.get("items") or []:
            writer.writerow([_csv_cell(value) for value in [
                item.get("score", 0),
                item.get("confidence", ""),
                " / ".join(tag.get("label", "") for tag in item.get("tags") or []),
                item.get("url", ""),
                item.get("method", ""),
                item.get("status_code", ""),
                item.get("verification_status", ""),
                item.get("response_title", ""),
                ", ".join(item.get("params") or []),
                ", ".join(item.get("sources") or []),
                item.get("task_id", ""),
                "；".join(item.get("evidence") or []),
                item.get("discovered_at", ""),
            ]])
        response = make_response("\ufeff" + output.getvalue())
        scope_name = str((data.get("scope") or {}).get("name") or "sensitive-interface")
        safe_name = "".join(char if char.isalnum() or char in ("-", "_", ".") else "_" for char in scope_name)
        response.headers["Content-Type"] = "text/csv; charset=utf-8"
        filename = "{}-sensitive-interfaces.csv".format(safe_name or "sensitive-interface")
        response.headers["Content-Disposition"] = (
            "attachment; filename=sensitive-interfaces.csv; filename*=UTF-8''{}".format(quote(filename))
        )
        response.headers["Access-Control-Expose-Headers"] = "Content-Disposition"
        return response


@ns.route("/rules/")
class SensitiveInterfaceRules(Resource):
    @auth
    def get(self):
        """列出系统标签与自定义关键词规则。"""
        return {
            "code": 200,
            "items": load_custom_rules(enabled_only=False),
            "tag_catalog": TAG_CATALOG,
        }

    @auth
    @ns.expect(rule_model)
    def post(self):
        """新增自定义关键词规则。"""
        payload = ns.payload or {}
        try:
            rule = validate_custom_rule(payload)
        except ValueError as exc:
            return _error(str(exc), 400)

        duplicate_query = {field: rule[field] for field in ("keyword", "tag_code", "location", "mode")}
        if utils.conn_db("sensitive_interface_rule").find_one(duplicate_query, {"_id": 1}):
            return _error("相同关键词规则已存在", 409)

        now = datetime.now()
        identity = user_login_header() or {}
        rule.update({
            "_id": _rule_object_id(rule),
            "enabled": payload.get("enabled", True),
            "created_by": identity.get("username", ""),
            "create_date": now,
            "update_date": now,
        })
        try:
            result = utils.conn_db("sensitive_interface_rule").insert_one(rule)
        except DuplicateKeyError:
            return _error("相同关键词规则已存在", 409)
        item = utils.conn_db("sensitive_interface_rule").find_one({"_id": result.inserted_id})
        return {"code": 200, "message": "规则已添加", "data": normalize_custom_rule(item)}


@ns.route("/rules/<string:rule_id>/")
class SensitiveInterfaceRuleDetail(Resource):
    @auth
    @ns.expect(rule_model, validate=False)
    def patch(self, rule_id):
        """更新自定义关键词规则。"""
        try:
            object_id = ObjectId(rule_id)
        except InvalidId:
            return _error("规则 ID 无效", 400)
        if not utils.conn_db("sensitive_interface_rule").find_one({"_id": object_id}, {"_id": 1}):
            return _error("规则不存在", 404)
        try:
            changes = validate_custom_rule(ns.payload or {}, partial=True)
        except ValueError as exc:
            return _error(str(exc), 400)
        if not changes:
            return _error("没有可更新字段", 400)

        duplicate_fields = ("keyword", "tag_code", "location", "mode")
        current = utils.conn_db("sensitive_interface_rule").find_one({"_id": object_id})
        duplicate_query = {field: changes.get(field, current.get(field)) for field in duplicate_fields}
        duplicate_query["_id"] = {"$ne": object_id}
        if utils.conn_db("sensitive_interface_rule").find_one(duplicate_query, {"_id": 1}):
            return _error("相同关键词规则已存在", 409)
        changes["update_date"] = datetime.now()
        utils.conn_db("sensitive_interface_rule").update_one({"_id": object_id}, {"$set": changes})
        item = utils.conn_db("sensitive_interface_rule").find_one({"_id": object_id})
        return {"code": 200, "message": "规则已更新", "data": normalize_custom_rule(item)}

    @auth
    def delete(self, rule_id):
        """删除自定义关键词规则。"""
        try:
            object_id = ObjectId(rule_id)
        except InvalidId:
            return _error("规则 ID 无效", 400)
        result = utils.conn_db("sensitive_interface_rule").delete_one({"_id": object_id})
        if not result.deleted_count:
            return _error("规则不存在", 404)
        return {"code": 200, "message": "规则已删除", "data": {"id": rule_id}}
