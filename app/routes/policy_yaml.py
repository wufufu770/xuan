"""扫描引擎（策略）YAML 化：导出/导入/克隆。

校验链与 /api/policy/add/ 完全一致（端口自定义、排除端口、PoC/弱口令
插件白名单、各 config 按模型默认值补齐）——YAML 不引入绕过白名单的通道。
"""

import yaml

from flask_restx import fields, Namespace, reqparse
from bson import ObjectId

from app import utils
from app.utils import get_logger, auth
from app.utils.audit import audit
from . import ARLResource
from .policy import (
    domain_config_fields,
    ip_config_fields,
    site_config_fields,
    scope_config_fields,
    _update_plugin_config,
    AddARLPolicy,
)
from app.modules import ErrorMsg

ns = Namespace('policy_yaml', description="扫描引擎 YAML（导出/导入/克隆）")

logger = get_logger()


def _normalize_policy_payload(policy):
    """复用 /add/ 校验链规范化 policy dict；返回 (policy, error_ret)。"""
    updater = AddARLPolicy()._update_arg

    domain_config = policy.pop("domain_config", {}) or {}
    domain_config = updater(domain_config, domain_config_fields)

    ip_config = policy.pop("ip_config", {}) or {}
    port_scan_type = ip_config.get("port_scan_type", "test")
    if port_scan_type == "custom":
        port_custom = ip_config.get("port_custom", "80,443")
        port_list = utils.arl.build_port_custom(port_custom)
        if isinstance(port_list, str):
            return None, utils.build_ret(ErrorMsg.PortCustomInvalid,
                                         {"port_custom": port_list})
        ip_config["port_custom"] = ",".join(port_list)

    exclude_ports = ip_config.get("exclude_ports", "")
    if exclude_ports and not utils.is_valid_exclude_ports(exclude_ports):
        return None, utils.build_ret(ErrorMsg.ExcludePortsInvalid,
                                     {"exclude_ports": exclude_ports})
    ip_config = updater(ip_config, ip_config_fields)

    site_config = policy.pop("site_config", {}) or {}
    site_config = updater(site_config, site_config_fields)

    poc_config = _update_plugin_config(policy.pop("poc_config", []) or [])
    if isinstance(poc_config, str):
        return None, utils.build_ret(poc_config, {})

    brute_config = _update_plugin_config(policy.pop("brute_config", []) or [])
    if isinstance(brute_config, str):
        return None, utils.build_ret(brute_config, {})

    scope_config = updater(policy.pop("scope_config", {}) or {},
                           scope_config_fields)

    normalized = {
        "domain_config": domain_config,
        "ip_config": ip_config,
        "site_config": site_config,
        "poc_config": poc_config,
        "brute_config": brute_config,
        "file_leak": fields.boolean(policy.pop("file_leak", False)),
        "npoc_service_detection": fields.boolean(
            policy.pop("npoc_service_detection", False)),
        "scope_config": scope_config,
    }
    if policy:
        logger.info("policy yaml 忽略未知键: %s", sorted(policy.keys()))
    return normalized, None


def _policy_to_yaml(doc):
    payload = {
        "name": doc.get("name"),
        "desc": doc.get("desc", ""),
        "policy": doc.get("policy") or {},
    }
    return yaml.safe_dump(payload, allow_unicode=True, sort_keys=False)


yaml_import_fields = ns.model('PolicyYamlImport', {
    'name': fields.String(required=True, description="策略名"),
    'yaml': fields.String(required=True, description="策略 YAML 文本"),
    'desc': fields.String(required=False, description="描述"),
})


@ns.route('/yaml_export/')
class PolicyYamlExport(ARLResource):
    @auth
    def get(self):
        """导出策略为 YAML（?policy_id=）"""
        parser = reqparse.RequestParser()
        parser.add_argument("policy_id", type=str, location="args")
        args = parser.parse_args()
        policy_id = str((args or {}).get("policy_id") or "").strip()
        try:
            doc = utils.conn_db("policy").find_one({"_id": ObjectId(policy_id)})
        except Exception:
            doc = None
        if not doc:
            return utils.build_ret(ErrorMsg.Error, {"error": "策略不存在"})
        return utils.build_ret(ErrorMsg.Success, {
            "policy_id": policy_id,
            "yaml": _policy_to_yaml(doc),
        })


@ns.route('/yaml_import/')
class PolicyYamlImport(ARLResource):
    @auth
    @ns.expect(yaml_import_fields)
    def post(self):
        """从 YAML 导入为新策略（校验链与 /add/ 一致）"""
        args = self.parse_args(yaml_import_fields)
        name = str(args["name"]).strip()
        if not name:
            return utils.build_ret(ErrorMsg.Error, {"error": "策略名不能为空"})
        try:
            payload = yaml.safe_load(args["yaml"])
        except Exception as exc:
            return utils.build_ret(ErrorMsg.Error,
                                   {"error": "YAML 解析失败: {}".format(exc)})
        if not isinstance(payload, dict) or not isinstance(payload.get("policy"), dict):
            return utils.build_ret(ErrorMsg.Error, {"error": "YAML 需包含 policy 节点"})

        policy, error = _normalize_policy_payload(payload["policy"])
        if error:
            return error

        item = {
            "name": name,
            "policy": policy,
            "desc": str(args.get("desc") or payload.get("desc") or ""),
            "update_date": utils.curr_date(),
        }
        utils.conn_db("policy").insert_one(item)
        audit("policy_yaml_import", detail={"name": name})
        return utils.build_ret(ErrorMsg.Success, {"policy_id": str(item["_id"])})


clone_fields = ns.model('PolicyClone', {
    'policy_id': fields.String(required=True, description="源策略 ID"),
    'name': fields.String(required=True, description="新策略名"),
})


@ns.route('/clone/')
class PolicyClone(ARLResource):
    @auth
    @ns.expect(clone_fields)
    def post(self):
        """按既有策略克隆"""
        args = self.parse_args(clone_fields)
        try:
            doc = utils.conn_db("policy").find_one(
                {"_id": ObjectId(str(args["policy_id"]).strip())})
        except Exception:
            doc = None
        if not doc:
            return utils.build_ret(ErrorMsg.Error, {"error": "策略不存在"})
        item = {
            "name": str(args["name"]).strip(),
            "policy": doc.get("policy") or {},
            "desc": "clone of: {}".format(doc.get("name")),
            "update_date": utils.curr_date(),
        }
        utils.conn_db("policy").insert_one(item)
        audit("policy_clone", detail={"src": doc.get("name"), "new": item["name"]})
        return utils.build_ret(ErrorMsg.Success, {"policy_id": str(item["_id"])})


@ns.route('/graph/')
class PolicyGraph(ARLResource):
    @auth
    def get(self):
        """策略执行图：分阶段节点与顺序边（?policy_id=）"""
        parser = reqparse.RequestParser()
        parser.add_argument("policy_id", type=str, location="args")
        args = parser.parse_args()
        policy_id = str((args or {}).get("policy_id") or "").strip()
        try:
            doc = utils.conn_db("policy").find_one({"_id": ObjectId(policy_id)})
        except Exception:
            doc = None
        if not doc:
            return utils.build_ret(ErrorMsg.Error, {"error": "策略不存在"})

        from app.services.engine_graph import build_engine_graph
        graph = build_engine_graph(doc.get("policy") or {})
        return utils.build_ret(ErrorMsg.Success, {
            "policy_id": policy_id,
            "name": doc.get("name"),
            "graph": graph,
        })
