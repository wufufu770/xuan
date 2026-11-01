import re
from flask_restx import Resource, reqparse, fields
from bson.objectid import ObjectId
from datetime import datetime
from urllib.parse import quote
from flask import make_response
import time

from app.utils import conn_db as conn
from app.utils.site_scope import (
    formal_domain_query,
    formal_pipeline_query,
    formal_site_query,
    host_collision_site_query,
    visible_site_query,
)

SITE_LIST_PROJECTION_EXCLUDES = {
    "headers": 0,
    "browser_title_chain": 0,
    "quality_evidence": 0,
    "noise_reasons": 0,
    "evidence_sources": 0,
    "js_evidence_sources": 0,
    "scan_policy_evidence": 0,
    "route_confirmed_urls": 0,
    "site_aliases": 0,
    "resolved_ips": 0,
}

URL_LIST_PROJECTION_EXCLUDES = {
    "js_evidence_sources": 0,
    "discovered_sources": 0,
    "route_evidence": 0,
}

WIH_LIST_PROJECTION_EXCLUDES = {
    "evidence_sources": 0,
    "discovered_urls": 0,
}

ENTRY_LIST_PROJECTION_EXCLUDES = {
    "evidence_sources": 0,
    "alive_urls": 0,
}

TASK_STAGE_LIST_PROJECTION_EXCLUDES = {
    "attempts": 0,
}

FILELEAK_LIST_PROJECTION_EXCLUDES = {
    "redirect_chain": 0,
    "template_evidence": 0,
    "response_headers": 0,
    "js_evidence_sources": 0,
}

LIST_PROJECTION_EXCLUDES_BY_COLLECTION = {
    "site": SITE_LIST_PROJECTION_EXCLUDES,
    "asset_site": SITE_LIST_PROJECTION_EXCLUDES,
    "url": URL_LIST_PROJECTION_EXCLUDES,
    "wih": WIH_LIST_PROJECTION_EXCLUDES,
    "asset_wih": WIH_LIST_PROJECTION_EXCLUDES,
    "entry_asset": ENTRY_LIST_PROJECTION_EXCLUDES,
    "fileleak": FILELEAK_LIST_PROJECTION_EXCLUDES,
    "task_stage": TASK_STAGE_LIST_PROJECTION_EXCLUDES,
}

base_query_fields = {
    'page': fields.Integer(description="当前页数", example=1),
    'size': fields.Integer(description="页面大小", example=10),
    'order': fields.String(description="排序字段", example='_id'),
}

# 只能用等号进行mongo查询的字段
EQUAL_FIELDS = [
    "task_id", "task_tag", "ip_type", "scope_id", "type", "quality_state",
    "asset_quality", "asset_visibility", "verification_status", "ai_state",
]


def scope_to_task_ids(scope_id, limit=500):
    """资产分组 ID -> 匹配分组范围域名的任务 ID 列表（资产数据仅以 task_id 关联）"""
    scope_id = str(scope_id or "").strip()
    if not scope_id:
        return []
    try:
        scope = conn("asset_scope").find_one({"_id": ObjectId(scope_id)}, {"scope_array": 1, "scope": 1})
    except Exception:
        return []
    if not scope:
        return []
    domains = [d.strip() for d in (scope.get("scope_array") or []) if d and d.strip()]
    if not domains:
        domains = [d.strip() for d in str(scope.get("scope") or "").split(",") if d.strip()]
    if not domains:
        return []
    pattern = "(?i)(^|\\.)(" + "|".join(re.escape(d) for d in domains) + ")($|\\.)"
    tasks = conn("task").find({"target": {"$regex": pattern}}, {"_id": 1})
    return [str(t["_id"]) for t in tasks][:limit]


class ARLResource(Resource):
    def get_parser(self, model, location='json'):
        parser = reqparse.RequestParser(bundle_errors=True)
        for name in model:
            curr_field = model[name]

            parser.add_argument(name,
                                required=curr_field.required,
                                type=curr_field.format,
                                help=curr_field.description,
                                location=location)
        return parser

    def parse_args(self, model, location='json'):
        parser = self.get_parser(model, location)
        args = parser.parse_args()
        return args

    def build_db_query(self, args):
        query_args = {}
        scope_id = str((args or {}).get("scope_id") or "").strip()
        if scope_id:
            query_args["task_id"] = {"$in": scope_to_task_ids(scope_id)}
        ai_state = str((args or {}).get("ai_state") or "").strip().lower()
        if ai_state == "judged":
            query_args["ai_state"] = "judged"
        elif ai_state == "pending":
            query_args["$and"] = query_args.get("$and", [])
            query_args["$and"].append({"$or": [
                {"ai_state": {"$exists": False}},
                {"ai_state": {"$in": ["pending", ""]}},
            ]})
        keyword = str((args or {}).get("keyword") or "").strip()
        if keyword:
            kw = {"$regex": re.escape(keyword), "$options": "i"}
            query_args["$and"] = query_args.get("$and", [])
            query_args["$and"].append({"$or": [
                {"site": kw}, {"hostname": kw}, {"title": kw},
            ]})
        for key in args:
            if key in ("scope_id", "ai_state", "keyword"):
                continue
            if key in base_query_fields:
                continue

            if key == '_id':
                if args[key]:
                    query_args[key] = ObjectId(args[key])

                continue

            if args[key] is None:
                continue

            if key.endswith("__dgt"):
                real_key = key.split('__dgt')[0]
                raw_value = query_args.get(real_key, {})
                raw_value.update({
                    "$gt": datetime.strptime(args[key],
                                             "%Y-%m-%d %H:%M:%S")
                })
                query_args[real_key] = raw_value

            elif key.endswith("__dlt"):
                real_key = key.split('__dlt')[0]
                raw_value = query_args.get(real_key, {})
                raw_value.update({
                    "$lt": datetime.strptime(args[key],
                                             "%Y-%m-%d %H:%M:%S")
                })
                query_args[real_key] = raw_value

            elif key.endswith("__neq"):
                real_key = key.split('__neq')[0]
                raw_value = {
                    "$ne": args[key]
                }
                query_args[real_key] = raw_value

            elif key.endswith("__not"):
                real_key = key.split('__not')[0]
                raw_value = {
                    "$not": re.compile(re.escape(args[key]))
                }
                query_args[real_key] = raw_value

            elif key.endswith("__gt") and isinstance(args[key], int):
                real_key = key.split('__gt')[0]
                raw_value = {
                    "$gt": args[key]
                }
                query_args[real_key] = raw_value
            elif key.endswith("__lt") and isinstance(args[key], int):
                real_key = key.split('__lt')[0]
                raw_value = {
                    "$lt": args[key]
                }
                query_args[real_key] = raw_value
            elif isinstance(args[key], str):
                if key == "source":
                    source_query = {
                        "$regex": re.escape(args[key]),
                        '$options': "i"
                    }
                    query_args["$or"] = [
                        {"source": source_query},
                        {"sources": source_query},
                    ]
                elif key in EQUAL_FIELDS:
                    query_args[key] = args[key]
                else:
                    query_args[key] = {
                        "$regex": re.escape(args[key]),
                        '$options': "i"
                    }
            else:
                query_args[key] = args[key]

        return query_args

    def build_return_items(self, data):
        items = []

        special_keys = ["_id", "save_date", "update_date"]

        for item in data:
            for key in item:
                if key in special_keys:
                    item[key] = str(item[key])

            items.append(item)

        return items

    @classmethod
    def serialize_query_value(cls, value):
        if isinstance(value, dict):
            return {
                key: cls.serialize_query_value(item)
                for key, item in value.items()
            }
        if isinstance(value, (list, tuple)):
            return [cls.serialize_query_value(item) for item in value]
        if isinstance(value, type(re.compile(""))):
            return value.pattern
        if isinstance(value, (ObjectId, datetime)):
            return str(value)
        return value

    def get_find_projection(self, _args=None, _collection=None):
        return LIST_PROJECTION_EXCLUDES_BY_COLLECTION.get(_collection)

    def build_data(self, args=None, collection=None, base_query=None):

        default_field = self.get_default_field(args)
        page = default_field.get("page", 1)
        size = default_field.get("size", 10)
        orderby_list = default_field.get('order', [("_id", -1)])
        query = self.build_db_query(args)
        if base_query:
            query = ({"$and": [query, base_query]} if query
                     else dict(base_query))
        projection = self.get_find_projection(args, collection)
        result = conn(collection).find(
            query, projection).sort(orderby_list).skip(
                size * (page - 1)).limit(size)
        count = conn(collection).count_documents(query)
        items = self.build_return_items(result)

        data = {
            "page": page,
            "size": size,
            "total": count,
            "items": items,
            "query": self.serialize_query_value(query),
            "code": 200
        }
        return data

    '''
    取默认字段的值，并且删除
    '''

    def get_default_field(self, args):
        default_field_map = {
            "page": 1,
            "size": 10,
            "order": "-_id"
        }

        ret = default_field_map.copy()

        for x in default_field_map:
            if x in args and args[x]:
                ret[x] = args.pop(x)
                if x == "size":
                    if ret[x] <= 0:
                        ret[x] = 10
                    if ret[x] >= 100000:
                        ret[x] = 100000

                if x == "page":
                    if ret[x] <= 0:
                        ret[x] = 1

        orderby_list = []
        orderby_field = ret.get("order", "-_id")
        for field in orderby_field.split(","):
            field = field.strip()
            if field.startswith("-"):
                orderby_list.append((field.split("-")[1], -1))
            elif field.startswith("+"):
                orderby_list.append((field.split("+")[1], 1))
            else:
                orderby_list.append((field, 1))

        ret['order'] = orderby_list
        return ret

    def send_export_file(self, args, _type):
        _type_map_field_name = {
            "site": "site",
            "domain": "domain",
            "ip": "ip",
            "asset_site": "site",
            "asset_domain": "domain",
            "asset_ip": "ip",
            "asset_wih": "content",
            "url": "url",
            "cip": "cidr_ip",
            "wih": "content",
        }
        data = self.build_data(args=args, collection=_type)["items"]
        items_set = set()
        for item in data:
            filed_name = _type_map_field_name.get(_type, "")
            if filed_name and filed_name in item:
                if filed_name == "ip":
                    curr_ip = item[filed_name]
                    for port_info in item.get("port_info", []):
                        items_set.add("{}:{}".format(curr_ip, port_info["port_id"]))
                else:
                    items_set.add(item[filed_name])

        return self.send_file(items_set, _type)

    # 表示从 给定集合中 导出相应的字段来
    def send_export_file_attr(self, args, collection, field):
        data = self.build_data(args=args, collection=collection)["items"]
        items_set = set()
        for item in data:
            if field in item:
                value = item[field]
                if isinstance(value, list):
                    items_set |= set(value)
                else:
                    items_set.add(value)

        return self.send_file(items_set, f"{collection}_{field}")

    def send_batch_export_file(self, task_id_list, _type):
        _type_map_field_name = {
            "site": "site",
            "domain": "domain",
            "ip": "ip",
            "url": "url",
            "cip": "cidr_ip",
            "wih": "content",
        }
        items_set = set()
        filed_name = _type_map_field_name.get(_type, "")

        for task_id in task_id_list:
            if not filed_name:
                continue
            if not task_id:
                continue
            query = {"task_id": task_id}
            if _type == "domain":
                query = formal_domain_query(query)
            elif _type == "site":
                query = visible_site_query(query)
            elif _type in ("url", "wih"):
                query = formal_pipeline_query(query)
            items = conn(_type).distinct(filed_name, query)
            items_set |= set(items)

        return self.send_file(items_set, _type)

    def send_scope_batch_export_file(self, scope_id_list, _type):
        _type_map_field_name = {
            "asset_site": "site",
            "asset_domain": "domain",
            "asset_ip": "ip",
            "asset_wih": "content"
        }

        items_set = set()
        filed_name = _type_map_field_name.get(_type, "")

        for scope_id in scope_id_list:
            if not filed_name:
                continue
            if not scope_id:
                continue
            query = {"scope_id": scope_id}
            if _type == "asset_site":
                query = visible_site_query(query)
            items = conn(_type).distinct(filed_name, query)
            items_set |= set(items)

        return self.send_file(items_set, _type)

    def send_file(self, items_set, _type):
        response = make_response("\r\n".join(items_set))
        filename = "{}_{}_{}.txt".format(_type, len(items_set), int(time.time()))
        response.headers['Content-Type'] = 'application/octet-stream'
        response.headers["Access-Control-Expose-Headers"] = "Content-Disposition"
        response.headers["Content-Disposition"] = "attachment; filename={}".format(quote(filename))
        return response


class SiteScopedResource(ARLResource):
    def get_find_projection(self, args=None, collection=None):
        return super().get_find_projection(args, collection)

    @staticmethod
    def wants_full_evidence(args):
        args = args or {}
        if args.get("include_noise") is True:
            return True
        if args.get("quality_state") is not None:
            return True
        if args.get("asset_quality") is not None:
            return True
        if args.get("asset_visibility") is not None:
            return True
        if args.get("verification_status") is not None:
            return True
        if args.get("display_eligible") is not None:
            return True
        title = str(args.get("title") or "").strip().lower()
        tag = str(args.get("tag") or "").strip().lower()
        return any(value in title or value in tag for value in (
            "无效", "默认", "页面不存在", "没有找到站点", "page not found",
            "404 not found", "welcome to nginx", "welcome to openresty",
            "301 moved", "302 found", "307 temporary", "308 permanent",
        ))

    def build_db_query(self, args):
        raw_args = dict(args or {})
        title_filter = raw_args.pop("title", None)
        host_collision = raw_args.pop("host_collision", None)
        include_noise = raw_args.pop("include_noise", None)
        full_evidence = self.wants_full_evidence({
            **raw_args,
            "title": title_filter,
            "include_noise": include_noise,
        })
        if host_collision is None:
            source = str(raw_args.get("source") or "").lower()
            tag = str(raw_args.get("tag") or "")
            host_collision = "findvhost" in source or "Host碰撞" in tag
        query = super().build_db_query(raw_args)
        if title_filter not in (None, ""):
            title_query = {
                "$or": [
                    {field: {
                        "$regex": re.escape(str(title_filter)),
                        "$options": "i",
                    }}
                    for field in ("title", "browser_title", "browser_final_title")
                ]
            }
            query = {"$and": [query, title_query]} if query else title_query
        if host_collision:
            return host_collision_site_query(query)
        if full_evidence:
            return formal_site_query(query)
        return visible_site_query(query)


class FormalPipelineResource(ARLResource):
    def build_db_query(self, args):
        return formal_pipeline_query(super().build_db_query(args))


def get_arl_parser(model, location='args'):
    r = ARLResource()
    return r.get_parser(model, location)


from .task import ns as task_ns
from .domain import ns as domain_ns
from .site import ns as site_ns
from .ip import ns as ip_ns
from .url import ns as url_ns
from .user import ns as user_ns
from .image import ns as image_ns
from .cert import ns as cert_ns
from .service import ns as service_ns
from .fileleak import ns as fileleak_ns
from .export import ns as export_ns
from .assetScope import ns as asset_scope_ns
from .assetDomain import ns as asset_domain_ns
from .assetIP import ns as asset_ip_ns
from .assetSite import ns as asset_site_ns
from .scheduler import ns as scheduler_ns
from .poc import ns as poc_ns
from .engines import ns as engines_ns
from .ai_judge import ns as ai_judge_ns
from .integration import ns as integration_ns
from .supply_chain import ns as supply_chain_ns
from .vuln import ns as vuln_ns
from .batchExport import ns as batch_export_ns
from .policy import ns as policy_ns
from .npoc_service import ns as npoc_service_ns
from .taskFofa import ns as task_fofa_ns
from .console import ns as console_ns
from .cip import ns as cip_ns
from .fingerprint import ns as fingerprint_ns
from .stat_finger import ns as stat_finger_ns
from .github_task import ns as github_task_ns
from .github_result import ns as github_result_ns
from .github_monitor_result import ns as github_monitor_result_ns
from .github_scheduler import ns as github_scheduler_ns
from .task_schedule import ns as task_schedule_ns
from .nuclei_result import ns as nuclei_result_ns
from .wih import ns as wih_ns
from .assetWih import ns as asset_wih_ns
from .project import ns as project_ns
from .entry import ns as entry_ns
from .hostCollision import ns as host_collision_ns
from .assetReport import ns as asset_report_ns
from .sensitiveInterface import ns as sensitive_interface_ns
from .stats import ns as stats_ns
from .fengniao import ns as fengniao_ns
from .appdl import ns as appdl_ns
from .session_pool import ns as session_pool_ns
from .policy_yaml import ns as policy_yaml_ns
from .report import ns as report_ns
from .monitor_diff import ns as monitor_diff_ns
from .asset_ext import ns as asset_ext_ns
from .agent import ns as agent_ns
from .mcp_server import ns as mcp_ns
from .notify_config import ns as notify_config_ns
from .plugin_update import ns as plugin_update_ns
