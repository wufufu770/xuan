import re
import time
from datetime import date, datetime

from bson import ObjectId
from flask_restx import Namespace, fields

from app import utils
from app.services.hostCollisionExport import (
    host_collision_page,
    host_collision_rows,
    normalize_host_collision_item,
)
from app.services.taskStage import TASK_STAGE_DISPLAY_NAMES
from app.utils import auth, get_logger
from app.utils.host_collision import (
    HOST_COLLISION_CONFIRMED_MATCH,
    HOST_COLLISION_EXCLUDE,
)
from app.utils.site_scope import (
    formal_domain_query,
    formal_pipeline_query,
    formal_site_query,
    visible_site_query,
)
from app.utils.site_quality import LEGACY_HIDDEN_TITLE_REGEX
from . import (
    ARLResource,
    LIST_PROJECTION_EXCLUDES_BY_COLLECTION,
    base_query_fields,
    get_arl_parser,
)


ns = Namespace("project", description="项目管理")
logger = get_logger()

PRIMARY_SITE_QUALITY_STATES = (
    "active", "route_confirmed", "spa_shell", "template_content",
)
REVIEW_SITE_QUALITY_STATES = ("restricted", "transient_block")
REVIEW_SITE_STATUS_CODES = (
    401, 403, 408, 418, 425, 429, 500, 501, 502, 503, 504,
)
REVIEW_SITE_STATUS_VALUES = REVIEW_SITE_STATUS_CODES + tuple(
    str(value) for value in REVIEW_SITE_STATUS_CODES
)

PROJECT_COUNT_CACHE_TTL = 15.0
_PROJECT_COUNT_CACHE = {}


PROJECT_ASSETS = {
    "task": {
        "collection": "task",
        "search_fields": ["name", "target", "status"],
        "default_order": "-_id",
    },
    "site": {
        "collection": "site",
        "search_fields": [
            "site", "title", "browser_title", "browser_final_title",
            "spa_framework", "spa_confidence", "spa_render_mode",
            "spa_route_mode", "ip", "source", "sources", "finger.name", "tag",
        ],
        "default_order": "-_id",
    },
    "domain": {
        "collection": "domain",
        "search_fields": ["domain", "record", "ips", "type", "source", "sources"],
        "default_order": "-_id",
    },
    "ip": {
        "collection": "ip",
        "search_fields": ["ip", "domain", "port_info.port_id", "port_info.service_name", "cdn_name"],
        "default_order": "-_id",
    },
    "url": {
        "collection": "url",
        "search_fields": ["url", "site", "title", "source", "url_type"],
        "default_order": "-_id",
    },
    "fileleak": {
        "collection": "fileleak",
        "search_fields": ["url", "site", "title"],
        "default_order": "-_id",
    },
    "wih": {
        "collection": "wih",
        "search_fields": ["content", "site", "source", "record_type", "evidence_type"],
        "default_order": "-_id",
    },
    "cert": {
        "collection": "cert",
        "search_fields": [
            "ip", "cert.subject_dn", "cert.issuer_dn", "cert.extensions.subjectAltName",
            "source_type", "relation_level",
        ],
        "default_order": "-_id",
    },
    "vuln": {
        "collection": "vuln",
        "search_fields": ["target", "vul_name", "plg_name", "app_name", "verify_data"],
        "default_order": "-_id",
    },
    "host_collision": {
        "collection": "vuln",
        "search_fields": [
            "target", "verify_obj.domain", "verify_obj.title", "task_id",
        ],
        "default_order": "ip,host",
    },
    "stage": {
        "collection": "task_stage",
        "search_fields": [
            "stage", "status", "error", "warning", "partial_reason",
            "extra.source_reports.source", "extra.source_reports.error_kind",
        ],
        "default_order": "-task_id,stage",
    },
}


PROJECT_COUNT_COLLECTIONS = {
    "site": "site",
    "domain": "domain",
    "ip": "ip",
    "url": "url",
    "fileleak": "fileleak",
    "wih": "wih",
    "cert": "cert",
    "vuln": "vuln",
    "stage": "task_stage",
}

PROJECT_STATISTIC_FIELDS = {
    "site": "site_cnt",
    "domain": "domain_cnt",
    "ip": "ip_cnt",
    "url": "url_cnt",
    "fileleak": "fileleak_cnt",
    "wih": "wih_cnt",
    "cert": "cert_cnt",
    "vuln": "vuln_cnt",
}
TERMINAL_TASK_STATUSES = {"done", "stop", "error"}


project_search_fields = {
    "name": fields.String(required=False, description="项目名/任务名"),
}
project_search_fields.update(base_query_fields)

project_asset_search_fields = {
    "name": fields.String(required=True, description="项目名/任务名"),
    "asset_type": fields.String(required=False, description="资产类型"),
    "q": fields.String(required=False, description="关键词"),
    "focus": fields.String(required=False, description="站点测试焦点"),
    "include_counts": fields.Boolean(required=False, description="是否返回项目统计"),
    "include_noise": fields.Boolean(required=False, description="站点是否包含低价值证据"),
    "quality_view": fields.String(required=False, description="站点质量视图"),
}
project_asset_search_fields.update(base_query_fields)


def _json_safe(value):
    if isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, tuple):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_safe(val) for key, val in value.items()}
    return value


def _task_time(task):
    for field in ("end_time", "start_time", "create_time", "schedule_time"):
        value = task.get(field)
        if value:
            return str(value)
    try:
        return task.get("_id").generation_time.isoformat()
    except Exception:
        return ""


def _task_ids_for_project(name):
    name = str(name or "").strip()
    if not name:
        return [], {}

    tasks = list(utils.conn_db("task").find(
        {"name": name},
        {"_id": 1, "name": 1, "target": 1, "status": 1, "start_time": 1, "end_time": 1, "create_time": 1}
    ).sort([("_id", -1)]))
    task_ids = [str(item.get("_id")) for item in tasks]
    task_meta = {
        str(item.get("_id")): {
            "task_id": str(item.get("_id")),
            "task_name": item.get("name", ""),
            "task_target": item.get("target", ""),
            "task_status": item.get("status", ""),
        }
        for item in tasks
    }
    return task_ids, task_meta


def _apply_keyword_query(query, keyword, fields_list):
    keyword = str(keyword or "").strip()
    if not keyword:
        return

    regex = {"$regex": re.escape(keyword), "$options": "i"}
    query["$or"] = [{field: regex} for field in fields_list]


def _open_ports(item):
    ports = []
    for port_info in item.get("port_info") or []:
        port_id = port_info.get("port_id")
        if port_id in (None, ""):
            continue
        service_name = port_info.get("service_name") or ""
        if service_name:
            ports.append("{}({})".format(port_id, service_name))
        else:
            ports.append(str(port_id))
    return ports


def _finger_names(item):
    names = []
    for finger in item.get("finger") or []:
        name = finger.get("name") if isinstance(finger, dict) else finger
        if name and name not in names:
            names.append(name)
    return names


def _enrich_item(item, task_meta, project_name):
    item = _json_safe(item)
    task_id = str(item.get("task_id") or item.get("_id") or "")
    meta = task_meta.get(task_id, {})
    item["project_name"] = project_name
    item["task_id"] = task_id
    item["task_name"] = meta.get("task_name", item.get("name", ""))
    item["task_target"] = meta.get("task_target", item.get("target", ""))
    item["task_status"] = meta.get("task_status", item.get("status", ""))

    sources = item.get("sources") or item.get("source") or []
    if not isinstance(sources, list):
        sources = [sources]
    item["source_display"] = ", ".join(dict.fromkeys(
        [str(source) for source in sources if source]))

    if item.get("stage") and not item.get("display_name"):
        item["display_name"] = TASK_STAGE_DISPLAY_NAMES.get(
            item.get("stage"), item.get("stage"))

    if item.get("port_info"):
        item["open_ports"] = _open_ports(item)
    if item.get("finger"):
        item["finger_names"] = _finger_names(item)
    return item


def _project_counts(task_ids, include_noise=False):
    return _project_counts_map(
        {"project": task_ids}, include_noise=include_noise,
    ).get("project", {"task": len(task_ids)})


def _site_quality_counts(task_ids):
    if not task_ids:
        return {"primary": 0, "review": 0, "hidden_noise": 0, "all": 0}
    pipeline = [
        {"$match": formal_site_query({"task_id": {"$in": task_ids}})},
        {"$project": {
            "quality": {"$switch": {
                "branches": [
                    {"case": {"$eq": ["$asset_quality", "primary"]}, "then": "primary"},
                    {"case": {"$eq": ["$asset_quality", "review"]}, "then": "review"},
                    {"case": {"$in": ["$quality_state", list(REVIEW_SITE_QUALITY_STATES)]}, "then": "review"},
                    {"case": {"$in": ["$quality_state", list(PRIMARY_SITE_QUALITY_STATES)]}, "then": "primary"},
                    {"case": {"$and": [
                        {"$in": [{"$ifNull": ["$quality_state", ""]}, [None, ""]]},
                        {"$or": [
                            {"$in": ["$status", list(REVIEW_SITE_STATUS_VALUES)]},
                            {"$in": ["$status_code", list(REVIEW_SITE_STATUS_VALUES)]},
                        ]},
                    ]}, "then": "review"},
                    {"case": {"$eq": ["$display_eligible", True]}, "then": "primary"},
                    {"case": {"$and": [
                        {"$in": [{"$ifNull": ["$asset_quality", ""]}, [None, ""]]},
                        {"$in": [{"$ifNull": ["$quality_state", ""]}, [None, ""]]},
                        {"$eq": [{"$ifNull": ["$display_eligible", None]}, None]},
                        {"$not": [{"$in": [
                            "$status", [404, "404", 410, "410"],
                        ]}]},
                        {"$not": [{"$in": [
                            "$status_code", [404, "404", 410, "410"],
                        ]}]},
                        {"$or": [
                            {"$ne": [
                                {"$ifNull": ["$browser_title", ""]}, "",
                            ]},
                            {"$not": [{"$regexMatch": {
                                "input": {"$ifNull": ["$title", ""]},
                                "regex": LEGACY_HIDDEN_TITLE_REGEX,
                                "options": "i",
                            }}]},
                        ]},
                    ]}, "then": "primary"},
                ],
                "default": "hidden_noise",
            }},
            "focused": {"$and": [
                {"$ne": [
                    {"$ifNull": ["$quality_cluster_representative", True]},
                    False,
                ]},
                {"$ne": [
                    {"$ifNull": ["$display_eligible", True]},
                    False,
                ]},
                {"$ne": [
                    {"$ifNull": ["$asset_visibility", "visible"]},
                    "hidden_noise",
                ]},
            ]},
        }},
        {"$group": {
            "_id": "$quality",
            "raw": {"$sum": 1},
            "focused": {"$sum": {"$cond": ["$focused", 1, 0]}},
        }},
    ]
    result = {"primary": 0, "review": 0, "hidden_noise": 0, "all": 0}
    for item in utils.conn_db("site").aggregate(pipeline):
        quality = str(item.get("_id") or "hidden_noise")
        raw = int(item.get("raw", 0) or 0)
        focused = int(item.get("focused", 0) or 0)
        result["all"] += raw
        if quality in ("primary", "review"):
            result[quality] += focused
            # Non-representative rows are retained as evidence but collapsed
            # from the focused view. Count them as hidden noise so the quality
            # buckets always add up to the raw total shown to the tester.
            result["hidden_noise"] += max(raw - focused, 0)
        else:
            result["hidden_noise"] += raw
    return result


def _site_quality_query(query, quality_view):
    quality_view = str(quality_view or "focus").strip().lower()
    if quality_view == "all":
        return formal_site_query(query)
    scoped = visible_site_query(query)
    if quality_view == "primary":
        legacy_primary = {"$and": [
            {"asset_quality": {"$in": [None, ""]}},
            {"$or": [
                {"quality_state": {"$in": list(PRIMARY_SITE_QUALITY_STATES)}},
                {"$and": [
                    {"quality_state": {"$in": [None, ""]}},
                    {"display_eligible": True},
                    {"status": {"$nin": list(REVIEW_SITE_STATUS_VALUES)}},
                    {"status_code": {"$nin": list(REVIEW_SITE_STATUS_VALUES)}},
                ]},
            ]},
        ]}
        return {"$and": [scoped, {"$or": [
            {"asset_quality": "primary"}, legacy_primary,
        ]}]}
    if quality_view == "review":
        legacy_review = {"$and": [
            {"asset_quality": {"$in": [None, ""]}},
            {"$or": [
                {"quality_state": {"$in": list(REVIEW_SITE_QUALITY_STATES)}},
                {"$and": [
                    {"quality_state": {"$in": [None, ""]}},
                    {"$or": [
                        {"status": {"$in": list(REVIEW_SITE_STATUS_VALUES)}},
                        {"status_code": {"$in": list(REVIEW_SITE_STATUS_VALUES)}},
                    ]},
                ]},
            ]},
        ]}
        return {"$and": [scoped, {"$or": [
            {"asset_quality": "review"}, legacy_review,
        ]}]}
    return scoped


def _site_focus_query(query, focus):
    focus = str(focus or "").strip().lower()
    focus_map = {
        "spa": {"$or": [
            {"browser_spa_detected": True},
            {"spa_score": {"$gte": 55}},
            {"spa_confidence": {"$in": ["medium", "high"]}},
            {"runtime_script_count": {"$gt": 0}},
            {"spa_signals": {"$exists": True, "$ne": []}},
        ]},
        "sso": {"$or": [
            {"browser_cross_origin_redirect": True},
        ]},
        "browser_title": {
            "browser_title": {"$exists": True, "$nin": ["", "-"]},
        },
        "route_confirmed": {"quality_state": "route_confirmed"},
    }
    focus_query = focus_map.get(focus)
    if not focus_query:
        return query
    return {"$and": [query, focus_query]}


def _stored_task_counts(task_ids, include_noise=False):
    object_ids = [
        ObjectId(task_id)
        for task_id in task_ids
        if ObjectId.is_valid(task_id)
    ]
    if not object_ids:
        return {}

    stored = {}
    cursor = utils.conn_db("task").find(
        {"_id": {"$in": object_ids}},
        {"_id": 1, "status": 1, "statistic": 1},
    )
    for task in cursor:
        task_id = str(task.get("_id") or "")
        statistic = task.get("statistic")
        if (
            str(task.get("status") or "").lower() not in TERMINAL_TASK_STATUSES
            or not isinstance(statistic, dict)
        ):
            continue

        fields_map = dict(PROJECT_STATISTIC_FIELDS)
        if include_noise:
            fields_map["site"] = "site_observed_cnt"
        if any(field not in statistic for field in fields_map.values()):
            continue
        stored[task_id] = {
            key: int(statistic.get(field, 0) or 0)
            for key, field in fields_map.items()
        }
    return stored


def _project_counts_map(project_task_ids, include_noise=False):
    normalized = {
        name: [str(task_id) for task_id in task_ids if task_id]
        for name, task_ids in project_task_ids.items()
    }
    all_task_ids = sorted({task_id for task_ids in normalized.values() for task_id in task_ids})
    ret = {
        name: {"task": len(task_ids)}
        for name, task_ids in normalized.items()
    }
    if not all_task_ids:
        return ret

    cache_key = (
        bool(include_noise),
        tuple(sorted(
            (name, tuple(sorted(task_ids)))
            for name, task_ids in normalized.items()
        )),
    )
    cached = _PROJECT_COUNT_CACHE.get(cache_key)
    if cached and time.monotonic() - cached[0] < PROJECT_COUNT_CACHE_TTL:
        return cached[1]

    stored_counts = _stored_task_counts(
        all_task_ids, include_noise=include_noise)
    live_task_ids = [
        task_id for task_id in all_task_ids
        if task_id not in stored_counts
    ]
    for name, task_ids in normalized.items():
        for task_id in task_ids:
            for key, value in stored_counts.get(task_id, {}).items():
                ret[name][key] = ret[name].get(key, 0) + value

    for key, collection in PROJECT_COUNT_COLLECTIONS.items():
        query_task_ids = (
            live_task_ids
            if key in PROJECT_STATISTIC_FIELDS
            else all_task_ids
        )
        if not query_task_ids:
            continue
        per_task = {}
        match_query = {"task_id": {"$in": query_task_ids}}
        if key == "vuln":
            match_query.update(HOST_COLLISION_EXCLUDE)
        if key == "site":
            scope = formal_site_query if include_noise else visible_site_query
            match_query = scope(match_query)
        elif key == "domain":
            match_query = formal_domain_query(match_query)
        elif key in ("url", "fileleak", "wih", "vuln"):
            match_query = formal_pipeline_query(match_query)
        pipeline = [
            {"$match": match_query},
            {"$group": {"_id": "$task_id", "count": {"$sum": 1}}},
        ]
        for item in utils.conn_db(collection).aggregate(pipeline):
            per_task[str(item.get("_id") or "")] = int(item.get("count", 0) or 0)

        for name, task_ids in normalized.items():
            ret[name][key] = ret[name].get(key, 0) + sum(
                per_task.get(task_id, 0)
                for task_id in task_ids
                if task_id in query_task_ids
            )

    task_projects = {
        task_id: name
        for name, task_ids in normalized.items()
        for task_id in task_ids
    }
    collision_pairs = {name: set() for name in normalized}
    collision_query = {
        "task_id": {"$in": all_task_ids},
        **HOST_COLLISION_CONFIRMED_MATCH,
    }
    collision_projection = {
        "task_id": 1,
        "target": 1,
        "verify_obj": 1,
        "domain": 1,
        "host_collision_domain": 1,
    }
    for item in utils.conn_db("vuln").find(
            collision_query, collision_projection):
        row = normalize_host_collision_item(item)
        project_name = task_projects.get(str(item.get("task_id") or ""))
        if row and project_name:
            collision_pairs[project_name].add((row["ip"], row["host"]))
    for name in normalized:
        ret[name]["host_collision"] = len(collision_pairs[name])
    if len(_PROJECT_COUNT_CACHE) >= 64:
        oldest_key = min(
            _PROJECT_COUNT_CACHE,
            key=lambda key: _PROJECT_COUNT_CACHE[key][0],
        )
        _PROJECT_COUNT_CACHE.pop(oldest_key, None)
    _PROJECT_COUNT_CACHE[cache_key] = (time.monotonic(), ret)
    return ret


PROJECT_COUNT_SORT_FIELDS = {
    "site_cnt": "site",
    "domain_cnt": "domain",
    "ip_cnt": "ip",
    "url_cnt": "url",
    "fileleak_cnt": "fileleak",
    "wih_cnt": "wih",
    "cert_cnt": "cert",
    "vuln_cnt": "vuln",
    "host_collision_cnt": "host_collision",
}


def _project_sort_value(item, field):
    field = {
        "task_cnt": "task_count",
        "update_date": "latest_time",
    }.get(field, field)
    if field == "task_count":
        return len(item.get("task_ids") or [])
    if field == "target_count":
        return len(item.get("targets") or [])
    count_key = PROJECT_COUNT_SORT_FIELDS.get(field)
    if count_key:
        return int((item.get("counts") or {}).get(count_key, 0) or 0)
    return str(item.get(field) or "").lower()


def _sort_project_items(items, orderby_list):
    for field, direction in reversed(orderby_list or [("latest_time", -1)]):
        items.sort(
            key=lambda item: _project_sort_value(item, field),
            reverse=direction < 0,
        )
    return items


@ns.route("/")
class ARLProject(ARLResource):
    parser = get_arl_parser(project_search_fields, location="args")

    @auth
    @ns.expect(parser)
    def get(self):
        args = self.parser.parse_args()
        requested_order = args.get("order") or "-latest_time"
        default_field = self.get_default_field(args)
        page = default_field.get("page", 1)
        size = default_field.get("size", 10)
        orderby_list = self.get_default_field({
            "order": requested_order,
        }).get("order")
        name_filter = str(args.get("name") or "").strip()

        query = {"name": {"$exists": True, "$ne": ""}}
        if name_filter:
            query["name"] = {"$regex": re.escape(name_filter), "$options": "i"}

        tasks = list(utils.conn_db("task").find(
            query,
            {"_id": 1, "name": 1, "target": 1, "status": 1, "start_time": 1, "end_time": 1, "create_time": 1}
        ).sort([("_id", -1)]))

        projects = {}
        for task in tasks:
            name = str(task.get("name") or "").strip()
            if not name:
                continue
            project = projects.setdefault(name, {
                "name": name,
                "task_ids": [],
                "targets": [],
                "statuses": {},
                "latest_time": "",
            })
            task_id = str(task.get("_id"))
            project["task_ids"].append(task_id)
            target = task.get("target")
            if target and target not in project["targets"]:
                project["targets"].append(target)
            status = str(task.get("status") or "")
            if status:
                project["statuses"][status] = project["statuses"].get(status, 0) + 1
            latest = _task_time(task)
            if latest > project["latest_time"]:
                project["latest_time"] = latest

        items = list(projects.values())
        for item in items:
            item["task_count"] = len(item["task_ids"])
            item["target_count"] = len(item["targets"])

        sort_fields = {field for field, _direction in orderby_list}
        needs_all_counts = bool(sort_fields.intersection(PROJECT_COUNT_SORT_FIELDS))
        all_counts_map = {}
        if needs_all_counts:
            all_counts_map = _project_counts_map({
                item["name"]: item["task_ids"]
                for item in items
            })
            for item in items:
                item["counts"] = all_counts_map.get(
                    item["name"], {"task": item["task_count"]})

        _sort_project_items(items, orderby_list)
        total = len(items)
        start = size * (page - 1)
        page_items = items[start:start + size]

        counts_map = all_counts_map or _project_counts_map({
            item["name"]: item["task_ids"]
            for item in page_items
        })

        for item in page_items:
            item["counts"] = counts_map.get(item["name"], {"task": item["task_count"]})
            item["targets"] = item["targets"][:50]

        return {
            "code": 200,
            "page": page,
            "size": size,
            "total": total,
            "items": page_items,
            "query": {"name": name_filter, "order": requested_order},
        }


@ns.route("/assets/")
class ARLProjectAssets(ARLResource):
    parser = get_arl_parser(project_asset_search_fields, location="args")

    @auth
    @ns.expect(parser)
    def get(self):
        args = self.parser.parse_args()
        requested_order = args.get("order")
        default_field = self.get_default_field(args)
        page = default_field.get("page", 1)
        size = default_field.get("size", 10)
        orderby_list = default_field.get("order")

        project_name = str(args.get("name") or "").strip()
        asset_type = str(args.get("asset_type") or "site").strip().lower()
        keyword = str(args.get("q") or "").strip()
        focus = str(args.get("focus") or "").strip().lower()
        include_counts = args.get("include_counts")
        include_noise = bool(args.get("include_noise"))
        quality_view = str(args.get("quality_view") or "focus").strip().lower()
        if include_noise:
            quality_view = "all"
        if quality_view not in ("focus", "primary", "review", "all"):
            quality_view = "focus"
        if include_counts is None:
            include_counts = True
        if asset_type not in PROJECT_ASSETS:
            asset_type = "site"

        task_ids, task_meta = _task_ids_for_project(project_name)
        if not task_ids:
            return {
                "code": 200,
                "page": page,
                "size": size,
                "total": 0,
                "items": [],
                "project": {"name": project_name, "task_count": 0, "task_ids": []},
            }

        if asset_type == "host_collision":
            collision_data = host_collision_page(
                task_ids,
                keyword=keyword,
                order=requested_order or "ip,host",
                page=page,
                size=size,
            )
            project_info = {
                "name": project_name,
                "task_count": len(task_ids),
                "task_ids": task_ids,
            }
            if include_counts:
                project_info["counts"] = _project_counts(
                    task_ids, include_noise=include_noise)
            return {
                "code": 200,
                "page": page,
                "size": size,
                "total": collision_data["total"],
                "items": collision_data["items"],
                "asset_type": asset_type,
                "project": project_info,
                "query": {
                    "name": project_name,
                    "asset_type": asset_type,
                    "q": keyword,
                },
            }

        config = PROJECT_ASSETS[asset_type]
        collection_name = config["collection"]
        if not requested_order:
            orderby_list = self.get_default_field({
                "order": config.get("default_order", "-_id"),
            }).get("order")

        if asset_type == "task":
            object_ids = [ObjectId(task_id) for task_id in task_ids if ObjectId.is_valid(task_id)]
            query = {"_id": {"$in": object_ids}}
        else:
            query = {"task_id": {"$in": task_ids}}
            if asset_type == "vuln":
                query.update(HOST_COLLISION_EXCLUDE)
            if asset_type == "site":
                query = _site_quality_query(query, quality_view)
                query = _site_focus_query(query, focus)
            elif asset_type == "domain":
                query = formal_domain_query(query)
            elif asset_type in ("url", "fileleak", "wih", "vuln"):
                query = formal_pipeline_query(query)
        _apply_keyword_query(query, keyword, config["search_fields"])

        projection = LIST_PROJECTION_EXCLUDES_BY_COLLECTION.get(
            collection_name)
        cursor = utils.conn_db(collection_name).find(
            query, projection).sort(orderby_list).skip(
                size * (page - 1)).limit(size)
        total = utils.conn_db(collection_name).count_documents(query)
        items = [_enrich_item(item, task_meta, project_name) for item in cursor]

        project_info = {
            "name": project_name,
            "task_count": len(task_ids),
            "task_ids": task_ids,
        }
        if include_counts:
            project_info["counts"] = _project_counts(
                task_ids, include_noise=include_noise)
        if asset_type == "site" and include_counts:
            project_info["site_quality_counts"] = _site_quality_counts(task_ids)

        return {
            "code": 200,
            "page": page,
            "size": size,
            "total": total,
            "items": items,
            "asset_type": asset_type,
            "project": project_info,
            "query": {
                "name": project_name,
                "asset_type": asset_type,
                "q": keyword,
                "focus": focus,
                "include_noise": include_noise,
                "quality_view": quality_view,
            },
        }
