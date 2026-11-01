import os
import re
import bson
from datetime import datetime
from flask_restx import Resource, Api, reqparse, fields, Namespace
from bson import ObjectId
from app import celerytask
from app.utils import get_logger, auth
from . import base_query_fields, ARLResource, get_arl_parser, conn
from app import utils
from app.modules import TaskStatus, ErrorMsg, TaskSyncStatus, CeleryAction, TaskTag, TaskType
from app.helpers import get_options_by_policy_id, submit_task_task,\
    submit_risk_cruising, get_scope_by_scope_id, check_target_in_scope
from app.helpers.task import get_task_data, restart_task
from app.services.taskStage import TASK_STAGE_DISPLAY_NAMES, stage_order
from app.utils.host_collision import HOST_COLLISION_EXCLUDE

ns = Namespace('task', description="资产发现任务信息")

logger = get_logger()


def _apply_task_risk_counts(items):
    task_ids = [
        str(item.get("_id") or "")
        for item in items or []
        if item.get("_id")
    ]
    if not task_ids:
        return items

    query = {
        "task_id": {"$in": task_ids},
        **HOST_COLLISION_EXCLUDE,
    }
    pipeline = [
        {"$match": query},
        {"$group": {"_id": "$task_id", "count": {"$sum": 1}}},
    ]
    counts = {
        str(item.get("_id") or ""): int(item.get("count", 0) or 0)
        for item in utils.conn_db("vuln").aggregate(pipeline)
    }
    for item in items:
        statistic = item.get("statistic")
        if not isinstance(statistic, dict):
            statistic = {}
            item["statistic"] = statistic
        statistic["vuln_cnt"] = counts.get(str(item.get("_id") or ""), 0)
    return items

TASK_DATA_COLLECTIONS = (
    "cert", "cert_candidate", "domain", "fileleak", "ip", "service",
    "site", "url", "vuln", "cip", "npoc_service", "wih",
    "nuclei_result", "stat_finger", "asset_seed_candidate",
    "asset_seed_alive", "vhost_ip_candidate", "port_candidate",
    "entry_asset", "cert_probe_state", "fileleak_scan_state",
    "port_site_probe_state", "port_scan_checkpoint",
    "host_collision_checkpoint",
    "asset_seed_probe_state", "domain_brute_batch_state",
    "discovery_delta_state",
)

base_search_task_fields = {
    'name': fields.String(required=False, description="任务名"),
    'target': fields.String(description="任务目标"),
    'query': fields.String(description="任务名称或目标"),
    'status': fields.String(description="任务状态"),
    '_id': fields.String(description="任务ID"),
    'task_tag': fields.String(description="监控任务和侦查任务tag"),
    'options.domain_brute': fields.Boolean(description="是否开启域名爆破"),
    'options.domain_brute_type': fields.String(description="域名爆破类型"),
    'options.port_scan_type': fields.String(description="端口扫描类型"),
    'options.port_scan': fields.Boolean(description="是否的端口扫描"),
    'options.service_detection': fields.Boolean(description="是否开启服务识别"),
    'options.service_brute': fields.Boolean(description="是否开启服务弱口令爆破"),
    'options.os_detection': fields.Boolean(description="是否开启操作系统识别"),
    'options.site_identify': fields.Boolean(description="是否开启站点识别"),
    'options.file_leak': fields.Boolean(description="是否开启文件泄露扫描"),
    'options.alt_dns': fields.Boolean(description="是否开启DNS字典智能生成"),
    'options.search_engines': fields.Boolean(description="是否开启搜索引擎调用"),
    'options.site_spider': fields.Boolean(description="是否开启站点爬虫"),
    'options.arl_search': fields.Boolean(description="是否开启 ARL 历史查询"),
    'options.dns_query_plugin': fields.Boolean(description="是否开启域名插件查询"),
    'options.skip_scan_cdn_ip': fields.Boolean(description="是否跳过CDN IP端口扫描"),
    'options.nuclei_scan': fields.Boolean(description="是否开启nuclei 扫描"),
    'options.findvhost': fields.Boolean(description="是否开启Host碰撞检测"),
    'options.web_info_hunter': fields.Boolean(description="是否开启 webInfoHunter"),
    'statistic.site_cnt': fields.Integer(description="站点数量等于"),
    'statistic.site_cnt__gt': fields.Integer(description="站点数量大于"),
    'statistic.site_cnt__lt': fields.Integer(description="站点数量小于"),
    'statistic.domain_cnt': fields.Integer(description="域名数量等于"),
    'statistic.domain_cnt__gt': fields.Integer(description="域名数量大于"),
    'statistic.domain_cnt__lt': fields.Integer(description="域名数量小于"),
    'statistic.wih_cnt': fields.Integer(description="WIH 数量等于"),
    'statistic.wih_cnt__gt': fields.Integer(description="WIH 数量大于"),
    'statistic.wih_cnt__lt': fields.Integer(description="WIH 数量小于"),
}

base_search_task_fields.update(base_query_fields)

search_task_fields = ns.model('SearchTask', base_search_task_fields)

add_task_fields = ns.model('AddTask', {
    'name': fields.String(required=True, example="task name", description="任务名"),
    'target': fields.String(required=True, example="www.freebuf.com", description="目标"),
    "domain_brute": fields.Boolean(example=True),
    'domain_brute_type': fields.String(example="test"),
    "port_scan_type": fields.String(
        example="test",
        description="端口扫描类型",
        enum=["test", "top100", "top1000", "all", "custom"],
    ),
    "port_scan": fields.Boolean(example=True),
    "service_detection": fields.Boolean(example=False),
    "service_brute": fields.Boolean(example=False),
    "os_detection": fields.Boolean(example=False),
    "site_identify": fields.Boolean(example=False),
    "site_capture": fields.Boolean(example=False),
    "file_leak": fields.Boolean(example=False),
    "search_engines": fields.Boolean(example=False),
    "site_spider": fields.Boolean(example=False),
    "arl_search": fields.Boolean(example=False),
    "alt_dns": fields.Boolean(example=False),
    "ssl_cert": fields.Boolean(example=False),
    "dns_query_plugin": fields.Boolean(example=False, default=False),
    "skip_scan_cdn_ip": fields.Boolean(example=False, default=False),
    "nuclei_scan": fields.Boolean(description="nuclei 扫描", example=False, default=False),
    "nuclei_scan_confirm": fields.Boolean(description="确认启用 nuclei 扫描", example=False, default=False),
    "findvhost": fields.Boolean(example=False, default=False),
    "web_info_hunter": fields.Boolean(example=False, default=False, description="WEB JS 中的信息收集"),
    "wayback_backtrack": fields.Boolean(example=False, default=False, description="wayback 历史回溯"),
    "bface_discover": fields.Boolean(example=False, default=False, description="B 面管理面发现"),
    "bing_deep": fields.Boolean(example=False, default=False, description="Bing 深度搜索"),
    "js_deep": fields.Boolean(example=False, default=False, description="JS 深度分析"),
    "framework_probe": fields.Boolean(example=False, default=False, description="框架驱动目录探测"),
    "ai_judge": fields.Boolean(example=False, default=False, description="AI 资产研判"),
    "port_custom": fields.String(description="自定义扫描端口", example="80,443"),
    "shadow_asset": fields.Boolean(example=False, default=False, description="影子资产识别"),
    "supply_chain_reverse": fields.Boolean(example=False, default=False, description="供应链横向反查"),
})


task_stage_search_fields = ns.model('TaskStageSearch', {
    'task_id': fields.String(required=True, description="任务 ID"),
    'stage': fields.String(description="阶段名"),
    'status': fields.String(description="阶段状态"),
    'error': fields.String(description="失败原因"),
    'page': fields.Integer(description="当前页数", example=1),
    'size': fields.Integer(description="页面大小", example=100),
})


def _task_stage_order(stage_name):
    return stage_order(stage_name)


def _stage_elapsed_seconds(start_value, end_value=None):
    if not start_value:
        return None

    def parse(value):
        if isinstance(value, datetime):
            return value
        if not value:
            return None
        return datetime.strptime(str(value), "%Y-%m-%d %H:%M:%S")

    try:
        start_time = parse(start_value)
        end_time = parse(end_value) or datetime.now()
    except (TypeError, ValueError):
        return None
    return round(max((end_time - start_time).total_seconds(), 0.0), 2)


def _stage_positive_int(value):
    try:
        return max(int(value or 0), 0)
    except (TypeError, ValueError):
        return 0


def _runtime_stage_message(stage_name, extra):
    if stage_name not in (
        "runtime_artifact",
        "entry_feedback_runtime_artifact",
        "discovery_delta_runtime_artifact",
    ):
        return ""
    extra = extra or {}
    parts = []
    metrics = (
        ("runtime_enriched_site_count", "浏览器补全站点"),
        ("browser_title_enriched_site_count", "补标题"),
        ("browser_spa_site_count", "SPA"),
        ("browser_final_title_site_count", "SSO标题"),
        ("script_url_count", "脚本URL"),
        ("js_downloaded_count", "JS落盘"),
        ("map_downloaded_count", "Map"),
        ("source_recovered_count", "源码还原"),
    )
    for field, label in metrics:
        count = _stage_positive_int(extra.get(field))
        if count:
            parts.append("{} {}".format(label, count))
    return "，".join(parts[:5])


def _spider_stage_message(stage_name, extra):
    if stage_name not in (
        "site_spider",
        "entry_feedback_spider",
        "discovery_delta_spider",
    ):
        return ""
    extra = extra or {}
    parts = []
    metrics = (
        ("dynamic_target_count", "动态浏览器目标"),
        ("dynamic_unique_all_url_count", "动态新增URL"),
        ("dynamic_unique_domain_count", "动态新增域名"),
        ("runtime_title_target_count", "标题探测候选"),
        ("runtime_artifact_target_count", "资源归档候选"),
    )
    for field, label in metrics:
        count = _stage_positive_int(extra.get(field))
        if count:
            parts.append("{} {}".format(label, count))
    return "，".join(parts[:5])


def _stage_success_message(stage_name, extra):
    return (
        _runtime_stage_message(stage_name, extra) or
        _spider_stage_message(stage_name, extra)
    )


def _normalize_task_stage_item(item, index):
    stage_name = item.get("stage", "")
    extra = item.get("extra") or {}
    status = str(item.get("status") or "")
    status_display = {
        "running": "运行中",
        "done": "完成",
        "done_with_warnings": "完成（有告警）",
        "partial": "部分完成",
        "deferred": "等待续跑",
        "error": "失败",
        "stop": "已停止",
    }.get(status, status)
    completion_ratio = extra.get("completion_ratio")
    try:
        completion_percent = round(float(completion_ratio) * 100, 1)
    except (TypeError, ValueError):
        completion_percent = None
    source_health = []
    source_status_labels = {
        "done": "完成",
        "done_with_warnings": "完成（有告警）",
        "empty": "无结果",
        "no_resolved_records": "无解析记录",
        "partial": "异常",
        "failed": "失败",
        "timeout": "超时",
        "rate_limited": "限流",
        "skipped": "跳过",
        "running": "运行中",
    }
    for report in extra.get("source_reports") or []:
        if not isinstance(report, dict):
            continue
        source = str(report.get("source") or "unknown")
        source_status = str(report.get("status") or "unknown")
        source_status = source_status_labels.get(source_status, source_status)
        source_health.append("{}: {}".format(source, source_status))
    item["_id"] = str(item.get("_id", ""))
    item["index"] = index
    item["display_name"] = TASK_STAGE_DISPLAY_NAMES.get(stage_name, stage_name)
    item["stage_order"] = _task_stage_order(stage_name)
    item["status_display"] = status_display
    item["completion_percent"] = (
        "{}%".format(completion_percent) if completion_percent is not None else "-")
    item["throughput_per_second"] = extra.get("throughput_per_second", "-")
    item["eta_seconds"] = extra.get("eta_seconds", "-")
    attempt_elapsed = item.get("elapsed")
    if attempt_elapsed is None:
        attempt_elapsed = _stage_elapsed_seconds(
            item.get("start_time"), item.get("end_time"))
    display_start_time = item.get("first_start_time") or item.get("start_time")
    total_elapsed = _stage_elapsed_seconds(
        display_start_time,
        item.get("end_time") if status != "running" else None,
    )
    item["attempt_start_time"] = item.get("start_time") or "-"
    item["display_start_time"] = display_start_time or "-"
    item["attempt_elapsed"] = (
        round(float(attempt_elapsed), 2)
        if attempt_elapsed is not None else "-")
    item["total_elapsed"] = total_elapsed if total_elapsed is not None else "-"
    item["source_health"] = "; ".join(source_health) or "-"
    default_message = _stage_success_message(stage_name, extra) or "-"
    item["message"] = (
        item.get("error") or item.get("warning") or
        item.get("partial_reason") or extra.get("warning") or
        extra.get("partial_reason") or default_message)
    for key in ("input_count", "output_count", "filtered_count", "error_count", "elapsed", "run_count"):
        if item.get(key) == 0:
            item[key] = "0"
    return item


@ns.route('/')
class ARLTask(ARLResource):
    parser = get_arl_parser(search_task_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        任务信息查询
        """
        args = self.parser.parse_args()
        keyword = str(args.pop('query', '') or '').strip()
        base_query = {"archived": {"$ne": True}}
        if keyword:
            base_query['$or'] = [
                {'name': {'$regex': re.escape(keyword), '$options': 'i'}},
                {'target': {'$regex': re.escape(keyword), '$options': 'i'}},
            ]
        data = self.build_data(
            args=args,
            collection='task',
            base_query=base_query,
        )
        _apply_task_risk_counts(data.get("items", []))

        return data

    @auth
    @ns.expect(add_task_fields)
    def post(self):
        """
        任务提交
        """
        args = self.parse_args(add_task_fields)

        name = args.pop('name')
        target = args.pop('target')

        try:
            task_data_list = submit_task_task(target=target, name=name, options=args)
        except Exception as e:
            logger.exception(e)
            return utils.build_ret(ErrorMsg.Error, {"error": str(e)})

        if not task_data_list:
            return utils.build_ret(ErrorMsg.TaskTargetIsEmpty, {"target": target})

        ret = {
            "code": 200,
            "message": "success",
            "items": task_data_list
        }
        return ret

        # return utils.build_ret(ErrorMsg.Success, {"items": task_data_list})



@ns.route('/stage/')
class ARLTaskStage(ARLResource):
    parser = get_arl_parser(task_stage_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        任务阶段详情查询
        """
        args = self.parser.parse_args()
        task_id = args.get("task_id")
        if not task_id or not re.match(r"^[a-fA-F0-9]{24}$", task_id):
            return utils.build_ret(ErrorMsg.Error, {"error": "invalid task_id"})

        task_data = utils.conn_db('task').find_one({'_id': ObjectId(task_id)}, {'_id': 1})
        if not task_data:
            return utils.build_ret(ErrorMsg.NotFoundTask, {"task_id": task_id})

        page = args.get("page") or 1
        size = args.get("size") or 100
        if page <= 0:
            page = 1
        if size <= 0:
            size = 100
        if size > 500:
            size = 500

        query = {'task_id': task_id}
        for field in ("stage", "status", "error"):
            value = args.get(field)
            if value:
                query[field] = {"$regex": re.escape(value), '$options': "i"}

        # Attempt history is useful only in the detail view and can make a
        # stage list response disproportionately large for retry-heavy tasks.
        items = list(utils.conn_db('task_stage').find(query, {"attempts": 0}))
        items.sort(key=lambda item: (_task_stage_order(item.get("stage", "")), item.get("start_time", "")))
        items = [_normalize_task_stage_item(item, index + 1) for index, item in enumerate(items)]

        start = size * (page - 1)
        end = start + size
        return {
            "code": 200,
            "page": page,
            "size": size,
            "total": len(items),
            "items": items[start:end],
        }

batch_stop_fields = ns.model('BatchStop',  {
    "task_id": fields.List(fields.String(description="任务 ID"), required=True),
})


@ns.route('/batch_stop/')
class BatchStopTask(ARLResource):

    @auth
    @ns.expect(batch_stop_fields)
    def post(self):
        """
        任务批量停止
        """
        args = self.parse_args(batch_stop_fields)
        task_id_list = args.pop("task_id", [])
        stop_results = []

        for task_id in task_id_list:
            if not task_id:
                continue
            stop_results.append(_stop_task_fast(task_id, source="batch_stop"))

        return utils.build_ret(ErrorMsg.Success, {"items": stop_results})


@ns.route('/stop/<string:task_id>')
class StopTask(ARLResource):
    @auth
    def get(self, task_id=None):
        """
        任务停止
        """
        return stop_task(task_id=task_id)


def stop_task(task_id, source="api_stop"):
    """任务停止"""
    return _stop_task(task_id=task_id, source=source)


def _revoke_celery_ids(celery_ids, task_id=""):
    control = celerytask.celery.control
    revoked = []
    for celery_id in sorted(set([x for x in celery_ids if x])):
        try:
            control.revoke(celery_id, signal='SIGTERM', terminate=True)
            revoked.append(celery_id)
        except Exception as e:
            logger.warning("revoke celery task error task_id:{} celery_id:{} error:{}".format(
                task_id, celery_id, e))
    return revoked


def _task_celery_ids(task_data):
    celery_ids = set()
    for field in (
            "celery_id", "heavy_top_celery_id", "heavy_full_celery_id",
            "post_celery_id", "post_retry_celery_id", "collision_celery_id",
            "active_celery_id"):
        celery_id = (task_data or {}).get(field)
        if celery_id:
            celery_ids.add(celery_id)
    return celery_ids


def _get_active_celery_ids_by_task_id(task_id):
    active_matches = []
    celery_ids = set()
    try:
        active_tasks = celerytask.celery.control.inspect(timeout=3).active() or {}
    except Exception as e:
        logger.warning("inspect active celery task error task_id:{} error:{}".format(task_id, e))
        return celery_ids, active_matches

    for worker_name, task_items in active_tasks.items():
        for item in task_items or []:
            try:
                data = item.get("kwargs", {}).get("options", {}).get("data", {}) or {}
            except Exception:
                data = {}

            if data.get("task_id") != task_id:
                continue

            celery_id = item.get("id")
            if celery_id:
                celery_ids.add(celery_id)

            delivery_info = item.get("delivery_info", {}) or {}
            active_matches.append({
                "worker": worker_name,
                "celery_id": celery_id,
                "worker_pid": item.get("worker_pid"),
                "redelivered": delivery_info.get("redelivered"),
            })

    return celery_ids, active_matches


def _safe_task_statistic(task_id):
    try:
        return utils.arl.task_statistic(task_id)
    except Exception as e:
        logger.warning("build task statistic error task_id:{} error:{}".format(task_id, e))
        return None


def _finish_running_stages(task_id, status=TaskStatus.STOP, reason=""):
    fields = {
        "status": status,
        "end_time": utils.curr_date(),
        "updated_at": utils.curr_date(),
    }
    if reason:
        fields["stop_reason"] = reason

    return utils.conn_db("task_stage").update_many(
        {"task_id": task_id, "status": "running"},
        {"$set": fields}
    )


def _owner_pid(owner):
    parts = str(owner or "").split(":")
    if len(parts) < 2:
        return None
    try:
        return int(parts[1])
    except (TypeError, ValueError):
        return None


def _cleanup_task_runtime(task_id, reason=""):
    """Clear task runtime locks and scanner child processes left by stopped/deleted tasks."""
    task_id = str(task_id or "")
    if not task_id:
        return {
            "runtime_resource_locks": 0,
            "task_runtime_locks": 0,
            "scanner_parent_pids": [],
        }

    resource_locks = list(utils.conn_db('runtime_resource_lock').find(
        {"task_id": task_id}, {"_id": 1, "owner": 1, "resource": 1, "stage": 1}))
    killed_parent_pids = []
    current_pid = os.getpid()
    for lock in resource_locks:
        pid = _owner_pid(lock.get("owner"))
        if not pid or pid == current_pid or pid in killed_parent_pids:
            continue
        try:
            utils.kill_child_process(pid)
            killed_parent_pids.append(pid)
            logger.info("cleanup task runtime killed scanner children task_id:{} pid:{} resource:{} reason:{}".format(
                task_id, pid, lock.get("resource"), reason))
        except Exception as e:
            logger.warning("cleanup task runtime kill child failed task_id:{} pid:{} resource:{} error:{}".format(
                task_id, pid, lock.get("resource"), e))

    resource_ret = utils.conn_db('runtime_resource_lock').delete_many({"task_id": task_id})
    task_lock_ret = utils.conn_db('task_runtime_lock').delete_many({
        "$or": [{"_id": task_id}, {"task_id": task_id}],
    })
    checkpoint_ret = utils.conn_db('port_scan_checkpoint').update_many(
        {"task_id": task_id, "status": "running"},
        {"$set": {
            "status": "interrupted",
            "updated_at": utils.curr_date(),
            "error": str(reason or "task runtime cleanup")[:1000],
        }},
    )
    host_checkpoint_ret = utils.conn_db('host_collision_checkpoint').update_many(
        {"task_id": task_id, "status": "running"},
        {"$set": {
            "status": "interrupted",
            "updated_at": utils.curr_date(),
            "error": str(reason or "task runtime cleanup")[:1000],
        }},
    )
    return {
        "runtime_resource_locks": resource_ret.deleted_count,
        "task_runtime_locks": task_lock_ret.deleted_count,
        "scanner_parent_pids": killed_parent_pids,
        "port_scan_checkpoints": checkpoint_ret.modified_count,
        "host_collision_checkpoints": host_checkpoint_ret.modified_count,
    }


def _stop_task_fast(task_id, source="batch_stop"):
    """批量停止走快速路径，避免逐个 celery inspect 阻塞前端请求。"""
    done_status = [TaskStatus.DONE, TaskStatus.STOP, TaskStatus.ERROR]

    if not ObjectId.is_valid(str(task_id or "")):
        return utils.build_ret(ErrorMsg.Error, {
            "task_id": task_id,
            "error": "invalid task_id",
        })
    task_obj_id = ObjectId(task_id)
    task_data = utils.conn_db('task').find_one({'_id': task_obj_id})
    if not task_data:
        return utils.build_ret(ErrorMsg.NotFoundTask, {"task_id": task_id})

    if task_data["status"] in done_status:
        return utils.build_ret(ErrorMsg.TaskIsDone, {"task_id": task_id})

    celery_ids = _task_celery_ids(task_data)

    statistic = _safe_task_statistic(task_id)
    update_data = {
        "$set": {
            "status": TaskStatus.STOP,
            "end_time": utils.curr_date(),
            "workflow_phase": "stopped",
            "workflow_updated_at": utils.curr_date(),
            "workflow_recovery_pending": False,
            "stop_reason": source,
            "stop_source": "api",
            "stopped_celery_ids": [],
            "active_celery_matches": [],
            "fast_stop": True,
        }
    }
    if statistic is not None:
        update_data["$set"]["statistic"] = statistic

    utils.conn_db('task').update_one({'_id': task_obj_id}, update_data)
    revoked = _revoke_celery_ids(celery_ids, task_id=task_id)
    utils.conn_db('task').update_one(
        {'_id': task_obj_id},
        {"$set": {"stopped_celery_ids": revoked}},
    )
    _finish_running_stages(task_id, status=TaskStatus.STOP, reason=source)
    cleanup = _cleanup_task_runtime(task_id, reason=source)

    return utils.build_ret(ErrorMsg.Success, {
        "task_id": task_id,
        "revoked_celery_ids": revoked,
        "active_celery_matches": [],
        "fast_stop": True,
        "cleanup": cleanup,
    })


def _stop_task(task_id, source="api_stop"):
    """任务停止"""
    done_status = [TaskStatus.DONE, TaskStatus.STOP, TaskStatus.ERROR]

    if not ObjectId.is_valid(str(task_id or "")):
        return utils.build_ret(ErrorMsg.Error, {
            "task_id": task_id,
            "error": "invalid task_id",
        })
    task_obj_id = ObjectId(task_id)
    task_data = utils.conn_db('task').find_one({'_id': task_obj_id})
    if not task_data:
        return utils.build_ret(ErrorMsg.NotFoundTask, {"task_id": task_id})

    if task_data["status"] in done_status:
        return utils.build_ret(ErrorMsg.TaskIsDone, {"task_id": task_id})

    celery_ids, active_matches = _get_active_celery_ids_by_task_id(task_id)
    celery_ids.update(_task_celery_ids(task_data))

    statistic = _safe_task_statistic(task_id)
    update_data = {
        "$set": {
            "status": TaskStatus.STOP,
            "end_time": utils.curr_date(),
            "workflow_phase": "stopped",
            "workflow_updated_at": utils.curr_date(),
            "workflow_recovery_pending": False,
            "stop_reason": source,
            "stop_source": "api",
            "stopped_celery_ids": [],
            "active_celery_matches": active_matches,
        }
    }
    if statistic is not None:
        update_data["$set"]["statistic"] = statistic

    utils.conn_db('task').update_one({'_id': task_obj_id}, update_data)
    revoked = _revoke_celery_ids(celery_ids, task_id=task_id)
    utils.conn_db('task').update_one(
        {'_id': task_obj_id},
        {"$set": {"stopped_celery_ids": revoked}},
    )
    _finish_running_stages(task_id, status=TaskStatus.STOP, reason=source)
    cleanup = _cleanup_task_runtime(task_id, reason=source)

    return utils.build_ret(ErrorMsg.Success, {
        "task_id": task_id,
        "revoked_celery_ids": revoked,
        "active_celery_matches": active_matches,
        "cleanup": cleanup,
    })


delete_task_fields = ns.model('DeleteTask',  {
    'del_task_data': fields.Boolean(required=False, default=False, description="是否删除任务数据"),
    'task_id': fields.List(fields.String(required=True, description="任务ID"))
})


@ns.route('/delete/')
class DeleteTask(ARLResource):
    @auth
    @ns.expect(delete_task_fields)
    def post(self):
        """
        任务删除
        """
        done_status = [TaskStatus.DONE, TaskStatus.STOP, TaskStatus.ERROR]
        args = self.parse_args(delete_task_fields)
        task_id_list = args.pop('task_id')
        del_task_data_flag = args.pop('del_task_data')
        deleted = []
        skipped = []

        for task_id in task_id_list:
            try:
                task_obj_id = ObjectId(task_id)
            except Exception:
                skipped.append({
                    "task_id": task_id,
                    "reason": "invalid_task_id",
                    "message": "invalid task_id",
                })
                continue

            task_data = utils.conn_db('task').find_one({'_id': task_obj_id})
            if not task_data:
                _cleanup_task_runtime(task_id, reason="delete_not_found")
                skipped.append({
                    "task_id": task_id,
                    "reason": "not_found",
                    "message": ErrorMsg.NotFoundTask["message"],
                })
                continue

            task_status = task_data.get("status")
            if task_status not in done_status:
                skipped.append({
                    "task_id": task_id,
                    "target": task_data.get("target"),
                    "status": task_status,
                    "reason": "running",
                    "message": ErrorMsg.TaskIsRunning["message"],
                })
                continue

            if del_task_data_flag:
                _cleanup_task_runtime(task_id, reason="delete_purge")
                ret = utils.conn_db('task').delete_many({'_id': task_obj_id})
                utils.conn_db('task_stage').delete_many({'task_id': task_id})
                for name in TASK_DATA_COLLECTIONS:
                    utils.conn_db(name).delete_many({'task_id': task_id})
                changed_count = ret.deleted_count
                delete_mode = "purged"
            else:
                _cleanup_task_runtime(task_id, reason="delete_archive")
                ret = utils.conn_db('task').update_one(
                    {'_id': task_obj_id},
                    {"$set": {
                        "archived": True,
                        "archived_at": utils.curr_date(),
                        "archived_status": task_status,
                    }},
                )
                changed_count = ret.modified_count
                delete_mode = "archived"

            deleted.append({
                "task_id": task_id,
                "target": task_data.get("target"),
                "status": task_status,
                "deleted": changed_count,
                "mode": delete_mode,
            })

        return utils.build_ret(ErrorMsg.Success, {
            "task_id": task_id_list,
            "deleted": deleted,
            "skipped": skipped,
            "deleted_count": len(deleted),
            "skipped_count": len(skipped),
        })


sync_task_fields = ns.model('SyncTask',  {
    'task_id': fields.String(required=True, description="任务ID"),
    'scope_id': fields.String(required=True, description="资产范围ID"),
})


def _submit_task_sync(task_data, task_id, scope_id):
    options = {
        "celery_action": CeleryAction.DOMAIN_TASK_SYNC_TASK,
        "data": {
            "task_id": task_id,
            "scope_id": scope_id,
        },
    }
    claim_query = {
        "_id": task_data["_id"],
        "$or": [
            {"sync_status": {"$exists": False}},
            {"sync_status": {"$in": [TaskSyncStatus.DEFAULT, TaskSyncStatus.ERROR]}},
        ],
    }
    claim_result = conn("task").update_one(claim_query, {"$set": {
        "sync_status": TaskSyncStatus.WAITING,
        "sync_scope_id": scope_id,
        "sync_requested_at": utils.curr_date(),
        "sync_error": "",
    }})
    if not claim_result.matched_count:
        return utils.build_ret(ErrorMsg.TaskSyncDealing, {"task_id": task_id})

    try:
        celery_id = celerytask.arl_task.delay(options=options)
        conn("task").update_one(
            {"_id": task_data["_id"], "sync_status": TaskSyncStatus.WAITING},
            {"$set": {"sync_celery_id": str(celery_id)}},
        )
    except Exception as e:
        logger.exception("submit task sync failed task_id:{} scope_id:{}".format(
            task_id, scope_id))
        conn("task").update_one(
            {"_id": task_data["_id"], "sync_status": TaskSyncStatus.WAITING},
            {"$set": {
                "sync_status": TaskSyncStatus.ERROR,
                "sync_error": str(e)[:500],
            }},
        )
        return utils.build_ret(ErrorMsg.Error, {
            "task_id": task_id,
            "error": str(e),
        })

    return utils.build_ret(ErrorMsg.Success, {"task_id": task_id})


@ns.route('/sync/')
class SyncTask(ARLResource):
    @auth
    @ns.expect(sync_task_fields)
    def post(self):
        """
        将任务结果同步到资产组
        """
        done_status = [TaskStatus.DONE, TaskStatus.STOP, TaskStatus.ERROR]
        args = self.parse_args(sync_task_fields)
        task_id = args.pop('task_id')
        scope_id = args.pop('scope_id')

        query = {'_id': ObjectId(task_id)}
        task_data = utils.conn_db('task').find_one(query)
        if not task_data:
            return utils.build_ret(ErrorMsg.NotFoundTask, {"task_id": task_id})

        asset_scope_data = utils.conn_db('asset_scope').find_one({'_id': ObjectId(scope_id)})
        if not asset_scope_data:
            return utils.build_ret(ErrorMsg.NotFoundScopeID, {"task_id": task_id})

        if task_data.get("type") != "domain":
            return utils.build_ret(ErrorMsg.TaskTypeIsNotDomain, {"task_id": task_id})

        if not utils.is_in_scopes(task_data["target"], asset_scope_data["scope_array"]):
            return utils.build_ret(ErrorMsg.TaskTargetNotInScope, {"task_id": task_id})

        if task_data["status"] not in done_status:
            return utils.build_ret(ErrorMsg.TaskIsRunning, {"task_id": task_id})

        task_sync_status = task_data.get("sync_status", TaskSyncStatus.DEFAULT)

        if task_sync_status not in [TaskSyncStatus.DEFAULT, TaskSyncStatus.ERROR]:
            return utils.build_ret(ErrorMsg.TaskSyncDealing, {"task_id": task_id})

        return _submit_task_sync(task_data, task_id, scope_id)


sync_scope_fields = ns.model('SyncScope',  {
    'target': fields.String(required=True, description="需要同步的目标"),
})


# ******* 根据目标找到要同步的资产分组ID *********
@ns.route('/sync_scope/')
class Target2Scope(ARLResource):
    parser = get_arl_parser(sync_scope_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        从目标映反查资产分组
        """
        args = self.parser.parse_args()
        target = args.pop("target")
        if not utils.is_valid_domain(target):
            return utils.build_ret(ErrorMsg.DomainInvalid, {"target": target})

        args["scope_array"] = utils.get_fld(target)
        args["size"] = 100
        args["order"] = "_id"

        data = self.build_data(args=args, collection='asset_scope')
        ret = []
        for item in data["items"]:
            if utils.is_in_scopes(target, item["scope_array"]):
                ret.append(item)

        data["items"] = ret
        data["total"] = len(ret)
        return data


'''任务通过策略下发字段'''
task_by_policy_fields = ns.model('TaskByPolicy', {
    "name": fields.String(description="任务名称", default=True, required=True),
    "task_tag": fields.String(description="任务类型标签", enum=["task", "risk_cruising"], required=True),
    "target": fields.String(description="任务目标", example="", required=False),
    "policy_id": fields.String(description="策略 ID", example="603c65316591e73dd717d176", required=True),
    "result_set_id": fields.String(description="结果集 ID", example="603c65316591e73dd717d176", required=False)
})


# ******* 通过指定策略ID 下发任务 *********
@ns.route('/policy/')
class TaskByPolicy(ARLResource):
    @auth
    @ns.expect(task_by_policy_fields)
    def post(self):
        """
        任务通过策略下发
        """
        args = self.parse_args(task_by_policy_fields)
        name = args.pop("name")
        policy_id = args.pop("policy_id")
        target = args.pop("target")
        task_tag = args.pop("task_tag")
        result_set_id = args.pop("result_set_id")
        task_tag_enum = task_by_policy_fields["task_tag"].enum

        if task_tag not in task_tag_enum:
            return utils.build_ret("task_tag 只能取 {}".format(",".join(task_tag_enum)), {})

        options = get_options_by_policy_id(policy_id, task_tag)

        if not options:
            return utils.build_ret(ErrorMsg.PolicyIDNotFound, {"policy_id": policy_id})

        task_data_list = []
        try:
            if task_tag == TaskTag.TASK:
                # 对于资产发现任务检验通过策略关联的资产组
                related_scope_id = options.get("related_scope_id", "")
                if related_scope_id:
                    scope_data = get_scope_by_scope_id(scope_id=related_scope_id)
                    if not scope_data:
                        return utils.build_ret(ErrorMsg.NotFoundScopeID, {"scope_id": related_scope_id})
                    
                    check_target_in_scope(target=target, scope_list=scope_data["scope_array"])

                task_data_list = submit_task_task(target=target, name=name, options=options)
                if not task_data_list:
                    return utils.build_ret(ErrorMsg.TaskTargetIsEmpty, {"target": target})

            if task_tag == TaskTag.RISK_CRUISING:
                if result_set_id:
                    query = {"_id": ObjectId(result_set_id)}
                    item = utils.conn_db('result_set').find_one(query, {"total": 1})
                    if not item:
                        return utils.build_ret(ErrorMsg.ResultSetIDNotFound, {"result_set_id": result_set_id})

                    target_len = item["total"]

                    if target_len == 0:
                        return utils.build_ret(ErrorMsg.ResultSetIsEmpty, {"result_set_id": result_set_id})

                    options["result_set_id"] = result_set_id
                    options["result_set_len"] = target_len

                    task_data_list = submit_risk_cruising(target=target, name=name, options=options)
                    if not task_data_list:
                        return utils.build_ret(ErrorMsg.Error, {"result_set_id": result_set_id})

                else:
                    task_data_list = submit_risk_cruising(target=target, name=name, options=options)
                    if not task_data_list:
                        return utils.build_ret(ErrorMsg.TaskTargetIsEmpty, {"target": target})
        except Exception as e:
            logger.exception(e)
            return utils.build_ret(ErrorMsg.Error, {"error": str(e)})

        return utils.build_ret(ErrorMsg.Success, {"items": task_data_list})


restart_task_fields = ns.model('DeleteTask',  {
    'task_id': fields.List(fields.String(required=True, description="任务ID"))
})


# ******* 重新下发任务功能 *********
@ns.route('/restart/')
class TaskRestart(ARLResource):
    @auth
    @ns.expect(restart_task_fields)
    def post(self):
        """
        任务重启
        """
        done_status = [TaskStatus.DONE, TaskStatus.STOP, TaskStatus.ERROR]
        args = self.parse_args(restart_task_fields)
        task_id_list = args.pop('task_id')

        try:
            for task_id in task_id_list:
                task_data = get_task_data(task_id)
                if not task_data:
                    return utils.build_ret(ErrorMsg.NotFoundTask, {"task_id": task_id})

                if task_data["status"] not in done_status:
                    return utils.build_ret(ErrorMsg.TaskIsRunning, {"task_id": task_id})

                restart_task(task_id)

        except Exception as e:
            return utils.build_ret(ErrorMsg.Error, {"error": str(e)})

        return utils.build_ret(ErrorMsg.Success, {"task_id": task_id_list})
