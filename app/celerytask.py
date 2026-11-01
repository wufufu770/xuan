import signal
import time
from bson import ObjectId
from app.config import Config
from celery import Celery, platforms, current_task
from kombu import Exchange, Queue
from app import utils
from app import tasks as wrap_tasks
from app.modules import CeleryAction, TaskSyncStatus, TaskStatus, CeleryRoutingKey
from app.helpers.task import normalize_task_options

logger = utils.get_logger()

celery = Celery('task', broker=Config.CELERY_BROKER_URL)
TASK_LOCK_TTL = 24 * 60 * 60
TASK_DONE_STATUS = [TaskStatus.DONE, TaskStatus.STOP, TaskStatus.ERROR]
LOCKED_TASK_ACTIONS = {
    CeleryAction.DOMAIN_TASK,
    CeleryAction.DOMAIN_HEAVY_TOP_TASK,
    CeleryAction.DOMAIN_HEAVY_FULL_TASK,
    CeleryAction.DOMAIN_POST_TASK,
    CeleryAction.DOMAIN_COLLISION_TASK,
    CeleryAction.IP_TASK,
    CeleryAction.FOFA_TASK,
    CeleryAction.RUN_RISK_CRUISING,
    CeleryAction.ASSET_SITE_UPDATE,
    CeleryAction.ADD_ASSET_SITE_TASK,
    CeleryAction.ASSET_WIH_UPDATE,
}


def _direct_queue(name, priority=False):
    queue_arguments = {"x-max-priority": 10} if priority else None
    return Queue(
        name,
        exchange=Exchange(name, type="direct", durable=True),
        routing_key=name,
        queue_arguments=queue_arguments,
    )


celery.conf.update(
    task_acks_late=False,
    worker_prefetch_multiplier=1,
    broker_transport_options={"max_retries": 3, "interval_start": 0, "interval_step": 0.2, "interval_max": 0.5},
    task_queues=(
        _direct_queue(CeleryRoutingKey.ASSET_TASK),
        _direct_queue(CeleryRoutingKey.HEAVY_TOP_TASK, priority=True),
        _direct_queue(CeleryRoutingKey.HEAVY_FULL_TASK, priority=True),
        _direct_queue(CeleryRoutingKey.POST_TASK),
        _direct_queue(CeleryRoutingKey.POST_RETRY_TASK, priority=True),
        _direct_queue(CeleryRoutingKey.COLLISION_TASK, priority=True),
        _direct_queue(CeleryRoutingKey.GITHUB_TASK),
    ),
)
platforms.C_FORCE_ROOT = True


def _current_task_data():
    try:
        return current_task.request.kwargs.get("options", {}).get("data", {}) or {}
    except Exception:
        return {}


def _task_is_done(task_id):
    if not task_id:
        return False
    try:
        task = utils.conn_db('task').find_one({"_id": ObjectId(task_id)}, {"status": 1})
    except Exception as e:
        logger.warning("check task status error task_id:{} error:{}".format(task_id, e))
        return False

    if not task:
        return True

    return task.get("status") in TASK_DONE_STATUS


def _should_lock_task(action, data):
    return action in LOCKED_TASK_ACTIONS and data.get("task_id")


def _task_lock_id(action, task_id):
    if action in {
            CeleryAction.DOMAIN_HEAVY_TOP_TASK,
            CeleryAction.DOMAIN_HEAVY_FULL_TASK,
            CeleryAction.DOMAIN_POST_TASK,
            CeleryAction.DOMAIN_COLLISION_TASK}:
        return "{}:{}".format(task_id, action)
    return task_id


def _acquire_task_lock(action, data):
    task_id = data.get("task_id")
    lock_id = _task_lock_id(action, task_id)
    target = data.get("target")
    celery_id = current_task.request.id
    now = time.time()
    expired_before = now - TASK_LOCK_TTL
    query = {
        "_id": lock_id,
        "$or": [
            {"celery_id": celery_id},
            {"locked_at": {"$lt": expired_before}},
        ]
    }
    update = {
        "$set": {
            "action": action,
            "task_id": task_id,
            "target": target,
            "celery_id": celery_id,
            "locked_at": now,
            "updated_at": now,
        },
        "$setOnInsert": {
            "created_at": now,
        }
    }

    try:
        result = utils.conn_db('task_runtime_lock').update_one(query, update, upsert=True)
    except Exception as e:
        logger.warning("skip duplicated task task_id:{} target:{} celery_id:{} lock_error:{}".format(
            task_id, target, celery_id, e))
        return ""

    acquired = bool(result.upserted_id or result.matched_count or result.modified_count)
    if not acquired:
        logger.warning("skip duplicated task task_id:{} target:{} celery_id:{} lock_not_acquired".format(
            task_id, target, celery_id))
    if acquired:
        try:
            utils.conn_db("task").update_one(
                {"_id": ObjectId(task_id)},
                {"$set": {
                    "active_celery_id": celery_id,
                    "active_celery_action": action,
                    "active_celery_updated_at": utils.curr_date(),
                }},
            )
        except Exception as e:
            logger.warning(
                "update active celery task:{} id:{} error:{}".format(
                    task_id, celery_id, e))
    return lock_id if acquired else ""


def _release_task_lock(lock_id, celery_id):
    if not lock_id or not celery_id:
        return

    try:
        utils.conn_db('task_runtime_lock').delete_one({"_id": lock_id, "celery_id": celery_id})
        utils.conn_db("task").update_one(
            {"active_celery_id": celery_id},
            {"$unset": {
                "active_celery_id": "",
                "active_celery_action": "",
                "active_celery_updated_at": "",
            }},
        )
    except Exception as e:
        logger.warning("release task lock error lock_id:{} celery_id:{} error:{}".format(
            lock_id, celery_id, e))


def _claim_workflow_phase(task_id, expected_phases, running_phase, allow_missing=False):
    phase_conditions = [{"workflow_phase": {"$in": list(expected_phases)}}]
    if allow_missing:
        phase_conditions.append({"workflow_phase": {"$exists": False}})
    try:
        celery_id = current_task.request.id
    except Exception:
        celery_id = ""
    if celery_id:
        phase_conditions.append({
            "workflow_phase": running_phase,
            "workflow_celery_id": celery_id,
        })
    query = {
        "_id": ObjectId(task_id),
        "status": {"$nin": TASK_DONE_STATUS},
        "$or": phase_conditions,
    }
    task_collection = utils.conn_db("task")
    task_data = task_collection.find_one(
        {"_id": ObjectId(task_id), "status": {"$nin": TASK_DONE_STATUS}},
        {
            "status": 1,
            "workflow_queued_status": 1,
            "workflow_queue": 1,
            "workflow_queued_at": 1,
        },
    ) or {}
    now = utils.curr_date()
    fields = {
        "workflow_phase": running_phase,
        "workflow_updated_at": now,
        "workflow_started_at": now,
        "workflow_error": "",
        "workflow_celery_id": celery_id,
        "workflow_recovery_pending": False,
    }
    queued_status = str(task_data.get("workflow_queued_status") or "").strip()
    if queued_status:
        fields.update({
            "status": queued_status,
            "workflow_running_status": queued_status,
        })
    if task_data.get("workflow_queue"):
        fields["workflow_last_queue"] = task_data["workflow_queue"]
    if task_data.get("workflow_queued_at"):
        fields["workflow_last_queued_at"] = task_data["workflow_queued_at"]
    result = task_collection.update_one(query, {
        "$set": fields,
        "$unset": {
            "worker_signal": "",
            "worker_signal_at": "",
            "worker_signal_celery_id": "",
            "workflow_queued_status": "",
            "workflow_queue": "",
            "workflow_queued_at": "",
        },
    })
    return bool(result.matched_count)


def _mark_workflow_error(task_id, phase, error):
    utils.conn_db("task").update_one(
        {"_id": ObjectId(task_id), "status": {"$nin": TASK_DONE_STATUS}},
        {"$set": {
            "status": TaskStatus.ERROR,
            "workflow_phase": "{}_error".format(phase),
            "workflow_error": str(error)[:1000],
            "end_time": utils.curr_date(),
        }},
    )


def _queue_domain_phase(data, current_phase, queued_phase, action, task_fun,
                        celery_id_field, status, priority=None, countdown=None,
                        queue=None):
    task_id = data.get("task_id")
    query = {
        "_id": ObjectId(task_id),
        "status": {"$nin": TASK_DONE_STATUS},
        "workflow_phase": current_phase,
    }
    now = utils.curr_date()
    result = utils.conn_db("task").update_one(query, {
        "$set": {
            "workflow_phase": queued_phase,
            "workflow_updated_at": now,
            "workflow_queued_at": now,
            "workflow_queued_status": status,
            "workflow_queue": str(queue or ""),
            "status": TaskStatus.WAITING,
        },
        "$unset": {
            "workflow_celery_id": "",
            "workflow_running_status": "",
        },
    })
    if not result.matched_count:
        logger.warning("skip enqueue workflow phase task:{} current:{} queued:{}".format(
            task_id, current_phase, queued_phase))
        return ""

    queued_data = dict(data)
    try:
        fresh_task = utils.conn_db("task").find_one(
            {"_id": ObjectId(task_id)},
            {"options": 1},
        )
        if fresh_task and isinstance(fresh_task.get("options"), dict):
            queued_data["options"] = normalize_task_options(fresh_task["options"])
    except Exception as e:
        logger.warning("refresh workflow options failed task:{} error:{}".format(
            task_id, e))

    task_options = {
        "celery_action": action,
        "data": queued_data,
    }
    try:
        kwargs = {"options": task_options}
        apply_options = {"kwargs": kwargs}
        if priority is not None:
            apply_options["priority"] = priority
        if countdown is not None:
            apply_options["countdown"] = countdown
        if queue:
            apply_options["queue"] = queue
        async_result = task_fun.apply_async(**apply_options)
        celery_id = str(async_result)
        utils.conn_db("task").update_one(
            {"_id": ObjectId(task_id)},
            {"$set": {celery_id_field: celery_id}},
        )
        logger.info("queued workflow task:{} phase:{} celery_id:{}".format(
            task_id, queued_phase, celery_id))
        return celery_id
    except Exception as e:
        logger.exception("enqueue workflow failed task:{} phase:{}".format(task_id, queued_phase))
        _mark_workflow_error(task_id, queued_phase, e)
        return ""


@celery.task(
    queue=CeleryRoutingKey.ASSET_TASK,
    acks_late=True,
    reject_on_worker_lost=True,
)
def arl_task(options):
    # 这里不检验 celery_action， 调用的时候区分
    run_task(options)


@celery.task(
    queue=CeleryRoutingKey.HEAVY_TASK,
    acks_late=True,
    reject_on_worker_lost=True,
)
def arl_heavy(options):
    run_task(options)


@celery.task(
    queue=CeleryRoutingKey.POST_TASK,
    acks_late=True,
    reject_on_worker_lost=True,
)
def arl_post(options):
    run_task(options)


@celery.task(
    queue=CeleryRoutingKey.COLLISION_TASK,
    acks_late=True,
    reject_on_worker_lost=True,
)
def arl_collision(options):
    run_task(options)


def sigterm_handler(signum, frame):
    if not current_task:
        return
    celery_id = current_task.request.id
    routing_key = current_task.request.delivery_info['routing_key']
    logger.info(f"Caught signal {signum}, celery_id:{celery_id} terminating {routing_key}...")

    logger.info(f"{current_task.request}")

    try:
        task_data = _current_task_data()
        task_id = task_data.get("task_id")
        if routing_key in {
                CeleryRoutingKey.ASSET_TASK,
                CeleryRoutingKey.HEAVY_TOP_TASK,
                CeleryRoutingKey.HEAVY_FULL_TASK,
                CeleryRoutingKey.POST_TASK,
                CeleryRoutingKey.POST_RETRY_TASK,
                CeleryRoutingKey.COLLISION_TASK}:
            if task_id:
                task_query = {"_id": ObjectId(task_id)}
                task_data = utils.conn_db("task").find_one(
                    task_query, {"status": 1, "stop_source": 1}) or {}
                if task_data.get("status") == TaskStatus.STOP:
                    utils.conn_db("task").update_one(task_query, {"$set": {
                        "stop_celery_id": celery_id,
                        "worker_signal": signum,
                        "worker_signal_at": utils.curr_date(),
                    }})
                elif task_data.get("status") not in (TaskStatus.DONE, TaskStatus.ERROR):
                    # Late-acked ARL work must remain resumable when a worker
                    # process disappears. The broker will redeliver the same
                    # Celery id, which can reclaim both workflow and task locks.
                    utils.conn_db("task").update_one(task_query, {"$set": {
                        "workflow_recovery_pending": True,
                        "worker_signal": signum,
                        "worker_signal_at": utils.curr_date(),
                        "worker_signal_celery_id": celery_id,
                    }})
                interrupted_at = utils.curr_date()
                interrupted_reason = "worker signal {} celery_id:{}".format(
                    signum, celery_id)
                if routing_key in {
                        CeleryRoutingKey.POST_TASK,
                        CeleryRoutingKey.POST_RETRY_TASK}:
                    result = utils.conn_db("fileleak_scan_state").update_many(
                        {"task_id": task_id, "status": "running"},
                        {"$set": {
                            "status": "interrupted",
                            "updated_at": interrupted_at,
                            "finished_at": interrupted_at,
                            "interrupted_reason": interrupted_reason,
                        }},
                    )
                    logger.info(
                        "worker signal interrupted ffuf checkpoints task:{} count:{}".format(
                            task_id, result.modified_count))
                if routing_key in {
                        CeleryRoutingKey.HEAVY_TOP_TASK,
                        CeleryRoutingKey.HEAVY_FULL_TASK}:
                    result = utils.conn_db("port_scan_checkpoint").update_many(
                        {"task_id": task_id, "status": "running"},
                        {"$set": {
                            "status": "interrupted",
                            "updated_at": interrupted_at,
                            "error": interrupted_reason,
                        }},
                    )
                    logger.info(
                        "worker signal interrupted port checkpoints task:{} count:{}".format(
                            task_id, result.modified_count))
                if routing_key == CeleryRoutingKey.COLLISION_TASK:
                    result = utils.conn_db("host_collision_checkpoint").update_many(
                        {"task_id": task_id, "status": "running"},
                        {"$set": {
                            "status": "interrupted",
                            "updated_at": interrupted_at,
                            "error": interrupted_reason,
                        }},
                    )
                    logger.info(
                        "worker signal interrupted host collision checkpoints "
                        "task:{} count:{}".format(
                            task_id, result.modified_count))
            else:
                logger.warning("worker signal without ARL task_id celery_id:{}".format(
                    celery_id))
            _release_task_lock(_task_lock_id(
                current_task.request.kwargs.get("options", {}).get("celery_action"), task_id), celery_id)
        elif routing_key == CeleryRoutingKey.GITHUB_TASK:
            query = {'celery_id': celery_id}
            utils.conn_db('github_task').update_one(query, {"$set": {
                "status": TaskStatus.STOP,
                "end_time": utils.curr_date(),
                "stop_reason": "sigterm:{}".format(signum),
                "stop_source": "worker_signal",
                "stop_celery_id": celery_id,
            }})
    except Exception as e:
        logger.error(f"update celery_id:{celery_id} status error: {e}")

    utils.exit_gracefully(signum, frame)


def run_task(options):
    signal.signal(signal.SIGTERM, sigterm_handler)
    action = options.get("celery_action")
    data = options.get("data") or {}
    action_map = {
        CeleryAction.DOMAIN_TASK_SYNC_TASK: domain_task_sync,
        CeleryAction.DOMAIN_EXEC_TASK: domain_exec,
        CeleryAction.IP_EXEC_TASK: ip_exec,
        CeleryAction.DOMAIN_TASK: domain_task,
        CeleryAction.DOMAIN_HEAVY_TOP_TASK: domain_heavy_top_task,
        CeleryAction.DOMAIN_HEAVY_FULL_TASK: domain_heavy_full_task,
        CeleryAction.DOMAIN_POST_TASK: domain_post_task,
        CeleryAction.DOMAIN_COLLISION_TASK: domain_collision_task,
        CeleryAction.IP_TASK: ip_task,
        CeleryAction.RUN_RISK_CRUISING: run_risk_cruising_task,
        CeleryAction.FOFA_TASK: fofa_task,
        CeleryAction.GITHUB_TASK_TASK: github_task_task,
        CeleryAction.GITHUB_TASK_MONITOR: github_task_monitor,
        CeleryAction.ASSET_SITE_UPDATE: asset_site_update,
        CeleryAction.ADD_ASSET_SITE_TASK: asset_site_add_task,
        CeleryAction.ASSET_WIH_UPDATE: asset_wih_update_task,
        CeleryAction.AI_JUDGE_TASK: ai_judge_task,
    }
    start_time = time.time()
    # 这里监控任务 task_id 和 target 是空的
    logger.info("run_task action:{} time: {}".format(action, start_time))
    logger.info("name:{}, target:{}, task_id:{}".format(
        data.get("name"), data.get("target"), data.get("task_id")))
    acquired_lock_id = ""
    try:
        fun = action_map.get(action)
        if fun:
            if _should_lock_task(action, data):
                task_id = data.get("task_id")
                if _task_is_done(task_id):
                    logger.warning("skip terminal task action:{} task_id:{} target:{}".format(
                        action, task_id, data.get("target")))
                    return

                acquired_lock_id = _acquire_task_lock(action, data)
                if not acquired_lock_id:
                    return

            fun(data)
        else:
            logger.warning("not found {} action".format(action))
    except Exception as e:
        logger.exception(e)
    finally:
        if acquired_lock_id:
            _release_task_lock(acquired_lock_id, current_task.request.id)

    elapsed = time.time() - start_time
    logger.info("end {} elapsed: {}".format(action, elapsed))


@celery.task(queue=CeleryRoutingKey.GITHUB_TASK)
def arl_github(options):
    # 这里不检验 celery_action， 调用的时候区分
    run_task(options)


def domain_exec(options):
    """域名监测任务"""
    scope_id = options.get("scope_id")
    domain = options.get("domain")
    job_id = options.get("job_id")
    monitor_options = options.get("monitor_options")
    name = options.get("name")
    wrap_tasks.domain_executors(base_domain=domain, job_id=job_id,
                                scope_id=scope_id, options=monitor_options, name=name)


def domain_task_sync(options):
    """域名同步任务"""
    from app.services.syncAsset import sync_asset
    scope_id = options.get("scope_id")
    task_id = options.get("task_id")
    query = {"_id": ObjectId(task_id)}
    try:
        update = {"$set": {"sync_status": TaskSyncStatus.RUNNING}}
        utils.conn_db('task').update_one(query, update)

        sync_asset(task_id, scope_id, update_flag=False)

        update = {"$set": {"sync_status": TaskSyncStatus.DEFAULT}}
        utils.conn_db('task').update_one(query, update)
    except Exception as e:
        update = {"$set": {"sync_status": TaskSyncStatus.ERROR}}
        utils.conn_db('task').update_one(query, update)
        logger.exception(e)


def domain_task(options):
    """常规域名任务"""
    target = options["target"]
    task_options = options["options"]
    task_id = options["task_id"]
    item = utils.conn_db('task').find_one({"_id": ObjectId(task_id)})
    if not item:
        logger.info("domain_task not found {} {}".format(target, item))
        return

    if not getattr(Config, "DOMAIN_PHASED_WORKFLOW", True):
        wrap_tasks.domain_task(target, task_id, task_options, phase="full")
        utils.conn_db("task").update_one(
            {"_id": ObjectId(task_id), "status": TaskStatus.DONE},
            {"$set": {"workflow_phase": "complete"}},
        )
        return

    if not _claim_workflow_phase(
            task_id, ["light_queued"], "light_running", allow_missing=True):
        logger.warning("skip unclaimable light workflow task:{} target:{}".format(task_id, target))
        return

    result = wrap_tasks.domain_task(target, task_id, task_options, phase="light") or {}
    if result.get("next_phase") != "heavy_top" or _task_is_done(task_id):
        return

    if task_options.get("port_scan"):
        next_status = (
            "port_scan_top1000"
            if task_options.get("port_scan_type") == "all" and Config.PORT_SCAN_TOP1000_FIRST
            else "port_scan"
        )
    elif task_options.get("ssl_cert"):
        next_status = "ssl_cert"
    else:
        next_status = "find_site"
    _queue_domain_phase(
        options,
        current_phase="light_running",
        queued_phase="heavy_top_queued",
        action=CeleryAction.DOMAIN_HEAVY_TOP_TASK,
        task_fun=arl_heavy,
        celery_id_field="heavy_top_celery_id",
        status=next_status,
        priority=9,
        queue=CeleryRoutingKey.HEAVY_TOP_TASK,
    )


def domain_heavy_top_task(options):
    target = options["target"]
    task_options = options["options"]
    task_id = options["task_id"]
    if not _claim_workflow_phase(
            task_id, ["heavy_top_queued"], "heavy_top_running"):
        logger.warning("skip unclaimable heavy top workflow task:{} target:{}".format(
            task_id, target))
        return

    result = wrap_tasks.domain_task(target, task_id, task_options, phase="heavy_top") or {}
    if result.get("next_phase") != "heavy_full" or _task_is_done(task_id):
        return

    next_status = (
        "port_scan_full"
        if task_options.get("port_scan") and task_options.get("port_scan_type") == "all"
        else "find_site"
    )
    _queue_domain_phase(
        options,
        current_phase="heavy_top_running",
        queued_phase="heavy_full_queued",
        action=CeleryAction.DOMAIN_HEAVY_FULL_TASK,
        task_fun=arl_heavy,
        celery_id_field="heavy_full_celery_id",
        status=next_status,
        priority=3,
        queue=CeleryRoutingKey.HEAVY_FULL_TASK,
    )


def domain_heavy_full_task(options):
    target = options["target"]
    task_options = options["options"]
    task_id = options["task_id"]
    if not _claim_workflow_phase(
            task_id, ["heavy_full_queued"], "heavy_full_running"):
        logger.warning("skip unclaimable heavy full workflow task:{} target:{}".format(
            task_id, target))
        return

    result = wrap_tasks.domain_task(target, task_id, task_options, phase="heavy_full") or {}
    if _task_is_done(task_id):
        utils.conn_db("task").update_one(
            {"_id": ObjectId(task_id), "status": TaskStatus.DONE},
            {"$set": {"workflow_phase": "complete", "workflow_updated_at": utils.curr_date()}},
        )
        return
    if result.get("full_port_continuation_required"):
        utils.conn_db("task").update_one(
            {"_id": ObjectId(task_id), "workflow_phase": "heavy_full_running"},
            {"$inc": {"full_port_slice_count": 1}},
        )
        queued = _queue_domain_phase(
            options,
            current_phase="heavy_full_running",
            queued_phase="heavy_full_queued",
            action=CeleryAction.DOMAIN_HEAVY_FULL_TASK,
            task_fun=arl_heavy,
            celery_id_field="heavy_full_celery_id",
            status="port_scan_full",
            priority=3,
            countdown=max(int(getattr(
                Config, "FULL_PORT_CONTINUATION_DELAY", 2) or 0), 0),
            queue=CeleryRoutingKey.HEAVY_FULL_TASK,
        )
        if queued:
            logger.info("queued full-port continuation task:{}".format(task_id))
        return
    if not result.get("post_required"):
        if result.get("finalize_required"):
            _queue_domain_phase(
                options,
                current_phase="heavy_full_running",
                queued_phase="collision_queued",
                action=CeleryAction.DOMAIN_COLLISION_TASK,
                task_fun=arl_collision,
                celery_id_field="collision_celery_id",
                status="findvhost",
                priority=5,
                queue=CeleryRoutingKey.COLLISION_TASK,
            )
        return

    next_status = "file_leak" if task_options.get("file_leak") else "nuclei_scan"
    utils.conn_db("task").update_one(
        {"_id": ObjectId(task_id), "workflow_phase": "heavy_full_running"},
        {"$set": {"post_attempt": 1}},
    )
    _queue_domain_phase(
        options,
        current_phase="heavy_full_running",
        queued_phase="post_queued",
        action=CeleryAction.DOMAIN_POST_TASK,
        task_fun=arl_post,
        celery_id_field="post_celery_id",
        status=next_status,
    )


def domain_post_task(options):
    target = options["target"]
    task_options = options["options"]
    task_id = options["task_id"]
    if not _claim_workflow_phase(task_id, ["post_queued"], "post_running"):
        logger.warning("skip unclaimable post workflow task:{} target:{}".format(
            task_id, target))
        return

    result = wrap_tasks.domain_task(target, task_id, task_options, phase="post") or {}
    if _task_is_done(task_id):
        return

    if result.get("continuation_required"):
        utils.conn_db("task").update_one(
            {"_id": ObjectId(task_id), "workflow_phase": "post_running"},
            {"$inc": {"post_slice_count": 1}},
        )
        queued = _queue_domain_phase(
            options,
            current_phase="post_running",
            queued_phase="post_queued",
            action=CeleryAction.DOMAIN_POST_TASK,
            task_fun=arl_post,
            celery_id_field="post_celery_id",
            status="file_leak",
            priority=5,
            countdown=max(int(getattr(
                Config, "FFUF_CONTINUATION_DELAY", 1) or 0), 0),
            queue=CeleryRoutingKey.POST_TASK,
        )
        if queued:
            logger.info("queued ffuf continuation task:{}".format(task_id))
        return

    task_data = utils.conn_db("task").find_one(
        {"_id": ObjectId(task_id)}, {"post_attempt": 1}) or {}
    attempt = max(int(task_data.get("post_attempt", 1) or 1), 1)
    max_attempts = max(int(getattr(Config, "FFUF_POST_MAX_ATTEMPTS", 2) or 2), 1)
    if result.get("retry_required") and attempt < max_attempts:
        next_attempt = attempt + 1
        utils.conn_db("task").update_one(
            {"_id": ObjectId(task_id), "workflow_phase": "post_running"},
            {"$set": {"post_attempt": next_attempt}},
        )
        queued = _queue_domain_phase(
            options,
            current_phase="post_running",
            queued_phase="post_queued",
            action=CeleryAction.DOMAIN_POST_TASK,
            task_fun=arl_post,
            celery_id_field="post_retry_celery_id",
            status="file_leak",
            priority=9,
            countdown=max(int(getattr(Config, "FFUF_POST_RETRY_DELAY", 30) or 30), 0),
            queue=CeleryRoutingKey.POST_RETRY_TASK,
        )
        if queued:
            logger.warning("queued ffuf retry task:{} attempt:{}/{}".format(
                task_id, next_attempt, max_attempts))
        return

    if result.get("retry_required"):
        utils.conn_db("task").update_one(
            {"_id": ObjectId(task_id), "workflow_phase": "post_running"},
            {"$set": {
                "workflow_warning": "ffuf partial after {} attempts".format(attempt),
            }},
        )
    _queue_domain_phase(
        options,
        current_phase="post_running",
        queued_phase="collision_queued",
        action=CeleryAction.DOMAIN_COLLISION_TASK,
        task_fun=arl_collision,
        celery_id_field="collision_celery_id",
        status="findvhost",
        priority=5,
        queue=CeleryRoutingKey.COLLISION_TASK,
    )


def domain_collision_task(options):
    target = options["target"]
    task_options = options["options"]
    task_id = options["task_id"]
    if not _claim_workflow_phase(
            task_id, ["collision_queued"], "collision_running"):
        logger.warning("skip unclaimable collision workflow task:{} target:{}".format(
            task_id, target))
        return

    wrap_tasks.domain_task(target, task_id, task_options, phase="post_finalize")
    if _task_is_done(task_id):
        utils.conn_db("task").update_one(
            {"_id": ObjectId(task_id), "status": TaskStatus.DONE},
            {"$set": {
                "workflow_phase": "complete",
                "workflow_updated_at": utils.curr_date(),
            }},
        )


def ip_task(options):
    """常规IP任务"""
    target = options["target"]
    task_options = options["options"]
    task_id = options["task_id"]
    wrap_tasks.ip_task(target, task_id, task_options)


def run_risk_cruising_task(options):
    task_id = options["task_id"]
    wrap_tasks.run_risk_cruising_task(task_id)


def fofa_task(options):
    task_id = options["task_id"]
    task_options = options["options"]
    target = " ".join(options["fofa_ip"])
    wrap_tasks.ip_task(target, task_id, task_options)


def ip_exec(options):
    """
    IP 监测任务
    """
    scope_id = options.get("scope_id")
    target = options.get("domain")
    job_id = options.get("job_id")
    monitor_options = options.get("monitor_options")
    name = options.get("name")
    wrap_tasks.ip_executor(target=target, scope_id=scope_id,
                           task_name=name, job_id=job_id,
                           options=monitor_options)


def github_task_task(options):
    task_id = options["task_id"]
    keyword = options["keyword"]
    wrap_tasks.github_task_task(task_id=task_id, keyword=keyword)


def github_task_monitor(options):
    task_id = options["task_id"]
    keyword = options["keyword"]
    scheduler_id = options["github_scheduler_id"]
    wrap_tasks.github_task_monitor(task_id=task_id, keyword=keyword, scheduler_id=scheduler_id)


def asset_site_update(options):
    task_id = options["task_id"]
    task_options = options["options"]
    scope_id = task_options["scope_id"]
    scheduler_id = task_options["scheduler_id"]
    wrap_tasks.asset_site_update_task(task_id=task_id,
                                      scope_id=scope_id, scheduler_id=scheduler_id)


def asset_wih_update_task(options):
    task_id = options["task_id"]
    task_options = options["options"]
    scope_id = task_options["scope_id"]
    scheduler_id = task_options["scheduler_id"]
    wrap_tasks.asset_wih_update_task(task_id=task_id,
                                     scope_id=scope_id, scheduler_id=scheduler_id)


def asset_site_add_task(options):
    task_id = options["task_id"]
    wrap_tasks.run_add_asset_site_task(task_id)


def ai_judge_task(data):
    from app.services.ai_judge import judge_sites_by_ids

    result = judge_sites_by_ids(
        data.get("site_ids") or [],
        collection=str(data.get("collection") or "site"),
        scope=str(data.get("scope") or "批量研判"),
    )
    logger.info("AI judge task done site_count:{} judged:{} failed:{}".format(
        result.get("input_count"), result.get("judged_count"),
        result.get("failed_count")))
    return result
