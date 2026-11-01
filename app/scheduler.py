import sys
from bson import ObjectId
from pymongo import ReturnDocument
from app.utils import conn_db as conn
from app import utils
from app import celerytask
import time
from app.modules import CeleryAction, SchedulerStatus, AssetScopeType
from app.helpers import task_schedule, asset_site_monitor, asset_wih_monitor
from app.services.monitorScheduler import update_job_run

logger = utils.get_logger()

domain_monitor_options = {
    'domain_brute': True,
    'domain_brute_type': 'big',
    'alt_dns': False,
    'arl_search': True,
    'port_scan_type': 'test',
    'port_scan': True,
    'dns_query_plugin': True,
    'site_identify': False
}

ip_monitor_options = {
    'port_scan_type': 'test',
    'port_scan': True,
    'site_identify': False
}


def add_job(domain, scope_id, options=None, interval=60 * 1, name="", scope_type=AssetScopeType.DOMAIN):
    logger.info("add {} job {} {} {}".format(scope_type, interval, domain, scope_id))
    base_options = domain_monitor_options.copy()
    if scope_type == AssetScopeType.IP:
        base_options = ip_monitor_options.copy()
    if options:
        base_options.update(dict(options))
    options = base_options

    # 对IP任务域名监测选项设置为False
    disable_options = {
        "domain_brute": False,
        "alt_dns": False,
        "dns_query_plugin": False,
        "arl_search": False
    }

    if scope_type == AssetScopeType.IP:
        options.update(disable_options)

    current_time = int(time.time()) + 30
    item = {
        "domain": domain,
        "scope_id": scope_id,
        "interval": interval,
        "next_run_time": current_time,
        "next_run_date": utils.time2date(current_time),
        "last_run_time": 0,
        "last_run_date": "-",
        "run_number": 0,
        "status": SchedulerStatus.RUNNING,
        "monitor_options": options,
        "name": name,
        "scope_type": scope_type

    }
    result = conn('scheduler').insert_one(item)

    return str(result.inserted_id)


def add_asset_site_monitor_job(scope_id, name, interval=60 * 1):
    current_time = int(time.time()) + 30

    item = {
        "domain": "资产站点更新",
        "scope_id": scope_id,
        "interval": interval,
        "next_run_time": current_time,
        "next_run_date": utils.time2date(current_time),
        "last_run_time": 0,
        "last_run_date": "-",
        "run_number": 0,
        "status": SchedulerStatus.RUNNING,
        "monitor_options": {},
        "name": name,
        "scope_type": "site_update_monitor"
    }
    result = conn('scheduler').insert_one(item)

    return str(result.inserted_id)


def add_asset_wih_monitor_job(scope_id, name, interval=60 * 1):
    current_time = int(time.time()) + 30

    item = {
        "domain": "资产分组 WIH 更新",
        "scope_id": scope_id,
        "interval": interval,
        "next_run_time": current_time,
        "next_run_date": utils.time2date(current_time),
        "last_run_time": 0,
        "last_run_date": "-",
        "run_number": 0,
        "status": SchedulerStatus.RUNNING,
        "monitor_options": {},
        "name": name,
        "scope_type": "wih_update_monitor"
    }
    result = conn('scheduler').insert_one(item)

    return str(result.inserted_id)


def delete_job(job_id):
    ret = conn("scheduler").delete_one({"_id": ObjectId(job_id)})
    return ret


def stop_job(job_id):
    query = {"_id": ObjectId(job_id)}
    ret = conn('scheduler').update_one(query, {"$set": {
        "next_run_date": "-",
        "next_run_time": sys.maxsize,
        "status": SchedulerStatus.STOP,
        "update_date": utils.curr_date_obj(),
    }})
    return ret


def recover_job(job_id):
    current_time = int(time.time()) + 30
    item = find_job(job_id)
    if not item:
        return None

    next_run_time = current_time + item["interval"]
    query = {"_id": ObjectId(job_id)}
    ret = conn('scheduler').update_one(query, {"$set": {
        "next_run_date": utils.time2date(next_run_time),
        "next_run_time": next_run_time,
        "status": SchedulerStatus.RUNNING,
        "dispatch_error": "",
        "update_date": utils.curr_date_obj(),
    }})
    return ret


def find_job(job_id):
    query = {"_id": ObjectId(job_id)}
    item = conn('scheduler').find_one(query)
    return item


def all_job():
    items = []
    for item in conn('scheduler').find():
        items.append(item)
    return items


def submit_job(domain, job_id, scope_id, options=None, name="", scope_type=AssetScopeType.DOMAIN):
    monitor_options = domain_monitor_options.copy()
    if scope_type == AssetScopeType.IP:
        monitor_options = ip_monitor_options.copy()

    if options is None:
        options = {}

    monitor_options.update(options)

    task_data = {
        "domain": domain,
        "scope_id": scope_id,
        "job_id": job_id,
        "type": scope_type,
        "monitor_options": monitor_options,
        "name": name
    }

    if scope_type == AssetScopeType.DOMAIN:
        task_options = {
            "celery_action": CeleryAction.DOMAIN_EXEC_TASK,
            "data": task_data
        }
        celery_id = celerytask.arl_task.delay(options=task_options)
        logger.info("submit domain job {} {} {}".format(celery_id, domain, scope_id))

    elif scope_type == AssetScopeType.IP:
        task_options = {
            "celery_action": CeleryAction.IP_EXEC_TASK,
            "data": task_data
        }
        celery_id = celerytask.arl_task.delay(options=task_options)
        logger.info("submit ip job {} {} {}".format(celery_id, domain, scope_id))
    else:
        raise ValueError("unsupported monitor scope_type: {}".format(scope_type))


def _claim_due_job(item, curr_time):
    """Atomically move a due job forward so only one scheduler can submit it."""
    interval = max(int(item.get("interval") or 60), 60)
    next_run_time = curr_time + interval
    query = {
        "_id": item["_id"],
        "status": SchedulerStatus.RUNNING,
        "next_run_time": {"$lte": curr_time},
    }
    update = {"$set": {
        "next_run_time": next_run_time,
        "next_run_date": utils.time2date(next_run_time),
        "last_dispatch_time": curr_time,
        "last_dispatch_date": utils.time2date(curr_time),
        "dispatch_error": "",
        "update_date": utils.curr_date_obj(),
    }}
    return conn("scheduler").find_one_and_update(
        query, update, return_document=ReturnDocument.AFTER)


def asset_monitor_scheduler():
    curr_time = int(time.time())
    for item in all_job():
        try:
            if item.get("status") != SchedulerStatus.RUNNING:
                continue
            if item["next_run_time"] <= curr_time:
                claimed = _claim_due_job(item, curr_time)
                if not claimed:
                    continue

                domain = claimed["domain"]
                scope_id = claimed["scope_id"]
                options = claimed["monitor_options"]
                name = claimed["name"]
                scope_type = claimed.get("scope_type")

                if not scope_type:
                    scope_type = AssetScopeType.DOMAIN

                if scope_type == "site_update_monitor":
                    asset_site_monitor.submit_asset_site_monitor_job(scope_id=scope_id,
                                                                     name=name,
                                                                     scheduler_id=str(claimed["_id"]))

                elif scope_type == "wih_update_monitor":
                    asset_wih_monitor.submit_asset_wih_monitor_job(scope_id=scope_id,
                                                                   name=name,
                                                                   scheduler_id=str(claimed["_id"]))

                else:
                    submit_job(domain=domain, job_id=str(claimed["_id"]),
                               scope_id=scope_id, options=options,
                               name=name, scope_type=scope_type)

        except Exception as e:
            logger.exception(e)
            try:
                conn("scheduler").update_one(
                    {"_id": item["_id"], "status": SchedulerStatus.RUNNING},
                    {"$set": {
                        "dispatch_error": str(e)[:500],
                        "dispatch_error_date": utils.curr_date(),
                    }},
                )
            except Exception as update_error:
                logger.warning("record scheduler dispatch error failed: {}".format(update_error))


def run_forever():
    from app.utils.github_task import github_task_scheduler
    logger.info("start scheduler server ")
    while True:
        # 资产监控任务调度
        asset_monitor_scheduler()

        # Github 监控任务调度
        github_task_scheduler()

        # 计划任务调度
        task_schedule.task_scheduler()

        # 凤鸟 token 到期预警（旁路能力，失败不影响调度）
        try:
            from app.utils.token_watch import check_fengniao_token
            check_fengniao_token()
        except Exception as exc:
            logger.warning("fengniao token watch failed: %s", exc)

        # 会话池静默续期（6h 一轮，旁路能力）
        try:
            from app.utils.session_refresh import check_sessions
            check_sessions()
        except Exception as exc:
            logger.warning("session refresh watch failed: %s", exc)

        # logger.debug(time.time())
        # sleep 时间不能超过60S，Github 里的任务可能运行不了。
        time.sleep(58)


if __name__ == '__main__':
    run_forever()
