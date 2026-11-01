import time
from crontab import CronTab
from bson import ObjectId
from pymongo import ReturnDocument
from app.modules import CeleryAction, SchedulerStatus, TaskStatus
from app import celerytask, utils

logger = utils.get_logger()

action_map_collection = {
    CeleryAction.GITHUB_TASK_TASK: "github_task",
    CeleryAction.GITHUB_TASK_MONITOR: "github_task"
}


def submit_github_task(task_data, action, delay_flag=True):
    if action not in action_map_collection:
        return "Not in action_map"

    collection = action_map_collection[action]
    task_options = {
        "celery_action": action,
        "data": task_data
    }
    keyword = task_data["keyword"]
    task_data["celery_id"] = ""
    utils.conn_db(collection).insert_one(task_data)
    task_id = str(task_data.pop("_id"))
    task_data["task_id"] = task_id

    try:
        if delay_flag:
            celery_id = celerytask.arl_github.delay(options=task_options)
        else:
            celery_id = "fake_celery_id"
            celerytask.arl_github(options=task_options)

        logger.info("target:{} task_id:{} celery_id:{}".format(keyword, task_id, celery_id))
        values = {"$set": {"celery_id": str(celery_id)}}
        task_data["celery_id"] = str(celery_id)
        utils.conn_db(collection).update_one({"_id": ObjectId(task_id)}, values)

    except Exception as e:
        utils.conn_db(collection).delete_one({"_id": ObjectId(task_id)})
        logger.info("Github 任务下发失败 {}".format(keyword))
        return str(e)

    return task_data


# Github 监控任务下发
def github_cron_run(item):
    task_data = {
        "name": "GitHub监控-" + item["name"],
        "keyword": item["keyword"],
        "start_time": "-",
        "end_time": "-",
        "github_scheduler_id": str(item["_id"]),
        "status": TaskStatus.WAITING,
    }
    # 下发周期运行任务
    result = submit_github_task(
        task_data=task_data, action=CeleryAction.GITHUB_TASK_MONITOR)
    if not isinstance(result, dict):
        raise RuntimeError(str(result or "GitHub monitor submit failed"))
    return result


def _claim_github_job(item, now_time):
    entry = CronTab(item["cron"])
    cron_base = now_time + 61
    next_sec = entry.next(now=cron_base, default_utc=False)
    next_run_date = utils.time2date(cron_base + next_sec - 60)
    query = {
        "_id": item["_id"],
        "status": SchedulerStatus.RUNNING,
    }
    if "last_run_time" in item:
        query["last_run_time"] = item.get("last_run_time")
    else:
        query["last_run_time"] = {"$exists": False}
    update = {
        "$set": {
            "last_run_date": utils.time2date(now_time),
            "last_run_time": now_time,
            "next_run_date": next_run_date,
            "dispatch_error": "",
        },
        "$inc": {"run_number": 1},
    }
    return utils.conn_db("github_scheduler").find_one_and_update(
        query, update, return_document=ReturnDocument.AFTER)


# Github 监控任务调度，有个循环
def github_task_scheduler():
    items = list(utils.conn_db('github_scheduler').find())
    for item in items:
        try:
            if item["status"] != SchedulerStatus.RUNNING:
                continue

            entry = CronTab(item["cron"])
            next_sec = entry.next(default_utc=False)
            if next_sec < 60 and abs(time.time() - item.get("last_run_time", 0)) > 60*3:
                claimed = _claim_github_job(item, int(time.time()))
                if not claimed:
                    continue
                logger.info("github_cron_run {} {}".format(
                    claimed["keyword"], str(claimed["_id"])))
                github_cron_run(claimed)

        except Exception as e:
            logger.exception(e)
            utils.conn_db("github_scheduler").update_one(
                {"_id": item["_id"]},
                {"$set": {
                    "dispatch_error": str(e)[:500],
                    "dispatch_error_date": utils.curr_date(),
                }},
            )


def find_github_scheduler(_id):
    query = {
        "_id": ObjectId(_id)
    }
    item = utils.conn_db('github_scheduler').find_one(query)
    return item


# 删除 Github 监控任务，还有结果和Hash
def delete_github_scheduler(_id):
    if len(_id) != 24:
        return

    query = {
        "_id": ObjectId(_id)
    }
    utils.conn_db('github_scheduler').delete_one(query)

    result_query = {
        "github_scheduler_id": _id
    }
    # 删除Github 结果 Hash
    utils.conn_db('github_hash').delete_many(result_query)
    # 删除Github 监控结果
    utils.conn_db('github_monitor_result').delete_many(result_query)


# 恢复 Github 监控任务，只是改变状态
def recover_task(_id):
    from app.modules import SchedulerStatus
    if len(_id) != 24:
        return

    item = find_github_scheduler(_id)
    if not item:
        return False
    entry = CronTab(item["cron"])
    next_sec = entry.next(default_utc=False)
    query = {
        "_id": ObjectId(_id)
    }
    result = utils.conn_db('github_scheduler').update_one(query, {"$set": {
        "status": SchedulerStatus.RUNNING,
        "next_run_date": utils.time2date(time.time() + next_sec),
        "dispatch_error": "",
    }})
    return bool(result.matched_count)


# 停止Github 监控任务，只是改变状态
def stop_task(_id):
    from app.modules import SchedulerStatus
    if len(_id) != 24:
        return

    query = {
        "_id": ObjectId(_id)
    }
    result = utils.conn_db('github_scheduler').update_one(query, {"$set": {
        "status": SchedulerStatus.STOP,
        "next_run_date": "-",
    }})
    return bool(result.matched_count)
