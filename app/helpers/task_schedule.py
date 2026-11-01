import bson
from pymongo import ReturnDocument
from app import utils
from app.modules import TaskScheduleStatus, TaskTag
from crontab import CronTab
import time

from .policy import get_options_by_policy_id


logger = utils.get_logger()


# 计划任务调度
def task_scheduler():
    items = list(utils.conn_db('task_schedule').find())
    for item in items:
        try:
            if item["status"] != TaskScheduleStatus.SCHEDULED:
                continue

            task_tag = item["task_tag"]
            should_scheduler_tag = [TaskTag.TASK, TaskTag.RISK_CRUISING]
            if task_tag not in should_scheduler_tag:
                logger.warning("非资产发现任务或风险巡航任务, {} {}", item["task_tag"], str(item["_id"]))
                continue

            if item["schedule_type"] == "recurrent_scan":
                entry = CronTab(item["cron"])
                next_sec = entry.next(default_utc=False)
                if next_sec < 60 and abs(time.time() - item.get("last_run_time", 0)) > 60*3:
                    logger.info("run_recurrent_scan {} {}".format(item["target"], str(item["_id"])))
                    run_recurrent_scan(item)

            elif item["schedule_type"] == "future_scan":
                start_time = item["start_time"]
                if 0 < start_time <= time.time():
                    logger.info("run_future_scan {} {}".format(item["target"], str(item["_id"])))
                    run_future_scan(item)

        except Exception as e:
            logger.exception(e)
            update_fields = {
                "last_error": str(e)[:500],
                "last_error_date": utils.curr_date(),
            }
            if item.get("schedule_type") == "future_scan":
                update_fields["status"] = TaskScheduleStatus.ERROR
                update_fields["next_run_date"] = "-"
            utils.conn_db("task_schedule").update_one(
                {"_id": item["_id"]}, {"$set": update_fields})


# 提交计划任务
def submit_task_schedule(item):
    from .task import submit_risk_cruising
    from .task import submit_task_task
    target = item["target"]
    task_tag = item["task_tag"]
    task_schedule_name = item["name"]
    policy_id = item["policy_id"]
    options = get_options_by_policy_id(policy_id, task_tag=task_tag)

    if not options:
        change_task_schedule_status(item["_id"], TaskScheduleStatus.ERROR)
        raise Exception("not found policy_id {}".format(policy_id))

    name = "定时任务-{}".format(task_schedule_name[:15])

    if item["schedule_type"] == "recurrent_scan":
        run_number = item.get("run_number", 0)
        name = "周期任务-{}-{}".format(task_schedule_name[:15], run_number)

    if task_tag == TaskTag.TASK:
        submit_task_task(target=target, name=name, options=options)
    if task_tag == TaskTag.RISK_CRUISING:
        task_data_list = submit_risk_cruising(target=target, name=name, options=options)
        if not task_data_list:
            raise Exception("not found task_data {}".format(target))


# 根据cron 生成下一次运行时间
def get_next_run_date(cron):
    entry = CronTab(cron)
    now_time = time.time() + 61
    next_sec = entry.next(now=now_time, default_utc=False)
    return utils.time2date(now_time + next_sec - 60)


# 触发周期任务执行
def run_recurrent_scan(item):
    last_run_time = int(time.time())
    query = {
        "_id": item["_id"],
        "status": TaskScheduleStatus.SCHEDULED,
        "last_run_time": item.get("last_run_time", 0),
    }
    update = {
        "$set": {
            "next_run_date": get_next_run_date(item["cron"]),
            "last_run_time": last_run_time,
            "last_run_date": utils.time2date(last_run_time),
            "last_error": "",
        },
        "$inc": {"run_number": 1},
    }
    claimed = utils.conn_db('task_schedule').find_one_and_update(
        query, update, return_document=ReturnDocument.AFTER)
    if not claimed:
        return False

    # 为了防止多次运行，后提交任务
    submit_task_schedule(claimed)
    return True


# 触发定时任务执行
def run_future_scan(item):
    query = {
        "_id": item["_id"],
        "status": TaskScheduleStatus.SCHEDULED,
    }
    update = {
        "$set": {
            "status": TaskScheduleStatus.DONE,
            "next_run_date": "-",
            "last_run_time": int(time.time()),
            "last_run_date": utils.curr_date(),
            "last_error": "",
        },
        "$inc": {"run_number": 1},
    }
    claimed = utils.conn_db('task_schedule').find_one_and_update(
        query, update, return_document=ReturnDocument.AFTER)
    if not claimed:
        return False

    # 为了防止多次运行，后提交任务
    submit_task_schedule(claimed)
    return True


# 查找计划任务
def find_task_schedule(_id):
    query = {'_id': bson.ObjectId(_id)}
    item = utils.conn_db('task_schedule').find_one(query)
    return item


# 删除计划任务
def remove_task_schedule(_id):
    query = {'_id': bson.ObjectId(_id)}
    result = utils.conn_db('task_schedule').delete_one(query)
    return result.deleted_count


# 改变计划任务状态
def change_task_schedule_status(_id, status):
    query = {'_id': bson.ObjectId(_id)}
    item = find_task_schedule(_id)
    if not item:
        return

    old_status = item["status"]

    if old_status == TaskScheduleStatus.ERROR:
        return "{} 不可改变状态".format(item["name"])

    if old_status == status:
        return "{} 已经处于 {} ".format(item["name"], status)

    done_status_list = [TaskScheduleStatus.DONE,
                        TaskScheduleStatus.ERROR,
                        TaskScheduleStatus.STOP]

    update_fields = {"status": status}
    if status in done_status_list:
        update_fields["next_run_date"] = "-"

    elif status == TaskScheduleStatus.SCHEDULED:
        if item["schedule_type"] == "recurrent_scan":
            update_fields["next_run_date"] = get_next_run_date(item["cron"])

        else:
            update_fields["next_run_date"] = item["start_date"]

    result = utils.conn_db('task_schedule').update_one(
        {"_id": item["_id"], "status": old_status},
        {"$set": update_fields},
    )
    if not result.matched_count:
        return "{} 状态已发生变化，请刷新后重试".format(item["name"])

    return utils.conn_db('task_schedule').find_one(query)
