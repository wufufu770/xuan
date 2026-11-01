import time

from bson import ObjectId

from app import utils


def find_job(job_id):
    return utils.conn_db("scheduler").find_one({"_id": ObjectId(job_id)})


def update_job_run(job_id):
    """Record a completed monitor run without importing the scheduler process."""
    curr_time = int(time.time())
    item = find_job(job_id)
    if not item:
        return False

    next_run_time = curr_time + int(item.get("interval") or 0)
    result = utils.conn_db("scheduler").update_one(
        {"_id": item["_id"]},
        {
            "$set": {
                "next_run_time": next_run_time,
                "next_run_date": utils.time2date(next_run_time),
                "last_run_time": curr_time,
                "last_run_date": utils.time2date(curr_time),
                "dispatch_error": "",
                "update_date": utils.curr_date_obj(),
            },
            "$inc": {"run_number": 1},
        },
    )
    return bool(result.matched_count)
