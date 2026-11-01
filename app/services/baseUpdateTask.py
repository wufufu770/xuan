from datetime import datetime

from bson import ObjectId
from app import utils
from app.config import Config
from app.modules import TaskStatus


DONE_STATUS = [TaskStatus.DONE, TaskStatus.STOP, TaskStatus.ERROR]
STAGE_TRANSIENT_FIELDS = ("error", "warning", "partial_reason", "skip_reason")


# 用于更新任务状态
class BaseUpdateTask(object):
    def __init__(self, task_id: str):
        self.task_id = task_id

    def _stage_query(self, stage_name):
        return {"task_id": self.task_id, "stage": stage_name}

    def _build_stage_fields(self, summary=None):
        summary = dict(summary or {})
        fields = {}
        for key in ("input_count", "output_count", "filtered_count", "error_count"):
            if summary.get(key) is not None:
                fields[key] = summary.get(key)

        for key in ("error", "warning", "partial_reason"):
            if summary.get(key):
                fields[key] = str(summary.get(key))

        extra = {k: v for k, v in summary.items() if k not in fields}
        if extra:
            fields["extra"] = extra

        return fields

    def start_stage(self, stage_name, input_count=None, summary=None):
        terminal_status = self.get_status()
        if not terminal_status:
            return False
        now = utils.curr_date()
        current = utils.conn_db("task_stage").find_one(
            self._stage_query(stage_name),
            {"_id": 0, "start_time": 1, "first_start_time": 1},
        ) or {}
        fields = {
            "task_id": self.task_id,
            "stage": stage_name,
            "status": "running",
            "start_time": now,
            "first_start_time": (
                current.get("first_start_time") or
                current.get("start_time") or
                now
            ),
            "updated_at": now,
        }
        if input_count is not None:
            fields["input_count"] = input_count
        fields.update(self._build_stage_fields(summary=summary))

        if terminal_status in DONE_STATUS:
            fields["status"] = terminal_status
            fields["end_time"] = utils.curr_date()
            fields["skip_reason"] = "task_terminal"
            update = {
                "$set": fields,
                "$inc": {"run_count": 1},
                "$unset": {
                    "elapsed": "", "error": "", "warning": "", "partial_reason": "",
                },
            }
            utils.conn_db("task_stage").update_one(self._stage_query(stage_name), update, upsert=True)
            return False

        update = {
            "$set": fields,
            "$inc": {"run_count": 1},
            "$unset": {
                "end_time": "", "elapsed": "", "error": "", "warning": "",
                "partial_reason": "", "skip_reason": "",
            },
        }
        utils.conn_db("task_stage").update_one(self._stage_query(stage_name), update, upsert=True)
        return True

    def finish_stage(self, stage_name, elapsed=None, summary=None, status="done"):
        summary = dict(summary or {})
        current = utils.conn_db("task_stage").find_one(
            self._stage_query(stage_name),
            {"run_count": 1, "start_time": 1, "extra.resources": 1},
        ) or {}
        existing_resources = dict(
            ((current.get("extra") or {}).get("resources") or {}))
        if existing_resources:
            existing_resources.update(dict(summary.get("resources") or {}))
            summary["resources"] = existing_resources
        summary.update(self._progress_metrics(stage_name, summary))
        fields = {
            "status": status,
            "updated_at": utils.curr_date(),
            "end_time": utils.curr_date(),
        }
        if elapsed is not None:
            fields["elapsed"] = float("{:.2f}".format(float(elapsed)))
        fields.update(self._build_stage_fields(summary=summary))
        update = {"$set": fields}
        history_limit = max(int(getattr(
            Config, "TASK_STAGE_ATTEMPT_HISTORY_LIMIT", 10) or 0), 0)
        if history_limit:
            attempt = {
                "attempt": max(int(current.get("run_count", 1) or 1), 1),
                "status": status,
                "start_time": current.get("start_time", ""),
                "end_time": fields["end_time"],
            }
            if elapsed is not None:
                attempt["elapsed"] = fields.get("elapsed")
            for key in (
                    "input_count", "output_count", "filtered_count", "error_count",
                    "error", "warning", "partial_reason", "extra"):
                if key in fields:
                    attempt[key] = fields[key]
            update["$push"] = {
                "attempts": {
                    "$each": [attempt],
                    "$slice": -history_limit,
                }
            }
        stale_fields = {
            key: "" for key in STAGE_TRANSIENT_FIELDS
            if key not in fields
        }
        if stale_fields:
            update["$unset"] = stale_fields
        utils.conn_db("task_stage").update_one(
            self._stage_query(stage_name),
            update,
            upsert=True
        )

    def update_stage_progress(self, stage_name, summary=None):
        summary = dict(summary or {})
        summary.update(self._progress_metrics(stage_name, summary))
        fields = {
            "updated_at": utils.curr_date(),
        }

        for key in ("input_count", "output_count", "filtered_count", "error_count"):
            if summary.get(key) is not None:
                fields[key] = summary.get(key)

        for key, value in summary.items():
            if key in fields or value is None:
                continue
            fields["extra.{}".format(key)] = value

        result = utils.conn_db("task_stage").update_one(
            {"task_id": self.task_id, "stage": stage_name, "status": "running"},
            {"$set": fields},
        )
        return bool(result.matched_count)

    def _progress_metrics(self, stage_name, summary):
        pairs = (
            ("completed_site_count", "input_count"),
            ("completed_batches", "total_batches"),
            ("completed_targets", "total_targets"),
            ("processed_site_count", "input_count"),
        )
        completed = total = None
        for completed_key, total_key in pairs:
            if summary.get(completed_key) is None or summary.get(total_key) is None:
                continue
            try:
                completed = max(float(summary.get(completed_key) or 0), 0.0)
                total = max(float(summary.get(total_key) or 0), 0.0)
            except (TypeError, ValueError):
                completed = total = None
                continue
            if total > 0:
                break
        if completed is None or not total:
            return {}

        metrics = {
            "completion_ratio": round(min(completed / total, 1.0), 4),
        }
        try:
            item = utils.conn_db("task_stage").find_one(
                self._stage_query(stage_name), {
                    "_id": 0,
                    "start_time": 1,
                    "first_start_time": 1,
                }) or {}
            started_at = datetime.strptime(
                str(
                    item.get("start_time") or
                    item.get("first_start_time") or
                    ""
                ),
                "%Y-%m-%d %H:%M:%S",
            )
            elapsed = max((datetime.now() - started_at).total_seconds(), 0.0)
        except Exception:
            elapsed = 0.0
        if elapsed > 0 and completed > 0:
            throughput = completed / elapsed
            metrics["throughput_per_second"] = round(throughput, 4)
            metrics["eta_seconds"] = round(max(total - completed, 0.0) / throughput, 1)
        return metrics

    def fail_stage(self, stage_name, error, elapsed=None, summary=None):
        fields = dict(summary or {})
        fields["error"] = str(error)
        self.finish_stage(stage_name, elapsed=elapsed, summary=fields, status="error")

    def update_services(self, service_name: str, elapsed: float, summary=None, status="done"):
        elapsed = "{:.2f}".format(elapsed)
        if not self.update_task_field("status", service_name):
            terminal_status = self.get_status()
            if terminal_status in DONE_STATUS:
                terminal_summary = dict(summary or {})
                terminal_summary["terminal_status"] = terminal_status
                self.finish_stage(service_name, elapsed=float(elapsed), summary=terminal_summary, status=terminal_status)
            return False

        query = {"_id": ObjectId(self.task_id)}
        service_item = {"name": service_name, "elapsed": float(elapsed)}
        utils.conn_db('task').update_one(query, [{
            "$set": {
                "service": {
                    "$concatArrays": [
                        {
                            "$filter": {
                                "input": {"$ifNull": ["$service", []]},
                                "as": "item",
                                "cond": {"$ne": ["$$item.name", service_name]},
                            }
                        },
                        [service_item],
                    ]
                }
            }
        }])
        self.finish_stage(service_name, elapsed=float(elapsed), summary=summary, status=status)
        return True

    def update_task_field(self, field=None, value=None):
        query = {"_id": ObjectId(self.task_id)}
        if field == "status":
            query["status"] = {"$nin": DONE_STATUS}

        update = {"$set": {field: value}}
        result = utils.conn_db('task').update_one(query, update)
        return bool(result.matched_count)

    def get_status(self):
        task = utils.conn_db('task').find_one({"_id": ObjectId(self.task_id)}, {"status": 1})
        if not task:
            return ""
        return task.get("status", "")

    def is_terminal(self):
        status = self.get_status()
        return not status or status in DONE_STATUS

    def is_stopped(self):
        return self.get_status() == TaskStatus.STOP

    def finish_running_stages(self, status=TaskStatus.STOP, reason=""):
        fields = {
            "status": status,
            "end_time": utils.curr_date(),
            "updated_at": utils.curr_date(),
        }
        if reason:
            fields["stop_reason"] = reason

        return utils.conn_db("task_stage").update_many(
            {"task_id": self.task_id, "status": "running"},
            {"$set": fields}
        )
