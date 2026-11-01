import os
import re
import socket
import threading
import time
from contextlib import contextmanager

from bson import ObjectId
from pymongo.errors import DuplicateKeyError

from app import utils
from app.config import Config
from app.modules import TaskStatus


logger = utils.get_logger()
DONE_STATUS = [TaskStatus.DONE, TaskStatus.STOP, TaskStatus.ERROR]

DEFAULT_LIMITS = {
    "api:fofa": 1,
    "api:hunter_qax": 1,
    "api:quake_360": 1,
    "tool:nmap:top1000": 2,
    "tool:nmap:full": 1,
    "tool:ffuf": 2,
    "tool:katana": 2,
    "tool:httpx": 3,
    "tool:observer_ward": 2,
    "tool:cert": 2,
    "tool:dns_auxiliary": 2,
}


class ResourceBudgetError(RuntimeError):
    pass


class ResourceBudgetCancelled(ResourceBudgetError):
    pass


class ResourceBudgetTimeout(ResourceBudgetError):
    pass


def _enabled():
    return bool(getattr(Config, "RESOURCE_BUDGET_ENABLE", True))


def _limit_for(resource, max_concurrency=None):
    if max_concurrency is not None:
        return max(int(max_concurrency), 1)

    limits = getattr(Config, "RESOURCE_BUDGET_LIMITS", None) or DEFAULT_LIMITS
    return max(int(limits.get(resource, getattr(Config, "RESOURCE_BUDGET_DEFAULT_CONCURRENCY", 4))), 1)


def _current_stage(task_id, stage=None):
    if stage:
        return stage
    if not task_id:
        return ""
    try:
        task = utils.conn_db("task").find_one({"_id": ObjectId(task_id)}, {"status": 1})
    except Exception:
        task = None
    return str((task or {}).get("status") or "")


def _terminal_or_missing_task_ids(task_ids):
    object_id_map = {}
    for task_id in set([str(x or "") for x in task_ids if x]):
        try:
            object_id_map[ObjectId(task_id)] = task_id
        except Exception:
            continue
    if not object_id_map:
        return set()

    active_ids = set()
    query = {
        "_id": {"$in": list(object_id_map.keys())},
        "status": {"$nin": DONE_STATUS},
    }
    for task in utils.conn_db("task").find(query, {"_id": 1}):
        task_id = object_id_map.get(task.get("_id"))
        if task_id:
            active_ids.add(task_id)
    return set(object_id_map.values()) - active_ids


def _process_start_ticks(pid):
    try:
        with open("/proc/{}/stat".format(int(pid)), "r", encoding="ascii") as handle:
            fields = handle.read().split()
        return int(fields[21]) if len(fields) > 21 else 0
    except (OSError, TypeError, ValueError, IndexError):
        return 0


def _local_owner_is_dead(owner, owner_start_ticks=None):
    parts = str(owner or "").split(":")
    if len(parts) < 2 or parts[0] != socket.gethostname():
        return False
    try:
        pid = int(parts[1])
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    expected_ticks = owner_start_ticks
    if expected_ticks in (None, "") and len(parts) >= 4:
        expected_ticks = parts[2]
    try:
        expected_ticks = int(expected_ticks or 0)
    except (TypeError, ValueError):
        expected_ticks = 0
    current_ticks = _process_start_ticks(pid)
    return bool(
        expected_ticks and current_ticks and expected_ticks != current_ticks)


def _cleanup_resource_locks(resource, now):
    lock_collection = utils.conn_db("runtime_resource_lock")
    lock_collection.delete_many({
        "resource": resource,
        "expires_at": {"$lt": now},
    })

    local_locks = list(lock_collection.find(
        {"resource": resource},
        {"_id": 1, "owner": 1, "owner_start_ticks": 1},
    ))
    dead_lock_ids = [
        item.get("_id") for item in local_locks
        if item.get("_id") and _local_owner_is_dead(
            item.get("owner"), item.get("owner_start_ticks"))
    ]
    if dead_lock_ids:
        result = lock_collection.delete_many({"_id": {"$in": dead_lock_ids}})
        logger.warning("resource budget cleared dead local owners resource:{} count:{}".format(
            resource, result.deleted_count))

    locks = list(lock_collection.find(
        {"resource": resource},
        {"_id": 1, "task_id": 1},
    ))
    stale_task_ids = _terminal_or_missing_task_ids(
        [lock.get("task_id") for lock in locks]
    )
    if not stale_task_ids:
        return 0

    result = lock_collection.delete_many({
        "resource": resource,
        "task_id": {"$in": sorted(stale_task_ids)},
    })
    if result.deleted_count:
        logger.info("resource budget cleared terminal locks resource:{} count:{}".format(
            resource, result.deleted_count))
    return result.deleted_count


def _update_stage_budget(
        task_id, stage, resource, wait_seconds, status,
        held_seconds=None, total_seconds=None):
    if not task_id or not stage or stage in DONE_STATUS:
        return
    try:
        resource_key = re.sub(r"[^a-zA-Z0-9_-]+", "_", resource).strip("_")
        if not resource_key:
            return
        fields = {
            "extra.resources.{}.resource".format(resource_key): resource,
            "extra.resources.{}.wait_seconds".format(resource_key): round(
                float(wait_seconds), 2),
            "extra.resources.{}.status".format(resource_key): status,
            "extra.resources.{}.updated_at".format(resource_key): utils.curr_date(),
            "updated_at": utils.curr_date(),
        }
        if held_seconds is not None:
            fields["extra.resources.{}.held_seconds".format(resource_key)] = round(
                max(float(held_seconds), 0.0), 2)
        if total_seconds is not None:
            fields["extra.resources.{}.total_seconds".format(resource_key)] = round(
                max(float(total_seconds), 0.0), 2)
        utils.conn_db("task_stage").update_one(
            {"task_id": task_id, "stage": stage, "status": "running"},
            {"$set": fields},
            upsert=False,
        )
    except Exception as e:
        logger.warning("resource budget stage update failed resource:{} task_id:{} error:{}".format(
            resource, task_id, e))


def _owner():
    pid = os.getpid()
    return "{}:{}:{}:{}".format(
        socket.gethostname(), pid, _process_start_ticks(pid),
        utils.random_choices(8),
    )


def _task_terminal(task_id):
    if not task_id:
        return False
    try:
        item = utils.conn_db("task").find_one(
            {"_id": ObjectId(task_id)}, {"status": 1})
    except Exception:
        return False
    return not item or item.get("status") in DONE_STATUS


class _LockHeartbeat(object):
    def __init__(self, lock_id, owner, ttl):
        self.lock_id = lock_id
        self.owner = owner
        self.ttl = max(float(ttl), 30.0)
        configured = float(getattr(Config, "RESOURCE_BUDGET_HEARTBEAT_INTERVAL", 60) or 60)
        self.interval = max(5.0, min(configured, self.ttl / 3.0))
        self.stop_event = threading.Event()
        self.thread = None

    def start(self):
        if not self.lock_id:
            return
        self.thread = threading.Thread(
            target=self._run,
            name="resource-budget-heartbeat",
            daemon=True,
        )
        self.thread.start()

    def _run(self):
        while not self.stop_event.wait(self.interval):
            now = time.time()
            try:
                utils.conn_db("runtime_resource_lock").update_one(
                    {"_id": self.lock_id, "owner": self.owner},
                    {"$set": {
                        "expires_at": now + self.ttl,
                        "heartbeat_at": now,
                        "updated_at": utils.curr_date(),
                    }},
                )
            except Exception as e:
                logger.warning("resource budget heartbeat failed lock:{} error:{}".format(
                    self.lock_id, e))

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=min(self.interval, 2.0))


@contextmanager
def acquire(resource, task_id="", stage="", max_concurrency=None, wait_timeout=None, ttl=None, poll_interval=None):
    if not _enabled():
        yield True
        return

    resource = str(resource or "").strip()
    if not resource:
        yield True
        return

    limit = _limit_for(resource, max_concurrency=max_concurrency)
    wait_timeout = float(wait_timeout if wait_timeout is not None else getattr(Config, "RESOURCE_BUDGET_WAIT_TIMEOUT", 60 * 60))
    ttl = float(ttl if ttl is not None else getattr(Config, "RESOURCE_BUDGET_LOCK_TTL", 12 * 60 * 60))
    poll_interval = float(poll_interval if poll_interval is not None else getattr(Config, "RESOURCE_BUDGET_POLL_INTERVAL", 1.0))
    stage = _current_stage(task_id, stage)
    owner = _owner()
    owner_pid = os.getpid()
    owner_start_ticks = _process_start_ticks(owner_pid)
    lock_id = ""
    started = time.time()
    deadline = started + wait_timeout
    status = "waiting"
    cleanup_interval = max(float(getattr(Config, "RESOURCE_BUDGET_CLEANUP_INTERVAL", 15.0)), 1.0)
    next_cleanup = 0.0
    db_errors = 0
    max_db_errors = max(int(getattr(Config, "RESOURCE_BUDGET_MAX_DB_ERRORS", 3) or 3), 1)
    heartbeat = None
    wait_seconds = 0.0
    acquired_at = None

    try:
        while True:
            now = time.time()
            if now >= next_cleanup:
                try:
                    _cleanup_resource_locks(resource, now)
                except Exception as e:
                    logger.warning("resource budget cleanup failed resource:{} error:{}".format(resource, e))
                next_cleanup = now + cleanup_interval

            for slot in range(limit):
                candidate_id = "{}:{}".format(resource, slot)
                query = {
                    "_id": candidate_id,
                    "$or": [
                        {"expires_at": {"$lt": now}},
                        {"owner": owner},
                    ],
                }
                update = {"$set": {
                    "resource": resource,
                    "slot": slot,
                    "owner": owner,
                    "owner_pid": owner_pid,
                    "owner_start_ticks": owner_start_ticks,
                    "task_id": task_id,
                    "stage": stage,
                    "acquired_at": now,
                    "expires_at": now + ttl,
                    "heartbeat_at": now,
                    "updated_at": utils.curr_date(),
                }}
                try:
                    result = utils.conn_db("runtime_resource_lock").update_one(query, update, upsert=True)
                except DuplicateKeyError:
                    continue
                except Exception as e:
                    logger.warning("resource budget acquire failed resource:{} error:{}".format(resource, e))
                    db_errors += 1
                    status = "backend_error"
                    if db_errors >= max_db_errors:
                        raise ResourceBudgetError(
                            "resource budget backend failed for {} after {} attempts".format(
                                resource, db_errors))
                    break

                if result.upserted_id or result.matched_count or result.modified_count:
                    lock_id = candidate_id
                    status = "acquired"
                    db_errors = 0
                    break

            if lock_id:
                break

            if _task_terminal(task_id):
                status = "cancelled"
                raise ResourceBudgetCancelled(
                    "task stopped while waiting for {}".format(resource))

            if time.time() >= deadline:
                wait_seconds = time.time() - started
                if not task_id:
                    status = "timeout"
                    raise ResourceBudgetTimeout(
                        "resource budget timeout for {} after {:.2f}s".format(
                            resource, wait_seconds))
                status = "waiting_extended"
                _update_stage_budget(task_id, stage, resource, wait_seconds, status)
                logger.warning(
                    "resource budget still waiting resource:{} task_id:{} stage:{} wait:{:.2f}s".format(
                        resource, task_id, stage, wait_seconds))
                deadline = time.time() + wait_timeout

            time.sleep(max(poll_interval, 0.1))

        wait_seconds = time.time() - started
        acquired_at = time.time()
        _update_stage_budget(task_id, stage, resource, wait_seconds, status)
        if wait_seconds >= 1:
            logger.info("resource budget {} resource:{} wait:{:.2f}s task_id:{} stage:{}".format(
                status, resource, wait_seconds, task_id, stage))

        heartbeat = _LockHeartbeat(lock_id, owner, ttl)
        heartbeat.start()
        yield True
    finally:
        if heartbeat:
            heartbeat.stop()
        if lock_id:
            finished_at = time.time()
            _update_stage_budget(
                task_id,
                stage,
                resource,
                wait_seconds,
                "released",
                held_seconds=(
                    finished_at - acquired_at if acquired_at is not None else 0),
                total_seconds=finished_at - started,
            )
        if lock_id:
            try:
                utils.conn_db("runtime_resource_lock").delete_one({"_id": lock_id, "owner": owner})
            except Exception as e:
                logger.warning("resource budget release failed resource:{} lock:{} error:{}".format(
                    resource, lock_id, e))
