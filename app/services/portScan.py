import hashlib
import json
import os
import re
import shlex
import signal
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from pymongo import UpdateOne

from app import utils
from app.utils import nmap, is_valid_exclude_ports
from app.config import Config
from app.services.baseUpdateTask import BaseUpdateTask
from app.services.resourceBudget import acquire as acquire_resource_budget

logger = utils.get_logger()


CHECKPOINT_COLLECTION = "port_scan_checkpoint"
SUM_META_FIELDS = (
    "naabu_batch_total",
    "naabu_batch_succeeded",
    "naabu_timeout_count",
    "naabu_failure_count",
    "naabu_fallback_batch_count",
    "naabu_fallback_target_count",
    "naabu_circuit_skipped_batch_count",
    "naabu_circuit_skipped_target_count",
    "nmap_batch_total",
    "nmap_batch_succeeded",
    "nmap_timeout_count",
    "nmap_failed_batch_count",
    "nmap_exit_error_count",
    "nmap_parse_error_count",
    "nmap_salvaged_batch_count",
    "nmap_overopen_host_count",
    "batch_callback_failure_count",
    "checkpoint_completed_target_count",
)


class PortScanResult(list):
    def __init__(self, values=None, meta=None):
        super().__init__(values or [])
        self.meta = dict(meta or {})


def _chunked(items, size):
    size = max(int(size or 1), 1)
    for i in range(0, len(items), size):
        yield items[i:i + size]


def _normalize_port_text(ports):
    return ",".join(str(ports or "").replace(" ", "").split(","))


def _is_top1000_ports(ports):
    return _normalize_port_text(ports) == _normalize_port_text(Config.TOP_1000)


def _count_port_spec(port_text):
    intervals = []
    for part in str(port_text or "").replace(" ", "").split(","):
        if not part:
            continue
        try:
            if "-" in part:
                start, end = [int(value) for value in part.split("-", 1)]
            else:
                start = end = int(part)
        except (TypeError, ValueError):
            continue
        start, end = sorted((start, end))
        start = max(start, 1)
        end = min(end, 65535)
        if start <= end:
            intervals.append((start, end))
    if not intervals:
        return 0
    merged = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return sum(end - start + 1 for start, end in merged)


def _sort_ports(ports):
    def _key(port):
        try:
            return int(port)
        except (TypeError, ValueError):
            return 0

    return sorted(set([str(p) for p in ports if str(p or "").strip()]), key=_key)


def _port_to_int(port):
    try:
        port_int = int(str(port).strip())
    except (TypeError, ValueError):
        return None
    if port_int <= 0 or port_int > 65535:
        return None
    return port_int


def _expand_port_text(port_text, max_range_span=4096):
    ports = set()
    for part in str(port_text or "").replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            try:
                start, end = [int(x) for x in part.split("-", 1)]
            except ValueError:
                continue
            if start > end:
                start, end = end, start
            if max_range_span is not None and end - start > max_range_span:
                continue
            for port in range(start, end + 1):
                if 0 < port <= 65535:
                    ports.add(str(port))
            continue

        port_int = _port_to_int(part)
        if port_int:
            ports.add(str(port_int))
    return ports


def _compress_port_numbers(ports):
    normalized = set()
    for port in ports:
        port_int = _port_to_int(port)
        if port_int:
            normalized.add(port_int)
    values = sorted(normalized)
    if not values:
        return ""

    ranges = []
    start = previous = values[0]
    for port in values[1:]:
        if port == previous + 1:
            previous = port
            continue
        ranges.append(str(start) if start == previous else "{}-{}".format(start, previous))
        start = previous = port
    ranges.append(str(start) if start == previous else "{}-{}".format(start, previous))
    return ",".join(ranges)


def _remaining_port_text(exclude_ports):
    excluded = set(int(port) for port in _expand_port_text(exclude_ports, max_range_span=None))
    return _compress_port_numbers(port for port in range(1, 65536) if port not in excluded)


class PortScan:
    def __init__(self, targets, ports=None, service_detect=False, os_detect=False,
                 port_parallelism=None, port_min_rate=None, custom_host_timeout=None,
                 exclude_ports=None, task_id=None, batch_callback=None,
                 trusted_port_map=None, skip_host_discovery=False,
                 ):
        self.targets = sorted(set(targets))
        self.ports = ports
        self.max_host_group = 32
        self.alive_port = "22,80,443,843,3389,8007-8011,8443,9090,8080-8091,8093,8099,5000-5004,2222,3306,1433,21,25"
        self.max_retries = 3
        self.host_timeout = 60*5
        self.parallelism = port_parallelism if port_parallelism is not None else 32
        self.min_rate = port_min_rate if port_min_rate is not None else 64
        self.exclude_ports = exclude_ports
        self.skip_host_discovery = bool(skip_host_discovery)
        self.task_id = task_id
        self.batch_callback = batch_callback
        self.profile = "full" if self.ports == "0-65535" else "top1000" if _is_top1000_ports(self.ports) else "default"
        scan_type = "-sT"
        if self.profile == "full" and str(
                getattr(Config, "FULL_PORT_SCAN_TYPE", "connect") or "connect").lower() == "syn":
            if getattr(os, "geteuid", lambda: 1)() == 0:
                scan_type = "-sS"
            else:
                logger.warning("full port SYN scan requires root; fallback to TCP connect")
        self.nmap_arguments = "{} -n --open".format(scan_type)
        self.full_remaining_only = bool(self.profile == "full" and self.exclude_ports)
        if self.full_remaining_only:
            self.ports = _remaining_port_text(self.exclude_ports)
            self.exclude_ports = None
        self.port_fingerprint = hashlib.sha256(
            "{}:{}".format(self.profile, _normalize_port_text(self.ports)).encode("utf-8")
        ).hexdigest()
        self.base_update_task = BaseUpdateTask(task_id) if task_id else None
        self.trusted_port_map = self._normalize_trusted_port_map(trusted_port_map)
        self.overopen_hosts = {}
        self.meta = {
            "profile": self.profile,
            "input_target_count": len(self.targets),
            "naabu_batch_total": 0,
            "naabu_batch_succeeded": 0,
            "naabu_timeout_count": 0,
            "naabu_failure_count": 0,
            "naabu_fallback": False,
            "naabu_fallback_batch_count": 0,
            "naabu_fallback_target_count": 0,
            "naabu_circuit_open": False,
            "naabu_circuit_skipped_batch_count": 0,
            "naabu_circuit_skipped_target_count": 0,
            "naabu_skip_reason": "",
            "naabu_port_count": _count_port_spec(self.ports),
            "nmap_batch_total": 0,
            "nmap_batch_succeeded": 0,
            "nmap_timeout_count": 0,
            "nmap_failed_batch_count": 0,
            "nmap_exit_error_count": 0,
            "nmap_parse_error_count": 0,
            "nmap_salvaged_batch_count": 0,
            "nmap_overopen_host_count": 0,
            "batch_callback_failure_count": 0,
            "checkpoint_skipped_target_count": 0,
            "checkpoint_completed_target_count": 0,
            "pool_count": 1,
            "warnings": [],
        }

        if service_detect:
            self.host_timeout += 60 * 5
            self.nmap_arguments += " -sV"

        if os_detect:
            self.host_timeout += 60 * 4
            self.nmap_arguments += " -O"

        if self.skip_host_discovery:
            self.nmap_arguments += " -Pn"
        elif self.profile == "full":
            self.nmap_arguments += " -PE -PS{}".format(self.alive_port)
            self.max_retries = 2
        elif len(self.ports.split(",")) > 60:
            self.nmap_arguments += " -PE -PS{}".format(self.alive_port)
            self.max_retries = 2
        else:
            if self.profile != "full":
                self.nmap_arguments += " -Pn"

        if self.profile == "top1000":
            self.max_host_group = Config.TOP1000_PORT_BATCH_SIZE
            self.min_rate = Config.TOP1000_PORT_MIN_RATE
            self.parallelism = Config.TOP1000_PORT_PARALLELISM
            self.host_timeout = Config.TOP1000_PORT_HOST_TIMEOUT
            self.max_retries = Config.TOP1000_PORT_MAX_RETRIES

        if self.profile == "full":
            self.max_host_group = 2
            self.min_rate = Config.FULL_PORT_MIN_RATE
            self.parallelism = Config.FULL_PORT_PARALLELISM

            self.host_timeout = Config.FULL_PORT_HOST_TIMEOUT
            self.max_retries = Config.FULL_PORT_MAX_RETRIES

        self.nmap_arguments += " --max-rtt-timeout 800ms"
        self.nmap_arguments += " --min-rate {}".format(self.min_rate)
        self.nmap_arguments += " --script-timeout 6s"
        self.nmap_arguments += " --max-hostgroup {}".format(self.max_host_group)

        # 依据传过来的超时为准
        if custom_host_timeout is not None:
            if int(custom_host_timeout) > 0:
                self.host_timeout = custom_host_timeout
        self.nmap_arguments += " --host-timeout {}s".format(self.host_timeout)
        self.nmap_arguments += " --min-parallelism {}".format(self.parallelism)
        self.nmap_arguments += " --max-retries {}".format(self.max_retries)

        if self.exclude_ports is not None:
            if self.exclude_ports != "" and\
                    is_valid_exclude_ports(self.exclude_ports):
                self.nmap_arguments += " --exclude-ports {}".format(self.exclude_ports)

    def task_stopped(self):
        if not self.base_update_task:
            return False
        try:
            return self.base_update_task.is_terminal()
        except Exception as e:
            logger.warning("nmap check task status failed: {}".format(e))
            return False

    def add_warning(self, message):
        message = str(message or "").strip()
        if message and message not in self.meta["warnings"]:
            self.meta["warnings"].append(message)

    def checkpoint_enabled(self):
        return bool(
            self.task_id and
            self.profile == "full" and
            getattr(Config, "PORT_SCAN_CHECKPOINT_ENABLE", True)
        )

    def completed_checkpoint_targets(self):
        if not self.checkpoint_enabled():
            return set()
        try:
            cursor = utils.conn_db(CHECKPOINT_COLLECTION).find(
                {
                    "task_id": self.task_id,
                    "profile": self.profile,
                    "port_fingerprint": self.port_fingerprint,
                    "status": "done",
                },
                {"_id": 0, "ip": 1},
            )
            return {
                str(item.get("ip") or "").strip()
                for item in cursor
                if str(item.get("ip") or "").strip()
            }
        except Exception as e:
            logger.warning("load port scan checkpoints failed task:{} error:{}".format(
                self.task_id, e))
            return set()

    def checkpoint_target_states(self):
        if not self.checkpoint_enabled():
            return {}
        try:
            cursor = utils.conn_db(CHECKPOINT_COLLECTION).find(
                {
                    "task_id": self.task_id,
                    "profile": self.profile,
                    "port_fingerprint": self.port_fingerprint,
                },
                {
                    "_id": 0,
                    "ip": 1,
                    "status": 1,
                    "attempt_count": 1,
                    "updated_at": 1,
                },
            )
            return {
                str(item.get("ip") or "").strip(): item
                for item in cursor
                if str(item.get("ip") or "").strip()
            }
        except Exception as e:
            logger.warning("load port scan checkpoint states failed task:{} error:{}".format(
                self.task_id, e))
            return {}

    def mark_checkpoint(self, targets, status, result_host_count=0, error=""):
        if not self.checkpoint_enabled() or not targets:
            return 0

        now = utils.curr_date()
        target_set = sorted(set(targets))
        existing_states = {}
        if status == "running":
            try:
                existing_states = {
                    str(item.get("ip") or "").strip(): item
                    for item in utils.conn_db(CHECKPOINT_COLLECTION).find(
                        {
                            "task_id": self.task_id,
                            "profile": self.profile,
                            "ip": {"$in": target_set},
                        },
                        {
                            "_id": 0,
                            "ip": 1,
                            "port_fingerprint": 1,
                            "attempt_count": 1,
                        },
                    )
                    if str(item.get("ip") or "").strip()
                }
            except Exception as e:
                logger.warning(
                    "load checkpoint attempts failed task:{} error:{}".format(
                        self.task_id, e))
        operations = []
        for host in target_set:
            item = {
                "task_id": self.task_id,
                "profile": self.profile,
                "ip": host,
                "port_fingerprint": self.port_fingerprint,
                "status": status,
                "scan_type": "syn" if "-sS" in self.nmap_arguments else "connect",
                "result_host_count": int(result_host_count or 0),
                "updated_at": now,
            }
            if status == "done":
                item["completed_at"] = now
            if error:
                item["error"] = str(error)[:1000]

            update = {
                "$set": item,
                "$setOnInsert": {"created_at": now},
            }
            if status == "running":
                old_state = existing_states.get(host) or {}
                old_attempts = int(old_state.get("attempt_count", 0) or 0)
                if old_state.get("port_fingerprint") != self.port_fingerprint:
                    old_attempts = 0
                update["$set"]["attempt_count"] = old_attempts + 1
            if not error:
                update["$unset"] = {"error": ""}
            operations.append(UpdateOne(
                {
                    "task_id": self.task_id,
                    "profile": self.profile,
                    "ip": host,
                },
                update,
                upsert=True,
            ))

        try:
            utils.conn_db(CHECKPOINT_COLLECTION).bulk_write(operations, ordered=False)
            return len(operations)
        except Exception as e:
            logger.warning("save port scan checkpoints failed task:{} status:{} error:{}".format(
                self.task_id, status, e))
            return 0

    def build_result(self, values):
        error_count = (
            self.meta["naabu_timeout_count"] +
            self.meta["naabu_failure_count"] +
            self.meta["nmap_timeout_count"] +
            self.meta["nmap_failed_batch_count"] +
            self.meta["nmap_exit_error_count"] +
            self.meta["batch_callback_failure_count"] +
            int(self.meta.get("checkpoint_exhausted_target_count", 0) or 0)
        )
        degraded_reasons = []
        if self.meta["naabu_timeout_count"]:
            degraded_reasons.append("naabu_timeout")
        if self.meta["naabu_failure_count"]:
            degraded_reasons.append("naabu_failed")
        partial_reasons = []
        if self.meta["nmap_timeout_count"]:
            partial_reasons.append("nmap_timeout")
        if self.meta["nmap_failed_batch_count"]:
            partial_reasons.append("nmap_batch_failed")
        if self.meta["nmap_exit_error_count"]:
            partial_reasons.append("nmap_exit_error")
        if self.meta["nmap_parse_error_count"]:
            partial_reasons.append("nmap_parse_recovery")
        if self.meta["batch_callback_failure_count"]:
            partial_reasons.append("port_batch_callback_failed")
        if self.meta.get("checkpoint_exhausted_target_count"):
            partial_reasons.append("checkpoint_retry_exhausted")

        self.meta.update({
            "output_host_count": len(values),
            "error_count": error_count,
            "partial": bool(partial_reasons),
            "partial_reason": ",".join(partial_reasons),
            "completion_state": (
                "partial" if partial_reasons else
                "done_with_warnings" if degraded_reasons else "done"
            ),
            "degraded_reasons": degraded_reasons,
            "warning": "; ".join(self.meta["warnings"][:5]),
        })
        return PortScanResult(values, meta=self.meta)

    def batch_size(self):
        if self.profile == "full":
            return max(int(getattr(Config, "FULL_PORT_BATCH_SIZE", 4)), 1)
        if self.profile == "top1000":
            return max(int(getattr(Config, "TOP1000_PORT_BATCH_SIZE", 8)), 1)
        return max(int(getattr(Config, "PORT_SCAN_BATCH_SIZE", 32)), 1)

    def process_timeout(self, batch):
        # Nmap --host-timeout is per host; process timeout is only a final guard.
        return max(self.host_timeout + 60, self.host_timeout * max(len(batch), 1) + 60)

    def terminate_process(self, proc, reason):
        output = b""
        stderr = b""
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            return output, stderr

        try:
            output, stderr = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            output, stderr = proc.communicate()

        logger.warning("nmap process terminated: {}".format(reason))
        return output or b"", stderr or b""

    def _split_nmap_stderr(self, nmap_err):
        nmap_err_keep_trace = []
        nmap_warn_keep_trace = []
        if nmap_err:
            regex_warning = re.compile("^Warning: .*", re.IGNORECASE)
            for line in nmap_err.split(os.linesep):
                if not line:
                    continue
                if regex_warning.search(line) is not None:
                    nmap_warn_keep_trace.append(line + os.linesep)
                else:
                    nmap_err_keep_trace.append(line + os.linesep)
        return nmap_err_keep_trace, nmap_warn_keep_trace

    def _salvage_nmap_xml(self, xml_output):
        if not xml_output:
            return ""

        host_blocks = re.findall(r"<host\b[\s\S]*?</host>", xml_output)
        if not host_blocks:
            return ""

        total = len(host_blocks)
        scan_type = "syn" if "-sS" in self.nmap_arguments else "connect"
        return (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<nmaprun scanner="nmap" args="salvaged-timeout-output" start="0" startstr="">'
            '<scaninfo type="{}" protocol="tcp" services=""/>'
            '{}'
            '<runstats><finished time="0" timestr="salvaged" elapsed="0" summary="salvaged timeout output"/>'
            '<hosts up="{}" down="0" total="{}"/></runstats>'
            '</nmaprun>'
        ).format(scan_type, "".join(host_blocks), total, total)

    def _analyse_nmap_output(self, nm, xml_output, nmap_err):
        nmap_err_keep_trace, nmap_warn_keep_trace = self._split_nmap_stderr(nmap_err)
        try:
            nm.analyse_nmap_xml_scan(
                nmap_xml_output=xml_output,
                nmap_err=nmap_err,
                nmap_err_keep_trace=nmap_err_keep_trace,
                nmap_warn_keep_trace=nmap_warn_keep_trace
            )
            return nm
        except Exception as e:
            self.meta["nmap_parse_error_count"] += 1
            salvaged_xml = self._salvage_nmap_xml(xml_output)
            if not salvaged_xml:
                logger.warning("nmap parse failed batch xml_len:{} error:{}".format(len(xml_output or ""), e))
                return None

            try:
                nm.analyse_nmap_xml_scan(
                    nmap_xml_output=salvaged_xml,
                    nmap_err="",
                    nmap_err_keep_trace=[],
                    nmap_warn_keep_trace=nmap_warn_keep_trace
                )
                logger.warning("nmap parsed salvaged timeout xml hosts:{}".format(
                    len(re.findall(r"<host\b", salvaged_xml))))
                self.meta["nmap_salvaged_batch_count"] += 1
                return nm
            except Exception as salvage_error:
                logger.warning("nmap salvage parse failed xml_len:{} error:{}".format(
                    len(xml_output or ""), salvage_error))
                return None

    def scan_batch(self, batch, nm, ports_override=None):
        hosts = " ".join(batch)
        h_args = shlex.split(hosts)
        f_args = shlex.split(self.nmap_arguments)
        args = [nm._nmap_path, "-oX", "-"] + h_args
        scan_ports = ports_override if ports_override is not None else self.ports
        if scan_ports is not None:
            args.extend(["-p", scan_ports])
        args.extend(f_args)

        proc = subprocess.Popen(
            args,
            bufsize=100000,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )

        deadline = time.time() + self.process_timeout(batch)
        timed_out = False
        while True:
            try:
                # communicate() drains both pipes while Nmap is running. Polling
                # first can deadlock once verbose XML output fills stdout.
                output, stderr = proc.communicate(timeout=1)
                break
            except subprocess.TimeoutExpired:
                pass

            if self.task_stopped():
                self.terminate_process(proc, "task stopped {}".format(self.task_id))
                return None

            if time.time() > deadline:
                timed_out = True
                self.meta["nmap_timeout_count"] += 1
                self.add_warning("nmap timeout on {} targets profile {}".format(len(batch), self.profile))
                output, stderr = self.terminate_process(
                    proc, "timeout after {}s".format(self.process_timeout(batch)))
                if not output:
                    return None
                break

            time.sleep(1)

        xml_output = bytes.decode(output or b"", errors="ignore")
        nmap_err = bytes.decode(stderr or b"", errors="ignore")
        if proc.returncode not in (0, None) and not timed_out:
            self.meta["nmap_exit_error_count"] += 1
            self.add_warning("nmap exit {} profile {}".format(proc.returncode, self.profile))
        return self._analyse_nmap_output(nm, xml_output, nmap_err)

    def use_naabu(self):
        if not getattr(Config, "PORT_SCAN_NAABU_ENABLE", True):
            return False
        if not self.ports:
            return False
        if self.profile == "full" and not getattr(Config, "PORT_SCAN_NAABU_FULL_ENABLE", False):
            logger.info("skip naabu full-port discovery; PORT_SCAN_NAABU_FULL_ENABLE=false")
            return False
        port_count = _count_port_spec(self.ports)
        max_ports = max(int(getattr(Config, "NAABU_MAX_PORTS", 512) or 0), 0)
        if max_ports and port_count > max_ports:
            self.meta["naabu_skip_reason"] = "port_count_exceeds_limit"
            self.meta["naabu_port_count"] = port_count
            logger.info(
                "skip naabu discovery; ports:{} exceeds limit:{} profile:{}; "
                "use direct nmap".format(port_count, max_ports, self.profile))
            return False
        return os.path.isfile(getattr(Config, "NAABU_BIN", "/usr/local/bin/naabu"))

    def naabu_ports(self):
        return self.ports

    def naabu_batch_size(self):
        if self.profile == "full":
            return max(int(getattr(Config, "NAABU_FULL_BATCH_SIZE", 32)), 1)
        return max(int(getattr(Config, "NAABU_BATCH_SIZE", 128)), 1)

    def naabu_process_timeout(self):
        if self.profile == "full":
            return max(int(getattr(Config, "NAABU_FULL_PROCESS_TIMEOUT", 1200)), 60)
        return max(int(getattr(Config, "NAABU_PROCESS_TIMEOUT", 600)), 60)

    def _parse_naabu_output(self, output):
        discovered = {}
        for line in (output or "").splitlines():
            line = line.strip()
            if not line:
                continue

            host = ""
            port = ""
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    host = item.get("host") or item.get("ip") or item.get("address") or ""
                    port = item.get("port") or ""
            except ValueError:
                match = re.match(r"^(.+?):(\d+)$", line)
                if match:
                    host, port = match.group(1), match.group(2)

            host = str(host or "").strip()
            port = str(port or "").strip()
            if not host or not re.match(r"^\d{1,5}$", port):
                continue
            port_int = int(port)
            if port_int <= 0 or port_int > 65535:
                continue
            discovered.setdefault(host, set()).add(str(port_int))

        return discovered

    def _normalize_trusted_port_map(self, trusted_port_map):
        ret = {}
        for host, ports in (trusted_port_map or {}).items():
            host = str(host or "").strip()
            if not host:
                continue
            if isinstance(ports, str):
                port_values = _expand_port_text(ports)
            else:
                port_values = set()
                for port in ports or []:
                    port_int = _port_to_int(port)
                    if port_int:
                        port_values.add(str(port_int))
            if port_values:
                ret[host] = port_values
        return ret

    def _overopen_threshold(self):
        if not getattr(Config, "PORT_SCAN_OVEROPEN_ENABLE", True):
            return 0
        if self.profile == "full":
            return int(getattr(Config, "PORT_SCAN_OVEROPEN_FULL_THRESHOLD", 200) or 200)
        if self.profile == "top1000":
            return int(getattr(Config, "PORT_SCAN_OVEROPEN_TOP1000_THRESHOLD", 80) or 80)
        return int(getattr(Config, "PORT_SCAN_OVEROPEN_DEFAULT_THRESHOLD", 120) or 120)

    def _is_overopen_ports(self, ports):
        threshold = self._overopen_threshold()
        return bool(threshold and len(ports or []) > threshold)

    def _overopen_keep_ports(self, host, ports):
        ports = set([str(p) for p in ports or []])
        trusted = self.trusted_port_map.get(host, set())
        common = _expand_port_text(getattr(Config, "PORT_SCAN_OVEROPEN_KEEP_PORTS", ""))
        keep = (ports & trusted) | (ports & common)
        limit = int(getattr(Config, "PORT_SCAN_OVEROPEN_CONFIRM_MAX_PORTS", 40) or 40)
        if limit > 0:
            return set(_sort_ports(keep)[:limit])
        return keep

    def _bulk_write_port_candidates(self, operations):
        if not operations:
            return
        try:
            utils.conn_db("port_candidate").bulk_write(operations, ordered=False)
        except Exception as e:
            logger.warning("save port_candidate failed task:{} error:{}".format(self.task_id, e))

    def _save_naabu_port_candidates(self, target_port_map):
        if not self.task_id or not target_port_map:
            return

        operations = []
        now = utils.curr_date()
        for host, ports in target_port_map.items():
            ports = set([str(p) for p in ports or []])
            raw_count = len(ports)
            overopen = self._is_overopen_ports(ports)
            for port in _sort_ports(ports):
                port_int = _port_to_int(port)
                if not port_int:
                    continue
                item = {
                    "task_id": self.task_id,
                    "ip": host,
                    "port": port_int,
                    "profile": self.profile,
                    "source": "naabu",
                    "status": "candidate",
                    "confirmed": False,
                    "overopen": overopen,
                    "raw_port_count": raw_count,
                    "relation_level": "candidate",
                    "relation_reason": "overopen_candidate" if overopen else "naabu_discovered",
                    "update_date": now,
                }
                query = {
                    "task_id": self.task_id,
                    "ip": host,
                    "port": port_int,
                    "profile": self.profile,
                    "source": "naabu",
                }
                operations.append(UpdateOne(query, {"$set": item, "$setOnInsert": {"save_date": now}}, upsert=True))
                if len(operations) >= 1000:
                    self._bulk_write_port_candidates(operations)
                    operations = []
        self._bulk_write_port_candidates(operations)

    def _mark_confirmed_port_candidates(self, ip_info_list):
        if not self.task_id or not ip_info_list:
            return

        operations = []
        now = utils.curr_date()
        for item in ip_info_list:
            host = item.get("ip")
            for port_info in item.get("port_info") or []:
                port_int = _port_to_int(port_info.get("port_id"))
                if not host or not port_int:
                    continue
                query = {
                    "task_id": self.task_id,
                    "ip": host,
                    "port": port_int,
                    "profile": self.profile,
                    "source": "naabu",
                }
                update = {
                    "$set": {
                        "status": "confirmed",
                        "confirmed": True,
                        "relation_level": "confirmed",
                        "relation_reason": "nmap_confirmed",
                        "confirmed_date": now,
                        "update_date": now,
                    },
                    "$setOnInsert": {"save_date": now},
                }
                operations.append(UpdateOne(query, update, upsert=True))
        self._bulk_write_port_candidates(operations)

    def _mark_overopen_host(self, host, raw_ports, confirm_ports):
        if not self.task_id or not host:
            return

        try:
            utils.conn_db("ip").update_one(
                {"task_id": self.task_id, "ip": host},
                {
                    "$set": {
                        "task_id": self.task_id,
                        "ip": host,
                        "port_scan_overopen": True,
                        "overopen_profile": self.profile,
                        "overopen_port_count": len(raw_ports),
                        "overopen_confirm_ports": [int(x) for x in _sort_ports(confirm_ports)],
                        "overopen_reason": "too_many_open_ports",
                        "overopen_update_date": utils.curr_date(),
                    },
                    "$addToSet": {"tag": "疑似泛开放端口"},
                },
                upsert=True,
            )
        except Exception as e:
            logger.warning("mark overopen host failed task:{} host:{} error:{}".format(
                self.task_id, host, e))

    def _prepare_target_port_map(self, target_port_map):
        self._save_naabu_port_candidates(target_port_map)
        prepared = {}
        skipped = 0
        for host, ports in target_port_map.items():
            ports = set([str(p) for p in ports or []])
            if not ports:
                continue
            if self._is_overopen_ports(ports):
                confirm_ports = self._overopen_keep_ports(host, ports)
                self.overopen_hosts[host] = {
                    "raw_count": len(ports),
                    "confirm_count": len(confirm_ports),
                }
                self._mark_overopen_host(host, ports, confirm_ports)
                if not confirm_ports:
                    skipped += 1
                    logger.warning("port overopen skip nmap host:{} raw_ports:{} profile:{}".format(
                        host, len(ports), self.profile))
                    continue
                prepared[host] = confirm_ports
                logger.warning("port overopen downgrade host:{} raw_ports:{} confirm_ports:{} profile:{}".format(
                    host, len(ports), len(confirm_ports), self.profile))
                continue
            prepared[host] = ports

        if skipped:
            logger.warning("port overopen skipped hosts:{} profile:{} task:{}".format(
                skipped, self.profile, self.task_id))
        return prepared

    def _filter_direct_nmap_overopen(self, ip_info_list):
        filtered = []
        for item in ip_info_list or []:
            host = item.get("ip")
            port_info = list(item.get("port_info") or [])
            raw_ports = set(str(value.get("port_id")) for value in port_info if value.get("port_id"))
            if not self._is_overopen_ports(raw_ports):
                filtered.append(item)
                continue

            confirm_ports = self._overopen_keep_ports(host, raw_ports)
            self.overopen_hosts[host] = {
                "raw_count": len(raw_ports),
                "confirm_count": len(confirm_ports),
            }
            self._save_direct_overopen_candidates(host, port_info, len(raw_ports))
            self._mark_overopen_host(host, raw_ports, confirm_ports)
            self.meta["nmap_overopen_host_count"] += 1
            item["port_info"] = [
                value for value in port_info
                if str(value.get("port_id")) in confirm_ports
            ]
            logger.warning(
                "direct nmap overopen downgrade host:{} raw_ports:{} confirm_ports:{} profile:{}".format(
                    host, len(raw_ports), len(item["port_info"]), self.profile
                )
            )
            if item["port_info"]:
                filtered.append(item)
        return filtered

    def _save_direct_overopen_candidates(self, host, port_info, raw_count):
        if not self.task_id or not host:
            return
        operations = []
        now = utils.curr_date()
        for value in port_info or []:
            port_int = _port_to_int(value.get("port_id"))
            if not port_int:
                continue
            item = {
                "task_id": self.task_id,
                "ip": host,
                "port": port_int,
                "profile": self.profile,
                "source": "nmap",
                "status": "overopen_candidate",
                "confirmed": False,
                "overopen": True,
                "raw_port_count": raw_count,
                "relation_level": "candidate",
                "relation_reason": "direct_nmap_overopen",
                "update_date": now,
            }
            query = {
                "task_id": self.task_id,
                "ip": host,
                "port": port_int,
                "profile": self.profile,
                "source": "nmap",
            }
            operations.append(UpdateOne(
                query, {"$set": item, "$setOnInsert": {"save_date": now}}, upsert=True))
            if len(operations) >= 1000:
                self._bulk_write_port_candidates(operations)
                operations = []
        self._bulk_write_port_candidates(operations)

    def _run_naabu_batch(self, batch):
        fd, input_path = tempfile.mkstemp(prefix="arl_naabu_", suffix=".txt")
        try:
            with os.fdopen(fd, "w") as fp:
                fp.write("\n".join(batch) + "\n")

            command = [
                getattr(Config, "NAABU_BIN", "/usr/local/bin/naabu"),
                "-l", input_path,
                "-p", self.naabu_ports(),
                "-json",
                "-silent",
                "-scan-type", "c",
                "-Pn",
                "-ip-version", "4",
                "-rate", str(getattr(Config, "NAABU_RATE", 3000)),
                "-c", str(getattr(Config, "NAABU_CONCURRENCY", 100)),
                "-retries", str(getattr(Config, "NAABU_RETRIES", 1)),
                "-timeout", str(getattr(Config, "NAABU_TIMEOUT", 1000)),
                "-duc",
            ]
            if getattr(Config, "NAABU_VERIFY", True):
                command.append("-verify")
            if self.exclude_ports is not None and self.exclude_ports != "" and is_valid_exclude_ports(self.exclude_ports):
                command.extend(["-exclude-ports", self.exclude_ports])

            logger.info("naabu batch targets:{} ports:{} profile:{}".format(
                len(batch), self.naabu_ports(), self.profile))

            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                text=True,
            )
            try:
                stdout, stderr = proc.communicate(timeout=self.naabu_process_timeout())
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    stdout, stderr = proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    stdout, stderr = proc.communicate()
                logger.warning("naabu timeout after {}s targets:{} profile:{}".format(
                    self.naabu_process_timeout(), len(batch), self.profile))
                self.meta["naabu_timeout_count"] += 1
                self.add_warning("naabu timeout on {} targets profile {}".format(len(batch), self.profile))
                raise RuntimeError("naabu timeout after {}s".format(self.naabu_process_timeout()))

            if proc.returncode not in (0, None):
                logger.warning("naabu exit {} stderr:{}".format(
                    proc.returncode, (stderr or "").strip()[-500:]))
                self.meta["naabu_failure_count"] += 1
                self.add_warning("naabu exit {} profile {}".format(proc.returncode, self.profile))
                raise RuntimeError("naabu exit {}".format(proc.returncode))

            return self._parse_naabu_output(stdout or "")
        finally:
            try:
                os.unlink(input_path)
            except OSError:
                pass

    def run_naabu_discovery(self):
        discovered = {}
        fallback_targets = []
        batch_size = self.naabu_batch_size()
        total_batches = (len(self.targets) + batch_size - 1) // batch_size
        self.meta["naabu_batch_total"] = total_batches
        batches = list(_chunked(self.targets, batch_size))
        failed_batches = 0
        consecutive_failures = 0
        failure_threshold = max(int(getattr(
            Config, "NAABU_CIRCUIT_FAILURE_THRESHOLD", 2) or 2), 1)
        minimum_batches = max(int(getattr(
            Config, "NAABU_CIRCUIT_MIN_BATCHES", 3) or 3), 1)
        failure_ratio = min(max(float(getattr(
            Config, "NAABU_CIRCUIT_FAILURE_RATIO", 0.5) or 0.5), 0.0), 1.0)
        for batch_index, batch in enumerate(batches, 1):
            if self.task_stopped():
                logger.warning("naabu stop before batch {}/{}".format(batch_index, total_batches))
                return discovered, fallback_targets

            attempted_batches = batch_index - 1
            open_circuit = consecutive_failures >= failure_threshold
            if attempted_batches >= minimum_batches:
                open_circuit = open_circuit or (
                    failed_batches / float(max(attempted_batches, 1)) >= failure_ratio)
            if open_circuit:
                remaining_batches = batches[batch_index - 1:]
                remaining_targets = [
                    target for remaining in remaining_batches for target in remaining
                ]
                fallback_targets.extend(remaining_targets)
                self.meta["naabu_fallback"] = True
                self.meta["naabu_circuit_open"] = True
                self.meta["naabu_fallback_batch_count"] += len(remaining_batches)
                self.meta["naabu_fallback_target_count"] += len(remaining_targets)
                self.meta["naabu_circuit_skipped_batch_count"] += len(remaining_batches)
                self.meta["naabu_circuit_skipped_target_count"] += len(remaining_targets)
                warning = (
                    "naabu circuit breaker opened after {} failed batch(es); "
                    "{} remaining target(s) use nmap fallback"
                ).format(failed_batches, len(remaining_targets))
                self.add_warning(warning)
                logger.warning("{} profile:{}".format(warning, self.profile))
                break

            error_count_before = (
                self.meta["naabu_timeout_count"] +
                self.meta["naabu_failure_count"]
            )
            try:
                with acquire_resource_budget("tool:naabu", task_id=self.task_id):
                    batch_result = self._run_naabu_batch(batch)
            except Exception as e:
                failed_batches += 1
                consecutive_failures += 1
                error_count_after = (
                    self.meta["naabu_timeout_count"] +
                    self.meta["naabu_failure_count"]
                )
                if error_count_after == error_count_before:
                    self.meta["naabu_failure_count"] += 1
                fallback_targets.extend(batch)
                self.meta["naabu_fallback"] = True
                self.meta["naabu_fallback_batch_count"] += 1
                self.meta["naabu_fallback_target_count"] += len(batch)
                self.add_warning(
                    "naabu batch {}/{} fallback to direct nmap: {}".format(
                        batch_index, total_batches, e))
                logger.warning(
                    "naabu batch {}/{} failed targets:{} profile:{}; keep prior "
                    "results and fallback this batch to nmap: {}".format(
                        batch_index, total_batches, len(batch), self.profile, e))
                continue
            self.meta["naabu_batch_succeeded"] += 1
            consecutive_failures = 0

            for host, ports in batch_result.items():
                discovered.setdefault(host, set()).update(ports)

            logger.info("naabu batch {}/{} targets:{} open_hosts:{} open_ports:{}".format(
                batch_index, total_batches, len(batch), len(batch_result),
                sum(len(x) for x in batch_result.values())))

        return discovered, sorted(set(fallback_targets))

    def _ports_for_batch(self, batch, target_port_map):
        ports = []
        for host in batch:
            ports.extend(target_port_map.get(host, []))
        return ",".join(_sort_ports(ports))

    def _nmap_work_items(self, target_port_map, batch_size, direct_targets=None):
        if not target_port_map:
            targets = self.targets if direct_targets is None else direct_targets
            return [(batch, None) for batch in _chunked(targets, batch_size)]

        groups = {}
        for host in self.targets:
            ports_text = ",".join(_sort_ports(target_port_map.get(host, [])))
            if not ports_text:
                continue
            groups.setdefault(ports_text, []).append(host)

        work_items = []
        for ports_text in sorted(groups.keys()):
            for batch in _chunked(groups[ports_text], batch_size):
                work_items.append((batch, ports_text))
        for batch in _chunked(sorted(set(direct_targets or [])), batch_size):
            work_items.append((batch, None))
        return work_items

    def parse_result(self, nm):
        ip_info_list = []
        for host in nm.all_hosts():
            port_info_list = []
            for proto in nm[host].all_protocols():
                port_len = len(nm[host][proto])

                for port in nm[host][proto]:
                    # 对于开了很多端口的直接丢弃
                    if port_len > 600 and (port not in [80, 443]):
                        continue

                    port_info = nm[host][proto][port]
                    item = {
                        "port_id": port,
                        "service_name": port_info["name"],
                        "version": port_info["version"],
                        "product": port_info["product"],
                        "protocol": proto
                    }

                    port_info_list.append(item)

            osmatch_list = nm[host].get("osmatch", [])
            os_info = self.os_match_by_accuracy(osmatch_list)

            ip_info = {
                "ip": host,
                "port_info": port_info_list,
                "os_info": os_info
            }
            ip_info_list.append(ip_info)

        return ip_info_list

    def run(self):
        logger.info("nmap target {}  ports {}  profile {}  arguments {}".format(
            str(self.targets[:3])[:120], self.ports[:20], self.profile, self.nmap_arguments))
        target_port_map = None
        direct_nmap_targets = None
        if self.use_naabu():
            try:
                target_port_map, direct_nmap_targets = self.run_naabu_discovery()
            except Exception as e:
                logger.warning("naabu discovery failed, fallback to direct nmap: {}".format(e))
                if not self.meta["naabu_timeout_count"] and not self.meta["naabu_failure_count"]:
                    self.meta["naabu_failure_count"] += 1
                self.meta["naabu_fallback"] = True
                self.add_warning("naabu fallback to direct nmap: {}".format(e))
                target_port_map = None
                direct_nmap_targets = list(self.targets)

            if target_port_map is not None:
                if not target_port_map and not direct_nmap_targets:
                    logger.info("naabu found no open ports profile:{} targets:{}".format(
                        self.profile, len(self.targets)))
                    return self.build_result([])
                raw_open_hosts = len(target_port_map)
                raw_open_ports = sum(len(x) for x in target_port_map.values())
                target_port_map = self._prepare_target_port_map(target_port_map)
                if not target_port_map and not direct_nmap_targets:
                    logger.info("naabu found only candidate ports after overopen filter profile:{} raw_hosts:{} raw_ports:{}".format(
                        self.profile, raw_open_hosts, raw_open_ports))
                    return self.build_result([])
                logger.info("naabu discovered open hosts:{} open ports:{} profile:{}".format(
                    raw_open_hosts, raw_open_ports, self.profile))
                logger.info("nmap confirm hosts:{} ports:{} fallback_targets:{} profile:{} overopen_hosts:{}".format(
                    len(self.targets), sum(len(x) for x in target_port_map.values()),
                    len(direct_nmap_targets or []), self.profile, len(self.overopen_hosts)))

        ip_info_list = []
        batch_size = self.batch_size()
        work_items = self._nmap_work_items(
            target_port_map, batch_size, direct_targets=direct_nmap_targets)
        total_batches = len(work_items)
        self.meta["nmap_batch_total"] = total_batches
        for batch_index, (batch, ports_override) in enumerate(work_items, 1):
            if self.task_stopped():
                logger.warning("nmap stop before batch {}/{}".format(batch_index, total_batches))
                break

            self.mark_checkpoint(batch, "running")
            logger.info("nmap batch {}/{} targets:{} ports:{} profile:{}".format(
                batch_index, total_batches, len(batch),
                len(ports_override.split(",")) if ports_override else "default", self.profile))
            incomplete_before = (
                self.meta["nmap_timeout_count"],
                self.meta["nmap_exit_error_count"],
                self.meta["nmap_parse_error_count"],
            )
            try:
                batch_nm = self.scan_batch(batch, nmap.PortScanner(), ports_override=ports_override)
            except Exception as e:
                self.meta["nmap_failed_batch_count"] += 1
                self.add_warning("nmap batch {}/{} exception profile {}: {}".format(
                    batch_index, total_batches, self.profile, e))
                self.mark_checkpoint(batch, "failed", error=e)
                logger.exception(e)
                continue
            if batch_nm is None:
                if self.task_stopped():
                    self.mark_checkpoint(batch, "interrupted", error="task stopped")
                    break
                self.meta["nmap_failed_batch_count"] += 1
                self.add_warning("nmap batch {}/{} failed profile {}".format(
                    batch_index, total_batches, self.profile))
                self.mark_checkpoint(batch, "failed", error="nmap batch failed")
                continue

            try:
                batch_result = self.parse_result(batch_nm)
            except Exception as e:
                self.meta["nmap_failed_batch_count"] += 1
                self.add_warning("nmap parse batch {}/{} exception profile {}: {}".format(
                    batch_index, total_batches, self.profile, e))
                self.mark_checkpoint(batch, "failed", error=e)
                logger.exception(e)
                continue
            batch_result = self._filter_direct_nmap_overopen(batch_result)
            self.meta["nmap_batch_succeeded"] += 1
            self._mark_confirmed_port_candidates(batch_result)
            callback_ok = True
            if self.batch_callback is not None:
                try:
                    self.batch_callback(batch_result, batch_index, total_batches, self.profile)
                except Exception as e:
                    callback_ok = False
                    self.meta["batch_callback_failure_count"] += 1
                    self.add_warning(
                        "port batch callback {}/{} failed profile {}: {}".format(
                            batch_index, total_batches, self.profile, e))
                    logger.warning("nmap batch callback failed: {}".format(e))
            incomplete_after = (
                self.meta["nmap_timeout_count"],
                self.meta["nmap_exit_error_count"],
                self.meta["nmap_parse_error_count"],
            )
            batch_complete = callback_ok and incomplete_after == incomplete_before
            if batch_complete:
                saved = self.mark_checkpoint(
                    batch, "done", result_host_count=len(batch_result))
                self.meta["checkpoint_completed_target_count"] += saved
            else:
                reason = "batch callback failed" if not callback_ok else "incomplete nmap batch"
                self.mark_checkpoint(batch, "failed", error=reason)
            ip_info_list.extend(batch_result)

        return self.build_result(ip_info_list)

    def os_match_by_accuracy(self, os_match_list):
        for os_match in os_match_list:
            accuracy = os_match.get('accuracy', '0')
            if int(accuracy) > 90:
                return os_match

        return {}


def _merge_pool_results(
        prototype, pool_results, pool_count, skipped_targets,
        slice_targets=None, deferred_targets=None, exhausted_targets=None,
        failed_pool_count=0):
    values = []
    meta = dict(prototype.meta)
    for field in SUM_META_FIELDS:
        meta[field] = 0
    meta["naabu_fallback"] = False
    meta["naabu_circuit_open"] = False
    warnings = []

    for result in pool_results:
        values.extend(result)
        result_meta = dict(getattr(result, "meta", {}) or {})
        for field in SUM_META_FIELDS:
            meta[field] += int(result_meta.get(field, 0) or 0)
        meta["naabu_fallback"] = bool(
            meta["naabu_fallback"] or result_meta.get("naabu_fallback"))
        meta["naabu_circuit_open"] = bool(
            meta["naabu_circuit_open"] or result_meta.get("naabu_circuit_open"))
        for warning in result_meta.get("warnings") or []:
            if warning and warning not in warnings:
                warnings.append(warning)

    if failed_pool_count:
        meta["nmap_failed_batch_count"] += failed_pool_count
        warnings.append("{} full-port scan pool(s) failed".format(failed_pool_count))

    slice_targets = list(slice_targets or [])
    deferred_targets = list(deferred_targets or [])
    exhausted_targets = list(exhausted_targets or [])
    completed_targets = (
        len(skipped_targets) +
        int(meta.get("checkpoint_completed_target_count", 0) or 0)
    )
    total_targets = len(prototype.targets)
    meta.update({
        "input_target_count": len(prototype.targets),
        "checkpoint_skipped_target_count": len(skipped_targets),
        "checkpoint_exhausted_target_count": len(exhausted_targets),
        "slice_target_count": len(slice_targets),
        "deferred_target_count": len(deferred_targets),
        "continuation_required": bool(deferred_targets),
        "completed_targets": completed_targets,
        "total_targets": total_targets,
        "completion_ratio": round(
            float(completed_targets) / float(total_targets), 4
        ) if total_targets else 1.0,
        "pool_count": pool_count,
        "warnings": warnings,
    })
    if exhausted_targets:
        warnings.append(
            "{} full-port target(s) exhausted checkpoint retries".format(
                len(exhausted_targets)))
    prototype.meta = meta
    result = prototype.build_result(values)
    if deferred_targets and result.meta.get("completion_state") != "partial":
        result.meta["completion_state"] = "deferred"
    return result


def _run_full_port_pools(
        prototype, scanner_options, worker_count, max_targets=None):
    checkpoint_states = prototype.checkpoint_target_states()
    completed_targets = {
        host for host, item in checkpoint_states.items()
        if item.get("status") == "done"
    }
    skipped_targets = set(prototype.targets) & completed_targets
    pending_targets = [
        host for host in prototype.targets if host not in completed_targets
    ]
    if skipped_targets:
        logger.info(
            "full port checkpoint task:{} skipped:{} pending:{} fingerprint:{}".format(
                prototype.task_id, len(skipped_targets), len(pending_targets),
                prototype.port_fingerprint[:12]))

    if not pending_targets:
        prototype.meta.update({
            "checkpoint_skipped_target_count": len(skipped_targets),
            "checkpoint_exhausted_target_count": 0,
            "slice_target_count": 0,
            "deferred_target_count": 0,
            "continuation_required": False,
            "completed_targets": len(skipped_targets),
            "total_targets": len(prototype.targets),
            "completion_ratio": 1.0,
            "pool_count": 0,
        })
        logger.info("full port checkpoint complete task:{} targets:{}".format(
            prototype.task_id, len(skipped_targets)))
        return prototype.build_result([])

    max_attempts = max(int(getattr(
        Config, "FULL_PORT_CHECKPOINT_MAX_ATTEMPTS", 2) or 1), 1)
    exhausted_targets = []
    eligible_targets = []
    for host in pending_targets:
        state = checkpoint_states.get(host) or {}
        attempts = int(state.get("attempt_count", 0) or 0)
        if state and attempts >= max_attempts:
            exhausted_targets.append(host)
        else:
            eligible_targets.append(host)

    eligible_targets.sort(key=lambda host: (
        0 if host not in checkpoint_states else 1,
        str((checkpoint_states.get(host) or {}).get("updated_at") or ""),
        host,
    ))
    slice_limit = max(int(max_targets or 0), 0)
    if slice_limit:
        slice_targets = eligible_targets[:slice_limit]
        deferred_targets = eligible_targets[slice_limit:]
    else:
        slice_targets = eligible_targets
        deferred_targets = []

    if not slice_targets:
        prototype.meta.update({
            "checkpoint_skipped_target_count": len(skipped_targets),
            "checkpoint_exhausted_target_count": len(exhausted_targets),
            "slice_target_count": 0,
            "deferred_target_count": 0,
            "continuation_required": False,
            "completed_targets": len(skipped_targets),
            "total_targets": len(prototype.targets),
            "completion_ratio": round(
                float(len(skipped_targets)) / float(len(prototype.targets)), 4
            ) if prototype.targets else 1.0,
            "pool_count": 0,
        })
        if exhausted_targets:
            prototype.meta["warnings"].append(
                "{} full-port target(s) exhausted checkpoint retries".format(
                    len(exhausted_targets)))
        return prototype.build_result([])

    pool_count = min(max(int(worker_count or 1), 1), len(slice_targets))
    pool_targets = [slice_targets[index::pool_count] for index in range(pool_count)]
    batch_size = prototype.batch_size()
    total_batches = sum(
        (len(targets) + batch_size - 1) // batch_size
        for targets in pool_targets
    )
    callback_lock = threading.Lock()
    progress = {"completed_batches": 0, "completed_targets": 0}
    original_callback = scanner_options.get("batch_callback")

    def shared_callback(
            batch_result, _batch_index, _batch_total, profile,
            batch_target_count):
        with callback_lock:
            progress["completed_batches"] += 1
            progress["completed_targets"] += int(batch_target_count or 0)
            global_index = progress["completed_batches"]
            if original_callback is not None:
                original_callback(batch_result, global_index, total_batches, profile)
            if prototype.base_update_task is not None:
                prototype.base_update_task.update_stage_progress(
                    "port_scan_full",
                    {
                        "completed_targets": (
                            len(skipped_targets) +
                            progress["completed_targets"]),
                        "total_targets": len(prototype.targets),
                        "slice_target_count": len(slice_targets),
                        "deferred_target_count": len(deferred_targets),
                    },
                )

    def run_pool(pool_index, targets):
        options = dict(scanner_options)
        pool_batches = list(_chunked(targets, prototype.batch_size()))

        def pool_callback(
                batch_result, batch_index, batch_total, profile):
            batch_target_count = 0
            if 0 < int(batch_index or 0) <= len(pool_batches):
                batch_target_count = len(pool_batches[int(batch_index) - 1])
            shared_callback(
                batch_result, batch_index, batch_total, profile,
                batch_target_count)

        options["batch_callback"] = pool_callback
        scanner = PortScan(targets=targets, **options)
        scanner.meta["pool_count"] = pool_count
        logger.info(
            "full port pool {}/{} start task:{} targets:{} batches:{} scan_type:{}".format(
                pool_index, pool_count, prototype.task_id, len(targets),
                (len(targets) + scanner.batch_size() - 1) // scanner.batch_size(),
                "syn" if "-sS" in scanner.nmap_arguments else "connect"))
        result = scanner.run()
        logger.info(
            "full port pool {}/{} end task:{} completed_targets:{} errors:{}".format(
                pool_index, pool_count, prototype.task_id,
                result.meta.get("checkpoint_completed_target_count", 0),
                result.meta.get("error_count", 0)))
        return result

    logger.info(
        "full port pools task:{} input:{} skipped:{} pending:{} slice:{} deferred:{} exhausted:{} pools:{} batches:{}".format(
            prototype.task_id, len(prototype.targets), len(skipped_targets),
            len(pending_targets), len(slice_targets), len(deferred_targets),
            len(exhausted_targets), pool_count, total_batches))
    pool_results = []
    failed_pool_count = 0
    with ThreadPoolExecutor(
            max_workers=pool_count, thread_name_prefix="arl-nmap-full") as executor:
        futures = {
            executor.submit(run_pool, index + 1, targets): index + 1
            for index, targets in enumerate(pool_targets)
        }
        for future in as_completed(futures):
            pool_index = futures[future]
            try:
                pool_results.append(future.result())
            except Exception as e:
                failed_pool_count += 1
                logger.exception("full port pool {} failed task:{} error:{}".format(
                    pool_index, prototype.task_id, e))

    updated_states = prototype.checkpoint_target_states()
    retry_targets = []
    exhausted_after_scan = set(exhausted_targets)
    for host in slice_targets:
        state = updated_states.get(host) or {}
        if state.get("status") == "done":
            continue
        attempts = int(state.get("attempt_count", 0) or 0)
        if attempts >= max_attempts:
            exhausted_after_scan.add(host)
        else:
            retry_targets.append(host)
    deferred_targets = sorted(set(deferred_targets) | set(retry_targets))
    exhausted_targets = sorted(exhausted_after_scan)

    return _merge_pool_results(
        prototype, pool_results, pool_count, skipped_targets,
        slice_targets=slice_targets,
        deferred_targets=deferred_targets,
        exhausted_targets=exhausted_targets,
        failed_pool_count=failed_pool_count)


def port_scan(targets, ports=Config.TOP_10, service_detect=False, os_detect=False,
              port_parallelism=32, port_min_rate=64, custom_host_timeout=None, exclude_ports=None,
              task_id=None, batch_callback=None, trusted_port_map=None,
              skip_host_discovery=False, max_targets=None):
    targets = sorted(set(targets))
    targets = list(filter(utils.not_in_black_ips, targets))
    scanner_options = {
        "ports": ports,
        "service_detect": service_detect,
        "os_detect": os_detect,
        "port_parallelism": port_parallelism,
        "port_min_rate": port_min_rate,
        "custom_host_timeout": custom_host_timeout,
        "exclude_ports": exclude_ports,
        "task_id": task_id,
        "batch_callback": batch_callback,
        "trusted_port_map": trusted_port_map,
        "skip_host_discovery": skip_host_discovery,
    }
    ps = PortScan(targets=targets, **scanner_options)
    resource = "tool:nmap:full" if ports == "0-65535" else "tool:nmap:top1000" if _is_top1000_ports(ports) else "tool:nmap:default"
    with acquire_resource_budget(resource, task_id=task_id):
        workers = max(int(getattr(Config, "FULL_PORT_WORKERS", 1) or 1), 1)
        if ps.profile == "full" and (workers > 1 or ps.checkpoint_enabled()):
            if getattr(Config, "PORT_SCAN_NAABU_FULL_ENABLE", False):
                workers = 1
            return _run_full_port_pools(
                ps, scanner_options, workers, max_targets=max_targets)
        return ps.run()
