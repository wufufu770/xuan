import json
import os
from collections import Counter
import subprocess
import tempfile
from urllib.parse import urlparse

from app.config import Config
from app import utils
from app.services.baseUpdateTask import BaseUpdateTask
from app.services.resourceBudget import acquire as acquire_resource_budget


logger = utils.get_logger()


class ObserverWardResult(dict):
    def __init__(self, values=None, meta=None):
        super().__init__(values or {})
        self.meta = dict(meta or {})


class ObserverWardBatchResult(dict):
    def __init__(self, values=None, meta=None):
        super().__init__(values or {})
        self.meta = dict(meta or {})


def _observer_ward_base_command(bin_path, timeout):
    cmd = [
        bin_path,
        "--format", "json",
        "--mode", getattr(Config, "OBSERVER_WARD_MODE", "http"),
        "--timeout", str(timeout),
        "--thread", str(getattr(Config, "OBSERVER_WARD_THREAD", 4)),
        "--silent",
    ]
    ua = str(getattr(Config, "OBSERVER_WARD_UA", "") or "").strip()
    if ua:
        cmd.extend(["--ua", ua])
    return cmd


def _append_name(names, value):
    if not value:
        return

    if isinstance(value, str):
        item = value.strip()
        if item:
            names.append(item)
        return

    if isinstance(value, list):
        for item in value:
            _append_name(names, item)


def _extract_names(data):
    names = []
    matched_items = data.get("matched", [])
    if not isinstance(matched_items, list):
        return names

    for matched in matched_items:
        if not isinstance(matched, dict):
            continue

        result = matched.get("result", {})
        if not isinstance(result, dict):
            continue

        _append_name(names, result.get("name"))
        fingerprints = result.get("fingerprints", [])
        if not isinstance(fingerprints, list):
            continue

        for fingerprint in fingerprints:
            if not isinstance(fingerprint, dict):
                continue

            matcher_results = fingerprint.get("matcher-results", [])
            if not isinstance(matcher_results, list):
                continue

            for matcher_result in matcher_results:
                if not isinstance(matcher_result, dict):
                    continue

                info = matcher_result.get("info", {})
                if isinstance(info, dict):
                    _append_name(names, info.get("name"))

    return names


def observer_ward_fingerprint(site):
    if not getattr(Config, "OBSERVER_WARD_ENABLE", False):
        return []

    bin_path = getattr(Config, "OBSERVER_WARD_BIN", "")
    if not bin_path or not os.path.isfile(bin_path):
        logger.warning("observer_ward bin not found: {}".format(bin_path))
        return []

    timeout = int(getattr(Config, "OBSERVER_WARD_TIMEOUT", 8))
    cmd = _observer_ward_base_command(bin_path, timeout)
    cmd[1:1] = ["-t", site]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout + 5,
            universal_newlines=True,
        )
    except subprocess.TimeoutExpired:
        logger.warning("observer_ward timeout on {}".format(site))
        return []
    except Exception as e:
        logger.warning("observer_ward error on {} {}".format(site, e))
        return []

    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        logger.warning("observer_ward failed on {} {}".format(site, stderr[:300]))
        return []

    output = (proc.stdout or "").strip()
    if not output:
        return []

    try:
        data = json.loads(output.splitlines()[-1])
    except Exception as e:
        logger.warning("observer_ward json parse error on {} {}".format(site, e))
        return []

    result = []
    known = set()
    for name in _extract_names(data):
        name = name.strip()
        if not name:
            continue

        name_key = name.lower()
        if name_key in known:
            continue

        result.append(name)
        known.add(name_key)

    return result


def _target_keys(value):
    keys = set()
    if not value:
        return keys

    value = value.strip()
    if not value:
        return keys

    keys.add(value.rstrip("/"))
    keys.add(value.rstrip("/") + "/")

    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        normalized = "{}://{}".format(parsed.scheme, parsed.netloc)
        if parsed.path and parsed.path != "/":
            normalized += parsed.path.rstrip("/")
        keys.add(normalized)
        keys.add(normalized + "/")

    return keys


def _dedupe_names(names):
    result = []
    known = set()
    for name in names:
        name = name.strip()
        if not name:
            continue

        name_key = name.lower()
        if name_key in known:
            continue

        result.append(name)
        known.add(name_key)

    return result


def _task_stopped(task_id):
    if not task_id:
        return False
    if len(str(task_id)) != 24:
        return False
    try:
        return BaseUpdateTask(task_id).is_terminal()
    except Exception as e:
        logger.warning("observer_ward check task status failed: {}".format(e))
        return False


def _chunked(items, size):
    size = max(int(size or 1), 1)
    for i in range(0, len(items), size):
        yield items[i:i + size]


def _observer_ward_no_match_summary(data):
    status_list = []
    title_list = []
    for matched in data.get("matched", []) or []:
        if not isinstance(matched, dict):
            continue
        result = matched.get("result", {})
        if not isinstance(result, dict):
            continue
        status = result.get("status")
        if status is not None:
            status_list.append(str(status))
        titles = result.get("title", [])
        if isinstance(titles, list):
            title_list.extend([str(x).strip() for x in titles if str(x).strip()])
        elif titles:
            title_list.append(str(titles).strip())

    return {
        "target": data.get("target", ""),
        "status": ",".join(sorted(set(status_list)))[:80],
        "title": ",".join(sorted(set(title_list)))[:120],
    }


def _parse_observer_ward_output(output, task_id=None):
    result = {}
    parse_errors = 0
    no_match_count = 0
    status_counter = Counter()
    no_match_samples = []
    processed_target_keys = set()
    for line in str(output or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except Exception:
            parse_errors += 1
            continue
        if not isinstance(data, dict):
            parse_errors += 1
            continue

        target_keys = _target_keys(data.get("target", ""))
        processed_target_keys.update(target_keys)
        names = _dedupe_names(_extract_names(data))
        if not names:
            no_match_count += 1
            summary = _observer_ward_no_match_summary(data)
            if summary.get("status"):
                for status in summary["status"].split(","):
                    status_counter[status] += 1
            if len(no_match_samples) < 5:
                no_match_samples.append(summary)
            continue

        for key in target_keys:
            result[key] = names

    if parse_errors:
        logger.warning("observer_ward batch json parse errors:{} task_id:{}".format(
            parse_errors, task_id or ""))
    if no_match_count:
        logger.info(
            "observer_ward no fingerprint task_id:{} count:{} status:{} samples:{}".format(
                task_id or "", no_match_count, dict(status_counter), no_match_samples))
    return ObserverWardBatchResult(result, meta={
        "processed_target_keys": sorted(processed_target_keys),
        "parse_error_count": parse_errors,
        "no_match_count": no_match_count,
    })


def _observer_ward_batch(bin_path, site_list, timeout, task_id=None):
    process_timeout = max(
        timeout + 10,
        timeout * max(len(site_list), 1) // max(int(getattr(Config, "OBSERVER_WARD_THREAD", 4)), 1) + 30
    )

    fd, list_path = tempfile.mkstemp(prefix="arl_observer_ward_", suffix=".txt", dir=Config.TMP_PATH)
    try:
        with os.fdopen(fd, "w") as f:
            for site in site_list:
                f.write(site + "\n")

        cmd = _observer_ward_base_command(bin_path, timeout)
        cmd[1:1] = ["-l", list_path]

        timed_out = False
        return_code = 0
        stderr = ""
        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=process_timeout,
                universal_newlines=True,
            )
            stdout = proc.stdout or ""
            stderr = (proc.stderr or "").strip()
            return_code = proc.returncode
        except subprocess.TimeoutExpired as exc:
            logger.warning("observer_ward batch timeout sites:{} process_timeout:{}".format(
                len(site_list), process_timeout))
            timed_out = True
            stdout = exc.stdout or exc.output or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode("utf-8", errors="replace")
            stderr = exc.stderr or ""
            if isinstance(stderr, bytes):
                stderr = stderr.decode("utf-8", errors="replace")
        except Exception as e:
            logger.warning("observer_ward batch error {}".format(e))
            return None

        if return_code != 0:
            logger.warning("observer_ward batch failed {}".format(stderr[:500]))
        parsed = _parse_observer_ward_output(stdout, task_id=task_id)
        parsed.meta.update({
            "timed_out": timed_out,
            "return_code": return_code,
            "stderr": str(stderr or "")[-500:],
            "partial_output": bool(timed_out or return_code != 0),
            "complete_process": not timed_out and return_code == 0,
        })
        if parsed.meta.get("processed_target_keys"):
            return parsed
        if timed_out or return_code != 0:
            return None
        return parsed
    finally:
        try:
            os.remove(list_path)
        except OSError:
            pass


def observer_ward_fingerprint_batch(sites, enabled=None, task_id=None):
    if enabled is None:
        enabled = getattr(Config, "OBSERVER_WARD_ENABLE", False)

    if not enabled:
        return ObserverWardResult(meta={"disabled": True})

    bin_path = getattr(Config, "OBSERVER_WARD_BIN", "")
    if not bin_path or not os.path.isfile(bin_path):
        logger.warning("observer_ward bin not found: {}".format(bin_path))
        return ObserverWardResult(meta={
            "partial": True,
            "error_count": 1,
            "error": "observer_ward binary not found",
        })

    site_list = []
    known_sites = set()
    for site in sites:
        site = str(site or "").strip()
        if not site or site in known_sites:
            continue

        site_list.append(site)
        known_sites.add(site)

    if not site_list:
        return ObserverWardResult(meta={"input_count": 0, "processed_site_count": 0})

    timeout = int(getattr(Config, "OBSERVER_WARD_TIMEOUT", 8))
    batch_size = max(int(getattr(Config, "OBSERVER_WARD_BATCH_SIZE", 100)), 1)
    result = {}
    processed_sites = set()
    failed_sites = set()
    attempts = Counter()
    partial_output_batch_count = 0
    stopped = False
    total_batches = (len(site_list) + batch_size - 1) // batch_size
    logger.info("start observer_ward batch task_id:{} sites:{} batch_size:{}".format(
        task_id or "", len(site_list), batch_size))

    retry_size = max(int(getattr(
        Config, "OBSERVER_WARD_RETRY_BATCH_SIZE", 10) or 10), 1)
    max_attempts = max(int(getattr(
        Config, "OBSERVER_WARD_MAX_ATTEMPTS", 3) or 3), 1)
    individual_retry = bool(getattr(
        Config, "OBSERVER_WARD_INDIVIDUAL_RETRY", True))

    def processed_from_result(batch_result, batch):
        if batch_result is None:
            return set()
        meta = getattr(batch_result, "meta", None)
        if not isinstance(meta, dict):
            # Preserve compatibility with callers/tests returning a plain
            # mapping: a successful empty mapping means a no-match batch.
            return set(batch)
        if meta.get("complete_process"):
            return set(batch)
        observed_keys = set(meta.get("processed_target_keys") or [])
        return {
            site for site in batch
            if _target_keys(site) & observed_keys
        }

    def process_batch(batch, label):
        nonlocal stopped, partial_output_batch_count
        batch = [
            site for site in batch
            if site not in processed_sites and site not in failed_sites
        ]
        if not batch or stopped:
            return
        if _task_stopped(task_id):
            logger.warning("observer_ward stop before batch {}".format(label))
            stopped = True
            return

        for site in batch:
            attempts[site] += 1
        logger.info("observer_ward batch task_id:{} label:{} sites:{}".format(
            task_id or "", label, len(batch)))
        with acquire_resource_budget("tool:observer_ward", task_id=task_id):
            batch_result = _observer_ward_batch(
                bin_path, batch, timeout, task_id=task_id)
        if batch_result is not None:
            result.update(batch_result)
            batch_meta = getattr(batch_result, "meta", {}) or {}
            if batch_meta.get("partial_output"):
                partial_output_batch_count += 1

        completed = processed_from_result(batch_result, batch)
        processed_sites.update(completed)
        unresolved = [site for site in batch if site not in completed]
        if not unresolved:
            return

        retryable = [
            site for site in unresolved if attempts[site] < max_attempts
        ]
        failed_sites.update(
            site for site in unresolved if attempts[site] >= max_attempts)
        if not retryable:
            return

        if len(retryable) == 1:
            process_batch(retryable, "{}.retry".format(label))
            return
        if not individual_retry and len(retryable) <= retry_size:
            process_batch(retryable, "{}.retry".format(label))
            return

        next_size = min(retry_size, max(len(retryable) // 2, 1))
        for index, retry_batch in enumerate(_chunked(retryable, next_size), 1):
            process_batch(retry_batch, "{}.{}".format(label, index))
            if stopped:
                return

    for batch_index, batch in enumerate(_chunked(site_list, batch_size), 1):
        process_batch(batch, "{}/{}".format(batch_index, total_batches))
        if stopped:
            break

    logger.info("end observer_ward batch task_id:{} sites:{} matched:{}".format(
        task_id or "", len(site_list), len(result)))
    meta = {
        "input_count": len(site_list),
        "processed_site_count": len(processed_sites),
        "failed_batch_count": len(failed_sites),
        "failed_site_count": len(failed_sites),
        "partial_output_batch_count": partial_output_batch_count,
        "retry_site_count": sum(1 for count in attempts.values() if count > 1),
        "attempt_count": sum(attempts.values()),
        "stopped": stopped,
        "partial": bool(failed_sites or stopped),
    }
    if failed_sites:
        meta["error_count"] = len(failed_sites)
        meta["error"] = "observer_ward incomplete sites: {}".format(len(failed_sites))
    elif stopped:
        meta["error_count"] = 1
        meta["error"] = "observer_ward stopped before completion"
    return ObserverWardResult(result, meta=meta)
