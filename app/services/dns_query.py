import logging
import time
import concurrent.futures
import os
import fcntl
import ipaddress
import random
from contextlib import contextmanager
from urllib.parse import urlparse
from app import utils
from app.config import Config
from app.services.resourceBudget import acquire as acquire_resource_budget
from app.services.sourceEvidence import aggregate_plugin_results


RATE_LIMIT_WORDS = (
    "429", "rate limit", "too many", "q3005", "请求太多", "频繁", "过于频繁",
)

SURVEY_SOURCE_FAMILIES = {"fofa", "hunter", "quake"}


def classify_source_error(error):
    """Classify expected upstream failures without treating them as system failures."""
    error_text = str(error or "")
    normalized = error_text.lower()
    class_name = type(error).__name__.lower() if not isinstance(error, str) else ""

    if any(word in normalized for word in RATE_LIMIT_WORDS):
        return "rate_limited"
    if "timeout" in class_name or "timed out" in normalized or "readtimeout" in normalized:
        return "timeout"
    if any(word in normalized for word in ("unauthorized", "invalid key", "invalid token", "401")):
        return "authentication"
    if any(word in normalized for word in ("connection", "dns", "name resolution", "network")):
        return "network"
    if any(word in normalized for word in ("json", "response type", "unexpected")):
        return "invalid_response"
    return "upstream_error"


def retry_after_seconds(response, default=0, maximum=300):
    """Return a bounded Retry-After value without trusting upstream blindly."""
    value = ""
    if response is not None:
        value = str(getattr(response, "headers", {}).get("Retry-After") or "").strip()
    try:
        seconds = float(value) if value else float(default)
    except (TypeError, ValueError):
        seconds = float(default)
    return max(0.0, min(seconds, float(maximum)))


def retry_backoff(base_seconds, attempt, maximum=60, jitter=True):
    """Short exponential backoff for transient upstream/network failures."""
    base_seconds = max(float(base_seconds or 0), 0.1)
    delay = min(base_seconds * (2 ** max(int(attempt), 0)), float(maximum))
    if jitter:
        delay += random.uniform(0, min(base_seconds, 1.0))
    return delay


def _is_ip_literal(value):
    try:
        ipaddress.ip_address(str(value or "").strip("[]"))
        return True
    except ValueError:
        return False


def _normalize_plugin_domain(item):
    if isinstance(item, dict):
        domain = item.get("domain") or item.get("host") or item.get("hostname")
    else:
        domain = item

    if not isinstance(domain, str):
        return ""

    domain = domain.strip().strip("*.").lower()
    if "://" in domain:
        domain = urlparse(domain).hostname or ""

    if domain.startswith("[") and "]" in domain:
        domain = domain[1:domain.index("]")]
    elif domain.count(":") == 1:
        host, port = domain.rsplit(":", 1)
        if port.isdigit():
            domain = host

    return domain.strip(".")


def _normalize_candidate_item(item, fallback_ip=""):
    if not isinstance(item, dict):
        return None

    normalized = dict(item)
    intels = list(normalized.get("intels") or [])
    if normalized.get("intel"):
        intels.append(normalized.get("intel"))
    intels = [dict(value) for value in intels if isinstance(value, dict)]

    if fallback_ip:
        if intels:
            intels[0].setdefault("ip", fallback_ip)
        else:
            intels.append({
                "ip": fallback_ip,
                "source": normalized.get("source", ""),
                "query_type": normalized.get("query_type", "domain"),
            })

    if not any(str(value.get("ip") or "").strip() for value in intels):
        return None

    query_types = {
        str(value.get("query_type") or "").strip().lower()
        for value in intels
    }
    candidate_type = str(normalized.get("candidate_type") or "").strip()
    if "cert" in query_types:
        candidate_type = "cert_ip"
    elif candidate_type in ("", "mapping"):
        candidate_type = "mapping_ip"

    normalized["domain"] = ""
    normalized["candidate_only"] = True
    normalized["candidate_type"] = candidate_type
    normalized["intel"] = intels[0]
    normalized["intels"] = intels
    return normalized


@contextmanager
def source_rate_limit(source_name, min_interval=1.0):
    """Cross-process rate limit for paid/passive API sources."""
    logger = utils.get_logger()
    lock_path, stamp_path = _source_rate_paths(source_name)
    with open(lock_path, "a+") as lock_fp:
        fcntl.flock(lock_fp, fcntl.LOCK_EX)
        try:
            last_ts = 0.0
            try:
                with open(stamp_path, "r") as stamp_fp:
                    last_ts = float((stamp_fp.read() or "0").strip() or 0)
            except (OSError, ValueError):
                last_ts = 0.0

            sleep_time = float(min_interval) - (time.time() - last_ts)
            if sleep_time > 0:
                logger.info("{} request pacing wait {:.2f}s".format(
                    source_name, sleep_time))
                time.sleep(sleep_time)

            try:
                yield
            finally:
                # Failed API calls still consume provider rate limits.
                try:
                    with open(stamp_path, "w") as stamp_fp:
                        stamp_fp.write(str(time.time()))
                except OSError as error:
                    logger.warning("{} rate stamp update failed: {}".format(
                        source_name, type(error).__name__))
        finally:
            fcntl.flock(lock_fp, fcntl.LOCK_UN)


def _source_rate_paths(source_name):
    safe_name = str(source_name).replace(os.sep, "_")
    lock_path = os.path.join(Config.TMP_PATH, "{}_rate.lock".format(safe_name))
    stamp_path = os.path.join(Config.TMP_PATH, "{}_rate.stamp".format(safe_name))
    return lock_path, stamp_path


def _source_circuit_paths(source_name):
    safe_name = str(source_name).replace(os.sep, "_")
    lock_path = os.path.join(Config.TMP_PATH, "{}_circuit.lock".format(safe_name))
    state_path = os.path.join(Config.TMP_PATH, "{}_circuit.state".format(safe_name))
    return lock_path, state_path


def source_circuit_reason(source_name):
    """Return the active upstream circuit reason without making callers wait."""
    lock_path, state_path = _source_circuit_paths(source_name)
    with open(lock_path, "a+") as lock_fp:
        fcntl.flock(lock_fp, fcntl.LOCK_EX)
        try:
            try:
                with open(state_path, "r") as state_fp:
                    lines = state_fp.read().splitlines()
                circuit_until = float(lines[0]) if lines else 0.0
            except (OSError, ValueError):
                circuit_until = 0.0
                lines = []

            if circuit_until <= time.time():
                try:
                    os.remove(state_path)
                except OSError:
                    pass
                return ""

            reason = lines[1] if len(lines) > 1 else "upstream temporarily unavailable"
            return "{} (retry in {:.1f}s)".format(
                reason, max(0.0, circuit_until - time.time()))
        finally:
            fcntl.flock(lock_fp, fcntl.LOCK_UN)


def open_source_circuit(source_name, cooldown_seconds, reason=""):
    """Temporarily skip a source after repeated upstream failures."""
    logger = utils.get_logger()
    try:
        cooldown_seconds = float(cooldown_seconds)
    except (TypeError, ValueError):
        cooldown_seconds = 0.0
    if cooldown_seconds <= 0:
        return

    reason = " ".join(str(reason or "upstream temporarily unavailable").split())[:300]
    lock_path, state_path = _source_circuit_paths(source_name)
    circuit_until = time.time() + cooldown_seconds
    with open(lock_path, "a+") as lock_fp:
        fcntl.flock(lock_fp, fcntl.LOCK_EX)
        try:
            try:
                with open(state_path, "r") as state_fp:
                    current_until = float((state_fp.readline() or "0").strip() or 0)
            except (OSError, ValueError):
                current_until = 0.0
            circuit_until = max(current_until, circuit_until)
            with open(state_path, "w") as state_fp:
                state_fp.write("{}\n{}\n".format(circuit_until, reason))
        finally:
            fcntl.flock(lock_fp, fcntl.LOCK_UN)

    logger.warning("{} upstream circuit open {:.1f}s reason:{}".format(
        source_name, max(0.0, circuit_until - time.time()), reason))


def clear_source_circuit(source_name):
    lock_path, state_path = _source_circuit_paths(source_name)
    with open(lock_path, "a+") as lock_fp:
        fcntl.flock(lock_fp, fcntl.LOCK_EX)
        try:
            try:
                os.remove(state_path)
            except OSError:
                pass
        finally:
            fcntl.flock(lock_fp, fcntl.LOCK_UN)


def set_source_cooldown(source_name, cooldown_seconds):
    """Push one source into a shared cooldown after remote API throttling."""
    logger = utils.get_logger()
    try:
        cooldown_seconds = float(cooldown_seconds)
    except (TypeError, ValueError):
        cooldown_seconds = 0.0

    if cooldown_seconds <= 0:
        return

    lock_path, stamp_path = _source_rate_paths(source_name)
    cooldown_until = time.time() + cooldown_seconds
    with open(lock_path, "a+") as lock_fp:
        fcntl.flock(lock_fp, fcntl.LOCK_EX)
        try:
            current_until = 0.0
            try:
                with open(stamp_path, "r") as stamp_fp:
                    current_until = float((stamp_fp.read() or "0").strip() or 0)
            except (OSError, ValueError):
                current_until = 0.0

            cooldown_until = max(current_until, cooldown_until)
            with open(stamp_path, "w") as stamp_fp:
                stamp_fp.write(str(cooldown_until))

            logger.warning("{} global cooldown {:.2f}s".format(
                source_name, max(0.0, cooldown_until - time.time())))
        finally:
            fcntl.flock(lock_fp, fcntl.LOCK_UN)


class DNSQueryBase(object):
    def __init__(self):
        self.source_name = None
        self.source_family = ""
        self.query_type = "passive"
        self.config_source_name = ""
        self.use_whole_query_budget = True
        self.logger = utils.get_logger()
        self.query_status = "pending"
        self.query_error = ""
        self.query_error_kind = ""
        self.query_elapsed = 0.0
        self.raw_result_count = 0
        self.page_count = 0
        self.rate_retries_used = 0
        self.upstream_retries_used = 0
        self.network_retries_used = 0

    def mark_partial(self, error, error_kind=None):
        self.query_status = "partial"
        self.query_error = str(error or "")[:500]
        self.query_error_kind = error_kind or classify_source_error(error)

    def init_key(self, **kwargs):
        """
        用来初始化各种key
        :param kwargs:
        :return:
        """
        raise NotImplementedError()

    def configuration_error(self):
        return ""

    def sub_domains(self, target):
        """
        根据子域名查询
        :param target:
        :return:
        """
        raise NotImplementedError()

    def query(self, target):
        t1 = time.time()
        target = str(target or "").strip(".").lower()
        self.query_status = "done"
        self.query_error = ""
        self.query_error_kind = ""
        self.raw_result_count = 0
        self.page_count = 0
        self.rate_retries_used = 0
        self.upstream_retries_used = 0
        self.network_retries_used = 0
        self.logger.info("start query {} on {}".format(target, self.source_name))
        try:
            domains = self.sub_domains(target)
        except Exception as e:
            self.mark_partial(e)
            self.query_elapsed = time.time() - t1
            self.logger.warning("{} upstream {}: {}".format(
                self.source_name, self.query_error_kind, self.query_error))
            return []

        if not isinstance(domains, list):
            self.mark_partial("unexpected response type: {}".format(type(domains).__name__), "invalid_response")
            self.query_elapsed = time.time() - t1
            self.logger.warning("{} {}".format(self.source_name, self.query_error))
            return []

        """下面是过滤掉不合法的数据"""
        subdomains = []

        for item in domains:
            domain = _normalize_plugin_domain(item)
            domain_ip = domain if _is_ip_literal(domain) else ""
            if domain_ip:
                domain = ""

            if not domain or not (domain == target or domain.endswith(".{}".format(target))):
                candidate = _normalize_candidate_item(item, fallback_ip=domain_ip)
                if candidate:
                    subdomains.append(candidate)
                continue

            # 删除掉过长的域名
            if len(domain) - len(target) >= Config.DOMAIN_MAX_LEN:
                continue

            if not utils.is_valid_domain(domain):
                continue

            # 屏蔽和谐域名和黑名单域名
            if utils.check_domain_black(domain):
                continue

            if utils.domain_parsed(domain):
                if isinstance(item, dict):
                    normalized_item = dict(item)
                    normalized_item["domain"] = domain
                    subdomains.append(normalized_item)
                else:
                    subdomains.append(domain)

        unique_subdomains = []
        seen_results = set()
        for item in subdomains:
            if isinstance(item, dict):
                domain = item["domain"]
                intels = list(item.get("intels") or [])
                if item.get("intel"):
                    intels.append(item.get("intel"))
                intel_keys = []
                for intel in intels:
                    if not isinstance(intel, dict):
                        continue
                    intel_keys.append((
                        str(intel.get("source") or ""),
                        str(intel.get("ip") or ""),
                        str(intel.get("port") or ""),
                        str(intel.get("query_type") or ""),
                        str(intel.get("url") or ""),
                    ))
                identity = (
                    domain,
                    str(item.get("candidate_type") or ""),
                    tuple(sorted(set(intel_keys))),
                )
            else:
                domain = item
                identity = (domain, "", ())

            if identity in seen_results:
                continue

            unique_subdomains.append(item)
            seen_results.add(identity)

        t2 = time.time()
        self.query_elapsed = t2 - t1
        if self.query_status == "done" and not unique_subdomains:
            self.query_status = "empty"
        self.logger.info("end query {} on {}, source result:{}, real result:{} ({:.2f}s)".format(
            target, self.source_name, len(domains), len(unique_subdomains), t2 - t1))

        return unique_subdomains


def _plugin_report(source_name, status, results=None, error="", error_kind="", elapsed=0.0,
                   source_family="", query_type="", raw_result_count=0, page_count=0,
                   rate_retries_used=0, upstream_retries_used=0,
                   network_retries_used=0):
    return {
        "source": source_name,
        "source_family": source_family or source_name,
        "query_type": query_type or "passive",
        "status": status,
        "result_count": len(results or []),
        "raw_result_count": int(raw_result_count or 0),
        "page_count": int(page_count or 0),
        "rate_retries_used": int(rate_retries_used or 0),
        "upstream_retries_used": int(upstream_retries_used or 0),
        "network_retries_used": int(network_retries_used or 0),
        "error": str(error or "")[:500],
        "error_kind": error_kind or "",
        "elapsed": round(float(elapsed or 0), 2),
    }


def _plugin_config(plugin):
    # 凭证热更新：config.yaml 变化后，worker 在插件分发点同步内存 Config
    from app.services.integration import reload_runtime
    reload_runtime()

    source_name = plugin.source_name
    config_name = getattr(plugin, "config_source_name", "") or source_name
    query_config = Config.QUERY_PLUGIN_CONFIG

    base_config = query_config.get(config_name, {})
    source_config = query_config.get(source_name, {}) if source_name != config_name else {}
    for name, value in ((config_name, base_config), (source_name, source_config)):
        if value and not isinstance(value, dict):
            raise TypeError("{} config is not a mapping".format(name))

    base_config = dict(base_config or {})
    source_config = dict(source_config or {})
    enabled = bool(base_config.get("enable", True)) and bool(
        source_config.get("enable", True))
    kwargs = {key: value for key, value in base_config.items() if key != "enable"}
    kwargs.update({key: value for key, value in source_config.items() if key != "enable"})
    return bool(enabled), kwargs


def run_plugin(p, target, task_id=None):
    """
    运行单个插件
    """
    logger = utils.get_logger()
    try:
        source_name = p.source_name
        source_family = getattr(p, "source_family", "") or source_name
        query_type = getattr(p, "query_type", "") or "passive"
        plugin_enable_flag, source_kwargs = _plugin_config(p)
        if not plugin_enable_flag:
            logger.debug(f"skip {source_name}, enable is set false")
            return source_name, [], _plugin_report(
                source_name, "skipped", source_family=source_family,
                query_type=query_type)

        if source_kwargs:
            p.init_key(**source_kwargs)

        config_error = str(p.configuration_error() or "").strip()
        if config_error:
            logger.warning("skip {}: {}".format(source_name, config_error))
            return source_name, [], _plugin_report(
                source_name, "skipped", error=config_error,
                error_kind="configuration", source_family=source_family,
                query_type=query_type)

        budget_source_name = getattr(p, "budget_source_name", source_name)
        if getattr(p, "use_whole_query_budget", True):
            with acquire_resource_budget(
                    "api:{}".format(budget_source_name),
                    task_id=task_id,
                    stage="dns_query_plugin"):
                results = p.query(target)
        else:
            results = p.query(target)
        logger.debug(f"run {source_name} target:{target}, result:{len(results)}")
        report = _plugin_report(
            source_name,
            getattr(p, "query_status", "done"),
            results=results,
            error=getattr(p, "query_error", ""),
            error_kind=getattr(p, "query_error_kind", ""),
            elapsed=getattr(p, "query_elapsed", 0.0),
            source_family=source_family,
            query_type=query_type,
            raw_result_count=getattr(p, "raw_result_count", 0),
            page_count=getattr(p, "page_count", 0),
            rate_retries_used=getattr(p, "rate_retries_used", 0),
            upstream_retries_used=getattr(p, "upstream_retries_used", 0),
            network_retries_used=getattr(p, "network_retries_used", 0),
        )
        return source_name, results, report

    except Exception as e:
        error_str = str(e)
        error_kind = classify_source_error(e)
        if "please set fofa key" in error_str:
            logger.debug(error_str)
        else:
            logger.warning(f"{p.source_name} upstream {error_kind}: {error_str}")
        return p.source_name, [], _plugin_report(
            p.source_name, "partial", error=error_str, error_kind=error_kind,
            source_family=getattr(p, "source_family", "") or p.source_name,
            query_type=getattr(p, "query_type", "") or "passive")


# *****  执行域名查询插件
"""
返回: [{
    "domain": "www.baidu.com",
    "source": "crtsh"
}]
"""


def run_query_plugin(target, sources=None, task_id=None, include_report=False):
    """
    批量运行子域名查询插件
    :param sources:
    :param target:
    :return:
    """
    if sources is None:
        sources = []

    plugins = utils.load_query_plugins(Config.dns_query_plugin_path)
    logger = utils.get_logger()
    source_results = []
    source_reports = []
    t1 = time.time()

    if sources:
        plugins = [p for p in plugins if p.source_name in sources]

    logger.debug(f"load plugins len:{len(plugins)} sources: {sources}")

    max_workers = min(
        max(len(plugins), 1),
        max(int(getattr(Config, "DNS_QUERY_PLUGIN_WORKERS", 8)), 1),
    )
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(run_plugin, p, target, task_id): p for p in plugins}
        for future in concurrent.futures.as_completed(futures):
            source_name, results, report = future.result()
            source_reports.append(report)
            source_results.append((source_name, results))

    ret = aggregate_plugin_results(source_results)
    subdomain_count = len([item for item in ret if item.get("domain")])

    t2 = time.time()
    logger.info("{} subdomains result {} candidates:{} ({:.2f}s)".format(
        target, subdomain_count, len(ret) - subdomain_count, t2 - t1))
    if include_report:
        source_reports.sort(key=lambda item: item.get("source", ""))
        partial_reports = [item for item in source_reports if item.get("status") == "partial"]
        survey_reports = [
            item for item in source_reports
            if item.get("source_family") in SURVEY_SOURCE_FAMILIES
        ]
        report = {
            "source_count": len(source_reports),
            "source_done_count": len([item for item in source_reports if item.get("status") in ("done", "empty")]),
            "source_empty_count": len([item for item in source_reports if item.get("status") == "empty"]),
            "source_partial_count": len(partial_reports),
            "source_skipped_count": len([item for item in source_reports if item.get("status") == "skipped"]),
            "survey_source_count": len(survey_reports),
            "survey_source_done_count": len([
                item for item in survey_reports if item.get("status") in ("done", "empty")
            ]),
            "survey_source_partial_count": len([
                item for item in survey_reports if item.get("status") == "partial"
            ]),
            "survey_raw_result_count": sum(
                int(item.get("raw_result_count") or 0) for item in survey_reports
            ),
            "survey_result_count": sum(
                int(item.get("result_count") or 0) for item in survey_reports
            ),
            "source_reports": source_reports,
            "source_errors": [
                {
                    "source": item.get("source"),
                    "error_kind": item.get("error_kind"),
                    "error": item.get("error"),
                }
                for item in partial_reports
            ],
        }
        return ret, report
    return ret
