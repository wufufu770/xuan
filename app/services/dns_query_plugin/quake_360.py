import re
import time
from app.services.dns_query import (
    clear_source_circuit,
    DNSQueryBase,
    open_source_circuit,
    retry_after_seconds,
    retry_backoff,
    source_circuit_reason,
    source_rate_limit,
    set_source_cooldown,
)
from app import utils


def _extract_domains(value, target, results):
    if isinstance(value, dict):
        for child in value.values():
            _extract_domains(child, target, results)
        return
    if isinstance(value, list):
        for child in value:
            _extract_domains(child, target, results)
        return
    if not isinstance(value, str):
        return

    pattern = r"(?i)(?<![a-z0-9_-])(?:[a-z0-9_-]+\.)*{}(?![a-z0-9_-])".format(
        re.escape(target))
    for match in re.findall(pattern, value):
        domain = match.strip().strip("*.").lower()
        if domain == target or domain.endswith("." + target):
            results.add(domain)


def parse_quake_results(item, target, source_name, query_type):
    if not isinstance(item, dict):
        return []

    service = item.get("service") or {}
    if not isinstance(service, dict):
        service = {}
    http = service.get("http") or {}
    if not isinstance(http, dict):
        http = {}

    domains = set()
    # Restrict extraction to identity-bearing fields. Recursing through the
    # whole service object also matches domains mentioned in HTML/body text.
    for value in (
        item.get("hostname"),
        item.get("domain"),
        item.get("host"),
        item.get("certificate"),
        item.get("cert"),
        service.get("hostname"),
        service.get("tls"),
        service.get("ssl"),
        http.get("host"),
        http.get("url"),
    ):
        _extract_domains(value, target, domains)

    intel = {
        "source": source_name,
        "source_family": "quake",
        "query_type": query_type,
        "ip": item.get("ip"),
        "port": service.get("port") or item.get("port"),
        "protocol": service.get("name") or service.get("protocol"),
        "url": http.get("url") or item.get("url"),
        "web_title": http.get("title"),
        "status_code": http.get("status_code"),
    }
    if domains:
        return [{"domain": domain, "intel": dict(intel)} for domain in sorted(domains)]
    if not intel.get("ip"):
        return []
    return [{
        "domain": "",
        "intel": intel,
        "candidate_type": "cert_ip" if query_type == "cert" else "mapping_ip",
    }]


class Query(DNSQueryBase):
    def __init__(self):
        super(Query, self).__init__()
        self.source_name = "quake_360"
        self.source_family = "quake"
        self.query_type = "domain"
        self.config_source_name = "quake_360"
        self.use_whole_query_budget = False
        self.rate_source_name = self.source_name
        self.api_url = "https://quake.360.net/api/v3/search/quake_service"
        self.quake_token = None
        self.max_size = 6000
        self.page_size = 100
        self.rate_interval = 1
        self.retry_count = 3
        self.retry_sleep = 15
        self.auth_retry_count = 0
        self.upstream_retry_count = 1
        self.upstream_retry_sleep = 3
        self.network_retry_count = 1
        self.connect_timeout = 8.1
        self.read_timeout = 20.1
        self.ignore_cache = True
        self.upstream_circuit_seconds = 120

    def init_key(self, quake_token=None, max_size=6000, page_size=100,
                 rate_interval=1, retry_count=3, retry_sleep=15,
                 auth_retry_count=0, network_retry_count=1,
                 upstream_retry_count=1, upstream_retry_sleep=3,
                 connect_timeout=8.1, read_timeout=20.1,
                 ignore_cache=True, upstream_circuit_seconds=120):
        self.quake_token = str(quake_token or "").strip()
        self.max_size = int(max_size)
        self.page_size = int(page_size)
        self.rate_interval = float(rate_interval)
        self.retry_count = int(retry_count)
        self.retry_sleep = float(retry_sleep)
        self.auth_retry_count = max(int(auth_retry_count), 0)
        self.network_retry_count = max(int(network_retry_count), 0)
        self.upstream_retry_count = max(int(upstream_retry_count), 0)
        self.upstream_retry_sleep = max(float(upstream_retry_sleep), 0.1)
        self.connect_timeout = max(float(connect_timeout), 1.0)
        self.read_timeout = max(float(read_timeout), 1.0)
        self.ignore_cache = bool(ignore_cache)
        self.upstream_circuit_seconds = max(
            float(upstream_circuit_seconds), 0.0)

    def configuration_error(self):
        if not self.quake_token:
            return "Quake token is not configured"
        return ""

    def query_api(self, json_data, headers):
        rate_retries = 0
        auth_retries = 0
        upstream_retries = 0
        network_retries = 0
        while True:
            circuit_reason = source_circuit_reason(self.rate_source_name)
            if circuit_reason:
                return None, {
                    "code": "circuit_open",
                    "message": circuit_reason,
                }
            try:
                with source_rate_limit(self.rate_source_name, self.rate_interval):
                    circuit_reason = source_circuit_reason(self.rate_source_name)
                    if circuit_reason:
                        return None, {
                            "code": "circuit_open",
                            "message": circuit_reason,
                        }
                    conn = utils.http_req(
                        self.api_url, 'post', json=json_data, headers=headers,
                        timeout=(self.connect_timeout, self.read_timeout))
            except Exception as e:
                if network_retries >= self.network_retry_count:
                    raise
                delay = retry_backoff(
                    self.upstream_retry_sleep, network_retries, maximum=20)
                network_retries += 1
                self.network_retries_used += 1
                self.logger.warning(
                    "{} network retry {}/{} sleep {:.2f}s error:{}".format(
                        self.source_name, network_retries,
                        self.network_retry_count, delay,
                        type(e).__name__))
                time.sleep(delay)
                continue

            try:
                data = conn.json()
            except Exception:
                data = {}
            if not isinstance(data, dict):
                data = {}
            if conn.status_code != 200:
                data.setdefault("code", conn.status_code)
                data.setdefault("message", "http status {}".format(conn.status_code))
            code = str(data.get("code", ""))
            message = str(data.get("message", ""))
            is_rate_limited = (
                conn.status_code == 429 or code == "q3005"
                or self.is_rate_limited_message(message)
            )
            if is_rate_limited:
                if rate_retries >= self.retry_count:
                    return conn, data
                default_delay = self.retry_sleep * (rate_retries + 1)
                delay = retry_after_seconds(conn, default=default_delay)
                rate_retries += 1
                self.rate_retries_used += 1
                set_source_cooldown(self.rate_source_name, delay)
                self.logger.warning(
                    "{} rate limited, sleep {:.2f}s then retry {}/{} reason:{}".format(
                        self.source_name, delay, rate_retries,
                        self.retry_count,
                        self._redact_secret(message[:160])))
                time.sleep(delay)
                continue

            is_auth_failure = (
                conn.status_code in (401, 403)
                or code in ("401", "403")
                or self.is_auth_message(message)
            )
            if is_auth_failure:
                if auth_retries >= self.auth_retry_count:
                    return conn, data
                delay = retry_backoff(
                    self.upstream_retry_sleep,
                    auth_retries,
                    maximum=10,
                    jitter=False,
                )
                auth_retries += 1
                self.logger.warning(
                    "{} authentication retry {}/{} sleep {:.2f}s reason:{}".format(
                        self.source_name,
                        auth_retries,
                        self.auth_retry_count,
                        delay,
                        self._redact_secret(message[:160]),
                    ))
                time.sleep(delay)
                continue

            if conn.status_code in (500, 502, 503, 504):
                if upstream_retries >= self.upstream_retry_count:
                    open_source_circuit(
                        self.rate_source_name,
                        self.upstream_circuit_seconds,
                        self.response_error(conn, data),
                    )
                    return conn, data
                delay = retry_backoff(
                    self.upstream_retry_sleep, upstream_retries, maximum=20)
                upstream_retries += 1
                self.upstream_retries_used += 1
                self.logger.warning(
                    "{} upstream retry {}/{} sleep {:.2f}s status:{}".format(
                        self.source_name, upstream_retries,
                        self.upstream_retry_count, delay,
                        conn.status_code))
                time.sleep(delay)
                continue

            if conn.status_code == 200:
                clear_source_circuit(self.rate_source_name)
            return conn, data

    def _redact_secret(self, value):
        value = str(value or "")
        if self.quake_token:
            value = value.replace(str(self.quake_token), "<redacted>")
        return value

    @staticmethod
    def is_auth_message(message):
        message = str(message or "").lower()
        return any(word in message for word in (
            "invalid token", "token invalid", "token is invalid",
            "quaketoken", "unauthorized",
        ))

    def response_error(self, conn, data):
        status = getattr(conn, "status_code", 0)
        code = data.get("code", "") if isinstance(data, dict) else ""
        message = data.get("message", "") if isinstance(data, dict) else ""
        return "http status:{} code:{} message:{}".format(
            status, code, self._redact_secret(str(message)[:300]))

    def response_error_kind(self, conn, data):
        status = getattr(conn, "status_code", 0)
        code = str(data.get("code", "") if isinstance(data, dict) else "")
        message = str(data.get("message", "") if isinstance(data, dict) else "").lower()
        if status in (401, 403) or self.is_auth_message(message):
            return "authentication"
        if status == 429 or self.is_rate_limited_message(message):
            return "rate_limited"
        if status in (500, 502, 503, 504) or code in ("500", "502", "503", "504"):
            return "upstream_error"
        return "invalid_response"

    def is_rate_limited_message(self, message):
        message = str(message or "").lower()
        rate_words = ["429", "rate", "limit", "too many", "频繁", "过于频繁", "调用api过于频繁"]
        return any(word in message for word in rate_words)

    def sub_domains(self, target):
        # 文档 https://quake.360.net/quake/#/help?id=5e77423bcb9954d2f8a01656&title=%E4%BD%BF%E7%94%A8%E8%AF%B4%E6%98%8E
        headers = {
            "X-QuakeToken": self.quake_token,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        results = []
        start = 0
        while start < self.max_size:
            page_size = min(self.page_size, self.max_size - start)
            json_data = {
                "query": "domain:\"{}\"".format(target),
                "include": ["ip", "port", "hostname"],
                "start": start,
                "size": page_size,
                "ignore_cache": self.ignore_cache,
            }
            try:
                conn, data = self.query_api(json_data, headers)
            except Exception as e:
                self.mark_partial("request failed: {}".format(e))
                break
            if conn is None:
                self.mark_partial(
                    self.response_error(conn, data), "upstream_error")
                break
            if conn.status_code != 200:
                self.mark_partial(
                    self.response_error(conn, data),
                    self.response_error_kind(conn, data))
                break

            if not isinstance(data, dict):
                self.mark_partial(
                    "unexpected response type: {}".format(type(data).__name__),
                    "invalid_response")
                break

            if data.get("code") != 0:
                self.mark_partial(
                    self.response_error(conn, data),
                    self.response_error_kind(conn, data))
                break

            self.logger.debug("{}: target:{} start:{} meta:{}".format(
                self.source_name, target, start, data.get("meta", {})))

            items = data.get("data") or []
            if not isinstance(items, list):
                self.mark_partial(
                    "unexpected data type: {}".format(type(items).__name__),
                    "invalid_response")
                break

            self.page_count += 1
            self.raw_result_count += len(items)

            for item in items:
                results.extend(parse_quake_results(
                    item, target, self.source_name, self.query_type))

            if len(items) < page_size:
                break

            start += len(items)
            meta = data.get("meta") or {}
            pagination = meta.get("pagination") or {}
            total = pagination.get("total")
            if isinstance(total, int) and start >= total:
                break

        return results
