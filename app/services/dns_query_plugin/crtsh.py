import time

from app.services.dns_query import (
    clear_source_circuit,
    DNSQueryBase,
    open_source_circuit,
    source_circuit_reason,
    source_rate_limit,
    set_source_cooldown,
)
from app import utils

logger = utils.get_logger()


class Query(DNSQueryBase):
    RETRYABLE_HTTP_STATUS = {429, 500, 502, 503, 504}

    def __init__(self):
        super(Query, self).__init__()
        self.source_name = "crtsh"
        self.api_url = "https://crt.sh/"
        self.rate_interval = 2.0
        self.retry_count = 2
        self.retry_sleep = 5.0
        self.include_expired = True
        self.upstream_circuit_seconds = 120.0

    def init_key(self, rate_interval=2, retry_count=2, retry_sleep=5,
                 include_expired=True, upstream_circuit_seconds=120):
        self.rate_interval = max(float(rate_interval), 0.0)
        self.retry_count = max(int(retry_count), 0)
        self.retry_sleep = max(float(retry_sleep), 0.0)
        self.include_expired = bool(include_expired)
        self.upstream_circuit_seconds = max(
            float(upstream_circuit_seconds), 0.0)

    def _retry_delay(self, retry, resp=None):
        headers = getattr(resp, "headers", {}) or {}
        try:
            retry_after = float(headers.get("Retry-After", 0) or 0)
        except (TypeError, ValueError):
            retry_after = 0.0
        return max(retry_after, self.retry_sleep * (retry + 1))

    def _wait_before_retry(self, retry, reason, resp=None):
        delay = self._retry_delay(retry, resp=resp)
        if delay <= 0:
            return
        set_source_cooldown(self.source_name, delay)
        self.logger.warning(
            "{} retry sleep {:.1f}s attempt {}/{} reason:{}".format(
                self.source_name, delay, retry + 1, self.retry_count, reason))
        time.sleep(delay)

    def sub_domains(self, target):
        items = self._query_items(target, "%.{}".format(target))
        if items is None and self.query_error_kind == "not_found":
            self.query_status = "done"
            self.query_error = ""
            self.query_error_kind = ""
            items = self._query_items(target, target)

        if items is None:
            return []

        results = []
        for item in items:
            if not isinstance(item, dict):
                continue
            for name in str(item.get("name_value", "")).split():
                if name.endswith("." + target):
                    results.append(name)

        return list(set(results))

    def _query_items(self, target, query_value):
        param = {"output": "json", "q": query_value}
        if not self.include_expired:
            param["exclude"] = "expired"

        circuit_reason = source_circuit_reason(self.source_name)
        if circuit_reason:
            self.mark_partial(circuit_reason, "upstream_error")
            return None

        for retry in range(self.retry_count + 1):
            try:
                with source_rate_limit(self.source_name, self.rate_interval):
                    circuit_reason = source_circuit_reason(self.source_name)
                    if circuit_reason:
                        self.mark_partial(circuit_reason, "upstream_error")
                        return None
                    resp = utils.http_req(
                        self.api_url, 'get', params=param,
                        headers={
                            "Accept": "application/json",
                            "User-Agent": "Mozilla/5.0 (compatible; ARL-Recon/1.0)",
                        },
                        timeout=(8.1, 30.1),
                    )
            except Exception as e:
                if retry >= self.retry_count:
                    self.mark_partial(
                        "query failed target:{} error:{}".format(target, e))
                    return None
                self._wait_before_retry(retry, type(e).__name__)
                continue

            if resp.status_code in self.RETRYABLE_HTTP_STATUS:
                if retry >= self.retry_count:
                    open_source_circuit(
                        self.source_name,
                        self.upstream_circuit_seconds,
                        "http status {}".format(resp.status_code),
                    )
                    self.mark_partial("http status {}".format(resp.status_code))
                    return None
                self._wait_before_retry(
                    retry, "http status {}".format(resp.status_code), resp=resp)
                continue

            if resp.status_code == 404:
                self.mark_partial("http status 404", "not_found")
                return None
            if resp.status_code != 200:
                self.mark_partial("http status {}".format(resp.status_code))
                return None

            clear_source_circuit(self.source_name)
            try:
                items = resp.json()
            except Exception as e:
                if retry >= self.retry_count:
                    self.mark_partial(
                        "invalid json target:{} error:{}".format(target, e),
                        "invalid_response")
                    return None
                self._wait_before_retry(retry, "invalid json response", resp=resp)
                continue

            if not isinstance(items, list):
                if retry >= self.retry_count:
                    self.mark_partial(
                        "unexpected response target:{} type:{}".format(
                            target, type(items).__name__),
                        "invalid_response",
                    )
                    return None
                self._wait_before_retry(
                    retry, "unexpected response type", resp=resp)
                continue
            return items

        self.mark_partial("empty upstream response", "invalid_response")
        return None
