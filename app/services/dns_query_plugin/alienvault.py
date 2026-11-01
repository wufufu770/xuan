import time
import ipaddress

from app.services.dns_query import (
    clear_source_circuit,
    DNSQueryBase,
    open_source_circuit,
    source_circuit_reason,
    source_rate_limit,
    set_source_cooldown,
)
from app import utils


class Query(DNSQueryBase):
    RETRYABLE_HTTP_STATUS = {429, 500, 502, 503, 504}

    def __init__(self):
        super(Query, self).__init__()
        self.source_name = "alienvault"
        self.api_url = "https://otx.alienvault.com/"
        self.rate_interval = 2.0
        self.retry_count = 2
        self.retry_sleep = 5.0
        self.rate_limit_cooldown = 300.0

    def init_key(self, rate_interval=2, retry_count=2, retry_sleep=5,
                 rate_limit_cooldown=300):
        self.rate_interval = max(float(rate_interval), 0.0)
        self.retry_count = max(int(retry_count), 0)
        self.retry_sleep = max(float(retry_sleep), 0.0)
        self.rate_limit_cooldown = max(float(rate_limit_cooldown), 0.0)

    def _retry_delay(self, retry, conn=None):
        headers = getattr(conn, "headers", {}) or {}
        try:
            retry_after = float(headers.get("Retry-After", 0) or 0)
        except (TypeError, ValueError):
            retry_after = 0.0
        return max(retry_after, self.retry_sleep * (retry + 1))

    def _wait_before_retry(self, retry, reason, conn=None):
        delay = self._retry_delay(retry, conn=conn)
        if delay <= 0:
            return
        set_source_cooldown(self.source_name, delay)
        self.logger.warning(
            "{} retry sleep {:.1f}s attempt {}/{} reason:{}".format(
                self.source_name, delay, retry + 1, self.retry_count, reason))
        time.sleep(delay)

    def sub_domains(self, target):
        url = "{}api/v1/indicators/domain/{}/passive_dns".format(self.api_url, target)
        headers = {
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0 (compatible; ARL-Recon/1.0)",
        }
        conn = None
        items = None
        for retry in range(self.retry_count + 1):
            circuit_reason = source_circuit_reason(self.source_name)
            if circuit_reason:
                self.mark_partial(circuit_reason, "rate_limited")
                return []
            try:
                with source_rate_limit(self.source_name, self.rate_interval):
                    circuit_reason = source_circuit_reason(self.source_name)
                    if circuit_reason:
                        self.mark_partial(circuit_reason, "rate_limited")
                        return []
                    conn = utils.http_req(
                        url, 'get', headers=headers, timeout=(10.1, 30.1))
            except Exception as e:
                if retry >= self.retry_count:
                    self.mark_partial("request failed: {}".format(e))
                    return []
                self._wait_before_retry(retry, type(e).__name__)
                continue

            if conn.status_code == 429:
                delay = max(
                    self._retry_delay(retry, conn=conn),
                    self.rate_limit_cooldown,
                )
                open_source_circuit(
                    self.source_name, delay, "http status 429")
                self.mark_partial("http status 429", "rate_limited")
                return []

            if conn.status_code in self.RETRYABLE_HTTP_STATUS:
                if retry >= self.retry_count:
                    self.mark_partial("http status {}".format(conn.status_code))
                    return []
                self._wait_before_retry(
                    retry, "http status {}".format(conn.status_code), conn=conn)
                continue

            if conn.status_code != 200:
                self.mark_partial("http status {}".format(conn.status_code))
                return []

            clear_source_circuit(self.source_name)

            try:
                items = conn.json()
            except Exception as e:
                if retry >= self.retry_count:
                    self.mark_partial("invalid json response: {}".format(e), "invalid_response")
                    return []
                self._wait_before_retry(retry, "invalid json response", conn=conn)
                continue
            break

        if items is None:
            self.mark_partial("empty upstream response", "invalid_response")
            return []

        results = []
        if not isinstance(items, dict):
            self.mark_partial(
                "unexpected response type: {}".format(type(items).__name__),
                "invalid_response")
            return results

        passive_dns = items.get("passive_dns") or []
        if not isinstance(passive_dns, list):
            self.mark_partial(
                "unexpected passive_dns type: {}".format(type(passive_dns).__name__),
                "invalid_response")
            return results

        for item in passive_dns:
            if not isinstance(item, dict):
                continue

            hostname = item.get("hostname")
            if not isinstance(hostname, str):
                continue

            hostname = hostname.strip().strip(".").lower()
            if hostname != target and not hostname.endswith("." + target):
                continue

            address = str(item.get("address") or "").strip()
            try:
                parsed_address = ipaddress.ip_address(address)
            except ValueError:
                parsed_address = None
            if parsed_address and parsed_address.version == 4 and parsed_address.is_global:
                results.append({
                    "domain": hostname,
                    "intel": {
                        "source": self.source_name,
                        "source_family": self.source_name,
                        "query_type": "historical_dns",
                        "ip": address,
                        "record_type": str(item.get("record_type") or "A"),
                        "first_seen_at": str(item.get("first") or ""),
                        "updated_at": str(item.get("last") or ""),
                    },
                })
            else:
                results.append(hostname)

        unique = {}
        for item in results:
            if isinstance(item, dict):
                intel = item.get("intel") or {}
                key = (item.get("domain"), intel.get("ip", ""))
            else:
                key = (item, "")
            unique[key] = item
        return [unique[key] for key in sorted(unique)]
