import base64
import json
import time
from urllib.parse import urlparse

from app.services.dns_query import (
    DNSQueryBase,
    retry_after_seconds,
    retry_backoff,
    source_rate_limit,
    set_source_cooldown,
)
from app import utils


def parse_hunter_result(item, target, source_name, query_type):
    if not isinstance(item, dict):
        return None

    name = str(item.get("domain") or "").strip(".").lower()
    if name != target and not name.endswith("." + target):
        raw_url = str(item.get("url") or "").strip()
        if raw_url:
            name = str(urlparse(raw_url).hostname or "").strip(".").lower()
    domain = name if name == target or name.endswith("." + target) else ""
    intel = {
        "source": source_name,
        "source_family": "hunter",
        "query_type": query_type,
        "ip": item.get("ip"),
        "port": item.get("port"),
        "url": item.get("url"),
        "protocol": item.get("protocol") or item.get("base_protocol"),
        "web_title": item.get("web_title"),
        "status_code": item.get("status_code"),
        "updated_at": item.get("updated_at"),
        "server": item.get("header_server"),
        "product": item.get("component"),
        "banner": item.get("banner"),
        "os": item.get("os"),
        "company": item.get("company"),
        "isp": item.get("isp"),
        "country": item.get("country"),
        "province": item.get("province"),
        "city": item.get("city"),
        "cert_sha256": item.get("cert_sha256"),
    }
    if not domain and not intel.get("ip"):
        return None
    return {
        "domain": domain,
        "intel": intel,
        "candidate_type": (
            "cert_ip" if not domain and query_type == "cert"
            else "mapping_ip" if not domain
            else ""
        ),
    }


class Query(DNSQueryBase):
    def __init__(self):
        super(Query, self).__init__()
        self.source_name = "hunter_qax"
        self.source_family = "hunter"
        self.query_type = "domain"
        self.config_source_name = "hunter_qax"
        self.use_whole_query_budget = False
        self.rate_source_name = self.source_name
        self.api_url = "https://hunter.qianxin.com/openApi/search"
        self.api_key = None
        self.page_size = 100
        self.max_page = 60
        self.is_web = "3"
        self.rate_interval = 1
        self.retry_count = 3
        self.retry_sleep = 15
        self.upstream_retry_count = 1
        self.upstream_retry_sleep = 3
        self.network_retry_count = 1
        self.connect_timeout = 8.1
        self.read_timeout = 30.1

    def init_key(self, api_key=None, page_size=100, max_page=60,
                 is_web=3, rate_interval=1, retry_count=3, retry_sleep=15,
                 upstream_retry_count=1, upstream_retry_sleep=3,
                 network_retry_count=1, connect_timeout=8.1,
                 read_timeout=30.1):
        api_key = str(api_key or "").strip()
        if "||" in api_key:
            api_key, custom_url = api_key.split("||", 1)
            custom_url = custom_url.strip().rstrip("/")
            if custom_url:
                self.api_url = custom_url
        self.api_key = api_key.strip()
        self.page_size = min(max(int(page_size), 10), 100)
        self.max_page = max(int(max_page), 1)
        self.is_web = str(is_web or 3)
        self.rate_interval = float(rate_interval)
        self.retry_count = int(retry_count)
        self.retry_sleep = float(retry_sleep)
        self.upstream_retry_count = max(int(upstream_retry_count), 0)
        self.upstream_retry_sleep = max(float(upstream_retry_sleep), 0.1)
        self.network_retry_count = max(int(network_retry_count), 0)
        self.connect_timeout = max(float(connect_timeout), 1.0)
        self.read_timeout = max(float(read_timeout), 1.0)

    def configuration_error(self):
        if not self.api_key:
            return "Hunter API key is not configured"
        return ""

    def query_api(self, param):
        rate_retries = 0
        upstream_retries = 0
        network_retries = 0
        while True:
            try:
                with source_rate_limit(self.rate_source_name, self.rate_interval):
                    conn = utils.http_req(
                        self.api_url, 'get', params=param,
                        timeout=(self.connect_timeout, self.read_timeout))
            except Exception as error:
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
                        type(error).__name__))
                time.sleep(delay)
                continue

            try:
                data = conn.json()
            except Exception:
                data = {}
            if not isinstance(data, dict):
                data = {}
            data.setdefault("_http_status", conn.status_code)
            if conn.status_code != 200:
                data.setdefault("code", conn.status_code)
                data.setdefault("message", "http status {}".format(conn.status_code))

            message = str(data.get("message", ""))
            is_rate_limited = (
                conn.status_code == 429 or self.is_rate_limited_message(message)
            )
            if is_rate_limited:
                if rate_retries >= self.retry_count:
                    return data
                default_delay = self.retry_sleep * (rate_retries + 1)
                delay = retry_after_seconds(conn, default=default_delay)
                rate_retries += 1
                self.rate_retries_used += 1
                set_source_cooldown(self.rate_source_name, delay)
                self.logger.warning(
                    "{} rate limited, sleep {:.2f}s then retry {}/{}".format(
                        self.source_name, delay, rate_retries,
                        self.retry_count))
                time.sleep(delay)
                continue

            if conn.status_code in (500, 502, 503, 504):
                if upstream_retries >= self.upstream_retry_count:
                    return data
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

            return data

    def is_rate_limited_message(self, message):
        message = str(message or "").lower()
        rate_words = ["429", "rate", "limit", "too many", "请求太多", "频繁", "过于频繁", "调用api过于频繁"]
        return any(word in message for word in rate_words)

    def response_error_kind(self, data):
        status = int(data.get("_http_status") or 0) if isinstance(data, dict) else 0
        message = str(data.get("message", "") if isinstance(data, dict) else "")
        if status in (401, 403):
            return "authentication"
        if status == 429 or self.is_rate_limited_message(message):
            return "rate_limited"
        if status in (500, 502, 503, 504):
            return "upstream_error"
        return "invalid_response"

    def sub_domains(self, target):
        search = "domain.suffix=\"{}\"".format(target)

        param = {
            "search": base64.urlsafe_b64encode(
                search.encode("utf-8")).decode("ascii"),
            "page": 1,
            "page_size": self.page_size,
            "is_web": self.is_web,
            "api-key": self.api_key
        }

        results = []

        curr_page = 1
        while True:
            self.logger.debug("hunter_qax target:{} page_size:{} curr_page:{}".format(target, self.page_size, curr_page))
            param["page"] = curr_page
            try:
                data = self.query_api(param)
            except Exception as error:
                self.mark_partial("hunter request failed: {}".format(error))
                break
            if not isinstance(data, dict):
                self.mark_partial(
                    "unexpected response type: {}".format(type(data).__name__),
                    "invalid_response")
                break

            code = data.get("code")
            if code != 200 and code != 40205:
                self.mark_partial("hunter_qax query error:{}".format(
                    json.dumps(data, ensure_ascii=False)),
                    self.response_error_kind(data))
                break

            if code == 40205:
                self.logger.info(data.get("message", "hunter_qax no data"))
                break

            data_body = data.get("data") or {}
            if not isinstance(data_body, dict):
                self.mark_partial(
                    "unexpected data type: {}".format(type(data_body).__name__),
                    "invalid_response")
                break

            arr = data_body.get("arr") or []
            if not isinstance(arr, list):
                self.mark_partial(
                    "unexpected arr type: {}".format(type(arr).__name__),
                    "invalid_response")
                break

            self.page_count = curr_page
            self.raw_result_count += len(arr)

            for item in arr:
                parsed = parse_hunter_result(
                    item, target, self.source_name, self.query_type)
                if parsed:
                    results.append(parsed)

            self.logger.debug(
                "hunter_qax target:{} page_size:{} curr_page:{} total:{} curr_size:{}".format(
                    target, self.page_size, curr_page, data_body.get("total", 0), len(arr)))

            if len(arr) < self.page_size:
                break

            total = data_body.get("total")
            if isinstance(total, int) and curr_page * self.page_size >= total:
                break

            curr_page += 1

            if curr_page > self.max_page:
                break

        return results
