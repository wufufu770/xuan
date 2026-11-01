#  -*- coding:UTF-8 -*-
import base64
import re
from app.config import Config
from app import utils
import time
from app.services.dns_query import (
    retry_after_seconds,
    retry_backoff,
    source_rate_limit,
    set_source_cooldown,
)
logger = utils.get_logger()


def _redact_fofa_error(value):
    value = str(value or "")
    secret = str(Config.FOFA_KEY or "")
    if secret:
        value = value.replace(secret, "<redacted>")
    return re.sub(
        r"([?&]key=)[^&\s]+",
        r"\1<redacted>",
        value,
        flags=re.IGNORECASE,
    )


class FofaClient:
    def __init__(self, key, page_size=100, max_page=60, fields="host,ip,port",
                 rate_interval=1, retry_count=3, retry_sleep=10,
                 max_records=None, upstream_retry_count=2,
                 upstream_retry_sleep=3, network_retry_count=2):
        self.key = key
        self.page_size = page_size
        self.max_page = max_page
        self.base_url = Config.FOFA_URL.rstrip("/")
        self.search_all_path = "/api/v1/search/all"
        self.base_params = {
            "key": self.key,
        }
        self.fields = fields
        self.rate_interval = float(rate_interval)
        self.retry_count = int(retry_count)
        self.retry_sleep = int(retry_sleep)
        self.max_records = max(int(max_records), 0) if max_records is not None else None
        self.upstream_retry_count = max(int(upstream_retry_count), 0)
        self.upstream_retry_sleep = max(float(upstream_retry_sleep), 0.1)
        self.network_retry_count = max(int(network_retry_count), 0)
        self.page_count = 0
        self.rate_retries_used = 0
        self.upstream_retries_used = 0
        self.network_retries_used = 0

    def search(self, query):
        page = 1
        yielded = 0
        while True:
            if page > self.max_page:
                break
            if self.max_records is not None and yielded >= self.max_records:
                break
            if page > 1:
                time.sleep(0.2)

            data = self.fofa_search_all(query, page)
            logger.debug("Page:{} Page Size:{} Query:{}".format(
                page, self.page_size, data.get("query", query)))

            results = data.get("results") or []
            if not isinstance(results, list):
                raise RuntimeError("fofa results is not a list")
            self.page_count = page

            if self.max_records is not None:
                results = results[:max(self.max_records - yielded, 0)]

            logger.debug("Current results size:{} All Size:{}".format(
                len(results), data.get("size", 0)))

            if results:
                yield results
                yielded += len(results)

            if len(results) < self.page_size:
                break

            page += 1

    def fofa_search_all(self, query, page=1):
        q_base64 = base64.b64encode(query.encode())
        params = {
            "qbase64": q_base64.decode('utf-8'),
            "page": page,
            "size": self.page_size,
            "full": "true",
            "fields": self.fields,
        }
        data = self._api(self.search_all_path, params)
        return data

    def _api(self, path, params=None):
        if params is None:
            params = self.base_params
        else:
            params.update(self.base_params)

        url = self.base_url + path
        rate_retries = 0
        upstream_retries = 0
        network_retries = 0
        while True:
            try:
                with source_rate_limit("fofa", self.rate_interval):
                    conn = utils.http_req(url, 'get', params=params)
            except Exception as error:
                if network_retries >= self.network_retry_count:
                    raise
                delay = retry_backoff(
                    self.upstream_retry_sleep, network_retries, maximum=20)
                network_retries += 1
                self.network_retries_used += 1
                logger.warning("fofa network retry {}/{} sleep {:.2f}s error:{}".format(
                    network_retries, self.network_retry_count, delay,
                    type(error).__name__))
                time.sleep(delay)
                continue

            try:
                data = conn.json()
            except Exception as error:
                if (conn.status_code in (500, 502, 503, 504)
                        and upstream_retries < self.upstream_retry_count):
                    delay = retry_backoff(
                        self.upstream_retry_sleep, upstream_retries, maximum=20)
                    upstream_retries += 1
                    self.upstream_retries_used += 1
                    logger.warning("fofa invalid upstream response retry {}/{} sleep {:.2f}s".format(
                        upstream_retries, self.upstream_retry_count, delay))
                    time.sleep(delay)
                    continue
                raise RuntimeError("fofa invalid JSON response status:{} error:{}".format(
                    conn.status_code, type(error).__name__))

            if not isinstance(data, dict):
                raise RuntimeError("fofa response is not a mapping")

            errmsg = str(data.get("errmsg") or data.get("message") or "")
            is_rate_limited = conn.status_code == 429 or self._is_rate_limited(errmsg)
            if conn.status_code == 200 and not data.get("error"):
                return data

            if is_rate_limited:
                if rate_retries >= self.retry_count:
                    raise RuntimeError(errmsg or "fofa rate limited")
                default_delay = self.retry_sleep * (rate_retries + 1)
                delay = retry_after_seconds(conn, default=default_delay)
                rate_retries += 1
                self.rate_retries_used += 1
                set_source_cooldown("fofa", delay)
                logger.warning("fofa rate limited, sleep {:.2f}s then retry {}/{}".format(
                    delay, rate_retries, self.retry_count))
                time.sleep(delay)
                continue

            if conn.status_code in (500, 502, 503, 504):
                if upstream_retries >= self.upstream_retry_count:
                    raise RuntimeError("fofa upstream http status:{}".format(conn.status_code))
                delay = retry_backoff(
                    self.upstream_retry_sleep, upstream_retries, maximum=20)
                upstream_retries += 1
                self.upstream_retries_used += 1
                logger.warning("fofa upstream retry {}/{} sleep {:.2f}s status:{}".format(
                    upstream_retries, self.upstream_retry_count, delay,
                    conn.status_code))
                time.sleep(delay)
                continue

            if data.get("error"):
                raise RuntimeError(errmsg or "fofa API returned an error")
            raise RuntimeError("{} http status code: {}".format(url, conn.status_code))

    def _is_rate_limited(self, message):
        message = str(message or "").lower()
        rate_words = ["429", "rate", "limit", "too many", "频繁", "请求太多", "过于频繁"]
        return any(word in message for word in rate_words)


def fofa_query(query, fields="host,ip,port",
               page_size=Config.FOFA_PAGE_SIZE,
               max_page=Config.FOFA_MAX_PAGE,
               max_records=None, include_meta=False):
    ret = []
    client = None
    error_msg = ""
    try:
        if not Config.FOFA_KEY:
            error_msg = "please set fofa key in config.yaml"
            if include_meta:
                return ret, {"error": error_msg, "page_count": 0, "result_count": 0}
            return error_msg

        client = FofaClient(Config.FOFA_KEY,
                            page_size=page_size, max_page=max_page,
                            fields=fields,
                            rate_interval=Config.FOFA_RATE_INTERVAL,
                            retry_count=Config.FOFA_RETRY_COUNT,
                            retry_sleep=Config.FOFA_RETRY_SLEEP,
                            max_records=max_records)
        for results in client.search(query):
            ret.extend(results)

        logger.info(f"fofa query: {query} result size: {len(ret)}")

    except Exception as e:
        error_msg = _redact_fofa_error(e)
        logger.warning(f"fofa query error: {error_msg}")

    if include_meta:
        return ret, {
            "error": error_msg,
            "page_count": getattr(client, "page_count", 0),
            "result_count": len(ret),
            "rate_retries_used": getattr(client, "rate_retries_used", 0),
            "upstream_retries_used": getattr(client, "upstream_retries_used", 0),
            "network_retries_used": getattr(client, "network_retries_used", 0),
        }
    if ret:
        return ret
    return error_msg or ret
