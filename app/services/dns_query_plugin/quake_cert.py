from app.config import Config
from app.services.dns_query_plugin.quake_360 import (
    Query as QuakeQuery,
    parse_quake_results,
)


class Query(QuakeQuery):
    def __init__(self):
        super(Query, self).__init__()
        self.source_name = "quake_cert"
        self.source_family = "quake"
        self.query_type = "cert"
        self.config_source_name = "quake_360"
        self.budget_source_name = "quake_360"
        self.rate_source_name = "quake_360"
        self.use_whole_query_budget = False

    def init_key(self, inherit="quake_360", **kwargs):
        base_conf = Config.QUERY_PLUGIN_CONFIG.get(inherit or "quake_360", {})
        if not isinstance(base_conf, dict):
            base_conf = {}
        merged = {key: value for key, value in base_conf.items() if key != "enable"}
        merged.update(kwargs)
        merged.pop("inherit", None)
        super(Query, self).init_key(**merged)

    def sub_domains(self, target):
        if not self.quake_token:
            self.init_key()

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
                "query": 'cert:"{}"'.format(target),
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

            self.logger.debug("{}: target:{} start:{} meta:{}".format(
                self.source_name, target, start, data.get("meta", {})))

            if len(items) < page_size:
                break

            start += len(items)
            meta = data.get("meta") or {}
            pagination = meta.get("pagination") or {}
            total = pagination.get("total")
            if isinstance(total, int) and start >= total:
                break

        return results
