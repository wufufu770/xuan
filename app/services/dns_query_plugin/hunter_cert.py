import base64
import json

from app.config import Config
from app.services.dns_query_plugin.hunter_qax import (
    Query as HunterQuery,
    parse_hunter_result,
)


class Query(HunterQuery):
    def __init__(self):
        super(Query, self).__init__()
        self.source_name = "hunter_cert"
        self.source_family = "hunter"
        self.query_type = "cert"
        self.config_source_name = "hunter_qax"
        self.budget_source_name = "hunter_qax"
        self.rate_source_name = "hunter_qax"
        self.use_whole_query_budget = False

    def init_key(self, inherit="hunter_qax", **kwargs):
        base_conf = Config.QUERY_PLUGIN_CONFIG.get(inherit or "hunter_qax", {})
        if not isinstance(base_conf, dict):
            base_conf = {}
        merged = {key: value for key, value in base_conf.items() if key != "enable"}
        merged.update(kwargs)
        merged.pop("inherit", None)
        super(Query, self).init_key(**merged)

    def sub_domains(self, target):
        if not self.api_key:
            self.init_key()

        search = 'cert="{}"'.format(target)
        param = {
            "search": base64.urlsafe_b64encode(
                search.encode("utf-8")).decode("ascii"),
            "page": 1,
            "page_size": self.page_size,
            "is_web": self.is_web,
            "api-key": self.api_key,
        }

        results = []
        curr_page = 1
        while True:
            self.logger.debug("hunter_cert target:{} page_size:{} curr_page:{}".format(
                target, self.page_size, curr_page))
            param["page"] = curr_page
            try:
                data = self.query_api(param)
            except Exception as error:
                self.mark_partial("hunter cert request failed: {}".format(error))
                break
            if not isinstance(data, dict):
                self.mark_partial(
                    "unexpected response type: {}".format(type(data).__name__),
                    "invalid_response")
                break

            code = data.get("code")
            if code != 200 and code != 40205:
                self.mark_partial("hunter_cert query error:{}".format(
                    json.dumps(data, ensure_ascii=False)),
                    self.response_error_kind(data))
                break

            if code == 40205:
                self.logger.info(data.get("message", "hunter_cert no data"))
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
                "hunter_cert target:{} page_size:{} curr_page:{} total:{} curr_size:{}".format(
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
