from app.config import Config
from app.services.fofaClient import fofa_query
from app.services.dns_query_plugin.fofa import (
    FOFA_SURVEY_FIELDS,
    Query as FofaQuery,
    parse_fofa_result,
)


class Query(FofaQuery):
    def __init__(self):
        super(Query, self).__init__()
        self.source_name = "fofa_cert"
        self.source_family = "fofa"
        self.query_type = "cert"
        self.config_source_name = "fofa"
        self.budget_source_name = "fofa"
        self.use_whole_query_budget = False

    def init_key(self, **kwargs):
        return

    def sub_domains(self, target):
        query = 'cert="{}"'.format(target)
        self.logger.debug("target:{}, fofa cert query: {}".format(target, query))

        max_records = int(Config.FOFA_PAGE_SIZE) * int(Config.FOFA_MAX_PAGE)
        fofa_results, meta = fofa_query(
            query,
            fields=FOFA_SURVEY_FIELDS,
            max_records=max_records,
            include_meta=True,
        )
        self.raw_result_count = int(meta.get("result_count") or 0)
        self.page_count = int(meta.get("page_count") or 0)
        self.rate_retries_used = int(meta.get("rate_retries_used") or 0)
        self.upstream_retries_used = int(meta.get("upstream_retries_used") or 0)
        self.network_retries_used = int(meta.get("network_retries_used") or 0)
        if meta.get("error"):
            self.mark_partial(meta["error"])

        results = []
        for item in fofa_results:
            parsed = parse_fofa_result(
                item, target, self.source_name, self.query_type)
            if parsed:
                results.append(parsed)

        return results
