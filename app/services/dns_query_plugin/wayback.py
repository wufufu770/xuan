from urllib.parse import urlparse

from app.config import Config
from app.services.dns_query import DNSQueryBase
from app import utils


class Query(DNSQueryBase):
    """Wayback Machine (web.archive.org) 历史子域查询，无需 key。"""

    def __init__(self):
        super(Query, self).__init__()
        self.source_name = "wayback"
        self.source_family = "wayback"
        self.query_type = "passive"
        self.config_source_name = "wayback"
        self.use_whole_query_budget = False
        self.timeout = 30
        self.max_results = 20000

    def init_key(self, **kwargs):
        try:
            self.timeout = int(kwargs.get("timeout") or self.timeout)
        except (TypeError, ValueError):
            self.timeout = 30
        try:
            self.max_results = int(kwargs.get("max_results") or self.max_results)
        except (TypeError, ValueError):
            self.max_results = 20000

    def configuration_error(self):
        return ""

    def _fetch_history_urls(self, target):
        url = (
            "http://web.archive.org/cdx/search/cdx"
            "?url=*.{target}&output=json&fl=original"
            "&collapse=urlkey&limit={limit}".format(
                target=target, limit=max(self.max_results, 1))
        )
        response = utils.http_req(url, timeout=(self.timeout, self.timeout + 20))
        rows = response.json()

        if not isinstance(rows, list) or len(rows) < 2:
            return []

        # 第一行是表头 ["original"]
        urls = []
        for row in rows[1:]:
            if isinstance(row, (list, tuple)) and row:
                urls.append(str(row[0] or ""))
            elif isinstance(row, str):
                urls.append(row)
        return urls

    def sub_domains(self, target):
        urls = self._fetch_history_urls(target)
        subdomains = set()
        suffix = "." + target
        for raw_url in urls:
            if "://" not in raw_url:
                raw_url = "http://" + raw_url
            host = (urlparse(raw_url).hostname or "").strip(".").lower()
            if not host:
                continue
            if host == target or host.endswith(suffix):
                subdomains.add(host)

        self.raw_result_count = len(urls)
        return [{"domain": domain, "intel": {
            "source": self.source_name,
            "source_family": self.source_family,
            "query_type": self.query_type,
        }, "candidate_type": ""} for domain in sorted(subdomains)]
