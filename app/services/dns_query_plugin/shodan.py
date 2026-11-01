import json

from app.services.dns_query import DNSQueryBase
from app import utils


class Query(DNSQueryBase):
    """Shodan 被动子域收集（GET /dns/domain/{domain}，一次返回全量前缀）。"""

    def __init__(self):
        super(Query, self).__init__()
        self.source_name = "shodan"
        self.api_url = "https://api.shodan.io"
        self.api_key = None

    def init_key(self, api_key=None):
        self.api_key = api_key

    def configuration_error(self):
        if not self.api_key:
            return "Shodan API key is not configured"
        return ""

    def sub_domains(self, target):
        url = "{}/dns/domain/{}".format(self.api_url, target)
        headers = {"Authorization": "Bearer {}".format(self.api_key)}
        params = {"key": self.api_key}

        conn = utils.http_req(url, 'get', params=params, headers=headers,
                              timeout=(30.1, 50.1))
        if conn.status_code != 200:
            data = {}
            try:
                data = conn.json()
            except Exception:
                pass
            self.logger.error("shodan query error:{} {}".format(
                conn.status_code, json.dumps(data, ensure_ascii=False)[:300]))
            return []

        data = conn.json()
        results = []
        for prefix in (data.get("subdomains") or []):
            name = "{}.{}".format(str(prefix).strip().lower(), target)
            results.append(name)

        return list(set(results))
