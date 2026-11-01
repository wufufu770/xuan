from app.services.dns_query import DNSQueryBase
from app import utils


class Query(DNSQueryBase):
    def __init__(self):
        super(Query, self).__init__()
        self.source_name = "chaos"
        self.api_url = "https://dns.projectdiscovery.io/"
        self.api_key = None

    def init_key(self, api_key=None):
        self.api_key = api_key

    def sub_domains(self, target):
        headers = {
            "Authorization": self.api_key
        }
        results = []
        url = "{}dns/{}/subdomains".format(self.api_url, target)
        conn = utils.http_req(url, 'get', headers=headers, timeout=(10.1, 30.1))
        try:
            items = conn.json()
        except Exception as e:
            self.mark_partial("invalid json target:{} status:{} error:{}".format(
                target, getattr(conn, "status_code", ""), e), "invalid_response")
            return []

        if not isinstance(items, dict):
            self.mark_partial("unexpected response target:{} type:{}".format(
                target, type(items).__name__), "invalid_response")
            return []

        subdomains = items.get("subdomains") or []
        if not isinstance(subdomains, list):
            self.mark_partial("subdomains is not list target:{} type:{}".format(
                target, type(subdomains).__name__), "invalid_response")
            return []

        for name in subdomains:
            if not isinstance(name, str):
                continue
            name = name.strip().strip(".")
            if not name:
                continue
            subdoamin = name + "." + target
            results.append(subdoamin)

        return list(set(results))
