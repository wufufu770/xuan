import json
import time

from app.services.dns_query import DNSQueryBase
from app import utils


class Query(DNSQueryBase):
    """Censys v2 被动子域收集（hosts/search + dns.names 查询，cursor 翻页）。"""

    def __init__(self):
        super(Query, self).__init__()
        self.source_name = "censys"
        self.api_url = "https://search.censys.io/api/v2/hosts/search"
        self.auth_email = None
        self.auth_key = None
        self.max_page = 5

    def init_key(self, auth_email=None, auth_key=None, max_page=5):
        self.auth_email = auth_email
        self.auth_key = auth_key
        self.max_page = max(int(max_page or 5), 1)

    def configuration_error(self):
        if not self.auth_email or not self.auth_key:
            return "Censys API ID / secret are not configured"
        return ""

    def sub_domains(self, target):
        auth = (self.auth_email, self.auth_key)
        payload = {"q": "dns.names: {}".format(target), "per_page": 100}

        results = []
        cursor = ""
        curr_page = 1
        while True:
            body = dict(payload)
            if cursor:
                body["cursor"] = cursor
            conn = utils.http_req(self.api_url, 'post', json=body, auth=auth,
                                  timeout=(30.1, 50.1))
            if conn.status_code != 200:
                data = {}
                try:
                    data = conn.json()
                except Exception:
                    pass
                self.logger.error("censys query error:{} {}".format(
                    conn.status_code, json.dumps(data, ensure_ascii=False)[:300]))
                break

            data = conn.json()
            result = data.get("result") or {}
            hits = result.get("hits") or []
            if not hits:
                break

            for hit in hits:
                names = (hit.get("dns_names")
                         or (hit.get("dns") or {}).get("names") or [])
                for name in names:
                    name = str(name).strip().lower().rstrip(".")
                    if name.endswith("." + target) or name == target:
                        results.append(name)

            cursor = ((result.get("links") or {}).get("next")) or ""
            if not cursor or curr_page >= self.max_page:
                break

            time.sleep(1)
            curr_page += 1

        return list(set(results))
