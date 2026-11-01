from urllib.parse import urlparse

from app.config import Config
from app.services.dns_query import DNSQueryBase
from app.utils import get_fld
from app.services.fofaClient import fofa_query


FOFA_SURVEY_FIELD_NAMES = (
    "host", "domain", "ip", "port", "protocol", "link", "title",
    "server", "product", "whois", "icp", "os", "country", "region",
    "city", "lastupdatetime",
)
FOFA_SURVEY_FIELDS = ",".join(FOFA_SURVEY_FIELD_NAMES)


def _host_from_value(value):
    value = str(value or "").strip()
    if not value:
        return ""
    if "://" in value:
        return (urlparse(value).hostname or "").strip(".").lower()
    if value.startswith("[") and "]" in value:
        return value[1:value.index("]")].lower()
    if value.count(":") == 1:
        host, port = value.rsplit(":", 1)
        if port.isdigit():
            value = host
    return value.strip(".").lower()


def parse_fofa_result(item, target, source_name, query_type):
    if isinstance(item, dict):
        row = item
    elif isinstance(item, (list, tuple)) and item:
        row = dict(zip(FOFA_SURVEY_FIELD_NAMES, item))
    else:
        return None

    raw_host = str(row.get("host") or "").strip()
    host = _host_from_value(raw_host)
    domain_hint = _host_from_value(row.get("domain"))
    domain = host if host == target or host.endswith("." + target) else ""
    if not domain and (domain_hint == target or domain_hint.endswith("." + target)):
        domain = domain_hint
    ip = str(row.get("ip") or "").strip()
    port = row.get("port")
    protocol = str(row.get("protocol") or "").strip().lower()
    title = str(row.get("title") or "").strip()
    updated_at = str(row.get("lastupdatetime") or "").strip()

    url = str(row.get("link") or "").strip()
    if not url and "://" in raw_host:
        url = raw_host
    endpoint_host = host or domain
    if not url and protocol in ("http", "https") and endpoint_host:
        default_port = 443 if protocol == "https" else 80
        try:
            normalized_port = int(port)
        except (TypeError, ValueError):
            normalized_port = default_port
        suffix = "" if normalized_port == default_port else ":{}".format(normalized_port)
        url = "{}://{}{}".format(protocol, endpoint_host, suffix)

    intel = {
        "source": source_name,
        "source_family": "fofa",
        "query_type": query_type,
        "ip": ip,
        "port": port,
        "protocol": protocol,
        "url": url,
        "web_title": title,
        "server": row.get("server"),
        "product": row.get("product"),
        "whois": row.get("whois"),
        "icp": row.get("icp"),
        "os": row.get("os"),
        "country": row.get("country"),
        "region": row.get("region"),
        "city": row.get("city"),
        "domain_hint": domain_hint,
        "updated_at": updated_at,
    }
    if not domain and not ip:
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
        self.source_name = "fofa"
        self.source_family = "fofa"
        self.query_type = "domain"
        self.config_source_name = "fofa"
        self.use_whole_query_budget = False

    def configuration_error(self):
        if not Config.FOFA_KEY:
            return "FOFA key is not configured"
        return ""

    def sub_domains(self, target):
        query = 'domain="{}"'.format(target)

        domain = get_fld(target)

        # Target 是非法域名
        if not domain:
            self.logger.warning("Invalid domain: {}".format(target))
            return []

        # 表示是子域名，需要用host 和 domain 一起查询
        if domain != target:
            query = 'host="{}" && domain="{}"'.format(target, domain)

        self.logger.debug("target:{}, fofa query: {}".format(target, query))

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
