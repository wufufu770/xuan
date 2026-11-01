import json
from .IPy import IP
from app.config import Config


cdn_ip_cidr_list = []
cdn_cname_list = []
cdn_info = []


def _iter_cname_values(value):
    """Yield normalized CNAME values from httpx/DNS result shapes."""
    if isinstance(value, (list, tuple, set)):
        for item in value:
            for cname in _iter_cname_values(item):
                yield cname
        return

    for item in str(value or "").split(","):
        cname = item.strip().strip(".").lower()
        if cname:
            yield cname


def _domain_matches_suffix(domain, suffix):
    domain = str(domain or "").strip().strip(".").lower()
    suffix = str(suffix or "").strip().strip(".").lower()
    return bool(domain and suffix and (
        domain == suffix or domain.endswith("." + suffix)
    ))


def _normalize_rule_kind(item):
    kind = str((item or {}).get("kind") or "").strip().lower()
    if kind in ("cdn", "waf", "edge"):
        return kind

    # Backward compatibility for old rule rows that do not yet declare a
    # structured kind. A few legacy CDN names contain words such as 云盾 or
    # 安全加速, so an explicit CDN token must win over generic security words.
    # Mixed CDN/WAF rows should be declared as edge in the JSON rules.
    name = str((item or {}).get("name") or "").strip().lower()
    if "cdn" in name:
        return "cdn"
    if "waf" in name or any(marker in name for marker in (
            "网站卫士", "玄武盾", "安全宝", "云盾")):
        return "waf"
    if "gslb" in name or any(marker in name for marker in (
            "边缘", "高防", "安全加速")):
        return "edge"
    return "cdn"


def _init_cdn_info():
    from . import load_file
    global cdn_ip_cidr_list, cdn_cname_list, cdn_info
    if not cdn_info:
        cdn_ip_cidr_list = []
        cdn_cname_list = []
        data = "\n".join(load_file(Config.CDN_JSON_PATH))
        cdn_info = json.loads(data)

        for item in cdn_info:
            cdn_cname_list.extend(item["cname_domain"])
            if item.get("ip_cidr"):
                cdn_ip_cidr_list.extend(item["ip_cidr"])


def _ip_in_cidr_list(ip):
    for item in cdn_ip_cidr_list:
        if IP(ip) in IP(item):
            return True


def _cname_in_cname_list(cname):
    for value in _iter_cname_values(cname):
        for item in cdn_cname_list:
            if _domain_matches_suffix(value, item):
                return True
    return False


def get_cdn_name_by_ip(ip):
    from . import get_logger
    logger = get_logger()
    try:
        _init_cdn_info()

        if not _ip_in_cidr_list(ip):
            return ""

        for item in cdn_info:
            if item.get("ip_cidr"):
                for ip_cidr in item["ip_cidr"]:
                    if IP(ip) in IP(ip_cidr):
                        return item["name"]

    except Exception as e:
        logger.warning("{} {}".format(e, ip))
        return ""


def _get_cdn_match_by_cname(cname):
    from . import get_logger
    logger = get_logger()
    try:
        _init_cdn_info()
        best_match = {}
        best_suffix_length = -1
        for value in _iter_cname_values(cname):
            for item in cdn_info:
                for target in item["cname_domain"]:
                    if _domain_matches_suffix(value, target):
                        suffix = str(target or "").strip().strip(".").lower()
                        # Prefer the most specific rule when provider suffixes
                        # overlap (for example dnsv1.com and cdn.dnsv1.com).
                        # Equal-length matches retain input/rule order.
                        if len(suffix) <= best_suffix_length:
                            continue
                        best_suffix_length = len(suffix)
                        best_match = {
                            "name": item["name"],
                            "kind": _normalize_rule_kind(item),
                            "match_scope": str(
                                item.get("match_scope") or "domain_or_record"
                            ).strip().lower(),
                            "suffix": suffix,
                            "record": value,
                            "strength": "strict",
                        }
        return best_match

    except Exception as e:
        logger.warning("{} {}".format(e, cname))
    return {}


def _get_cdn_name_by_cname(cname):
    return _get_cdn_match_by_cname(cname).get("name", "")


def get_cdn_match_by_cname_strict(cname):
    """Return structured evidence for a boundary-safe suffix rule."""
    return _get_cdn_match_by_cname(cname)


def get_cdn_name_by_cname_strict(cname):
    """Return a provider only for an explicit, boundary-safe suffix rule."""
    return _get_cdn_name_by_cname(cname)


def get_cdn_kind_by_cname_strict(cname):
    return _get_cdn_match_by_cname(cname).get("kind", "")


def get_cdn_name_by_cname(cname):
    cdn_name = _get_cdn_name_by_cname(cname)

    check_list = ["gslb", "dns", "cache"]

    if not cdn_name:
        for value in _iter_cname_values(cname):
            for check in check_list:
                if check in value:
                    return "CDN"

    return cdn_name
