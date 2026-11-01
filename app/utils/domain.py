import tld
from urllib.parse import urlparse
from app.config import Config

blackdomain_list = None
blackhexie_list = None
blackdomain_keyword_list = None

DEFAULT_BLACKDOMAIN_KEYWORDS = ("mali", "vpn")


def _normalize_black_domain(domain):
    domain = str(domain or "").strip().lower()
    if "://" in domain:
        domain = urlparse(domain).hostname or domain
    elif "/" in domain:
        domain = domain.split("/", 1)[0]

    domain = domain.strip().strip("*.")
    if domain.startswith("[") and "]" in domain:
        domain = domain[1:domain.index("]")]
    elif domain.count(":") == 1:
        host, port = domain.rsplit(":", 1)
        if port.isdigit():
            domain = host
    return domain.strip(".")


def _load_blackdomain_keywords():
    raw = getattr(Config, "DOMAIN_BLACK_KEYWORDS", DEFAULT_BLACKDOMAIN_KEYWORDS)
    if raw is None:
        raw = DEFAULT_BLACKDOMAIN_KEYWORDS
    if isinstance(raw, str):
        values = raw.replace("\n", ",").split(",")
    else:
        values = list(raw or [])

    keywords = []
    for value in list(DEFAULT_BLACKDOMAIN_KEYWORDS) + values:
        keyword = str(value or "").strip().lower()
        if keyword and keyword not in keywords:
            keywords.append(keyword)
    return keywords


def check_domain_black(domain):
    from app.utils import get_logger
    logger = get_logger()

    global blackdomain_list
    global blackhexie_list
    global blackdomain_keyword_list
    domain = _normalize_black_domain(domain)
    if not domain:
        return False

    if blackdomain_keyword_list is None:
        blackdomain_keyword_list = _load_blackdomain_keywords()

    for item in blackdomain_keyword_list:
        if item and item in domain:
            return True

    if blackdomain_list is None:
        with open(Config.black_domain_path) as f:
            blackdomain_list = f.readlines()

    for item in blackdomain_list:
        item = item.strip().lower()
        if item and domain.endswith(item):
            return True

    if blackhexie_list is None:
        with open(Config.black_hexie_path) as f:
            blackhexie_list = f.readlines()

    try:
        for item in blackhexie_list:
            item = item.strip().lower()
            _, _, subdomain = tld.parse_tld(domain, fix_protocol=True, fail_silently=True)
            if subdomain and item and item.strip() in subdomain:
                return True
    except Exception as e:
        logger.warning("Error on: {}, {}".format(domain, e))
        return True

    return False


def is_forbidden_domain(domain):
    for f_domain in Config.FORBIDDEN_DOMAINS:
        if not f_domain:
            continue
            
        if domain.endswith("." + f_domain):
            return True
        if domain == f_domain:
            return True

    return False


def is_valid_domain(domain):
    from app.utils import domain_parsed
    if "." not in domain:
        return False

    invalid_chars = "!@#$%&*():_\\"
    for c in invalid_chars:
        if c in domain:
            return False

    # 不允许下发特殊二级域名
    if domain in ["com.cn", "gov.cn", "edu.cn"]:
        return False

    if domain_parsed(domain):
        return True

    return False


def is_valid_fuzz_domain(domain):
    from app.utils import domain_parsed
    if "{fuzz}" not in domain:
        return False

    domain = domain.replace("{fuzz}", "12fuzz12")
    parsed = domain_parsed(domain)
    if not parsed:
        return False

    if "12fuzz12" in parsed['fld']:
        return False

    return True


def is_in_scope(src_domain, target_domain):
    from app.utils import get_fld

    fld1 = get_fld(src_domain)
    fld2 = get_fld(target_domain)

    if not fld1 or not fld2:
        return False

    if fld1 != fld2:
        return False

    if src_domain == target_domain:
        return True

    return src_domain.endswith("."+target_domain)


def is_in_scopes(domain, scopes):
    for target_scope in scopes:
        if is_in_scope(domain, target_scope):
            return True

    return False


def cut_first_name(domain):
    """将子域名剔除前面一节名称"""
    domain_parts, non_zero_i, _ = tld.utils.process_url(domain, fix_protocol=True, fail_silently=True)
    if not domain_parts:
        return

    if non_zero_i == 1:
        return

    item = ".".join(domain_parts[1:])
    return item
