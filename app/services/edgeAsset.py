import math
import re
from urllib.parse import urlparse


EDGE_TAG = "边缘入口"
ZTNA_TAG = "ZTNA"
WILDCARD_TAG = "泛解析"
RANDOM_TAG = "随机长域名"


MEANINGFUL_LABEL_WORDS = {
    "admin", "api", "app", "auth", "bill", "biz", "blog", "cdn", "cloud",
    "console", "crm", "dev", "download", "edu", "finance", "front",
    "gateway", "git", "hall", "help", "home", "login", "mail", "manage",
    "marketing", "mfa", "mobile", "monitor", "news", "oa", "open",
    "portal", "prod", "quote", "research", "scan", "server", "service",
    "sit", "sso", "stage", "static", "test", "trade", "uat", "vpn",
    "web", "www",
}

EDGE_LABEL_WORDS = {
    "ztna", "waf", "edge", "gateway", "cdn", "firewall", "sase", "vpn",
    "access", "proxy", "shield",
}

BLOCKED_TITLE_RE = re.compile(
    r"安全威胁|请求已被阻断|已被拦截|event\s*id|access\s+denied|"
    r"blocked\s+by|forbidden|web\s+application\s+firewall",
    re.I,
)

EDGE_INFRA_PATTERNS = (
    (
        "volc_dcdn",
        re.compile(
            r"\bvolc[-_. ]?dcdn\b|\bbytecdn\b|\bvedcdnlb\.com\b|\bbdcdn\b",
            re.I,
        ),
    ),
    ("stgw", re.compile(r"\bstgw\b", re.I)),
)


def _host_from_value(value):
    parsed = urlparse(str(value or ""))
    if parsed.hostname:
        return parsed.hostname.strip(".").lower()
    return str(value or "").split("/")[0].split(":")[0].strip(".").lower()


def _base_suffix_labels(host, base_domain):
    labels = [x for x in str(host or "").strip(".").lower().split(".") if x]
    base_labels = [x for x in str(base_domain or "").strip(".").lower().split(".") if x]
    if base_labels and labels[-len(base_labels):] == base_labels:
        return labels[:-len(base_labels)]
    return labels


def _entropy(value):
    if not value:
        return 0.0
    counter = {}
    for ch in value:
        counter[ch] = counter.get(ch, 0) + 1
    total = float(len(value))
    return -sum((count / total) * math.log(count / total, 2) for count in counter.values())


def classify_edge_infrastructure(value):
    text = str(value or "")
    for name, pattern in EDGE_INFRA_PATTERNS:
        if pattern.search(text):
            return name
    return ""


def is_random_long_label(label):
    raw = str(label or "").strip("-").lower()
    compact = re.sub(r"[^a-z0-9]", "", raw)
    if len(compact) < 10:
        return False
    if not re.search(r"[a-z]", compact) or not re.search(r"\d", compact):
        return False
    if any(word in raw for word in MEANINGFUL_LABEL_WORDS):
        return False
    return _entropy(compact) >= 2.7


def classify_edge_host(value, base_domain="", title="", status_code=None, extra_text=""):
    host = _host_from_value(value)
    labels = _base_suffix_labels(host, base_domain)
    text = " ".join([str(title or ""), str(extra_text or "")]).lower()

    reasons = []
    tags = []

    has_ztna = "ztna" in labels
    has_edge_word = any(label in EDGE_LABEL_WORDS for label in labels)
    random_labels = [label for label in labels if is_random_long_label(label)]
    deep_gateway = has_ztna and len(labels) >= 3
    blocked_page = bool(BLOCKED_TITLE_RE.search(text))
    infrastructure = classify_edge_infrastructure(extra_text)

    if has_ztna:
        tags.append(ZTNA_TAG)
        reasons.append("ztna_zone")
    if random_labels:
        tags.append(RANDOM_TAG)
        reasons.append("random_label:{}".format(",".join(random_labels[:3])))
    if deep_gateway:
        reasons.append("deep_ztna_host")
    if has_edge_word and not has_ztna:
        reasons.append("edge_keyword")
    if blocked_page:
        reasons.append("blocked_template")
    if infrastructure:
        tags.append(EDGE_TAG)
        reasons.append("edge_infrastructure:{}".format(infrastructure))

    # Block pages are noisy symptoms. They help explain an edge decision, but
    # they must not be the sole trigger or normal 403 sites get filtered out.
    is_edge = bool(infrastructure)
    if has_ztna and (random_labels or deep_gateway):
        is_edge = True
    elif has_edge_word and random_labels:
        is_edge = True
    elif random_labels and blocked_page:
        is_edge = True

    if is_edge:
        tags.insert(0, EDGE_TAG)
        if infrastructure:
            edge_name = infrastructure
        elif has_ztna:
            edge_name = "ztna_gateway"
        elif has_edge_word:
            edge_name = "edge_gateway"
        else:
            edge_name = "random_gateway"
    else:
        edge_name = ""

    return {
        "is_edge": is_edge,
        "edge_name": edge_name,
        "edge_reasons": reasons,
        "tags": sorted(set(tags)),
        "host": host,
    }


def is_ztna_host(value):
    host = _host_from_value(value)
    return "ztna" in [x for x in host.split(".") if x]


def merge_tags(*values):
    tags = []
    for value in values:
        if not value:
            continue
        if isinstance(value, str):
            value = [value]
        for tag in value:
            tag = str(tag or "").strip()
            if tag and tag not in tags:
                tags.append(tag)
    return tags


def is_edge_tagged(item):
    if not item:
        return False
    tags = item.get("tag") or item.get("tags") or []
    if isinstance(tags, str):
        tags = [tags]
    return bool(item.get("edge") or item.get("edge_name") or EDGE_TAG in tags)
