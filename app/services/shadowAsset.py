import concurrent.futures
import socket

from app import utils
from app.config import Config

logger = utils.get_logger()

SHADOW_TAG = "shadow"

RESOLVE_TIMEOUT = 2.0
CNAME_CHECK_CONCURRENCY = 30


def shadow_tag_task(task_id):
    """任务后处理影子资产打标：
    1) 标题/域名关键词（已在 autoTag 流程覆盖新入库站点，这里补存量）
    2) wayback 有记录但当前失活
    3) CNAME 悬空（指向已注销域名）
    """
    tagged_site_count = _tag_keyword_sites(task_id)
    wayback_site_count, wayback_domain_count = _tag_wayback_dead(task_id)
    cname_domain_count, cname_site_count = _tag_dangling_cname(task_id)

    summary = {
        "keyword_tagged_site_count": tagged_site_count,
        "wayback_dead_tagged_site_count": wayback_site_count,
        "wayback_dead_tagged_domain_count": wayback_domain_count,
        "dangling_cname_domain_count": cname_domain_count,
        "dangling_cname_site_count": cname_site_count,
    }
    logger.info("shadow tag task:{} {}".format(task_id, summary))
    return summary


def _add_site_tag(task_id, query, tag=SHADOW_TAG):
    return utils.conn_db("site").update_many(
        dict(query, task_id=task_id, tag={"$ne": tag}),
        {"$addToSet": {"tag": tag}},
    ).modified_count


def _add_domain_tag(task_id, domains, tag=SHADOW_TAG):
    if not domains:
        return 0
    return utils.conn_db("domain").update_many(
        {
            "task_id": task_id,
            "domain": {"$in": list(domains)},
            "tag": {"$ne": tag},
        },
        {"$addToSet": {"tag": tag}},
    ).modified_count


def _tag_keyword_sites(task_id):
    """补打存量站点：标题/主机名命中影子关键词。"""
    from app.services.autoTag import AutoTag

    tagged = 0
    cursor = utils.conn_db("site").find(
        {"task_id": task_id, "tag": {"$ne": SHADOW_TAG}},
        {"_id": 1, "title": 1, "hostname": 1},
    )
    shadow_ids = []
    for item in cursor:
        checker = AutoTag({
            "title": item.get("title") or "",
            "hostname": item.get("hostname") or "",
        })
        if checker.is_shadow_asset():
            shadow_ids.append(item["_id"])
    if shadow_ids:
        result = utils.conn_db("site").update_many(
            {"_id": {"$in": shadow_ids}},
            {"$addToSet": {"tag": SHADOW_TAG}},
        )
        tagged = result.modified_count
    return tagged


def _tag_wayback_dead(task_id):
    """wayback 有历史记录、但当前任务没有存活站点的主机 → 影子资产。"""
    from app.services.waybackPaths import wayback_documented_hosts

    documented_hosts = wayback_documented_hosts(task_id)
    if not documented_hosts:
        return 0, 0

    alive_hosts = set()
    for item in utils.conn_db("site").find(
        {"task_id": task_id, "status": 200},
        {"_id": 0, "hostname": 1},
    ):
        hostname = str(item.get("hostname") or "").strip(".").lower()
        if hostname:
            alive_hosts.add(hostname)

    dead_hosts = sorted(documented_hosts - alive_hosts)
    if not dead_hosts:
        return 0, 0

    site_tagged = _add_site_tag(
        task_id, {"hostname": {"$in": dead_hosts}, "status": {"$ne": 200}})
    domain_tagged = _add_domain_tag(task_id, dead_hosts)
    return site_tagged, domain_tagged


def _resolve_hostname(hostname):
    try:
        socket.setdefaulttimeout(RESOLVE_TIMEOUT)
        socket.getaddrinfo(hostname, None)
        return hostname, True
    except (socket.gaierror, OSError):
        return hostname, False


def _tag_dangling_cname(task_id):
    """CNAME 指向的目标已无法解析 → 悬空，影子资产。"""
    dangling_domains = []
    cname_map = {}
    for item in utils.conn_db("domain").find(
        {"task_id": task_id, "type": "CNAME"},
        {"_id": 0, "domain": 1, "record": 1},
    ):
        domain = str(item.get("domain") or "").strip(".").lower()
        records = item.get("record") or []
        target = str(records[0]).strip(".").lower() if records else ""
        if not domain or not target:
            continue
        # 指向云厂商/CDN 的别名不算悬空
        if _looks_like_provider_cname(target):
            continue
        cname_map[domain] = target
        dangling_domains.append(domain)

    if not dangling_domains:
        return 0, 0

    targets = sorted(set(cname_map.values()))
    dead_targets = set()
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=CNAME_CHECK_CONCURRENCY) as executor:
        for hostname, alive in executor.map(_resolve_hostname, targets):
            if not alive:
                dead_targets.add(hostname)

    dangling = [
        domain for domain in dangling_domains
        if cname_map.get(domain) in dead_targets
    ]
    if not dangling:
        return 0, 0

    domain_tagged = _add_domain_tag(task_id, dangling)
    site_tagged = _add_site_tag(task_id, {"hostname": {"$in": dangling}})
    return domain_tagged, site_tagged


PROVIDER_CNAME_KEYWORDS = (
    "cdn", "w.kunlun", "alicdn", "cdnhwc", "cdn.dnsv1", "cloudcdn",
    "amazonaws", "azureedge", "cloudfront", "fastly", "akamai",
    "aliyun", "tencent", "qiniudns", "huaweicdn", "waf", "volces",
    "cdn20", "cdnx", "edgekey", "edgesuite", "footprint", "google",
)


def _looks_like_provider_cname(target):
    return any(keyword in target for keyword in PROVIDER_CNAME_KEYWORDS)
