import os
import re
import socket
import concurrent.futures

from app import utils
from app.config import Config, basedir
from app.modules import CollectSource

logger = utils.get_logger()

BFACE_WORDS_PATH = os.path.join(basedir, 'dicts/bface_words.txt')

CANDIDATE_LIMIT = 3000
RESOLVE_CONCURRENCY = 100
RESOLVE_TIMEOUT = 2.0

BFACE_TAG = "bface"

# 管理面语义关键词：命中才保留普通词组合，避免全词表噪声
WORD_HINT_RE = re.compile(r"[a-z0-9][a-z0-9-]*")


def load_bface_words():
    words = []
    try:
        with open(BFACE_WORDS_PATH) as f:
            for line in f:
                word = line.strip().lower()
                if word and not word.startswith("#"):
                    words.append(word)
    except OSError as e:
        logger.warning("load bface words failed: {}".format(e))
    return sorted(set(words))


def _domain_core(domain):
    fld = utils.get_fld(domain) or domain
    return fld.rsplit(".", 1)[0] if "." in fld else fld


def generate_candidates(base_domain, words=None, extra_seeds=None):
    """管理面前后缀组合候选：word.domain / core-word.domain / word-core.domain"""
    words = words if words is not None else load_bface_words()
    core = _domain_core(base_domain)

    candidates = set()
    for word in words:
        word = WORD_HINT_RE.match(word).group(0) if WORD_HINT_RE.match(word) else ""
        if not word or len(word) < 2:
            continue
        candidates.add("{}.{}".format(word, base_domain))
        if core and core != base_domain:
            candidates.add("{}-{}.{}".format(core, word, base_domain))
            candidates.add("{}-{}.{}".format(word, core, base_domain))

    for seed in extra_seeds or []:
        seed = str(seed or "").strip(".").lower()
        if (seed and utils.is_valid_domain(seed) and
                (seed == base_domain or seed.endswith("." + base_domain))):
            candidates.add(seed)

    candidates.discard(base_domain)
    return sorted(candidates)[:CANDIDATE_LIMIT]


def _resolve_host(host):
    try:
        socket.setdefaulttimeout(RESOLVE_TIMEOUT)
        results = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        ips = sorted({item[4][0] for item in results})
        return host, ips
    except (socket.gaierror, OSError):
        return host, []


def resolve_candidates(candidates, concurrency=None):
    concurrency = concurrency or RESOLVE_CONCURRENCY
    resolved = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        for host, ips in executor.map(_resolve_host, candidates):
            if ips:
                resolved[host] = ips
    return resolved


def extract_wih_seed_domains(task_id, base_domain, words=None):
    """从 WIH 的 JS 残留内容里反哺管理面候选域名。"""
    words = set(words if words is not None else load_bface_words())
    pattern = re.compile(
        r"([a-z0-9][a-z0-9-]{1,40}\." + re.escape(base_domain) + r")",
        re.I)

    seeds = set()
    try:
        cursor = utils.conn_db("wih").find(
            {"task_id": task_id}, {"_id": 0, "content": 1}).limit(2000)
        for item in cursor:
            content = str(item.get("content") or "")
            for match in pattern.findall(content):
                token = match.split(".")[0].lower()
                if any(word in token for word in words if len(word) >= 3):
                    seeds.add(match.lower())
    except Exception as e:
        logger.warning("wih bface seed extract failed: {}".format(e))
    return seeds


def run_bface_discover(task_id, base_domain, domain_task=None, max_site_update=200):
    """B 面发现主流程：候选生成 → DNS 验证 → 域名入库 → 站点探活打标。"""
    from app.services.domainSiteUpdate import domain_site_update

    words = load_bface_words()
    wih_seeds = extract_wih_seed_domains(task_id, base_domain, words=words)
    candidates = generate_candidates(base_domain, words=words,
                                     extra_seeds=wih_seeds)

    resolved = resolve_candidates(candidates)
    resolved_domains = sorted(resolved.keys())

    # 已在任务里的域名不再重复入库
    known_domains = {
        item.get("domain")
        for item in utils.conn_db("domain").find(
            {"task_id": task_id, "domain": {"$in": resolved_domains}},
            {"_id": 0, "domain": 1})
        if item.get("domain")
    }
    new_domains = [d for d in resolved_domains if d not in known_domains]

    saved_count = 0
    if new_domains and domain_task is not None:
        domain_info_list = domain_task.build_domain_info(new_domains)
        resolved_infos = [
            info for info in domain_info_list
            if getattr(info, "domain", "") and getattr(info, "ips", [])
        ]
        if resolved_infos:
            domain_task.save_domain_info_list(
                resolved_infos, source=CollectSource.BFACE)
            domain_task.domain_info_list.extend(resolved_infos)
            saved_count = len(resolved_infos)

    # 站点探活 + 打标（复用域名回流管线，限制数量防止拖垮任务）
    site_update_summary = {}
    probe_domains = resolved_domains[:max_site_update]
    if probe_domains:
        try:
            site_update_summary = domain_site_update(
                task_id, probe_domains, "bface", run_file_leak=False) or {}
        except Exception as e:
            logger.warning("bface domain_site_update failed: {}".format(e))

    tagged_count = _tag_bface_sites(task_id, resolved_domains)

    summary = {
        "candidate_count": len(candidates),
        "wih_seed_count": len(wih_seeds),
        "resolved_count": len(resolved_domains),
        "new_domain_count": len(new_domains),
        "saved_domain_count": saved_count,
        "probed_domain_count": len(probe_domains),
        "tagged_site_count": tagged_count,
        "resolved_domains": resolved_domains[:50],
    }
    logger.info("bface discover {} candidates:{} resolved:{} tagged:{}".format(
        base_domain, len(candidates), len(resolved_domains), tagged_count))
    return summary


def _tag_bface_sites(task_id, domains):
    if not domains:
        return 0
    result = utils.conn_db("site").update_many(
        {
            "task_id": task_id,
            "$or": [
                {"hostname": {"$in": domains}},
                {"site": {"$regex": "//([^/]+\\.)?(" + "|".join(
                    re.escape(d) for d in domains[:500]) + ")(/|:|$)", "$options": "i"}},
            ],
            "tag": {"$ne": BFACE_TAG},
        },
        {"$addToSet": {"tag": BFACE_TAG}},
    )
    return result.modified_count
