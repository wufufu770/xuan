"""监控资产变化 diff 引擎（持续监控 v1）。

以 scheduler job 为键，对资产组（scope）做全量快照；每次监控执行结束时
与上次快照对比，变化写入 monitor_diff 集合并经统一告警分发提醒。
首次运行只建快照不告警。

快照维度（方案书 369:6 六信号）：新增子域（domains）、端口（ports）、
指纹（sites）、页面标题（titles）、证书到期（certs，含临期窗口）、
新增 APP（apps，源自凤鸟集团 app 台账）。单列表上限 MAX_ITEMS，
超出标记 truncated——diff 用于发现"新增/消失/变化"，截断不影响告警语义。
旧格式快照缺新维度键时按"基线补齐"处理：本轮只建基线不告警。
"""

import time

from app import utils
from app.config import Config

SNAPSHOT_COLLECTION = "asset_snapshot"
DIFF_COLLECTION = "monitor_diff"

MAX_ITEMS = 20000          # 快照单维度上限
LIST_ALERT_ITEMS = 10      # 告警正文里每类最多列出的条数
DIFF_STORE_ITEMS = 200     # diff 文档里每类最多保存的条数
CERT_MAX_FETCH = 300       # 单轮证书探测上限（TLS 握手成本）
TLS_PORT_HINTS = {443, 444, 4443, 8443, 9443, 9091}

logger = utils.get_logger()


def _capped(values, limit=MAX_ITEMS):
    """去重排序并截断，返回 (列表, 总数, 是否截断)。"""
    unique = sorted({str(v) for v in values if v})
    return unique[:limit], len(unique), len(unique) > limit


def _pair_map(keys):
    """'host|value' 键 -> {host: value}（首处分割）。"""
    mapping = {}
    for key in keys or []:
        host, _, value = str(key).partition("|")
        mapping[host] = value
    return mapping


def _default_cert_end_date(target):
    """默认证书到期采集：utils.get_cert 的 end_date 字段。"""
    ip, _, port = str(target).rpartition(":")
    try:
        cert = utils.get_cert(ip, int(port))
        return (cert or {}).get("end_date")
    except Exception:
        return None


def _tls_candidates(ip_rows):
    """从 asset_ip.port_info 挑 TLS 候选（端口提示或服务名含 https/ssl/tls）。"""
    candidates = []
    for item in ip_rows:
        ip = item.get("ip")
        for port_info in item.get("port_info") or []:
            try:
                port_id = int(port_info.get("port_id"))
            except (TypeError, ValueError):
                continue
            name = str(port_info.get("name") or "").lower()
            if port_id in TLS_PORT_HINTS or any(h in name for h in ("https", "ssl", "tls")):
                candidates.append("{}:{}".format(ip, port_id))
    return sorted(set(candidates))


def cert_expiring_hosts(cert_keys, now=None, warn_days=None):
    """证书键（host|end_date）中已过期或临期的 host 列表（含 '已过期' 标注）。"""
    warn_days = int(getattr(Config, "MONITOR_CERT_WARN_DAYS", 15) if warn_days is None
                    else warn_days)
    now = time.time() if now is None else now
    expiring = []
    for host, end_date in _pair_map(cert_keys).items():
        try:
            end_ts = time.mktime(time.strptime(end_date, "%Y-%m-%d %H:%M:%S"))
        except (ValueError, TypeError):
            continue
        days_left = int((end_ts - now) // 86400)
        if days_left < 0:
            expiring.append("{}|{}|已过期".format(host, end_date))
        elif days_left <= warn_days:
            expiring.append("{}|{}|{}天后到期".format(host, end_date, days_left))
    return sorted(expiring)


def _app_key(row):
    """凤鸟 app 台账行 -> 去重键（appname，缺失则跳过）。"""
    name = str(row.get("appname") or row.get("name") or "").strip()
    return name


def collect_scope_fingerprint(scope_id, cert_fetcher=None):
    """采集资产组当前指纹：domains / ip:port / site|指纹 / site|标题 /
    ip:port|证书到期 / APP 名（凤鸟集团台账）。

    cert_fetcher 为测试注入点，默认 _default_cert_end_date（真实 TLS 握手）。
    """
    conn = utils.conn_db
    domains = utils.get_asset_domain_by_id(scope_id)
    domain_list, domain_total, domain_truncated = _capped(domains)

    ip_rows = list(conn("asset_ip").find({"scope_id": scope_id},
                                         {"ip": 1, "port_info": 1}))
    ports = []
    for item in ip_rows:
        ip = item.get("ip")
        for port_info in item.get("port_info") or []:
            ports.append("{}:{}".format(ip, port_info.get("port_id")))
    port_list, port_total, port_truncated = _capped(ports)

    sites = {}
    titles = {}
    for item in conn("asset_site").find({"scope_id": scope_id},
                                        {"site": 1, "finger": 1, "title": 1}):
        site = str(item.get("site") or "").strip()
        if not site:
            continue
        fingers = sorted({f.get("name", str(f)) if isinstance(f, dict) else str(f)
                          for f in item.get("finger") or []})
        sites[site] = ",".join(fingers)
        title = str(item.get("title") or "").strip()
        if title:
            titles[site] = title
    site_truncated = len(sites) > MAX_ITEMS
    site_fingerprint = {"{}|{}".format(k, v)
                        for k, v in sorted(sites.items())[:MAX_ITEMS]}
    title_keys = {"{}|{}".format(k, v)
                  for k, v in sorted(titles.items())[:MAX_ITEMS]}

    # 证书到期：TLS 候选探测（限量），end_date 落键
    fetch = cert_fetcher or _default_cert_end_date
    certs = set()
    for target in _tls_candidates(ip_rows)[:CERT_MAX_FETCH]:
        end_date = fetch(target)
        if end_date:
            certs.add("{}|{}".format(target, end_date))

    # 新增 APP：凤鸟集团台账（companies[].asset_scope_id 关联本组）中已入组节点的 app
    apps = set()
    for group in conn("fengniao_group").find({"companies.asset_scope_id": scope_id}):
        for node in group.get("companies") or []:
            if str(node.get("asset_scope_id") or "") != str(scope_id):
                continue
            for row in node.get("app") or []:
                key = _app_key(row)
                if key:
                    apps.add(key)

    return {
        "domains": domain_list, "domains_total": domain_total,
        "domains_truncated": domain_truncated,
        "ports": port_list, "ports_total": port_total,
        "ports_truncated": port_truncated,
        "sites": site_fingerprint,
        "sites_truncated": site_truncated,
        "titles": title_keys,
        "certs": certs,
        "apps": apps,
    }


def diff_snapshots(prev, curr):
    """对比两份指纹，返回纯数据 diff（各类含明细截断与总数）。

    新维度（titles/certs/apps）在 prev 缺键时返回空段——旧格式快照首轮
    只补基线不告警。
    """
    def section(prev_keys, curr_keys, store_limit=DIFF_STORE_ITEMS):
        prev_set, curr_set = set(prev_keys), set(curr_keys)
        added = sorted(curr_set - prev_set)
        removed = sorted(prev_set - curr_set)
        return {
            "added": added[:store_limit],
            "removed": removed[:store_limit],
            "added_total": len(added),
            "removed_total": len(removed),
        }

    def empty_section():
        return {"added": [], "removed": [], "added_total": 0, "removed_total": 0}

    result = {
        "domains": section(prev.get("domains") or [], curr.get("domains") or []),
        "ports": section(prev.get("ports") or [], curr.get("ports") or []),
    }

    # 站点按 site 分桶：新增/消失/指纹变化
    def keyed_changed(prev_keys, curr_keys, store_limit=DIFF_STORE_ITEMS):
        prev_map, curr_map = _pair_map(prev_keys), _pair_map(curr_keys)
        added = sorted(set(curr_map) - set(prev_map))
        removed = sorted(set(prev_map) - set(curr_map))
        changed = sorted(
            key for key in set(prev_map) & set(curr_map)
            if prev_map[key] != curr_map[key])
        return {
            "added": added[:store_limit],
            "removed": removed[:store_limit],
            "changed": changed[:store_limit],
            "added_total": len(added),
            "removed_total": len(removed),
            "changed_total": len(changed),
        }

    result["sites"] = keyed_changed(prev.get("sites") or [], curr.get("sites") or [])

    if "titles" in prev:
        result["titles"] = keyed_changed(prev.get("titles") or [],
                                         curr.get("titles") or [])
    else:
        result["titles"] = keyed_changed([], [])

    if "certs" in prev:
        result["certs"] = keyed_changed(prev.get("certs") or [], curr.get("certs") or [])
        prev_expiring = set(prev.get("certs_expiring") or [])
        curr_expiring = set(curr.get("certs_expiring") or [])
        newly = sorted(curr_expiring - prev_expiring)
        result["certs"]["expiring"] = newly[:DIFF_STORE_ITEMS]
        result["certs"]["expiring_total"] = len(newly)
    else:
        result["certs"] = keyed_changed([], [])
        result["certs"]["expiring"] = []
        result["certs"]["expiring_total"] = 0

    if "apps" in prev:
        result["apps"] = section(prev.get("apps") or [], curr.get("apps") or [])
    else:
        result["apps"] = empty_section()
    return result


def has_changes(diff):
    base = any(diff[key]["added_total"] or diff[key]["removed_total"]
               or diff[key].get("changed_total", 0)
               for key in ("domains", "ports", "sites", "titles", "certs"))
    return base or bool(diff.get("apps", {}).get("added_total")) \
        or bool(diff.get("apps", {}).get("removed_total")) \
        or bool(diff.get("certs", {}).get("expiring_total"))


def _format_items(items, total, limit=LIST_ALERT_ITEMS):
    shown = items[:limit]
    text = "、".join(shown) if shown else "无"
    if total > len(shown):
        text += " 等 {} 项".format(total)
    return text


def diff_to_markdown(target, diff):
    domains, ports, sites = diff["domains"], diff["ports"], diff["sites"]
    titles, certs, apps = diff["titles"], diff["certs"], diff["apps"]
    lines = [
        "**新增域名**({}): {}".format(domains["added_total"],
                                      _format_items(domains["added"], domains["added_total"])),
        "**消失域名**({}): {}".format(domains["removed_total"],
                                      _format_items(domains["removed"], domains["removed_total"])),
        "**新增端口**({}): {}".format(ports["added_total"],
                                      _format_items(ports["added"], ports["added_total"])),
        "**消失端口**({})".format(ports["removed_total"]),
        "**新增站点**({}): {}".format(sites["added_total"],
                                      _format_items(sites["added"], sites["added_total"])),
        "**指纹变化站点**({}): {}".format(sites["changed_total"],
                                          _format_items(sites["changed"], sites["changed_total"])),
        "**页面标题变化**({}): {}".format(titles["changed_total"],
                                          _format_items(titles["changed"], titles["changed_total"])),
        "**证书续期/变更**({}): {}".format(certs["changed_total"],
                                           _format_items(certs["changed"], certs["changed_total"])),
        "**证书临期/过期**({}): {}".format(certs.get("expiring_total", 0),
                                           _format_items(certs.get("expiring") or [],
                                                         certs.get("expiring_total", 0))),
        "**新增 APP**({}): {}".format(apps["added_total"],
                                       _format_items(apps["added"], apps["added_total"])),
        "**消失 APP**({}): {}".format(apps["removed_total"],
                                       _format_items(apps["removed"], apps["removed_total"])),
    ]
    return "**监控资产变化** [{}]\n".format(target) + "\n".join(lines)


def save_snapshot(job_id, scope_id, source, task_id, fingerprint, run_number):
    """以 job_id 为键 upsert 快照。"""
    utils.conn_db(SNAPSHOT_COLLECTION).update_one(
        {"job_id": job_id},
        {"$set": {
            "job_id": job_id, "scope_id": scope_id, "source": source,
            "task_id": task_id, "run_number": run_number,
            "updated_ts": time.time(),
            "updated_date": utils.curr_date(),
            "domains": fingerprint["domains"],
            "domains_total": fingerprint["domains_total"],
            "ports": fingerprint["ports"],
            "ports_total": fingerprint["ports_total"],
            "sites": sorted(fingerprint["sites"]),
            "titles": sorted(fingerprint["titles"]),
            "certs": sorted(fingerprint["certs"]),
            "certs_expiring": sorted(fingerprint.get("certs_expiring") or []),
            "apps": sorted(fingerprint["apps"]),
            "truncated": any([fingerprint["domains_truncated"],
                              fingerprint["ports_truncated"],
                              fingerprint["sites_truncated"]]),
        }},
        upsert=True)


def run_scope_diff(job_id, scope_id, source, task_id=None, target="",
                   notify=None, now=None):
    """监控执行结束时调用：对比快照、落 diff、按需告警。永不抛异常。

    返回 diff 文档 id（首次运行为 None）。
    """
    try:
        if not str(getattr(Config, "MONITOR_DIFF_ENABLE", True)).lower() in ("1", "true", "yes"):
            return None

        job_id = str(job_id or "")
        if not job_id or not scope_id:
            return None
        now = time.time() if now is None else now

        snapshot_conn = utils.conn_db(SNAPSHOT_COLLECTION)
        prev = snapshot_conn.find_one({"job_id": job_id})
        fingerprint = collect_scope_fingerprint(scope_id)
        # 证书临期窗口（含已过期）：本轮时点计算，diff 比较"新进入窗口"名单
        fingerprint["certs_expiring"] = cert_expiring_hosts(fingerprint["certs"], now=now)

        if prev is None:
            save_snapshot(job_id, scope_id, source, task_id, fingerprint, 1)
            logger.info("asset_diff 首次建快照 job={} scope={}".format(job_id, scope_id))
            return None

        diff = diff_snapshots(prev, fingerprint)
        run_number = int(prev.get("run_number") or 1) + 1
        save_snapshot(job_id, scope_id, source, task_id, fingerprint, run_number)

        if not has_changes(diff):
            return None

        doc = {
            "job_id": job_id, "scope_id": scope_id, "source": source,
            "task_id": task_id, "target": target,
            "run_date": utils.curr_date(), "run_ts": now,
            "run_number": run_number,
            "diff": diff,
        }
        diff_id = utils.conn_db(DIFF_COLLECTION).insert_one(doc).inserted_id

        from app.utils.notify import send_alert
        (notify or send_alert)(
            "监控资产变化 [{}]".format(target or scope_id),
            diff_to_markdown(target or str(scope_id), diff))
        logger.info(
            "asset_diff job={} changes: domains +{}/-{} ports +{}/-{} sites +{}/~{}/-{} "
            "titles ~{} certs ~{}/!{} apps +{}/-{}".format(
                job_id,
                diff["domains"]["added_total"], diff["domains"]["removed_total"],
                diff["ports"]["added_total"], diff["ports"]["removed_total"],
                diff["sites"]["added_total"], diff["sites"]["changed_total"],
                diff["sites"]["removed_total"],
                diff["titles"]["changed_total"],
                diff["certs"]["changed_total"], diff["certs"].get("expiring_total", 0),
                diff["apps"]["added_total"], diff["apps"]["removed_total"]))
        return str(diff_id)
    except Exception as exc:
        logger.warning("asset_diff failed job={}: {}".format(job_id, exc))
        return None
