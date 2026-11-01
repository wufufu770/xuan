import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from bson import ObjectId

from app import utils
from app.services.hostCollisionExport import normalize_host_collision_item
from app.utils.host_collision import (
    HOST_COLLISION_CONFIRMED_MATCH,
    HOST_COLLISION_EXCLUDE,
)
from app.utils.site_scope import (
    formal_domain_query,
    formal_pipeline_query,
    formal_site_query,
    visible_site_query,
)
from app.utils.site_quality import preferred_site_title


REPORT_TEMPLATE = (
    Path(__file__).resolve().parents[1] / "templates" / "asset_report.html"
)
SENSITIVE_WIH_TYPES = {
    "access_key", "app_key", "credential", "password", "secret",
    "secret_key", "token",
}


def text(value):
    return str(value or "").strip()


def values(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [item for item in value if item not in (None, "")]
    return [value]


def unique_values(value):
    output = []
    seen = set()
    for item in values(value):
        marker = json.dumps(item, ensure_ascii=False, sort_keys=True, default=str)
        if marker in seen:
            continue
        seen.add(marker)
        output.append(item)
    return output


def source_values(item):
    sources = values(item.get("sources"))
    if item.get("source"):
        sources.append(item.get("source"))
    return sorted(set(text(value) for value in sources if text(value)))


def cert_sans(cert):
    raw = text(((cert or {}).get("extensions") or {}).get("subjectAltName"))
    output = []
    for part in raw.split(","):
        part = part.strip()
        if part.upper().startswith("DNS:"):
            part = part[4:].strip()
        if part:
            output.append(part)
    return sorted(set(output))


def _certificate_name(value):
    if isinstance(value, dict):
        return text(
            value.get("common_name") or value.get("organizational") or
            value.get("organization")
        )
    value = text(value)
    match = re.search(r"(?:^|,\s*)CN\s*=\s*([^,]+)", value, re.I)
    return text(match.group(1)) if match else value


def _task_documents(task_ids=None, project_name=""):
    query = {}
    project_name = text(project_name)
    if project_name:
        query["name"] = project_name
    else:
        object_ids = [
            ObjectId(str(task_id))
            for task_id in unique_values(task_ids)
            if ObjectId.is_valid(str(task_id))
        ]
        query["_id"] = {"$in": object_ids}

    projection = {
        "name": 1,
        "target": 1,
        "status": 1,
        "start_time": 1,
        "end_time": 1,
        "create_time": 1,
    }
    return list(utils.conn_db("task").find(query, projection).sort([("_id", 1)]))


def _task_evidence(item, task_meta):
    task_id = text(item.get("task_id"))
    target = text((task_meta.get(task_id) or {}).get("target"))
    return {
        "task_ids": [task_id] if task_id else [],
        "task_targets": [target] if target else [],
    }


def merge_asset(index, key, row, list_fields=()):
    if not key or any(part in (None, "") for part in key):
        return
    key = tuple(key)
    for field in list_fields:
        row[field] = unique_values(row.get(field))
    row["task_ids"] = unique_values(row.get("task_ids"))
    row["task_targets"] = unique_values(row.get("task_targets"))

    current = index.get(key)
    if current is None:
        index[key] = row
        return

    for field in set(list_fields) | {"task_ids", "task_targets"}:
        current[field] = unique_values(
            values(current.get(field)) + values(row.get(field))
        )
    for field, value in row.items():
        if field in list_fields or field in ("task_ids", "task_targets"):
            continue
        if current.get(field) in (None, "", 0, False) and value not in (
                None, "", 0, False):
            current[field] = value


def _risk_count(task_ids):
    pipeline_query = formal_pipeline_query({"task_id": {"$in": task_ids}})
    query = {"$and": [pipeline_query, HOST_COLLISION_EXCLUDE]}
    return utils.conn_db("vuln").count_documents(query)


def _scope_meta(tasks, project_name=""):
    task_ids = [str(item.get("_id")) for item in tasks]
    targets = sorted(set(text(item.get("target")) for item in tasks if item.get("target")))
    names = sorted(set(text(item.get("name")) for item in tasks if item.get("name")))
    statuses = sorted(set(text(item.get("status")) for item in tasks if item.get("status")))
    starts = sorted(text(item.get("start_time") or item.get("create_time")) for item in tasks if item.get("start_time") or item.get("create_time"))
    ends = sorted(text(item.get("end_time")) for item in tasks if item.get("end_time"))

    if project_name:
        title = "{} 项目资产报告".format(project_name)
        project = project_name
        scope_type = "project"
    elif len(tasks) == 1:
        title = "{} 资产报告".format(targets[0] if targets else "任务")
        project = names[0] if names else ""
        scope_type = "task"
    else:
        title = "已选 {} 个任务资产报告".format(len(tasks))
        project = "、".join(names[:3]) + ("…" if len(names) > 3 else "")
        scope_type = "tasks"

    return {
        "report_version": 2,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scope_type": scope_type,
        "title": title,
        "project": project,
        "target": targets[0] if len(targets) == 1 else title,
        "task_id": task_ids[0] if len(task_ids) == 1 else "",
        "task_ids": task_ids,
        "task_count": len(task_ids),
        "targets": targets,
        "target_count": len(targets),
        "scope_detail": "{} 个任务 · {} 个目标".format(len(task_ids), len(targets)),
        "status": statuses[0] if len(statuses) == 1 else "mixed",
        "start_time": starts[0] if starts else "",
        "end_time": ends[-1] if ends else "",
    }


def build_asset_report(task_ids=None, project_name=""):
    tasks = _task_documents(task_ids=task_ids, project_name=project_name)
    if not tasks:
        raise ValueError("No matching tasks")

    meta = _scope_meta(tasks, project_name=project_name)
    selected_ids = meta["task_ids"]
    task_meta = {
        str(item.get("_id")): {
            "name": text(item.get("name")),
            "target": text(item.get("target")),
        }
        for item in tasks
    }
    base_query = {"task_id": {"$in": selected_ids}}

    domain_index = {}
    domain_query = formal_domain_query(base_query)
    for item in utils.conn_db("domain").find(domain_query, {"_id": 0}):
        row = {
            "domain": text(item.get("domain")),
            "type": text(item.get("type")),
            "records": values(item.get("record")),
            "ips": values(item.get("ips")),
            "sources": source_values(item),
            "family": text(item.get("dns_candidate_family")),
            "resolve_status": text(item.get("resolve_status") or item.get("last_resolve_status")),
            "host_candidate": bool(item.get("host_collision_candidate")),
            "host_dns_status": text(item.get("host_collision_dns_status")),
            "host_reason": text(item.get("host_collision_reason")),
            **_task_evidence(item, task_meta),
        }
        merge_asset(
            domain_index,
            (row["domain"], row["type"] or "unknown"),
            row,
            ("records", "ips", "sources"),
        )
    domains = sorted(domain_index.values(), key=lambda row: (row["domain"], row["type"]))

    ip_index = {}
    for item in utils.conn_db("ip").find(base_query, {"_id": 0}):
        ports = []
        services = []
        for port in values(item.get("port_info")):
            if not isinstance(port, dict):
                continue
            port_id = int(port.get("port_id") or 0)
            if port_id:
                ports.append(port_id)
            service = text(port.get("service_name"))
            if service:
                services.append(service)
        geo = item.get("geo_city") or {}
        asn = item.get("geo_asn") or {}
        row = {
            "ip": text(item.get("ip")),
            "type": text(item.get("ip_type")),
            "domains": values(item.get("domain")),
            "ports": sorted(set(ports)),
            "services": sorted(set(services)),
            "cdn": text(item.get("cdn_name")),
            "country": text(geo.get("country_name")) or "unknown",
            "city": text(geo.get("city")),
            "asn": text(asn.get("number")),
            "organization": text(asn.get("organization")),
            **_task_evidence(item, task_meta),
        }
        merge_asset(ip_index, (row["ip"],), row, ("domains", "ports", "services"))
    ips = sorted(ip_index.values(), key=lambda row: row["ip"])

    site_index = {}
    site_query = visible_site_query(base_query)
    for item in utils.conn_db("site").find(site_query, {"_id": 0}):
        tech = values(item.get("tech"))
        if not tech:
            tech = [
                finger.get("name") for finger in values(item.get("finger"))
                if isinstance(finger, dict) and finger.get("name")
            ]
        browser_title = text(item.get("browser_title"))
        browser_final_title = text(item.get("browser_final_title"))
        browser_spa = bool(item.get("browser_spa_detected"))
        browser_sso = bool(item.get("browser_cross_origin_redirect"))
        spa_score = int(item.get("spa_score") or 0)
        spa_confidence = text(item.get("spa_confidence"))
        spa_framework = text(item.get("spa_framework"))
        runtime_mode = (
            "SSO" if browser_sso else
            "SPA" if browser_spa or spa_score >= 55 else
            "浏览器标题" if browser_title else ""
        )
        row = {
            "site": text(item.get("site") or item.get("canonical_site")),
            "status": int(item.get("status") or item.get("best_status") or 0),
            "title": preferred_site_title(item),
            "http_title": text(item.get("title")),
            "browser_title": browser_title,
            "browser_title_source": text(item.get("browser_title_source")),
            "browser_final_title": browser_final_title,
            "browser_final_url": text(item.get("browser_final_url")),
            "runtime": runtime_mode,
            "spa_signals": values(item.get("spa_signals")),
            "spa_score": spa_score,
            "spa_confidence": spa_confidence,
            "spa_framework": spa_framework,
            "spa_render_mode": text(item.get("spa_render_mode")),
            "spa_route_mode": text(item.get("spa_route_mode")),
            "spa_reasons": values((item.get("spa_profile") or {}).get("reasons")),
            "ip": text(item.get("ip")),
            "tech": sorted(set(text(value) for value in tech if text(value))),
            "sources": source_values(item),
            "score": int(item.get("asset_score") or 0),
            "level": text(item.get("asset_level")),
            "policy": text(item.get("scan_policy")) or "unknown",
            "profile": text(item.get("scan_profile")),
            "waf": text(item.get("waf_strength") or item.get("waf_reason")),
            "content_type": text(item.get("content_type")),
            "body_length": int(item.get("body_length") or 0),
            "quality_state": text(item.get("quality_state")),
            "quality_reason": text(item.get("quality_reason")),
            **_task_evidence(item, task_meta),
        }
        merge_asset(site_index, (row["site"],), row, ("tech", "sources"))
    sites = sorted(site_index.values(), key=lambda row: row["site"])

    cert_index = {}
    cert_query = formal_pipeline_query(base_query)
    for item in utils.conn_db("cert").find(cert_query, {"_id": 0}):
        cert = item.get("cert") or {}
        subject = cert.get("subject") or cert.get("subject_dn") or {}
        issuer = cert.get("issuer") or cert.get("issuer_dn") or {}
        validity = cert.get("validity") or {}
        sans = cert_sans(cert)
        row = {
            "ip": text(item.get("ip")),
            "port": int(item.get("port") or 0),
            "common_name": _certificate_name(subject),
            "organization": text(subject.get("organizational")) if isinstance(subject, dict) else "",
            "issuer": _certificate_name(issuer),
            "valid_from": text(validity.get("start")),
            "valid_to": text(validity.get("end")),
            "expired": bool(validity.get("expired")),
            "sans": sans,
            "san_count": len(sans),
            "relation": text(item.get("relation_reason") or item.get("relation_level")),
            "phase": text(item.get("cert_phase")),
            **_task_evidence(item, task_meta),
        }
        merge_asset(
            cert_index,
            (row["ip"], row["port"], row["common_name"] or "unknown"),
            row,
            ("sans",),
        )
    certs = sorted(cert_index.values(), key=lambda row: (row["ip"], row["port"], row["common_name"]))

    path_index = {}
    path_query = formal_pipeline_query(base_query)
    for item in utils.conn_db("fileleak").find(path_query, {"_id": 0}):
        entry_type = text(item.get("entry_type")) or "unknown"
        row = {
            "url": text(item.get("url")),
            "site": text(item.get("site")),
            "path": text(item.get("path")),
            "status": int(item.get("status_code") or 0),
            "type": entry_type,
            "title": text(item.get("title") or item.get("final_title")),
            "length": int(item.get("content_length") or 0),
            "redirect": text(item.get("redirect_url") or item.get("final_url")),
            "redirect_system": text(item.get("redirect_system")),
            "verified": text(item.get("verification_status")),
            "reason": text(item.get("verification_reason")),
            "depth": int(item.get("scan_depth") or 0),
            **_task_evidence(item, task_meta),
        }
        merge_asset(path_index, (row["url"], row["type"]), row)
    paths = sorted(path_index.values(), key=lambda row: (row["url"], row["type"]))

    url_index = {}
    url_query = formal_pipeline_query(base_query)
    for item in utils.conn_db("url").find(url_query, {"_id": 0}):
        row = {
            "url": text(item.get("url")),
            "final_url": text(item.get("final_url")),
            "status": int(item.get("status_code") or 0),
            "title": text(item.get("title")),
            "type": text(item.get("url_type")),
            "source": text(item.get("source") or item.get("discovery_source")),
            "collector": text(item.get("collector") or item.get("crawler_engine")),
            "from": text(item.get("discovered_from")),
            **_task_evidence(item, task_meta),
        }
        merge_asset(url_index, (row["url"],), row)
    urls = sorted(url_index.values(), key=lambda row: row["url"])

    intelligence_index = {}
    wih_query = formal_pipeline_query(base_query)
    for item in utils.conn_db("wih").find(wih_query, {"_id": 0}):
        record_type = text(item.get("record_type")) or "unknown"
        row = {
            "content": text(item.get("content")),
            "type": record_type,
            "site": text(item.get("site")),
            "url_site": text(item.get("url_site")),
            "source": text(item.get("source")),
            "collector": text(item.get("collector")),
            "evidence": text(item.get("evidence_type")),
            "from": text(item.get("discovered_from")),
            **_task_evidence(item, task_meta),
        }
        merge_asset(intelligence_index, (row["content"], row["type"]), row)
    intelligence = sorted(
        intelligence_index.values(), key=lambda row: (row["type"], row["content"]))

    entry_index = {}
    entry_query = formal_pipeline_query(base_query)
    for item in utils.conn_db("entry_asset").find(entry_query, {"_id": 0}):
        status = text(item.get("status")) or "unknown"
        row = {
            "seed": text(item.get("seed")),
            "type": text(item.get("seed_type")),
            "domain": text(item.get("domain")),
            "status": status,
            "source": text(item.get("source")),
            "collectors": values(item.get("collectors")),
            "is_new": bool(item.get("is_new")),
            "is_duplicate": bool(item.get("is_duplicate")),
            "reprobe": bool(item.get("reprobe_existing")),
            "reprobe_reason": text(item.get("reprobe_reason")),
            **_task_evidence(item, task_meta),
        }
        merge_asset(entry_index, (row["seed"], row["type"] or "unknown"), row, ("collectors",))
    entries = sorted(entry_index.values(), key=lambda row: (row["seed"], row["type"]))

    host_index = {}
    host_query = {
        "task_id": {"$in": selected_ids},
        **HOST_COLLISION_CONFIRMED_MATCH,
    }
    for item in utils.conn_db("vuln").find(host_query, {"_id": 0}):
        normalized = normalize_host_collision_item(item, task_meta=task_meta)
        if not normalized:
            continue
        verify = item.get("verify_obj") or {}
        parsed = urlparse(normalized.get("target") or "")
        try:
            parsed_port = parsed.port
        except ValueError:
            parsed_port = None
        scheme = text(parsed.scheme or verify.get("scheme"))
        port = int(
            verify.get("port") or parsed_port or
            (443 if scheme == "https" else 80 if scheme == "http" else 0)
        )
        row = {
            "ip": normalized["ip"],
            "port": port,
            "scheme": scheme,
            "domain": normalized["host"],
            "url": normalized.get("target", ""),
            "status": int(normalized.get("status_code") or 0),
            "title": normalized.get("title", ""),
            "length": int(normalized.get("body_length") or 0),
            "confidence": normalized.get("confidence", "") or "unknown",
            "path": text(verify.get("path")),
            "redirect": text(verify.get("redirect_location")),
            "reason": text(verify.get("host_collision_reason")),
            "historical": bool(verify.get("historical_ip_match")),
            "endpoint_sources": values(verify.get("endpoint_sources")),
            "task_ids": normalized.get("task_ids") or [],
            "task_targets": normalized.get("task_targets") or [],
        }
        merge_asset(
            host_index,
            (row["ip"], row["port"], row["scheme"], row["domain"]),
            row,
            ("endpoint_sources",),
        )
    host_collisions = sorted(
        host_index.values(),
        key=lambda row: (
            row["ip"], row["port"], row["scheme"], row["domain"]
        ),
    )

    cidr_index = {}
    for item in utils.conn_db("cip").find(base_query, {"_id": 0}):
        row = {
            "cidr": text(item.get("cidr_ip")),
            "domain_count": int(item.get("domain_count") or 0),
            "ip_count": int(item.get("ip_count") or 0),
            "domains": values(item.get("domain_list")),
            "ips": values(item.get("ip_list")),
            **_task_evidence(item, task_meta),
        }
        merge_asset(cidr_index, (row["cidr"],), row, ("domains", "ips"))
    cidrs = sorted(cidr_index.values(), key=lambda row: row["cidr"])
    for row in cidrs:
        row["domain_count"] = len(row.get("domains") or [])
        row["ip_count"] = len(row.get("ips") or [])

    site_status_counter = Counter(str(row["status"] or "unknown") for row in sites)
    policy_counter = Counter(row["policy"] or "unknown" for row in sites)
    country_counter = Counter(row["country"] or "unknown" for row in ips)
    port_counter = Counter(str(port) for row in ips for port in row.get("ports") or [])
    path_type_counter = Counter(row["type"] or "unknown" for row in paths)
    wih_type_counter = Counter(row["type"] or "unknown" for row in intelligence)
    entry_status_counter = Counter(row["status"] or "unknown" for row in entries)
    host_status_counter = Counter(str(row["status"] or "unknown") for row in host_collisions)
    host_confidence_counter = Counter(row["confidence"] or "unknown" for row in host_collisions)
    finger_counter = Counter()
    for item in utils.conn_db("stat_finger").find(base_query, {"_id": 0}):
        name = text(item.get("name"))
        if name:
            finger_counter[name] += int(item.get("cnt") or 0)
    if not finger_counter:
        finger_counter.update(
            name for row in sites for name in row.get("tech") or [] if name
        )
    fingerprints = [
        {"name": name, "count": count}
        for name, count in finger_counter.most_common()
    ]
    sensitive = sum(
        1 for row in intelligence if row.get("type") in SENSITIVE_WIH_TYPES
    )

    datasets = {
        "domains": domains,
        "ips": ips,
        "sites": sites,
        "certs": certs,
        "entries": entries,
        "paths": paths,
        "urls": urls,
        "intelligence": intelligence,
        "host_collisions": host_collisions,
        "cidrs": cidrs,
        "fingerprints": fingerprints,
    }
    summary = {key: len(value) for key, value in datasets.items()}
    summary.update({
        "sensitive": sensitive,
        "risks": _risk_count(selected_ids),
        "browser_titles": sum(bool(row.get("browser_title")) for row in sites),
        "runtime_spa": sum(row.get("runtime") == "SPA" for row in sites),
        "runtime_sso": sum(row.get("runtime") == "SSO" for row in sites),
    })
    return {
        "meta": meta,
        "summary": summary,
        "distributions": {
            "site_status": dict(site_status_counter),
            "scan_policy": dict(policy_counter),
            "countries": dict(country_counter.most_common()),
            "ports": dict(port_counter.most_common()),
            "path_types": dict(path_type_counter),
            "wih_types": dict(wih_type_counter),
            "entry_status": dict(entry_status_counter),
            "host_status": dict(host_status_counter),
            "host_confidence": dict(host_confidence_counter),
        },
        "datasets": datasets,
    }


def render_asset_report(report):
    template = REPORT_TEMPLATE.read_text(encoding="utf-8")
    placeholder = "__REPORT_DATA__"
    if template.count(placeholder) != 1:
        raise RuntimeError("Invalid asset report template")
    payload = json.dumps(report, ensure_ascii=False, separators=(",", ":"), default=str)
    payload = (
        payload.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )
    return template.replace(placeholder, payload)


def safe_filename(value, fallback="asset-report"):
    value = re.sub(r"[\\/:*?\"<>|\s]+", "-", text(value)).strip("-.")
    return (value[:80] or fallback) + ".html"
