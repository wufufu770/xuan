import ipaddress
import re
from urllib.parse import urlparse

from bson import ObjectId
from pymongo import UpdateOne
from app import utils
from app.config import Config
from app.utils import signing
from app.services.edgeAsset import (
    classify_edge_host,
    classify_edge_infrastructure,
    is_edge_tagged,
    merge_tags,
)
from app.services.assetPolicy import directory_scan_decision, has_strong_edge_marker
from app.utils.site_quality import (
    classify_site_quality,
    preferred_site_title,
    site_has_confirmed_route,
)
from app.utils.site_scope import (
    formal_domain_query,
    formal_pipeline_query,
    is_formal_site,
    is_host_collision_site,
)


CERT_DOMAIN_RE = re.compile(
    r"(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
    re.IGNORECASE,
)

SITE_ARRAY_FIELDS = (
    "finger", "tag", "tech", "edge_reasons", "asset_reasons",
    "site_aliases", "resolved_ips", "scan_policy_evidence", "quality_evidence",
)

SITE_SPARSE_FIELDS = {
    "title", "headers", "http_server", "favicon", "cname", "ip",
    "hostname", "cdn_name", "waf_name", "edge_name", "body_length",
    "body_hash", "header_hash", "content_type", "location",
}


def _status_code(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _is_success_status(value):
    status = _status_code(value)
    return status is not None and 200 <= status < 400


def _edge_observation_text(item):
    cname = item.get("cname") or ""
    if isinstance(cname, list):
        cname = " ".join([str(value) for value in cname])
    return " ".join([
        str(item.get("webserver") or ""),
        str(item.get("http_server") or ""),
        str(cname),
        str(item.get("cdn_name") or ""),
        str(item.get("waf_name") or ""),
        str(item.get("edge_name") or ""),
    ])


def _is_edge_block_observation(item):
    status = _status_code(item.get("status"))
    if status is None or status < 400:
        return False
    if (
        item.get("cdn") or item.get("cdn_name") or item.get("waf") or
        item.get("waf_name") or item.get("edge") or item.get("edge_name") or
        is_edge_tagged(item)
    ):
        return True
    return bool(classify_edge_infrastructure(_edge_observation_text(item)))


def _load_existing_site_documents(task_id, sites):
    sites = sorted(set(str(site or "").strip() for site in sites if str(site or "").strip()))
    if not sites:
        return {}

    result = {}
    collection = utils.conn_db("site")
    fields = {
        "_id": 0,
        "site": 1,
        "canonical_site": 1,
        "status": 1,
        "title": 1,
        "body_length": 1,
        "content_length": 1,
        "headers": 1,
        "http_server": 1,
        "body_hash": 1,
        "header_hash": 1,
        "content_type": 1,
        "location": 1,
        "resolved_ips": 1,
        "favicon": 1,
        "source": 1,
        "sources": 1,
        "tag": 1,
        "asset_reasons": 1,
        "pipeline_eligible": 1,
        "candidate_disposition": 1,
        "host_collision_domain": 1,
        "quality_state": 1,
        "display_eligible": 1,
        "pipeline_mode": 1,
        "quality_reason": 1,
        "quality_evidence": 1,
        "quality_version": 1,
        "route_discovery_status": 1,
        "route_hit_count": 1,
        "route_confirmed_urls": 1,
        "asset_score": 1,
        "asset_level": 1,
        "browser_title": 1,
        "browser_title_source": 1,
        "browser_title_chain": 1,
        "browser_final_title": 1,
        "browser_final_url": 1,
        "browser_spa_detected": 1,
        "browser_cross_origin_redirect": 1,
        "runtime_script_count": 1,
        "runtime_request_count": 1,
        "spa_signals": 1,
        "spa_profile": 1,
        "spa_score": 1,
        "spa_confidence": 1,
        "spa_framework": 1,
        "spa_render_mode": 1,
        "spa_route_mode": 1,
        "spa_fingerprint_updated_at": 1,
        "browser_enriched_at": 1,
    }
    for query_field in ("canonical_site", "site"):
        for start in range(0, len(sites), 500):
            batch = sites[start:start + 500]
            for item in collection.find(
                    {"task_id": task_id, query_field: {"$in": batch}}, fields):
                canonical_site = (
                    item.get("canonical_site") or
                    utils.canonical_site_url(item.get("site"))
                )
                if canonical_site:
                    result[canonical_site] = item
    return result


def normalize_source(source):
    source = str(source or "").strip()
    return source or ""


def collect_sources(*values):
    sources = []
    for value in values:
        if value is None:
            continue
        if isinstance(value, (list, tuple, set)):
            for sub_value in value:
                source = normalize_source(sub_value)
                if source and source not in sources:
                    sources.append(source)
            continue
        source = normalize_source(value)
        if source and source not in sources:
            sources.append(source)
    return sources


def upsert_with_sources(collection, query, data, source=None):
    payload = dict(data or {})
    source_value = normalize_source(source or payload.get("source"))
    payload.pop("source", None)

    update = {"$set": payload}
    if source_value:
        update["$setOnInsert"] = {"source": source_value}
        update["$addToSet"] = {"sources": source_value}

    return utils.conn_db(collection).update_one(query, update, upsert=True)


def build_url_document(url, task_id, source, url_type=None, extra_fields=None):
    item = {
        "site": url,
        "url": url,
        "task_id": task_id,
        "source": source,
    }
    domain_parsed = utils.domain_parsed(url)
    if domain_parsed:
        item["fld"] = domain_parsed["fld"]

    if url_type:
        item["url_type"] = url_type

    if extra_fields:
        item.update(extra_fields)

    return item


def _site_host(site):
    parsed = urlparse(str(site or ""))
    return (parsed.hostname or "").strip(".").lower()


def _is_ip_host(host):
    parts = str(host or "").split(".")
    return len(parts) == 4 and all(x.isdigit() and 0 <= int(x) <= 255 for x in parts)


def _has_verified_ip_web_evidence(task_id, site, ip):
    # Only save IP-host sites when httpx has already confirmed this exact URL.
    if not task_id or not site or not ip:
        return False

    site = str(site or '').strip().rstrip('/')
    urls = [site, site + '/']
    query = {
        'task_id': task_id,
        'url': {chr(36) + 'in': urls},
        chr(36) + 'or': [{'ip': ip}, {'host': ip}],
    }
    evidence = utils.conn_db('asset_seed_alive').find_one(
        query,
        {'_id': 0, 'status_code': 1, 'source': 1, 'url': 1}
    )
    if not evidence:
        return False

    trusted_sources = {
        'find_site',
        'ip_find_site',
        'known_service_seed',
        'ip',
        'asset_seed_probe',
    }
    source = normalize_source(evidence.get('source'))
    if source in trusted_sources:
        return True

    return evidence.get('status_code') is not None


def _task_target(task_id):
    try:
        object_id = ObjectId(task_id)
    except Exception:
        return ""
    item = utils.conn_db("task").find_one({"_id": object_id}, {"target": 1})
    return str((item or {}).get("target") or "").strip(".").lower()


def _task_target_contains_ip(task_id, ip):
    try:
        address = ipaddress.ip_address(str(ip or "").strip())
    except ValueError:
        return False

    target = _task_target(task_id)
    for raw_token in re.split(r"[\s,;]+", target):
        token = str(raw_token or "").strip().strip("[]()")
        if not token:
            continue

        if "://" in token:
            token = urlparse(token).hostname or ""
        elif "/" not in token and ":" in token:
            token = urlparse("http://" + token).hostname or token

        try:
            if "/" in token:
                if address in ipaddress.ip_network(token, strict=False):
                    return True
            elif address == ipaddress.ip_address(token):
                return True
        except ValueError:
            continue

    return False


def _host_in_scope(host, base_domain):
    host = str(host or "").strip(".").lower()
    base_domain = str(base_domain or "").strip(".").lower()
    if not host or not base_domain:
        return True
    return host == base_domain or host.endswith("." + base_domain)


def _ip_has_current_dns_relation(task_id, ip):
    if not ip:
        return False
    return bool(utils.conn_db("domain").find_one(
        formal_domain_query({"task_id": task_id, "ips": ip}),
        {"_id": 1}
    ))


def extract_cert_domains(cert, base_domain="", include_wildcard=False):
    base_domain = str(base_domain or "").strip(".").lower()
    if not cert:
        return []

    values = [
        cert.get("subject_dn", ""),
        ((cert.get("subject") or {}).get("common_name") or ""),
        ((cert.get("extensions") or {}).get("subjectAltName") or ""),
    ]
    text = " ".join([str(x or "").lower() for x in values])
    domains = set()
    for match in CERT_DOMAIN_RE.findall(text):
        name = str(match or "").strip(".").lower()
        is_wildcard = name.startswith("*.")
        scope_name = name[2:] if is_wildcard else name
        if not scope_name or not utils.is_valid_domain(scope_name):
            continue
        if utils.check_domain_black(scope_name):
            continue
        if base_domain and not (
            scope_name == base_domain or scope_name.endswith("." + base_domain)
        ):
            continue
        if is_wildcard and not include_wildcard:
            continue
        domains.add(name)
    return sorted(domains)


def cert_matches_domain(cert, base_domain):
    base_domain = str(base_domain or "").strip(".").lower()
    if not cert or not base_domain:
        return True

    return bool(extract_cert_domains(
        cert, base_domain=base_domain, include_wildcard=True))


def _has_active_cert_relation(task_id, ip):
    if not ip:
        return False
    items = utils.conn_db("cert").find(
        {"task_id": task_id, "ip": ip, "relation_level": "strong"},
        {"_id": 1, "source": 1, "pipeline_eligible": 1}
    )
    for item in items:
        if item.get("source") != "cert_query_active_verify":
            return True
        if item.get("pipeline_eligible") is True:
            return True
    return False


def _load_asset_seed_evidence(task_id, site):
    host = _site_host(site)
    query = {
        "task_id": task_id,
        "$or": [{"url": site}]
    }
    if host:
        query["$or"].extend([{"host": host}, {"ip": host}])

    return utils.conn_db("asset_seed_alive").find_one(
        formal_pipeline_query(query),
        {
            "_id": 0,
            "source": 1,
            "cdn": 1,
            "cdn_name": 1,
            "waf": 1,
            "waf_name": 1,
            "waf_strength": 1,
            "waf_reason": 1,
            "edge": 1,
            "edge_name": 1,
            "edge_reasons": 1,
            "tag": 1,
            "ip": 1,
            "title": 1,
            "status_code": 1,
            "tech": 1,
            "webserver": 1,
            "cname": 1,
        }
    ) or {}


def _load_domain_evidence(task_id, host):
    if not host or not utils.domain_parsed(host):
        return {}

    return utils.conn_db("domain").find_one(
        formal_domain_query({"task_id": task_id, "domain": host}),
        {"_id": 0, "source": 1, "sources": 1, "ips": 1}
    ) or {}


def _has_cert_evidence(task_id, host):
    if not host or not utils.domain_parsed(host):
        return False

    host_pattern = re.escape(host)
    cert = utils.conn_db("cert").find_one({
        "task_id": task_id,
        "$or": [
            {"cert.extensions.subjectAltName": {"$regex": host_pattern}},
            {"cert.subject.common_name": host},
            {"cert.subject_dn": {"$regex": host_pattern}},
        ]
    }, {"_id": 1})
    return bool(cert)


def _score_level(score):
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _build_asset_score(task_id, item, evidence):
    score = 0
    reasons = []
    site = item.get("site", "")
    host = _site_host(site)
    domain_evidence = _load_domain_evidence(task_id, host)

    if host and utils.domain_parsed(host):
        score += 30
        reasons.append("domain_site")
    elif host:
        score += 10
        reasons.append("ip_site")

    if evidence.get("source"):
        score += 15
        reasons.append("asset_seed:{}".format(evidence.get("source")))

    sources = domain_evidence.get("sources") or []
    if not sources and domain_evidence.get("source"):
        sources = [domain_evidence.get("source")]
    passive_sources = {
        "fofa", "fofa_cert", "hunter", "hunter_cert", "hunter_qax",
        "quake", "quake_cert", "quake_360", "virustotal", "chaos",
        "subfinder", "crtsh",
    }
    matched_sources = sorted([x for x in sources if x in passive_sources])
    if matched_sources:
        score += 15
        reasons.append("passive:{}".format(",".join(matched_sources[:3])))

    if _has_cert_evidence(task_id, host):
        score += 25
        reasons.append("cert_san")

    if item.get("finger"):
        score += 10
        reasons.append("fingerprint")

    if item.get("title"):
        score += 5
        reasons.append("title")

    tags = item.get("tag") or []
    if isinstance(tags, str):
        tags = [tags]
    if "Host碰撞" in tags:
        if item.get("host_collision_verified"):
            score += 60
            reasons.append("host_collision_verified")
        else:
            score += 30
            reasons.append("host_collision_pending_review")

    if has_strong_edge_marker(item) or has_strong_edge_marker(evidence):
        score -= 20
        reasons.append("edge_or_waf")

    quality_state = str(item.get("quality_state") or "").strip().lower()
    if quality_state in ("soft_404", "placeholder"):
        score -= 60
        reasons.append(quality_state)
    elif quality_state == "redirect_alias":
        score -= 40
        reasons.append("redirect_alias")
    elif quality_state == "route_confirmed":
        score += 20
        reasons.append("route_confirmed")

    score = max(0, min(score, 100))
    return {
        "asset_score": score,
        "asset_level": _score_level(score),
        "asset_reasons": reasons,
    }


def enrich_site_document(task_id, item):
    evidence = _load_asset_seed_evidence(task_id, item.get("site", ""))
    host = _site_host(item.get("site", ""))
    domain_evidence = _load_domain_evidence(task_id, host)
    if evidence:
        if evidence.get("title") and not item.get("title"):
            item["title"] = evidence.get("title")
        if evidence.get("status_code") is not None and item.get("status") is None:
            item["status"] = evidence.get("status_code")
        if evidence.get("webserver") and not item.get("webserver"):
            item["webserver"] = evidence.get("webserver")
        if evidence.get("tech") and not item.get("finger"):
            item["finger"] = [{"name": x} for x in evidence.get("tech") or [] if x]
        for key in (
            "cdn", "cdn_name", "waf", "waf_name", "waf_strength",
            "waf_reason", "edge", "edge_name", "edge_reasons", "cname",
        ):
            if evidence.get(key) not in (None, ""):
                item[key] = evidence.get(key)
        if evidence.get("tag"):
            item["tag"] = merge_tags(item.get("tag"), evidence.get("tag"))
        if evidence.get("ip") and not item.get("ip"):
            item["ip"] = evidence.get("ip")
        item["asset_seed_source"] = evidence.get("source", "")

    sources = collect_sources(
        item.get("sources"),
        item.get("source"),
        evidence.get("source"),
        domain_evidence.get("source"),
        domain_evidence.get("sources"),
    )
    if sources:
        item["sources"] = sources
        if not item.get("source"):
            item["source"] = sources[0]

    edge_info = classify_edge_host(
        item.get("site", ""),
        _task_target(task_id),
        title=item.get("title", ""),
        status_code=item.get("status"),
        extra_text=" ".join([
            str(item.get("webserver") or ""),
            str(item.get("cdn_name") or ""),
            str(item.get("waf_name") or ""),
        ]),
    )
    if edge_info.get("is_edge"):
        item["edge"] = True
        item["edge_name"] = item.get("edge_name") or edge_info.get("edge_name", "")
        item["edge_reasons"] = merge_tags(item.get("edge_reasons"), edge_info.get("edge_reasons"))
        item["tag"] = merge_tags(item.get("tag"), edge_info.get("tags"))
        item["waf"] = True
        item["waf_name"] = item.get("waf_name") or item.get("edge_name", "")

    item.update(classify_site_quality(item))

    scan_decision = directory_scan_decision(item)
    item["scan_policy"] = scan_decision["scan_policy"]
    item["scan_profile"] = scan_decision["profile"] or "inventory_only"
    item["scan_policy_reason"] = scan_decision["reason"]
    item["scan_policy_evidence"] = scan_decision["evidence"]
    if scan_decision["scan_policy"] == "inventory_only":
        item["scan_skip_reason"] = scan_decision["reason"]
    else:
        item.pop("scan_skip_reason", None)

    item.update(_build_asset_score(task_id, item, evidence))
    return item


def should_save_main_site_document(task_id, item):
    site = item.get("site", "")
    host = _site_host(site)
    if not host:
        return False

    if is_host_collision_site(item):
        return False

    edge_or_waf = has_strong_edge_marker(item)
    base_domain = _task_target(task_id)
    if _is_ip_host(host):
        if edge_or_waf and not Config.ASSET_SEED_SAVE_EDGE_SITE:
            return False
        if not Config.SITE_SAVE_IP_HOSTS:
            return False
        if not _has_verified_ip_web_evidence(task_id, site, host):
            return False
        if _task_target_contains_ip(task_id, host):
            return True
        if Config.ASSET_SEED_SAVE_WEAK_IP_SITE:
            return True
        return _ip_has_current_dns_relation(task_id, host) or _has_active_cert_relation(task_id, host)

    return _host_in_scope(host, base_domain)


def prepare_site_documents(task_id, site_info_list, enforce_scope=True):
    docs = []
    for site_info in site_info_list or []:
        item = dict(site_info or {})
        raw_site = str(item.get("site") or "").strip()
        curr_site = utils.canonical_site_url(raw_site)
        if not curr_site:
            continue

        item["site"] = curr_site
        item["canonical_site"] = curr_site
        if raw_site != curr_site:
            item["site_aliases"] = collect_sources(
                item.get("site_aliases"), raw_site)

        item["task_id"] = task_id
        item["screenshot"] = signing.sign_image_url(
            task_id, "{}.jpg".format(utils.gen_filename(curr_site)))
        enrich_site_document(task_id, item)
        if enforce_scope and not should_save_main_site_document(task_id, item):
            continue
        docs.append(item)
    return docs


def _bulk_write(collection, operations):
    if not operations:
        return 0

    result = utils.conn_db(collection).bulk_write(operations, ordered=False)
    return result.upserted_count + result.modified_count + result.matched_count


def _merge_prepared_site_items(existing, incoming):
    existing = dict(existing or {})
    incoming = dict(incoming or {})
    existing_success = _is_success_status(existing.get("status"))
    incoming_success = _is_success_status(incoming.get("status"))
    if existing_success and not incoming_success:
        primary, secondary = existing, incoming
    else:
        primary, secondary = incoming, existing

    merged = dict(primary)
    for field, value in secondary.items():
        if field in SITE_ARRAY_FIELDS or field == "sources":
            continue
        if merged.get(field) in (None, "", [], {}, 0) and value not in (None, "", [], {}, 0):
            merged[field] = value

    for field in SITE_ARRAY_FIELDS:
        values = []
        for item in (existing, incoming):
            raw_values = item.get(field) or []
            if not isinstance(raw_values, (list, tuple, set)):
                raw_values = [raw_values]
            for value in raw_values:
                if value not in (None, "", [], {}) and value not in values:
                    values.append(value)
        if values:
            merged[field] = values

    sources = collect_sources(
        existing.get("sources"), existing.get("source"),
        incoming.get("sources"), incoming.get("source"),
    )
    if sources:
        merged["sources"] = sources
        if not merged.get("source"):
            merged["source"] = sources[0]
    return merged


def save_site_documents(task_id, site_info_list, enforce_scope=True):
    docs = {}
    for prepared_item in prepare_site_documents(
            task_id, site_info_list, enforce_scope=enforce_scope):
        item = dict(prepared_item or {})
        canonical_site = (
            item.get("canonical_site") or
            utils.canonical_site_url(item.get("site"))
        )
        if not canonical_site:
            continue
        item["site"] = canonical_site
        item["canonical_site"] = canonical_site
        docs[canonical_site] = _merge_prepared_site_items(
            docs.get(canonical_site), item)

    existing_sites = _load_existing_site_documents(task_id, docs.keys())
    operations = []
    for canonical_site, item in docs.items():
        query = {"task_id": task_id, "canonical_site": canonical_site}
        payload = dict(item)
        sources = collect_sources(payload.pop("sources", []), payload.get("source"))
        source_value = normalize_source(payload.pop("source", None))
        if not source_value and sources:
            source_value = sources[0]

        incoming_status = _status_code(payload.get("status"))
        if incoming_status is not None:
            payload["last_status"] = incoming_status
            payload["last_observed_at"] = utils.curr_date()
            if source_value:
                payload["last_status_source"] = source_value

        existing = existing_sites.get(canonical_site) or {}
        # Keep browser observations when a later HTTP probe has less context.
        for field in (
            "browser_title", "browser_title_source", "browser_title_chain",
            "browser_final_title", "browser_final_url", "browser_spa_detected",
            "browser_cross_origin_redirect", "runtime_script_count",
            "runtime_request_count", "spa_signals",
            "spa_profile", "spa_score", "spa_confidence", "spa_framework",
            "spa_render_mode", "spa_route_mode", "spa_fingerprint_updated_at",
            "browser_enriched_at",
        ):
            if payload.get(field) in (None, "", [], {}, 0) and existing.get(field) not in (None, "", [], {}, 0):
                payload[field] = existing[field]
        if not payload.get("title") and existing.get("title"):
            payload["title"] = existing["title"]
        display_title = preferred_site_title(payload)
        if display_title and display_title != str(payload.get("title") or "").strip():
            payload["title"] = display_title
            if display_title == str(payload.get("browser_title") or "").strip():
                payload["title_source"] = str(
                    payload.get("browser_title_source") or "browser.runtime")
        if not payload.get("quality_cluster_key") and existing.get("quality_cluster_key"):
            payload["quality_cluster_key"] = existing["quality_cluster_key"]
        if not site_has_confirmed_route(existing):
            payload.update(classify_site_quality(payload))
        if site_has_confirmed_route(existing):
            payload.update(classify_site_quality(existing))
            scan_decision = directory_scan_decision(payload)
            payload.update({
                "scan_policy": scan_decision["scan_policy"],
                "scan_profile": scan_decision["profile"] or "inventory_only",
                "scan_policy_reason": scan_decision["reason"],
                "scan_policy_evidence": scan_decision["evidence"],
            })
            score = max(
                int(existing.get("asset_score") or 0),
                int(payload.get("asset_score") or 0),
                40,
            )
            payload["asset_score"] = score
            payload["asset_level"] = "high" if score >= 70 else "medium"
        promote_from_host = (
            is_host_collision_site(existing) and is_formal_site(item)
        )
        existing_status = _status_code(existing.get("status"))
        preserve_success = (
            _is_success_status(existing_status) and
            _is_edge_block_observation(payload)
        )
        clear_status_preserved_reason = incoming_status is not None and not preserve_success
        if preserve_success:
            payload["best_status"] = existing_status
            payload["status_preserved_reason"] = "edge_block_after_success"
            for field in (
                "status", "title", "body_length", "content_length",
                "headers", "http_server", "favicon", "ip", "hostname",
            ):
                payload.pop(field, None)
        elif _is_success_status(incoming_status):
            payload["best_status"] = incoming_status

        array_updates = {}
        for field in SITE_ARRAY_FIELDS:
            values = payload.pop(field, None)
            if values is None:
                continue
            if not isinstance(values, (list, tuple, set)):
                values = [values]
            values = [value for value in values if value not in (None, "", [], {})]
            if values:
                array_updates[field] = {"$each": list(values)}

        for field in SITE_SPARSE_FIELDS:
            value = payload.get(field)
            if value in (None, "", [], {}, 0):
                payload.pop(field, None)
        for field in ("cdn", "waf", "edge", "fetch_site_complete", "observer_ward_complete"):
            if payload.get(field) is False:
                payload.pop(field, None)

        unset_fields = {}
        if payload.get("scan_policy") != "inventory_only":
            unset_fields["scan_skip_reason"] = ""
        if promote_from_host:
            host_tags = {"Host碰撞", "待复核"}
            existing_tags = existing.get("tag") or []
            if not isinstance(existing_tags, (list, tuple, set)):
                existing_tags = [existing_tags]
            incoming_tags = array_updates.pop("tag", {}).get("$each", [])
            payload["tag"] = list(dict.fromkeys(
                value for value in list(existing_tags) + list(incoming_tags)
                if value not in host_tags
            ))

            incoming_sources = list(sources)
            promoted_sources = collect_sources(
                existing.get("sources"), existing.get("source"), incoming_sources)
            promoted_sources = [
                value for value in promoted_sources
                if str(value or "").lower() != "findvhost"
            ]
            payload["sources"] = promoted_sources
            sources = []
            if str(existing.get("source") or "").lower() == "findvhost":
                if source_value and source_value.lower() != "findvhost":
                    payload["source"] = source_value
                elif promoted_sources:
                    payload["source"] = promoted_sources[0]
                else:
                    unset_fields["source"] = ""

            host_reasons = {"host_collision", "pending_review"}
            existing_reasons = existing.get("asset_reasons") or []
            if not isinstance(existing_reasons, (list, tuple, set)):
                existing_reasons = [existing_reasons]
            incoming_reasons = array_updates.pop(
                "asset_reasons", {}).get("$each", [])
            payload["asset_reasons"] = list(dict.fromkeys(
                value for value in list(existing_reasons) + list(incoming_reasons)
                if value not in host_reasons
            ))
            payload["pipeline_eligible"] = True
            for field in (
                "candidate_disposition", "review_status",
                "host_collision_domain", "host_collision_confidence",
            ):
                unset_fields[field] = ""

        update = {"$set": payload}
        if clear_status_preserved_reason:
            unset_fields["status_preserved_reason"] = ""
        if unset_fields:
            update["$unset"] = unset_fields
        if source_value:
            update["$setOnInsert"] = {"source": source_value}
        add_to_set = dict(array_updates)
        if sources:
            add_to_set["sources"] = {"$each": sources}
        if add_to_set:
            update["$addToSet"] = add_to_set
        operations.append(UpdateOne(query, update, upsert=True))

    _bulk_write("site", operations)
    return len(docs)


def _domain_to_document(domain_info_obj, task_id, source):
    if hasattr(domain_info_obj, "dump_json"):
        domain_info = domain_info_obj.dump_json(flag=False)
    else:
        domain_info = dict(domain_info_obj or {})

    domain = domain_info.get("domain")
    if not domain:
        return None

    domain_info["task_id"] = task_id
    domain_info["source"] = source
    domain_parsed = utils.domain_parsed(domain)
    if domain_parsed:
        domain_info["fld"] = domain_parsed["fld"]
    edge_info = classify_edge_host(domain, domain_info.get("fld", ""))
    if edge_info.get("is_edge"):
        domain_info["edge"] = True
        domain_info["edge_name"] = edge_info.get("edge_name", "")
        domain_info["edge_reasons"] = edge_info.get("edge_reasons", [])
        domain_info["tag"] = merge_tags(domain_info.get("tag"), edge_info.get("tags"))
    return domain_info


def _has_domain_resolution(item):
    return bool((item or {}).get("ips") or (item or {}).get("record"))


def _load_existing_domain_documents(task_id, domains):
    domains = sorted(set(str(domain or "").strip() for domain in domains if domain))
    if not domains:
        return {}
    result = {}
    collection = utils.conn_db("domain")
    projection = {
        "_id": 0,
        "domain": 1,
        "record": 1,
        "ips": 1,
        "type": 1,
        "resolve_status": 1,
    }
    for start in range(0, len(domains), 500):
        batch = domains[start:start + 500]
        for item in collection.find(
                {"task_id": task_id, "domain": {"$in": batch}}, projection):
            domain = item.get("domain")
            if domain:
                result[domain] = item
    return result


def save_domain_documents(task_id, domain_info_list, source):
    source_value = normalize_source(source)
    strong_domain_sources = {"active_ssl_san", "cert_query_verified", "task_target"}
    docs = {}
    for domain_info_obj in domain_info_list or []:
        item = _domain_to_document(domain_info_obj, task_id, source_value)
        if not item:
            continue
        if utils.check_domain_black(item["domain"]):
            continue
        docs[item["domain"]] = item

    existing_domains = _load_existing_domain_documents(task_id, docs.keys())
    operations = []
    observed_at = utils.curr_date()
    for domain, item in docs.items():
        query = {"task_id": task_id, "domain": domain}
        payload = dict(item)
        payload.pop("source", None)
        incoming_resolved = _has_domain_resolution(payload)
        existing_resolved = _has_domain_resolution(existing_domains.get(domain))
        payload["last_dns_observed_at"] = observed_at
        if source_value:
            payload["last_dns_source"] = source_value
        if incoming_resolved:
            payload["resolve_status"] = "resolved"
            payload["last_resolve_status"] = "resolved"
            payload.pop("dns_preserved_reason", None)
        else:
            payload["last_resolve_status"] = str(
                payload.get("resolve_status") or "unresolved")
            if existing_resolved:
                for field in ("record", "ips", "type", "resolve_status"):
                    payload.pop(field, None)
                payload["dns_preserved_reason"] = "empty_observation_after_resolution"
        update = {"$set": payload}
        if incoming_resolved:
            update["$unset"] = {"dns_preserved_reason": ""}
        if source_value in strong_domain_sources:
            update["$set"]["pipeline_eligible"] = True
            update.setdefault("$unset", {}).update({
                "wildcard_suspect": "",
                "wildcard_action": "",
                "candidate_disposition": "",
                "quarantined_at": "",
            })
        if source_value:
            update["$setOnInsert"] = {"source": source_value}
            update["$addToSet"] = {"sources": source_value}
        operations.append(UpdateOne(query, update, upsert=True))

    _bulk_write("domain", operations)
    return len(docs)


def save_url_page_map(task_id, page_map, source, url_type=None, extra_fields=None):
    source_value = normalize_source(source)
    docs = {}
    shared_fields = dict(extra_fields or {})
    for url, page_info in (page_map or {}).items():
        item = build_url_document(url, task_id, source_value, url_type=url_type, extra_fields=shared_fields)
        item.update(dict(page_info or {}))
        docs[item["url"]] = item

    operations = []
    for url, item in docs.items():
        query = {"task_id": task_id, "url": url}
        payload = dict(item)
        payload.pop("source", None)
        update = {"$set": payload}
        if source_value:
            update["$setOnInsert"] = {"source": source_value}
            update["$addToSet"] = {"sources": source_value}
        operations.append(UpdateOne(query, update, upsert=True))

    _bulk_write("url", operations)
    return len(docs)
