import sys
import os
import fcntl
import time
import threading
import ipaddress
from urllib.parse import urlparse
from bson import ObjectId
from pymongo import UpdateOne
from . import conn_db
from .url import canonical_site_url
from .site_scope import formal_site_query, visible_site_query
from app.config import Config


PREVIOUS_INDEX_SCHEMA_VERSION = "20260722_1"
INDEX_SCHEMA_VERSION = "20260724_1"

SITE_MERGE_ARRAY_FIELDS = (
    "finger", "tag", "tech", "edge_reasons", "asset_reasons",
    "site_aliases", "sources",
)
SITE_RECENT_FIELDS = (
    "last_status", "last_status_source", "last_observed_at", "updated_at",
    "update_date", "fetch_date",
)


def _candidate_sources(doc):
    sources = doc.get("sources") or []
    if not isinstance(sources, (list, tuple, set)):
        sources = [sources]
    sources = set(source for source in sources if source not in (None, ""))
    if doc.get("source") not in (None, ""):
        sources.add(doc.get("source"))
    return sorted(sources, key=str)


def _candidate_ports(doc):
    ports = doc.get("ports") or []
    if not isinstance(ports, (list, tuple, set)):
        ports = [ports]
    if doc.get("port") not in (None, ""):
        ports = list(ports) + [doc.get("port")]

    normalized = set()
    for port in ports:
        try:
            port = int(port)
        except (TypeError, ValueError):
            continue
        if 0 < port <= 65535:
            normalized.add(port)
    return sorted(normalized)


def _has_cert_candidate_evidence(doc, sources):
    if any(str(source).endswith("_cert") or source == "cert_query_active_verify"
           for source in sources):
        return True
    return any(
        isinstance(evidence, dict) and evidence.get("query_type") == "cert"
        for evidence in (doc.get("evidence") or [])
    )


def _is_strong_verified_candidate(doc):
    return bool(
        doc and
        doc.get("cert_verified") is True and
        doc.get("pipeline_eligible") is True and
        doc.get("relation_level") == "strong" and
        doc.get("cert_verify_status") in ("verified", "verified_sni", "verified_dns")
    )


def _normalized_target_host(value):
    value = str(value or "").strip()
    if not value:
        return ""
    if "://" in value:
        try:
            value = urlparse(value).hostname or ""
        except ValueError:
            return ""
    elif "/" in value:
        value = value.split("/", 1)[0]
    if value.startswith("*."):
        value = value[2:]
    return value.strip(".").lower()


def update_task_tag():
    """更新task任务tag信息"""
    table = "task"
    items = conn_db(table).find({})
    for item in items:
        task_tag = item.get("task_tag")
        query = {"_id": item["_id"]}
        if not task_tag:
            conn_db(table).update_one(query, {"$set": {"task_tag": "task"}})


def cleanup_tmp_files(max_age_seconds=6 * 60 * 60):
    """Remove stale scanner temp files left by stopped or killed tasks."""
    prefixes = (
        "arl_ffuf_",
        "arl_ffuf_result_",
        "arl_katana_",
        "arl_observer_ward_",
    )
    now = time.time()
    removed = 0
    tmp_path = getattr(Config, "TMP_PATH", "")
    if not tmp_path or not os.path.isdir(tmp_path):
        return removed

    for name in os.listdir(tmp_path):
        if not name.startswith(prefixes):
            continue

        path = os.path.join(tmp_path, name)
        if not os.path.isfile(path):
            continue

        try:
            if now - os.path.getmtime(path) < max_age_seconds:
                continue
            os.remove(path)
            removed += 1
        except OSError:
            continue

    return removed


def consolidate_candidate_duplicates(table, key_fields):
    collection = conn_db(table)
    group_id = {field: "${}".format(field) for field in key_fields}
    pipeline = [
        {"$group": {
            "_id": group_id,
            "ids": {"$push": "$_id"},
            "count": {"$sum": 1},
        }},
        {"$match": {"count": {"$gt": 1}}},
    ]
    merged_count = 0
    for group in collection.aggregate(pipeline, allowDiskUse=True):
        docs = list(collection.find({"_id": {"$in": group.get("ids", [])}}))
        if len(docs) < 2:
            continue
        docs.sort(key=lambda item: str(item.get("_id")))
        keeper = docs[0]
        merged = {
            "sources": set(),
            "ports": set(),
            "domains": set(),
            "web_titles": set(),
            "verified_domains": set(),
            "verified_ports": set(),
            "evidence": [],
        }
        evidence_seen = set()
        cert_evidence = False
        cert_verified = False
        pipeline_eligible = False
        quarantined = False
        candidate_type = str(keeper.get("candidate_type") or "")
        status = str(keeper.get("status") or "pending")
        relation_level = str(keeper.get("relation_level") or "")
        cert_verify_status = str(keeper.get("cert_verify_status") or "")
        latest_fields = {}
        for doc in docs:
            for field, single_field in (
                ("sources", "source"),
                ("ports", "port"),
                ("domains", "domain"),
                ("web_titles", "web_title"),
                ("verified_domains", None),
                ("verified_ports", None),
            ):
                values = doc.get(field) or []
                if not isinstance(values, (list, tuple, set)):
                    values = [values]
                if single_field and doc.get(single_field) not in (None, ""):
                    values = list(values) + [doc.get(single_field)]
                for value in values:
                    if value in (None, ""):
                        continue
                    if field in ("ports", "verified_ports"):
                        try:
                            value = int(value)
                        except (TypeError, ValueError):
                            continue
                        if value <= 0 or value > 65535:
                            continue
                    merged[field].add(value)
            for evidence in doc.get("evidence") or []:
                marker = repr(sorted(evidence.items())) if isinstance(evidence, dict) else repr(evidence)
                if marker not in evidence_seen:
                    evidence_seen.add(marker)
                    merged["evidence"].append(evidence)
                if isinstance(evidence, dict) and evidence.get("query_type") == "cert":
                    cert_evidence = True
            cert_verified = cert_verified or bool(doc.get("cert_verified"))
            pipeline_eligible = pipeline_eligible or doc.get("pipeline_eligible") is True
            quarantined = quarantined or doc.get("status") == "quarantined"
            if doc.get("candidate_type") == "cert_ip":
                candidate_type = "cert_ip"
            if doc.get("status") in ("verified", "alive"):
                status = doc.get("status")
            if doc.get("relation_level") == "strong":
                relation_level = "strong"
            elif doc.get("relation_level") == "weak" and not relation_level:
                relation_level = "weak"
            doc_verify_status = str(doc.get("cert_verify_status") or "")
            verify_rank = {
                "": 0,
                "no_cert": 1,
                "scope_mismatch": 2,
                "quarantined_no_cert": 3,
                "quarantined_scope_mismatch": 4,
                "quarantined_shared_default": 5,
                "quarantined_cert_only": 6,
                "quarantined_sni_oracle": 7,
                "legacy_revalidation_required": 8,
                "verified": 9,
                "verified_sni": 10,
                "verified_dns": 11,
            }
            if verify_rank.get(doc_verify_status, 0) > verify_rank.get(cert_verify_status, 0):
                cert_verify_status = doc_verify_status
            for field in ("last_source", "last_seen_at", "cert_checked_at"):
                value = doc.get(field)
                if value in (None, ""):
                    continue
                current = latest_fields.get(field)
                if current is None or str(value) > str(current):
                    latest_fields[field] = value

        if cert_evidence or any(
                str(source).endswith("_cert") or source == "cert_query_active_verify"
                for source in merged["sources"]):
            candidate_type = "cert_ip"
        if (
            cert_verified and pipeline_eligible and merged["verified_ports"] and
            cert_verify_status == "verified_dns"
        ):
            status = "verified"
            relation_level = "strong"
        elif candidate_type == "cert_ip" and (
                cert_verified or quarantined or pipeline_eligible):
            status = "quarantined"
            relation_level = "weak"
            pipeline_eligible = False
            if cert_verified:
                cert_verify_status = "legacy_revalidation_required"
                cert_verified = False

        update = {
            "sources": sorted(merged["sources"], key=str),
            "ports": sorted(merged["ports"]),
            "domains": sorted(merged["domains"], key=str),
            "web_titles": sorted(merged["web_titles"], key=str),
            "verified_domains": sorted(merged["verified_domains"], key=str),
            "verified_ports": sorted(merged["verified_ports"]),
            "evidence": merged["evidence"],
            "cert_verified": cert_verified,
            "pipeline_eligible": pipeline_eligible,
            "candidate_type": candidate_type or "mapping",
            "status": status,
            "migration_merged_at": time.time(),
        }
        if relation_level:
            update["relation_level"] = relation_level
        if cert_verify_status:
            update["cert_verify_status"] = cert_verify_status
        if update["ports"]:
            update["port"] = update["ports"][0]
        update.update(latest_fields)
        collection.update_one({"_id": keeper["_id"]}, {"$set": update})
        collection.delete_many({"_id": {"$in": [item["_id"] for item in docs[1:]]}})
        merged_count += len(docs) - 1
    return merged_count


def normalize_candidate_records(table):
    """Normalize canonical candidate rows after duplicate consolidation."""
    collection = conn_db(table)
    modified = 0
    projection = {
        "source": 1,
        "sources": 1,
        "port": 1,
        "ports": 1,
        "candidate_type": 1,
        "evidence": 1,
        "cert_verified": 1,
        "cert_verify_status": 1,
        "pipeline_eligible": 1,
        "status": 1,
        "relation_level": 1,
        "verified_ports": 1,
    }
    for doc in collection.find({}, projection):
        sources = _candidate_sources(doc)
        ports = _candidate_ports(doc)
        update = {}

        if doc.get("sources") != sources:
            update["sources"] = sources
        if doc.get("ports") != ports:
            update["ports"] = ports
        if ports and doc.get("port") != ports[0]:
            update["port"] = ports[0]
        if (_has_cert_candidate_evidence(doc, sources)
                and doc.get("candidate_type") != "cert_ip"):
            update["candidate_type"] = "cert_ip"
        elif not doc.get("candidate_type"):
            update["candidate_type"] = "mapping"

        effective_type = update.get("candidate_type", doc.get("candidate_type"))
        if effective_type == "cert_ip" and doc.get("cert_verified") and not (
                doc.get("pipeline_eligible") is True and doc.get("verified_ports")):
            update.update({
                "cert_verify_status": "legacy_revalidation_required",
                "pipeline_eligible": False,
                "status": "quarantined",
                "relation_level": "weak",
            })

        if update:
            collection.update_one({"_id": doc["_id"]}, {"$set": update})
            modified += 1
    return modified


def drop_legacy_candidate_indexes():
    legacy_specs = {
        "asset_seed_candidate": [
            ("task_id", 1), ("ip", 1), ("domain", 1), ("source", 1),
        ],
        "vhost_ip_candidate": [
            ("task_id", 1), ("domain", 1), ("ip", 1), ("source", 1),
        ],
    }
    removed = 0
    for table, legacy_spec in legacy_specs.items():
        collection = conn_db(table)
        for name, info in collection.index_information().items():
            if list(info.get("key") or []) != legacy_spec:
                continue
            collection.drop_index(name)
            removed += 1
    return removed


def _site_value_present(value):
    return value not in (None, "", [], {})


def _site_value_marker(value):
    if isinstance(value, dict):
        return repr(sorted(value.items(), key=lambda item: str(item[0])))
    if isinstance(value, (list, tuple, set)):
        return repr(list(value))
    return repr(value)


def _merge_site_array_values(docs, field):
    values = []
    seen = set()
    for doc in docs:
        raw_values = doc.get(field) or []
        if not isinstance(raw_values, (list, tuple, set)):
            raw_values = [raw_values]
        if field == "sources" and doc.get("source") not in (None, ""):
            raw_values = list(raw_values) + [doc.get("source")]
        for value in raw_values:
            if not _site_value_present(value):
                continue
            marker = _site_value_marker(value)
            if marker in seen:
                continue
            seen.add(marker)
            values.append(value)
    return values


def _site_status_rank(value):
    try:
        status = int(value)
    except (TypeError, ValueError):
        return (0, 0)
    if 200 <= status < 300:
        return (4, -abs(status - 200))
    if 300 <= status < 400:
        return (3, -abs(status - 302))
    if status in (401, 403):
        return (2, -status)
    return (1, -status)


def _site_document_richness(doc):
    score = _site_status_rank(doc.get("status"))[0] * 20
    weighted_fields = {
        "title": 8,
        "finger": 8,
        "headers": 5,
        "favicon": 4,
        "http_server": 4,
        "webserver": 4,
        "ip": 4,
        "hostname": 3,
        "body_length": 2,
        "content_length": 2,
    }
    for field, weight in weighted_fields.items():
        if _site_value_present(doc.get(field)):
            score += weight
    return score


def _site_observed_sort_key(doc):
    for field in ("last_observed_at", "updated_at", "update_date", "fetch_date", "save_date"):
        value = doc.get(field)
        if value not in (None, ""):
            return str(value)
    return str(doc.get("_id"))


def _canonical_site_for_migration(doc):
    raw_site = str(doc.get("site") or "").strip()
    canonical = canonical_site_url(raw_site)
    if canonical:
        return canonical
    if raw_site:
        return raw_site
    return "__legacy_site__:{}".format(doc.get("_id"))


def _merge_site_group(docs, canonical_site):
    ranked_docs = sorted(
        docs,
        key=lambda item: (_site_document_richness(item), _site_observed_sort_key(item)),
        reverse=True,
    )
    keeper = ranked_docs[0]
    merged = {
        key: value for key, value in keeper.items()
        if key != "_id"
    }

    for doc in ranked_docs[1:]:
        for field, value in doc.items():
            if field in ("_id", "site", "canonical_site") or field in SITE_MERGE_ARRAY_FIELDS:
                continue
            if not _site_value_present(merged.get(field)) and _site_value_present(value):
                merged[field] = value

    for field in SITE_MERGE_ARRAY_FIELDS:
        values = _merge_site_array_values(docs, field)
        if values:
            merged[field] = values

    aliases = _merge_site_array_values(docs, "site_aliases")
    for doc in docs:
        raw_site = str(doc.get("site") or "").strip()
        if raw_site and raw_site != canonical_site and raw_site not in aliases:
            aliases.append(raw_site)
    if aliases:
        merged["site_aliases"] = aliases

    status_values = []
    for doc in docs:
        status_values.extend([doc.get("status"), doc.get("best_status")])
    status_values = [value for value in status_values if _site_status_rank(value)[0]]
    if status_values:
        best_status = max(status_values, key=_site_status_rank)
        merged["status"] = int(best_status)
        if 200 <= int(best_status) < 400:
            merged["best_status"] = int(best_status)

    latest_doc = max(docs, key=_site_observed_sort_key)
    for field in SITE_RECENT_FIELDS:
        value = latest_doc.get(field)
        if _site_value_present(value):
            merged[field] = value
    latest_status = latest_doc.get("last_status", latest_doc.get("status"))
    if _site_status_rank(latest_status)[0]:
        merged["last_status"] = int(latest_status)
    if not latest_doc.get("last_status_source") and latest_doc.get("source"):
        merged["last_status_source"] = latest_doc.get("source")

    sources = merged.get("sources") or []
    if sources and not merged.get("source"):
        merged["source"] = sources[0]
    merged["site"] = canonical_site
    merged["canonical_site"] = canonical_site
    if len(docs) > 1:
        merged["migration_merged_at"] = time.time()
        merged["migration_merged_count"] = len(docs)
    return keeper, merged


def consolidate_site_documents():
    """Canonicalize site identity and merge legacy root/default-port variants."""
    collection = conn_db("site")
    operations = []
    normalized = 0
    for doc in collection.find({}, {"_id": 1, "site": 1, "canonical_site": 1}):
        canonical = _canonical_site_for_migration(doc)
        if doc.get("canonical_site") == canonical:
            continue
        operations.append(UpdateOne(
            {"_id": doc["_id"]}, {"$set": {"canonical_site": canonical}}))
        if len(operations) >= 1000:
            collection.bulk_write(operations, ordered=False)
            normalized += len(operations)
            operations = []
    if operations:
        collection.bulk_write(operations, ordered=False)
        normalized += len(operations)

    pipeline = [
        {"$group": {
            "_id": {"task_id": "$task_id", "canonical_site": "$canonical_site"},
            "ids": {"$push": "$_id"},
            "count": {"$sum": 1},
        }},
        {"$match": {"count": {"$gt": 1}}},
    ]
    merged_count = 0
    affected_task_ids = set()
    for group in collection.aggregate(pipeline, allowDiskUse=True):
        docs = list(collection.find({"_id": {"$in": group.get("ids", [])}}))
        if len(docs) < 2:
            continue
        canonical = group.get("_id", {}).get("canonical_site") or _canonical_site_for_migration(docs[0])
        keeper, merged = _merge_site_group(docs, canonical)
        task_id = group.get("_id", {}).get("task_id")
        if task_id:
            affected_task_ids.add(str(task_id))
        loser_ids = [doc["_id"] for doc in docs if doc["_id"] != keeper["_id"]]
        if loser_ids:
            collection.delete_many({"_id": {"$in": loser_ids}})
        collection.update_one({"_id": keeper["_id"]}, {"$set": merged})
        merged_count += len(loser_ids)

    operations = []
    display_normalized = 0
    for doc in collection.find({}, {"_id": 1, "site": 1, "canonical_site": 1}):
        canonical = doc.get("canonical_site") or _canonical_site_for_migration(doc)
        if doc.get("site") == canonical:
            continue
        operations.append(UpdateOne(
            {"_id": doc["_id"]}, {"$set": {"site": canonical, "canonical_site": canonical}}))
        if len(operations) >= 1000:
            collection.bulk_write(operations, ordered=False)
            display_normalized += len(operations)
            operations = []
    if operations:
        collection.bulk_write(operations, ordered=False)
        display_normalized += len(operations)

    return {
        "canonicalized_count": normalized,
        "merged_count": merged_count,
        "display_normalized_count": display_normalized,
        "affected_task_ids": sorted(affected_task_ids),
    }


def refresh_site_derived_statistics(task_ids):
    refreshed = 0
    site_collection = conn_db("site")
    finger_collection = conn_db("stat_finger")
    for task_id in sorted(set(str(value or "") for value in task_ids or [] if value)):
        base_query = {"task_id": task_id}
        site_query = visible_site_query(base_query)
        site_count = site_collection.count_documents(site_query)
        observed_count = site_collection.count_documents(
            formal_site_query(base_query))
        if ObjectId.is_valid(task_id):
            conn_db("task").update_one(
                {"_id": ObjectId(task_id)},
                {"$set": {
                    "statistic.site_cnt": site_count,
                    "statistic.site_observed_cnt": observed_count,
                    "statistic.site_filtered_cnt": max(
                        observed_count - site_count, 0),
                }},
            )

        finger_map = {}
        for item in site_collection.find(
                site_query, {"_id": 0, "finger": 1}):
            site_fingers = set()
            for finger in item.get("finger") or []:
                if isinstance(finger, dict):
                    name = str(finger.get("name") or "").strip()
                else:
                    name = str(finger or "").strip()
                if name:
                    site_fingers.add(name)
            for name in site_fingers:
                key = name.lower()
                finger_map.setdefault(key, {"name": name, "cnt": 0})
                finger_map[key]["cnt"] += 1

        finger_collection.delete_many({"task_id": task_id})
        for item in finger_map.values():
            payload = dict(item)
            payload["task_id"] = task_id
            finger_collection.update_one(
                {"task_id": task_id, "name": item["name"]},
                {"$set": payload},
                upsert=True,
            )
        refreshed += 1
    return refreshed


def drop_legacy_site_unique_indexes():
    collection = conn_db("site")
    legacy_spec = [("task_id", 1), ("site", 1)]
    removed = 0
    for name, info in collection.index_information().items():
        if list(info.get("key") or []) != legacy_spec or not info.get("unique"):
            continue
        collection.drop_index(name)
        removed += 1
    return removed


def backfill_host_collision_fields():
    from app.services.hostCollisionExport import normalize_host_collision_item
    from app.utils.host_collision import HOST_COLLISION_MATCH

    collection = conn_db("vuln")
    query = {"$and": [
        HOST_COLLISION_MATCH,
        {"$or": [
            {"host_collision_ip": {"$exists": False}},
            {"host_collision_ip": ""},
            {"host_collision_domain": {"$exists": False}},
            {"host_collision_domain": ""},
        ]},
    ]}
    operations = []
    updated = 0
    for item in collection.find(query):
        row = normalize_host_collision_item(item)
        if not row:
            continue
        try:
            address = ipaddress.ip_address(row["ip"])
            ip_sort = int(address) if address.version == 4 else None
        except ValueError:
            ip_sort = None
        operations.append(UpdateOne(
            {"_id": item["_id"]},
            {"$set": {
                "host_collision_ip": row["ip"],
                "host_collision_ip_sort": ip_sort,
                "host_collision_domain": row["host"],
                "pipeline_eligible": False,
                "candidate_disposition": "host_only",
            }},
        ))
        if len(operations) >= 500:
            result = collection.bulk_write(operations, ordered=False)
            updated += result.modified_count
            operations = []
    if operations:
        result = collection.bulk_write(operations, ordered=False)
        updated += result.modified_count
    return updated


def _refresh_task_statistics(task_ids):
    from app.utils.arl import task_statistic

    task_collection = conn_db("task")
    refreshed = 0
    for task_id in sorted({str(value or "") for value in task_ids if value}):
        try:
            object_id = ObjectId(task_id)
        except Exception:
            continue
        statistic = task_statistic(task_id)
        result = task_collection.update_one(
            {"_id": object_id},
            {"$set": {"statistic": statistic}},
        )
        refreshed += int(result.matched_count or 0)
    return refreshed


def refresh_host_collision_statistics():
    from app.utils.host_collision import HOST_COLLISION_MATCH

    task_ids = conn_db("vuln").distinct("task_id", HOST_COLLISION_MATCH)
    return _refresh_task_statistics(task_ids)


def refresh_filtered_asset_statistics():
    from app.utils.host_collision import HOST_COLLISION_MATCH

    task_ids = set(conn_db("vuln").distinct("task_id", HOST_COLLISION_MATCH))
    task_ids.update(conn_db("domain").distinct("task_id", {"$or": [
        {"wildcard_suspect": True},
        {"candidate_disposition": "wildcard_dns"},
    ]}))
    return _refresh_task_statistics(task_ids)


def quarantine_wildcard_assets():
    domain_collection = conn_db("domain")
    wildcard_by_task = {}
    domain_docs = list(domain_collection.find(
        {"wildcard_suspect": True},
        {
            "_id": 1, "task_id": 1, "domain": 1, "ips": 1,
            "record": 1, "source": 1, "sources": 1,
        },
    ))
    strong_sources = {"active_ssl_san", "cert_query_verified", "task_target"}
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    quarantined_domains = 0
    promoted_domains = 0
    candidate_collection = conn_db("asset_seed_candidate")
    task_targets = {
        str(item.get("_id")): _normalized_target_host(item.get("target"))
        for item in conn_db("task").find({}, {"_id": 1, "target": 1})
        if _normalized_target_host(item.get("target"))
    }
    verified_candidate_domains = {
        (
            str(item.get("task_id") or ""),
            _normalized_target_host(item.get("domain")),
        )
        for item in candidate_collection.find(
            {"cert_verified": True, "pipeline_eligible": True},
            {
                "task_id": 1, "domain": 1, "cert_verified": 1,
                "pipeline_eligible": 1, "relation_level": 1,
                "cert_verify_status": 1,
            },
        )
        if _is_strong_verified_candidate(item)
        and item.get("task_id") and _normalized_target_host(item.get("domain"))
    }
    for item in domain_docs:
        sources = item.get("sources") or []
        if not isinstance(sources, (list, tuple, set)):
            sources = [sources]
        sources = set(sources)
        if item.get("source"):
            sources.add(item.get("source"))
        task_id = str(item.get("task_id") or "")
        domain = _normalized_target_host(item.get("domain"))
        proof_source = ""
        if sources & strong_sources:
            proof_source = sorted(sources & strong_sources)[0]
        elif task_targets.get(task_id) == domain:
            proof_source = "task_target"
        elif (task_id, domain) in verified_candidate_domains:
            proof_source = "cert_query_verified"
        if proof_source:
            domain_collection.update_one(
                {"_id": item["_id"]},
                {
                    "$set": {
                        "pipeline_eligible": True,
                        "wildcard_override_reason": proof_source,
                    },
                    "$unset": {
                        "wildcard_suspect": "",
                        "wildcard_action": "",
                        "candidate_disposition": "",
                        "quarantined_at": "",
                    },
                    "$addToSet": {"sources": proof_source},
                },
            )
            promoted_domains += 1
            continue

        if not task_id or not domain:
            continue
        wildcard_by_task.setdefault(task_id, set()).add(domain)
        domain_collection.update_one(
            {"_id": item["_id"]},
            {"$set": {
                "wildcard_action": "quarantined",
                "candidate_disposition": "wildcard_dns",
                "pipeline_eligible": False,
                "quarantined_at": now,
            }},
        )
        quarantined_domains += 1

        ips = item.get("ips") or [""]
        if not isinstance(ips, (list, tuple, set)):
            ips = [ips]
        records = item.get("record") or []
        if not isinstance(records, (list, tuple, set)):
            records = [records]
        for ip in ips or [""]:
            ip = str(ip or "").strip()
            existing = candidate_collection.find_one(
                {"task_id": task_id, "ip": ip, "domain": domain},
                {
                    "_id": 1, "candidate_type": 1, "cert_verified": 1,
                    "pipeline_eligible": 1, "relation_level": 1,
                    "cert_verify_status": 1,
                },
            ) or {}
            candidate_values = {
                "task_id": task_id,
                "domain": domain,
                "ip": ip,
                "candidate_type": "wildcard_dns",
                "candidate_disposition": "host_only",
                "status": "quarantined",
                "pipeline_eligible": False,
                "host_collision_eligible": True,
                "wildcard_suspect": True,
                "wildcard_records": sorted(
                    str(value or "") for value in records if value),
                "quarantine_reason": "wildcard_dns",
                "last_seen_at": now,
            }
            if existing.get("candidate_type") == "cert_ip" or existing.get("cert_verified"):
                candidate_values.update({
                    "cert_verified": False,
                    "relation_level": "weak",
                    "cert_verify_status": "quarantined_wildcard_dns",
                })
            candidate_collection.update_one(
                {"task_id": task_id, "ip": ip, "domain": domain},
                {
                    "$set": candidate_values,
                    "$setOnInsert": {
                        "source": "wildcard_dns_migration",
                        "save_date": now,
                    },
                    "$addToSet": {"sources": "wildcard_dns_migration"},
                },
                upsert=True,
            )

    def value_host(value):
        value = str(value or "").strip()
        if not value:
            return ""
        if "://" in value:
            try:
                return str(urlparse(value).hostname or "").strip(".").lower()
            except ValueError:
                return ""
        return value.strip(".").lower() if "/" not in value else ""

    collection_fields = {
        "site": ("hostname", "site"),
        "asset_seed_alive": ("host", "url"),
        "url": ("hostname", "url"),
        "fileleak": ("hostname", "url", "site"),
        "entry_asset": ("domain", "seed", "final_url", "alive_url"),
        "wih": ("content",),
        "vuln": ("domain", "target"),
    }
    marked_assets = 0
    for task_id, wildcard_domains in wildcard_by_task.items():
        for collection_name, fields in collection_fields.items():
            collection = conn_db(collection_name)
            operations = []
            projection = {field: 1 for field in fields}
            for item in collection.find({"task_id": task_id}, projection):
                hosts = {value_host(item.get(field)) for field in fields}
                if not (hosts & wildcard_domains):
                    continue
                operations.append(UpdateOne(
                    {"_id": item["_id"]},
                    {"$set": {
                        "wildcard_suspect": True,
                        "candidate_disposition": "wildcard_dns",
                        "pipeline_eligible": False,
                        "quarantined_at": now,
                    }},
                ))
            if operations:
                result = collection.bulk_write(operations, ordered=False)
                marked_assets += result.modified_count

    return {
        "quarantined_domain_count": quarantined_domains,
        "promoted_domain_count": promoted_domains,
        "marked_asset_count": marked_assets,
    }


def create_index():
    index_map = {
        "cert": "task_id",
        "cert_candidate": [
            "task_id", "ip", "port", "pipeline_eligible",
            "candidate_disposition", "relation_level",
        ],
        "domain": ["task_id", "domain", "pipeline_eligible", "wildcard_suspect"],
        "fileleak": ["task_id", "pipeline_eligible", "wildcard_suspect"],
        "ip": "task_id",
        "npoc_service": "task_id",
        "site": [
            "task_id", "status", "title", "hostname", "site",
            "canonical_site", "http_server", "pipeline_eligible",
            "wildcard_suspect", "display_eligible", "quality_state",
        ],
        "service": "task_id",
        "url": ["task_id", "pipeline_eligible", "wildcard_suspect"],
        "vuln": [
            "task_id", "source", "plg_name", "host_collision_ip",
            "host_collision_domain", "host_collision_ip_sort",
        ],
        "asset_ip": "scope_id",
        "asset_site": [
            "scope_id", "task_id", "display_eligible", "quality_state",
        ],
        "asset_domain": ["scope_id", "domain"],
        "github_result": "github_task_id",
        "github_monitor_result": "github_scheduler_id",
        "wih": [
            "task_id", "record_type", "fnv_hash", "pipeline_eligible",
            "wildcard_suspect",
        ],
        "entry_asset": [
            "task_id", "seed_type", "status", "is_new", "is_duplicate", "source",
            "pipeline_eligible", "wildcard_suspect",
        ],
        "asset_seed_alive": ["task_id", "pipeline_eligible", "wildcard_suspect"],
        "cert_probe_state": "task_id",
        "fileleak_scan_state": "task_id",
        "port_site_probe_state": "task_id",
        "port_scan_checkpoint": "task_id",
        "host_collision_checkpoint": "task_id",
        "asset_seed_probe_state": "task_id",
        "domain_brute_batch_state": "task_id",
        "discovery_delta_state": "task_id",
    }
    for table in index_map:
        if isinstance(index_map[table], list):
            for index in index_map[table]:
                conn_db(table).create_index(index)
        else:
            conn_db(table).create_index(index_map[table])

    unique_index_map = {
        "asset_seed_candidate": [("task_id", 1), ("ip", 1), ("domain", 1)],
        "asset_seed_alive": [("task_id", 1), ("url", 1), ("source", 1)],
        "vhost_ip_candidate": [("task_id", 1), ("domain", 1), ("ip", 1)],
        "cert": [("task_id", 1), ("ip", 1), ("port", 1)],
        "cip": [("task_id", 1), ("cidr_ip", 1)],
        "domain": [("task_id", 1), ("domain", 1)],
        "fileleak": [("task_id", 1), ("url", 1)],
        "ip": [("task_id", 1), ("ip", 1)],
        "service": [("task_id", 1), ("service_name", 1)],
        "site": [("task_id", 1), ("canonical_site", 1)],
        "stat_finger": [("task_id", 1), ("name", 1)],
        "task_stage": [("task_id", 1), ("stage", 1)],
        "url": [("task_id", 1), ("url", 1)],
        "wih": [("task_id", 1), ("fnv_hash", 1)],
        "entry_asset": [("task_id", 1), ("seed_key", 1)],
        "cert_probe_state": [("task_id", 1), ("target", 1)],
        "fileleak_scan_state": [
            ("task_id", 1), ("site", 1), ("dict_fingerprint", 1)],
        "port_site_probe_state": [
            ("task_id", 1), ("ip", 1), ("port", 1)],
        "port_scan_checkpoint": [
            ("task_id", 1), ("profile", 1), ("ip", 1)],
        "host_collision_checkpoint": [
            ("task_id", 1), ("endpoint_key", 1)],
        "domain_brute_batch_state": [
            ("task_id", 1), ("profile", 1),
            ("candidate_fingerprint", 1), ("batch_key", 1), ("batch_hash", 1)],
    }
    for table, fields in unique_index_map.items():
        name = "{}_unique".format("_".join(["{}_{}".format(k, v) for k, v in fields]))
        conn_db(table).create_index(fields, unique=True, name=name)

    compound_index_map = {
        "task": [
            [("name", 1), ("_id", -1)],
            [("status", 1), ("_id", -1)],
            [("create_time", -1)],
            [("workflow_phase", 1), ("_id", -1)],
        ],
        "site": [
            [("task_id", 1), ("_id", -1)],
            [("task_id", 1), ("display_eligible", 1), ("_id", -1)],
            [("task_id", 1), ("quality_state", 1), ("_id", -1)],
            [("task_id", 1), ("content_length", -1)],
            [("task_id", 1), ("status", 1)],
            [("task_id", 1), ("title", 1)],
            [("task_id", 1), ("finger.name", 1)],
        ],
        "asset_site": [
            [("scope_id", 1), ("display_eligible", 1), ("_id", -1)],
            [("scope_id", 1), ("quality_state", 1), ("_id", -1)],
        ],
        "fileleak": [
            [("task_id", 1), ("_id", -1)],
            [("task_id", 1), ("content_length", -1)],
            [("task_id", 1), ("status_code", 1)],
            [("task_id", 1), ("title", 1)],
        ],
        "url": [
            [("task_id", 1), ("_id", -1)],
            [("task_id", 1), ("content_length", -1)],
            [("task_id", 1), ("status_code", 1)],
            [("task_id", 1), ("title", 1)],
            [("task_id", 1), ("url_type", 1)],
        ],
        "wih": [
            [("task_id", 1), ("_id", -1)],
            [("task_id", 1), ("record_type", 1), ("_id", -1)],
        ],
        "entry_asset": [
            [("task_id", 1), ("_id", -1)],
            [("task_id", 1), ("status", 1), ("is_new", 1), ("is_duplicate", 1)],
            [("task_id", 1), ("source", 1), ("status", 1), ("is_new", 1), ("is_duplicate", 1)],
            [("task_id", 1), ("seed_type", 1), ("_id", -1)],
            [("task_id", 1), ("status_code", 1)],
            [("task_id", 1), ("content_length", -1)],
            [("task_id", 1), ("title", 1)],
        ],
        "domain": [
            [("task_id", 1), ("_id", -1)],
        ],
        "ip": [
            [("task_id", 1), ("_id", -1)],
        ],
        "cert": [
            [("task_id", 1), ("_id", -1)],
        ],
        "cert_candidate": [
            [("task_id", 1), ("ip", 1), ("port", 1)],
            [("task_id", 1), ("pipeline_eligible", 1), ("_id", -1)],
        ],
        "vuln": [
            [("task_id", 1), ("source", 1),
             ("host_collision_ip_sort", 1), ("host_collision_domain", 1)],
            [("task_id", 1), ("plg_name", 1),
             ("host_collision_domain", 1)],
        ],
        "port_candidate": [
            [("task_id", 1), ("ip", 1), ("port", 1)],
            [("task_id", 1), ("profile", 1), ("confirmed", 1)],
        ],
        "cert_probe_state": [
            [("task_id", 1), ("phase", 1), ("status", 1)],
        ],
        "fileleak_scan_state": [
            [("task_id", 1), ("status", 1), ("updated_at", -1)],
        ],
        "port_site_probe_state": [
            [("task_id", 1), ("status", 1), ("updated_at", -1)],
        ],
        "port_scan_checkpoint": [
            [("task_id", 1), ("profile", 1), ("status", 1)],
            [("task_id", 1), ("profile", 1), ("port_fingerprint", 1), ("status", 1)],
        ],
        "host_collision_checkpoint": [
            [("task_id", 1), ("status", 1), ("updated_at", -1)],
            [("task_id", 1), ("plan_fingerprint", 1), ("status", 1)],
        ],
        "asset_seed_probe_state": [
            [("task_id", 1), ("label", 1), ("batch_fingerprint", 1)],
            [("task_id", 1), ("status", 1), ("updated_at", -1)],
        ],
        "domain_brute_batch_state": [
            [("task_id", 1), ("profile", 1),
             ("candidate_fingerprint", 1), ("batch_key", 1)],
            [("task_id", 1), ("status", 1), ("updated_at", -1)],
        ],
        "discovery_delta_state": [
            [("task_id", 1), ("status", 1), ("updated_at", -1)],
        ],
    }
    for table, indexes in compound_index_map.items():
        for fields in indexes:
            conn_db(table).create_index(fields)


def create_host_collision_indexes():
    collection = conn_db("host_collision_checkpoint")
    collection.create_index("task_id")
    collection.create_index(
        [("task_id", 1), ("endpoint_key", 1)],
        unique=True,
        name="task_id_1_endpoint_key_1_unique",
    )
    collection.create_index(
        [("task_id", 1), ("status", 1), ("updated_at", -1)])
    collection.create_index(
        [("task_id", 1), ("plan_fingerprint", 1), ("status", 1)])


def create_site_quality_indexes():
    site = conn_db("site")
    site.create_index([("task_id", 1), ("display_eligible", 1), ("_id", -1)])
    site.create_index([("task_id", 1), ("quality_state", 1), ("_id", -1)])

    asset_site = conn_db("asset_site")
    asset_site.create_index([
        ("scope_id", 1), ("display_eligible", 1), ("_id", -1),
    ])
    asset_site.create_index([
        ("scope_id", 1), ("quality_state", 1), ("_id", -1),
    ])


def create_asset_quality_indexes():
    site = conn_db("site")
    site.create_index([
        ("task_id", 1), ("asset_quality", 1),
        ("quality_cluster_representative", 1), ("_id", -1),
    ])
    site.create_index([
        ("task_id", 1), ("asset_visibility", 1), ("_id", -1),
    ])
    asset_site = conn_db("asset_site")
    asset_site.create_index([
        ("scope_id", 1), ("asset_quality", 1),
        ("quality_cluster_representative", 1), ("_id", -1),
    ])


def _write_index_schema_version(lock_fp):
    lock_fp.seek(0)
    lock_fp.truncate()
    lock_fp.write(INDEX_SCHEMA_VERSION)
    lock_fp.flush()
    os.fsync(lock_fp.fileno())


def run_db_migrations():
    update_lock = os.path.join(Config.TMP_PATH, 'arl_update.lock')
    with open(update_lock, 'a+') as lock_fp:
        fcntl.flock(lock_fp.fileno(), fcntl.LOCK_EX)
        try:
            lock_fp.seek(0)
            current_version = lock_fp.read().strip()
            if current_version == INDEX_SCHEMA_VERSION:
                # Index creation is idempotent and keeps upgrades compatible
                # with deployments that already have the previous schema lock.
                create_asset_quality_indexes()
                return False
            if current_version == PREVIOUS_INDEX_SCHEMA_VERSION:
                create_host_collision_indexes()
                create_site_quality_indexes()
                create_asset_quality_indexes()
                _write_index_schema_version(lock_fp)
                return True

            update_task_tag()
            consolidate_candidate_duplicates(
                "asset_seed_candidate", ["task_id", "ip", "domain"])
            consolidate_candidate_duplicates(
                "vhost_ip_candidate", ["task_id", "domain", "ip"])
            normalize_candidate_records("asset_seed_candidate")
            normalize_candidate_records("vhost_ip_candidate")
            drop_legacy_candidate_indexes()
            site_migration = consolidate_site_documents()
            refresh_site_derived_statistics(
                site_migration.get("affected_task_ids", []))
            drop_legacy_site_unique_indexes()
            quarantine_wildcard_assets()
            backfill_host_collision_fields()
            refresh_filtered_asset_statistics()
            create_index()
            _write_index_schema_version(lock_fp)
            return True
        finally:
            fcntl.flock(lock_fp.fileno(), fcntl.LOCK_UN)


def arl_update():
    if is_run_flask_routes():
        return

    npoc_info_update()
    cleanup_tmp_files()

    run_db_migrations()


# 创建锁，防止多线程同时更新
lock = threading.Lock()


def npoc_info_update():
    from app.services.npoc import NPoC
    with lock:
        if conn_db('poc').count_documents({}) > 0:
            return

        n = NPoC()
        n.sync_to_db()


# 判断是否是-m flask routes 模式运行
def is_run_flask_routes():
    if len(sys.argv) == 2:
        if "flask/__main__.py" in sys.argv[0]:
            if sys.argv[1] == "routes":
                return True

    return False
