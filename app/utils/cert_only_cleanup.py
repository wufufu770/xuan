import argparse
import gzip
import json
import os
import re
from collections import Counter
from datetime import datetime

from bson import ObjectId, json_util

from app import utils
from app.services.commonTask import CommonTask
from app.utils.site_scope import formal_domain_query


LEGACY_VERIFY_STATUSES = ("verified", "verified_sni")
KNOWN_SNI_ORACLE_IPS = {"82.156.224.203"}


def _latest_domain_task_ids(limit):
    cursor = utils.conn_db("task").find(
        {"type": "domain"}, {"_id": 1}).sort("_id", -1)
    if limit > 0:
        cursor = cursor.limit(limit)
    return [str(item["_id"]) for item in cursor]


def _has_current_dns(task_id, ip):
    return bool(utils.conn_db("domain").find_one(
        formal_domain_query({"task_id": task_id, "ips": ip}), {"_id": 1}))


def _legacy_cert_only_pairs(task_ids, only_ip=""):
    pairs = set()
    query = {
        "task_id": {"$in": task_ids},
        "candidate_type": "cert_ip",
        "pipeline_eligible": True,
        "$or": [
            {"cert_verify_status": {"$in": LEGACY_VERIFY_STATUSES}},
            {"relation_reason": "target_specific_sni_cert"},
            {"cert_sni_evidence.current_dns": False},
        ],
    }
    if only_ip:
        query["ip"] = only_ip

    for item in utils.conn_db("asset_seed_candidate").find(
            query, {"task_id": 1, "ip": 1, "cert_sni_evidence": 1}):
        task_id = str(item.get("task_id") or "")
        ip = str(item.get("ip") or "").strip()
        if not task_id or not ip:
            continue
        evidence = list(item.get("cert_sni_evidence") or [])
        if any(value.get("current_dns") is True for value in evidence):
            continue
        if _has_current_dns(task_id, ip):
            continue
        pairs.add((task_id, ip))
    return sorted(pairs)


def _url_regex(ip):
    return re.compile(
        r"^https?://\[?{}\]?(?::\d+)?(?:[/?#]|$)".format(
            re.escape(ip)),
        re.IGNORECASE,
    )


def _direct_ip_query(task_id, ip, fields, direct_fields=()):
    regex = _url_regex(ip)
    clauses = [{field: regex} for field in fields]
    clauses.extend({field: ip} for field in direct_fields)
    return {"task_id": task_id, "$or": clauses}


def _cleanup_queries(task_id, ip):
    provenance_fields = (
        "site", "url", "source_url", "discovered_from",
        "evidence_sources", "parent_entry",
    )
    queries = {
        "asset_seed_alive": _direct_ip_query(
            task_id, ip, ("url",), ("ip", "host")),
        "ip": {"task_id": task_id, "ip": ip},
        "site": _direct_ip_query(
            task_id, ip, ("site", "canonical_site"), ("ip", "hostname")),
        "cert": {"task_id": task_id, "ip": ip},
        "service": {"task_id": task_id, "ip": ip},
        "port_candidate": {"task_id": task_id, "ip": ip},
        "port_site_probe_state": {"task_id": task_id, "ip": ip},
        "port_scan_checkpoint": {"task_id": task_id, "ip": ip},
        "fileleak": _direct_ip_query(
            task_id, ip, ("site", "url", "final_url", "redirect_url")),
        "url": _direct_ip_query(task_id, ip, provenance_fields),
        "wih": _direct_ip_query(task_id, ip, provenance_fields),
        "entry_asset": _direct_ip_query(
            task_id, ip, provenance_fields + ("seed", "entry")),
        "stat_finger": _direct_ip_query(
            task_id, ip, ("site", "url", "target"), ("ip",)),
        "cip": {"task_id": task_id, "ip": ip},
        "npoc_service": _direct_ip_query(
            task_id, ip, ("site", "url", "target"), ("ip",)),
        "nuclei_result": _direct_ip_query(
            task_id, ip, ("site", "url", "target", "matched_at"), ("ip",)),
    }
    vuln_direct = _direct_ip_query(
        task_id, ip, ("site", "url", "target"), ("ip",))
    queries["vuln"] = {
        "$and": [
            vuln_direct,
            {"$nor": [
                {"source": "findvhost"},
                {"plg_name": "FindVhost"},
                {"candidate_disposition": "host_only"},
            ]},
        ],
    }
    return queries


def _quarantine_update(ip, now):
    is_oracle = ip in KNOWN_SNI_ORACLE_IPS
    reason = "multi_sni_cert_oracle" if is_oracle else "no_current_dns_relation"
    status = "quarantined_sni_oracle" if is_oracle else "quarantined_cert_only"
    return {
        "$set": {
            "cert_verified": False,
            "cert_verify_status": status,
            "cert_checked_at": now,
            "relation_level": "weak",
            "status": "quarantined",
            "pipeline_eligible": False,
            "pipeline_exclusion_reason": reason,
            "candidate_disposition": "host_only",
            "host_collision_eligible": not is_oracle,
            "verified_domains": [],
            "verified_ports": [],
            "quarantine_reason": reason,
            "quarantined_at": now,
        },
        "$unset": {
            "rejection_reason": "",
            "rejected_at": "",
        },
        "$addToSet": {
            "sources": "cert_only_cleanup_20260718",
        },
    }


def _backup_documents(handle, collection_name, query):
    count = 0
    for document in utils.conn_db(collection_name).find(query):
        handle.write(json_util.dumps({
            "collection": collection_name,
            "document": document,
        }, ensure_ascii=False))
        handle.write("\n")
        count += 1
    return count


def run(task_limit=28, only_ip="", apply=False, backup_path=""):
    task_ids = _latest_domain_task_ids(task_limit)
    pairs = _legacy_cert_only_pairs(task_ids, only_ip=only_ip)
    counts = Counter()
    quarantine_counts = Counter()
    pair_rows = []
    query_rows = []
    for task_id, ip in pairs:
        pair_count = Counter()
        candidate_query = {
            "task_id": task_id,
            "ip": ip,
            "candidate_type": "cert_ip",
        }
        for collection_name in (
                "asset_seed_candidate", "vhost_ip_candidate"):
            quarantine_counts[collection_name] += utils.conn_db(
                collection_name).count_documents(candidate_query)
        for collection_name, query in _cleanup_queries(task_id, ip).items():
            count = utils.conn_db(collection_name).count_documents(query)
            if count:
                pair_count[collection_name] += count
                counts[collection_name] += count
                query_rows.append((collection_name, query))
        pair_rows.append({
            "task_id": task_id,
            "ip": ip,
            "documents": dict(sorted(pair_count.items())),
        })

    result = {
        "apply": bool(apply),
        "task_limit": task_limit,
        "task_count": len(set(task_id for task_id, _ in pairs)),
        "pair_count": len(pairs),
        "unique_ip_count": len(set(ip for _, ip in pairs)),
        "document_counts": dict(sorted(counts.items())),
        "quarantine_counts": dict(sorted(quarantine_counts.items())),
        "pair_sample": pair_rows[:20],
        "pair_sample_omitted": max(len(pair_rows) - 20, 0),
    }
    if not apply or not pairs:
        return result

    if not backup_path:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = "/opt/ARL/backups/cert_only_cleanup_{}.jsonl.gz".format(stamp)
    os.makedirs(os.path.dirname(backup_path), exist_ok=True)
    with gzip.open(backup_path, "wt", encoding="utf-8") as handle:
        handle.write(json_util.dumps({
            "metadata": {
                "created_at": datetime.now(),
                "task_ids": sorted(set(task_id for task_id, _ in pairs)),
                "pairs": pairs,
                "document_counts": dict(counts),
                "quarantine_counts": dict(quarantine_counts),
            },
        }, ensure_ascii=False))
        handle.write("\n")
        for task_id in sorted(set(task_id for task_id, _ in pairs)):
            _backup_documents(
                handle, "task", {"_id": ObjectId(task_id)})
            for collection_name in ("stat_finger", "cip"):
                _backup_documents(
                    handle, collection_name, {"task_id": task_id})
        for task_id, ip in pairs:
            candidate_query = {
                "task_id": task_id,
                "ip": ip,
                "candidate_type": "cert_ip",
            }
            for collection_name in (
                    "asset_seed_candidate", "vhost_ip_candidate"):
                _backup_documents(handle, collection_name, candidate_query)
        for collection_name, query in query_rows:
            _backup_documents(handle, collection_name, query)

    now = utils.curr_date()
    changed_tasks = set()
    deleted = Counter()
    for task_id, ip in pairs:
        candidate_query = {
            "task_id": task_id,
            "ip": ip,
            "candidate_type": "cert_ip",
        }
        update = _quarantine_update(ip, now)
        utils.conn_db("asset_seed_candidate").update_many(candidate_query, update)
        utils.conn_db("vhost_ip_candidate").update_many(candidate_query, update)
        for collection_name, query in _cleanup_queries(task_id, ip).items():
            deleted[collection_name] += utils.conn_db(
                collection_name).delete_many(query).deleted_count
        changed_tasks.add(task_id)

    for task_id in sorted(changed_tasks):
        task = CommonTask(task_id)
        task.insert_finger_stat()
        task.insert_cip_stat()
        task.insert_task_stat()

    result["backup_path"] = backup_path
    result["deleted_counts"] = dict(sorted(deleted.items()))
    result["changed_task_count"] = len(changed_tasks)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--task-limit", type=int, default=28)
    parser.add_argument("--ip", default="")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--backup-path", default="")
    args = parser.parse_args()
    print(json.dumps(run(
        task_limit=args.task_limit,
        only_ip=args.ip,
        apply=args.apply,
        backup_path=args.backup_path,
    ), ensure_ascii=False, indent=2, default=str))


if __name__ == "__main__":
    main()
