from collections import defaultdict

from pymongo import UpdateOne

from app import utils
from app.utils.site_quality import classify_site_quality


QUALITY_FIELDS = (
    "quality_state", "display_eligible", "pipeline_mode", "quality_reason",
    "quality_evidence", "quality_version", "asset_quality", "asset_visibility",
    "quality_score", "noise_reasons", "evidence_sources", "verification_status",
    "policy_version", "quality_cluster_key",
)


def _body_length(item):
    for field in ("body_length", "content_length"):
        try:
            value = int((item or {}).get(field) or 0)
        except (TypeError, ValueError):
            value = 0
        if value > 0:
            return value
    return 0


def _write_operations(collection, operations, batch_size=500):
    written = 0
    for start in range(0, len(operations), batch_size):
        batch = operations[start:start + batch_size]
        if batch:
            result = collection.bulk_write(batch, ordered=False)
            # matched_count includes unchanged documents and must not be added
            # to modified_count, otherwise progress is reported twice.
            written += int(result.modified_count + result.upserted_count)
    return written


def refresh_site_quality_clusters(task_id, collection_name="site"):
    """Recompute display metadata without deleting or changing raw evidence.

    Only low-information response fingerprints are clustered. Application
    responses and route-confirmed sites remain one row per origin.
    """
    task_id = str(task_id or "").strip()
    if not task_id:
        return {"task_id": task_id, "updated_count": 0, "cluster_count": 0}

    collection = utils.conn_db(collection_name)
    projection = {"_id": 1, "task_id": 1, "site": 1, "title": 1,
                  "status": 1, "status_code": 1, "body_length": 1,
                  "content_length": 1, "body_hash": 1, "header_hash": 1,
                  "http_server": 1, "webserver": 1, "quality_state": 1,
                  "route_discovery_status": 1, "route_hit_count": 1,
                  "browser_title": 1, "browser_title_source": 1,
                  "browser_final_title": 1, "browser_final_url": 1,
                  "browser_cross_origin_redirect": 1,
                  "browser_spa_detected": 1, "runtime_script_count": 1,
                  "runtime_request_count": 1, "spa_profile": 1,
                  "spa_score": 1, "spa_confidence": 1,
                  "spa_framework": 1, "spa_render_mode": 1,
                  "spa_route_mode": 1,
                  "spa_signals": 1, "tech": 1, "finger": 1,
                  "source": 1, "sources": 1, "location": 1,
                  "redirect_location": 1, "canonical_site": 1,
                  "content_type": 1}
    groups = defaultdict(list)
    classified_rows = []
    document_count = 0

    for item in collection.find({"task_id": task_id}, projection):
        document_count += 1
        quality = classify_site_quality(item)
        set_data = {field: quality[field] for field in QUALITY_FIELDS
                    if field in quality}
        set_data.update({
            "quality_cluster_size": 1,
            "quality_cluster_representative": True,
        })
        classified_rows.append((item, quality, set_data))
        cluster_key = quality.get("quality_cluster_key")
        if cluster_key:
            groups[cluster_key].append((item, quality, set_data))

    cluster_count = 0
    collapsed_count = 0
    for cluster_key, members in groups.items():
        if len(members) < 2:
            continue
        cluster_count += 1
        members.sort(key=lambda pair: (
            -int(pair[1].get("quality_score", 0) or 0),
            not bool(pair[0].get("title") or pair[0].get("browser_title")),
            -_body_length(pair[0]),
            str(pair[0].get("_id")),
        ))
        representative_id = members[0][0]["_id"]
        for item, quality, set_data in members:
            item_id = item["_id"]
            visible = bool(
                item_id == representative_id and
                quality.get("display_eligible")
            )
            reasons = list(set_data.get("noise_reasons") or [])
            set_data.update({
                "quality_cluster_size": len(members),
                "quality_cluster_representative": item_id == representative_id,
                "display_eligible": visible,
                "asset_visibility": "visible" if visible else "hidden_noise",
                "noise_reasons": list(dict.fromkeys(
                    reasons + ["repeated_response_template"]
                )),
            })
        collapsed_count += max(len(members) - 1, 0)

    # Each document is written once with its final classification and cluster
    # metadata. This avoids a window where every duplicate temporarily becomes
    # a representative and cuts the rebuild write volume roughly in half.
    operations = [
        UpdateOne({"_id": item["_id"]}, {"$set": set_data})
        for item, _quality, set_data in classified_rows
    ]
    updated_count = _write_operations(collection, operations)

    return {
        "task_id": task_id,
        "document_count": document_count,
        "updated_count": updated_count,
        "cluster_count": cluster_count,
        "collapsed_count": collapsed_count,
    }
