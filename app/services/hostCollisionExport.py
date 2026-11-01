import ipaddress
import re
from collections import defaultdict
from urllib.parse import urlparse

from app import utils
from app.utils.host_collision import HOST_COLLISION_CONFIRMED_MATCH


def _list_value(value):
    if value in (None, ""):
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _collision_ip(item):
    verify_obj = item.get("verify_obj") or {}
    candidates = [
        item.get("host_collision_ip"),
        verify_obj.get("ip"),
        verify_obj.get("url"),
        item.get("target"),
    ]
    for value in candidates:
        value = str(value or "").strip()
        if not value:
            continue
        if "://" in value:
            hostname = urlparse(value).hostname or ""
        else:
            hostname = value.strip("[]")
            if ":" in hostname:
                hostname = urlparse("//" + hostname).hostname or hostname
        try:
            return str(ipaddress.ip_address(hostname))
        except ValueError:
            continue
    return ""


def _collision_host(item):
    verify_obj = item.get("verify_obj") or {}
    candidates = [
        verify_obj.get("domain"),
        item.get("host_collision_domain"),
        item.get("domain"),
    ]
    for value in candidates:
        host = str(value or "").strip().strip("*.").lower()
        if host and utils.is_valid_domain(host) and not utils.check_domain_black(host):
            return host
    return ""


def normalize_host_collision_item(item, task_meta=None):
    ip = _collision_ip(item)
    host = _collision_host(item)
    if not ip or not host:
        return None

    task_id = str(item.get("task_id") or "")
    task = (task_meta or {}).get(task_id, {})
    verify_obj = item.get("verify_obj") or {}
    return {
        "_id": "{}|{}".format(ip, host),
        "ip": ip,
        "host": host,
        "target": str(verify_obj.get("url") or item.get("target") or ""),
        "status_code": verify_obj.get("status_code"),
        "title": str(verify_obj.get("title") or ""),
        "body_length": verify_obj.get("body_length"),
        "confidence": str(verify_obj.get("confidence") or ""),
        "quality": str(
            verify_obj.get("quality") or
            item.get("host_collision_quality") or ""),
        "response_signature": str(
            verify_obj.get("response_signature") or
            item.get("host_collision_signature") or ""),
        "task_ids": [task_id] if task_id else [],
        "task_names": [str(task.get("name") or "")] if task.get("name") else [],
        "task_targets": [str(task.get("target") or "")] if task.get("target") else [],
        "save_date": str(item.get("save_date") or ""),
    }


def _merge_unique(target, values):
    for value in values:
        if value not in (None, "") and value not in target:
            target.append(value)


def merge_host_collision_rows(items, task_meta=None):
    rows = {}
    for item in items or []:
        row = normalize_host_collision_item(item, task_meta=task_meta)
        if not row:
            continue
        key = (row["ip"], row["host"])
        current = rows.get(key)
        if current is None:
            rows[key] = row
            continue

        _merge_unique(current["task_ids"], row["task_ids"])
        _merge_unique(current["task_names"], row["task_names"])
        _merge_unique(current["task_targets"], row["task_targets"])
        if row["save_date"] > current["save_date"]:
            for field in (
                    "target", "status_code", "title", "body_length", "confidence",
                    "quality", "response_signature", "save_date"):
                current[field] = row[field]

    result = list(rows.values())
    for row in result:
        row["task_ids"].sort()
        row["task_names"].sort()
        row["task_targets"].sort()
        row["task_count"] = len(row["task_ids"])
    return result


def _ip_sort_key(value):
    try:
        address = ipaddress.ip_address(str(value or ""))
        return address.version, int(address)
    except ValueError:
        return 99, str(value or "")


def sort_host_collision_rows(rows, order="ip,host"):
    order_fields = [field.strip() for field in str(order or "ip,host").split(",") if field.strip()]
    result = list(rows or [])
    for raw_field in reversed(order_fields or ["ip", "host"]):
        descending = raw_field.startswith("-")
        field = raw_field.lstrip("+-")
        if field == "ip":
            key = lambda item: _ip_sort_key(item.get("ip"))
        else:
            key = lambda item, name=field: str(item.get(name) or "").lower()
        result.sort(key=key, reverse=descending)
    return result


def task_meta(task_ids):
    valid_ids = [task_id for task_id in set(task_ids or []) if task_id]
    # Keep ObjectId handling local so malformed historical task IDs are ignored.
    from bson import ObjectId
    object_ids = [ObjectId(task_id) for task_id in valid_ids if ObjectId.is_valid(task_id)]
    ret = {}
    for item in utils.conn_db("task").find(
            {"_id": {"$in": object_ids}}, {"name": 1, "target": 1}):
        ret[str(item.get("_id"))] = {
            "name": item.get("name", ""),
            "target": item.get("target", ""),
        }
    return ret


def host_collision_rows(task_ids, keyword="", ip="", host="", order="ip,host"):
    task_ids = sorted(set(str(task_id or "") for task_id in task_ids if task_id))
    if not task_ids:
        return []

    query = {
        "task_id": {"$in": task_ids},
        **HOST_COLLISION_CONFIRMED_MATCH,
    }
    projection = {
        "_id": 1,
        "task_id": 1,
        "target": 1,
        "save_date": 1,
        "verify_obj": 1,
        "domain": 1,
        "host_collision_domain": 1,
        "host_collision_quality": 1,
        "host_collision_signature": 1,
    }
    rows = merge_host_collision_rows(
        utils.conn_db("vuln").find(query, projection),
        task_meta=task_meta(task_ids),
    )

    keyword = str(keyword or "").strip().lower()
    ip = str(ip or "").strip().lower()
    host = str(host or "").strip().lower()
    filtered = []
    for row in rows:
        if ip and ip not in row["ip"].lower():
            continue
        if host and host not in row["host"].lower():
            continue
        if keyword:
            values = [
                row.get("ip"), row.get("host"), row.get("title"),
                row.get("target"), row.get("task_names"), row.get("task_targets"),
            ]
            haystack = " ".join(
                str(value or "") for raw in values for value in _list_value(raw)
            ).lower()
            if keyword not in haystack:
                continue
        filtered.append(row)
    return sort_host_collision_rows(filtered, order=order)


def host_collision_page(
        task_ids, keyword="", ip="", host="", order="ip,host",
        page=1, size=10):
    task_ids = sorted(set(str(task_id or "") for task_id in task_ids if task_id))
    page = max(int(page or 1), 1)
    size = max(min(int(size or 10), 100000), 1)
    if not task_ids:
        return {"page": page, "size": size, "total": 0, "items": []}

    collection = utils.conn_db("vuln")
    base_query = {
        "task_id": {"$in": task_ids},
        "host_collision_ip": {"$exists": True, "$nin": [None, ""]},
        "host_collision_domain": {"$exists": True, "$nin": [None, ""]},
        **HOST_COLLISION_CONFIRMED_MATCH,
    }
    metadata = task_meta(task_ids)
    pipeline = [
        {"$match": base_query},
        {"$sort": {"save_date": -1, "_id": -1}},
        {"$group": {
            "_id": {
                "ip": "$host_collision_ip",
                "host": "$host_collision_domain",
            },
            "ip_sort": {"$first": "$host_collision_ip_sort"},
            "target": {"$first": "$target"},
            "status_code": {"$first": "$verify_obj.status_code"},
            "title": {"$first": "$verify_obj.title"},
            "body_length": {"$first": "$verify_obj.body_length"},
            "confidence": {"$first": "$verify_obj.confidence"},
            "quality": {"$first": {"$ifNull": [
                "$verify_obj.quality", "$host_collision_quality"]}},
            "response_signature": {"$first": {"$ifNull": [
                "$verify_obj.response_signature", "$host_collision_signature"]}},
            "save_date": {"$first": "$save_date"},
            "task_ids": {"$addToSet": "$task_id"},
        }},
        {"$project": {
            "_id": 0,
            "ip": "$_id.ip",
            "host": "$_id.host",
            "ip_sort": 1,
            "target": 1,
            "status_code": 1,
            "title": 1,
            "body_length": 1,
            "confidence": 1,
            "quality": 1,
            "response_signature": 1,
            "save_date": 1,
            "task_ids": 1,
            "task_count": {"$size": "$task_ids"},
        }},
    ]

    filters = []
    if ip:
        filters.append({"ip": {"$regex": re.escape(str(ip)), "$options": "i"}})
    if host:
        filters.append({"host": {"$regex": re.escape(str(host)), "$options": "i"}})
    keyword = str(keyword or "").strip()
    if keyword:
        regex = {"$regex": re.escape(keyword), "$options": "i"}
        matching_task_ids = [
            task_id for task_id, item in metadata.items()
            if keyword.lower() in "{} {}".format(
                item.get("name", ""), item.get("target", "")).lower()
        ]
        keyword_filters = [
            {"ip": regex}, {"host": regex}, {"title": regex}, {"target": regex},
        ]
        if matching_task_ids:
            keyword_filters.append({"task_ids": {"$in": matching_task_ids}})
        filters.append({"$or": keyword_filters})
    if filters:
        pipeline.append({"$match": {"$and": filters}})

    sort_spec = {}
    allowed_fields = {
        "ip": "ip_sort",
        "host": "host",
        "title": "title",
        "status_code": "status_code",
        "quality": "quality",
        "save_date": "save_date",
        "task_count": "task_count",
    }
    for raw_field in str(order or "ip,host").split(","):
        raw_field = raw_field.strip()
        field = raw_field.lstrip("+-")
        mapped = allowed_fields.get(field)
        if mapped:
            sort_spec[mapped] = -1 if raw_field.startswith("-") else 1
    sort_spec.setdefault("host", 1)
    pipeline.extend([
        {"$sort": sort_spec},
        {"$facet": {
            "items": [
                {"$skip": size * (page - 1)},
                {"$limit": size},
            ],
            "total": [{"$count": "value"}],
        }},
    ])

    aggregate = list(collection.aggregate(pipeline, allowDiskUse=True))
    payload = aggregate[0] if aggregate else {"items": [], "total": []}
    rows = payload.get("items") or []
    total_values = payload.get("total") or []
    total = int(total_values[0].get("value", 0) or 0) if total_values else 0

    # A deployment migration backfills normalized fields. Keep historical
    # installations usable if that migration has not run yet.
    if total == 0 and collection.count_documents({
            "task_id": {"$in": task_ids}, **HOST_COLLISION_CONFIRMED_MATCH}):
        fallback = host_collision_rows(
            task_ids, keyword=keyword, ip=ip, host=host, order=order)
        start = size * (page - 1)
        return {
            "page": page,
            "size": size,
            "total": len(fallback),
            "items": fallback[start:start + size],
            "aggregation_fallback": True,
        }

    for row in rows:
        row["_id"] = "{}|{}".format(row.get("ip", ""), row.get("host", ""))
        row["save_date"] = str(row.get("save_date") or "")
        row["task_ids"] = sorted(set(row.get("task_ids") or []))
        row["task_names"] = sorted({
            str(metadata.get(task_id, {}).get("name") or "")
            for task_id in row["task_ids"]
            if metadata.get(task_id, {}).get("name")
        })
        row["task_targets"] = sorted({
            str(metadata.get(task_id, {}).get("target") or "")
            for task_id in row["task_ids"]
            if metadata.get(task_id, {}).get("target")
        })
        row.pop("ip_sort", None)
    return {"page": page, "size": size, "total": total, "items": rows}


def hosts_file_lines(rows):
    hosts_by_ip = defaultdict(set)
    for row in rows or []:
        ip = str(row.get("ip") or "").strip()
        host = str(row.get("host") or "").strip().lower()
        if ip and host:
            hosts_by_ip[ip].add(host)

    lines = []
    for ip in sorted(hosts_by_ip, key=_ip_sort_key):
        lines.append("{}\t{}".format(ip, " ".join(sorted(hosts_by_ip[ip]))))
    return lines
