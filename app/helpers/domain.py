from app import utils
from app.utils.site_scope import formal_domain_query


def find_private_domain_by_task_id(task_id):
    query = {
        "task_id": task_id,
        "ip_type": "PRIVATE"
    }
    domains = []
    items = utils.conn_db('ip').find(query)
    for item in list(items):
        if not item.get("domain"):
            continue
        domains.extend(item["domain"])

    return list(set(domains))


def find_public_ip_by_task_id(task_id):
    query = {
        "task_id": task_id,
        "ip_type": "PUBLIC"
    }
    items = utils.conn_db('ip').distinct("ip", query)
    return list(items)


def find_vhost_candidate_ip_by_task_id(task_id):
    query = {
        "task_id": task_id,
        "ip_type": "PUBLIC"
    }
    ips = set()
    fields = {
        "_id": 0,
        "ip": 1,
        "candidate_type": 1,
        "cert_verified": 1,
        "pipeline_eligible": 1,
        "status": 1,
    }
    for item in utils.conn_db('vhost_ip_candidate').find(query, fields):
        if item.get("candidate_type") == "cert_ip" and not (
                item.get("cert_verified") is True and
                item.get("pipeline_eligible") is True and
                item.get("status") != "quarantined"):
            continue
        ip = str(item.get("ip") or "").strip()
        if ip:
            ips.add(ip)
    return sorted(ips)


def find_domain_by_task_id(task_id):
    query = formal_domain_query({
        "task_id": task_id
    })
    items = utils.conn_db('domain').distinct("domain", query)
    return list(items)
