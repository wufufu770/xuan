HOST_COLLISION_FILTERS = (
    {"plg_name": "FindVhost"},
    {"source": "findvhost"},
    {"vul_name": "发现Host碰撞漏洞"},
)

HOST_COLLISION_MATCH = {
    "$or": [dict(item) for item in HOST_COLLISION_FILTERS],
}

HOST_COLLISION_CONFIRMED_STATUS_CODES = (200,)
HOST_COLLISION_REJECTED_REASONS = (
    "alive_site_historical_ip",
    "candidate_blocked",
    "candidate_ip_blocked",
    "weak_candidate_source",
)
HOST_COLLISION_ALLOWED_DNS_STATUSES = (
    "public_unresolved",
    "private_resolve",
    "mixed_private_public_resolve",
    "non_public_resolve",
)
HOST_COLLISION_POLICY_VERSION = "20260811_strict_candidate_ip_v4"

HOST_COLLISION_CANDIDATE_COLLECTIONS = (
    "asset_seed_candidate",
    "vhost_ip_candidate",
    "cert_candidate",
)

HOST_COLLISION_WEAK_ENDPOINT_SOURCES = set(HOST_COLLISION_CANDIDATE_COLLECTIONS) | {
    "default_web_port",
}

HOST_COLLISION_BLOCKED_CANDIDATE_REASONS = {
    "multi_sni_cert_oracle",
    "quarantined_sni_oracle",
    "same_certificate_for_random_sni",
    "quarantined_shared_default",
    "cert_cn_san_mismatch",
    "rejected_scope_mismatch",
    "scope_mismatch",
}

HOST_COLLISION_BLOCKED_REASON_FRAGMENTS = (
    "sni_oracle",
    "random_sni",
    "shared_default",
    "cn_san_mismatch",
    "scope_mismatch",
)

# Non-200 responses remain available as raw evidence, but are never treated as
# successful Host mappings.
HOST_COLLISION_CONFIRMED_MATCH = {
    "$and": [
        {"$or": [dict(item) for item in HOST_COLLISION_FILTERS]},
        {"verify_obj.status_code": {
            "$in": list(HOST_COLLISION_CONFIRMED_STATUS_CODES),
        }},
        {"verify_obj.host_collision_reason": {
            "$nin": list(HOST_COLLISION_REJECTED_REASONS),
        }},
        {"verify_obj.host_dns_status": {
            "$in": list(HOST_COLLISION_ALLOWED_DNS_STATUSES),
        }},
        {"host_collision_archived": {"$ne": True}},
        {"$or": [
            {"host_collision_policy_version": HOST_COLLISION_POLICY_VERSION},
            {"verify_obj.host_collision_policy_version": HOST_COLLISION_POLICY_VERSION},
            {"verify_obj.endpoint_sources": {
                "$elemMatch": {
                    "$nin": sorted(HOST_COLLISION_WEAK_ENDPOINT_SOURCES),
                },
            }},
            {"verify_obj.endpoint_sources": {"$exists": False}},
        ]},
    ],
}

HOST_COLLISION_EXCLUDE = {
    "$nor": [dict(item) for item in HOST_COLLISION_FILTERS],
}
