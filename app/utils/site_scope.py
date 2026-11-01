from .site_quality import (
    LEGACY_HIDDEN_TITLE_REGEX,
    VISIBLE_SITE_QUALITY_STATES,
)


HOST_COLLISION_TAG = "Host碰撞"


def _host_collision_markers():
    return [
        {"candidate_disposition": "host_only"},
        {"source": "findvhost"},
        {"sources": "findvhost"},
        {"tag": HOST_COLLISION_TAG},
        {"host_collision_domain": {"$exists": True, "$nin": [None, ""]}},
    ]


def _pipeline_exclusion_markers():
    """Evidence-only records that must never enter the formal pipeline.

    Older formal records predate ``pipeline_eligible`` and legitimately have
    no flag. Candidate records, however, carry a stable relation/type marker,
    so those markers are also required here. This closes the Mongo ``$ne``
    missing-field loophole without hiding legacy formal assets.
    """
    return [
        {"pipeline_eligible": False},
        {"candidate_disposition": "host_only"},
        {"candidate_type": {"$in": ["mapping", "mapping_ip", "wildcard_dns"]}},
        {"relation_reason": "cert_cn_san_mismatch"},
    ]


def is_host_collision_site(item):
    item = item or {}
    tags = item.get("tag") or []
    if not isinstance(tags, (list, tuple, set)):
        tags = [tags]
    sources = item.get("sources") or []
    if not isinstance(sources, (list, tuple, set)):
        sources = [sources]
    return bool(
        item.get("candidate_disposition") == "host_only" or
        str(item.get("source") or "").lower() == "findvhost" or
        any(str(value or "").lower() == "findvhost" for value in sources) or
        HOST_COLLISION_TAG in tags or
        item.get("host_collision_domain")
    )


def is_formal_site(item):
    return bool(
        item and
        item.get("pipeline_eligible") is not False and
        not is_host_collision_site(item)
    )


def _merge_scope_query(query, scope_query):
    query = dict(query or {})
    if not query:
        return scope_query
    return {"$and": [query, scope_query]}


def formal_site_query(query=None):
    markers = _host_collision_markers() + _pipeline_exclusion_markers()
    return _merge_scope_query(query, {"$nor": markers})


def visible_site_query(query=None):
    """Return user-facing sites while retaining the complete evidence set.

    New rows use explicit quality fields. The final branch is a conservative
    compatibility filter for historical rows that have not been backfilled.
    """
    quality_query = {"$or": [
        {"quality_state": {"$in": sorted(VISIBLE_SITE_QUALITY_STATES)}},
        {"$and": [
            {"quality_state": {"$exists": False}},
            {"display_eligible": True},
        ]},
        {"$and": [
            {"display_eligible": {"$exists": False}},
            {"quality_state": {"$exists": False}},
            {"status": {"$nin": [404, "404", 410, "410"]}},
            {"status_code": {"$nin": [404, "404", 410, "410"]}},
            {"$or": [
                {"browser_title": {"$exists": True, "$nin": [None, ""]}},
                {"$nor": [{"title": {
                    "$regex": LEGACY_HIDDEN_TITLE_REGEX,
                    "$options": "i",
                }}]},
            ]},
        ]},
    ]}
    cluster_query = {"$or": [
        {"quality_cluster_representative": True},
        {"quality_cluster_representative": {"$exists": False}},
    ]}
    # Explicit suppression fields are authoritative. Keeping these guards at
    # query time makes Mongo list/count results agree with
    # site_is_display_eligible() even if a partial historical write leaves a
    # visible quality_state beside a hidden display flag.
    visibility_query = {"$and": [
        {"display_eligible": {"$ne": False}},
        {"asset_visibility": {"$ne": "hidden_noise"}},
    ]}
    return _merge_scope_query(
        _merge_scope_query(
            _merge_scope_query(formal_site_query(query), quality_query),
            cluster_query,
        ),
        visibility_query,
    )


def host_collision_site_query(query=None):
    return _merge_scope_query(query, {"$or": _host_collision_markers()})


def _wildcard_domain_markers():
    return _pipeline_exclusion_markers() + [
        {"wildcard_suspect": True},
        {"candidate_type": "wildcard_dns"},
        {"candidate_disposition": "wildcard_dns"},
    ]


def is_formal_domain(item):
    item = item or {}
    return bool(
        item and
        item.get("pipeline_eligible") is not False and
        item.get("wildcard_suspect") is not True and
        item.get("candidate_type") != "wildcard_dns" and
        item.get("candidate_disposition") != "wildcard_dns"
    )


def formal_domain_query(query=None):
    return _merge_scope_query(query, {"$nor": _wildcard_domain_markers()})


def formal_pipeline_query(query=None):
    query = dict(query or {})
    constraints = {
        "pipeline_eligible": {"$ne": False},
        "wildcard_suspect": {"$ne": True},
        "candidate_disposition": {"$ne": "wildcard_dns"},
        # Keep legacy formal rows with a missing flag, but reject known
        # candidate-only rows even when their older documents lack the flag.
        "candidate_type": {"$nin": ["mapping", "mapping_ip", "wildcard_dns"]},
        "relation_reason": {"$ne": "cert_cn_san_mismatch"},
    }
    if any(field in query for field in constraints):
        return _merge_scope_query(query, constraints)
    query.update(constraints)
    return query
