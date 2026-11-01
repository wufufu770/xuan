from urllib.parse import urlparse


def normalize_domain(value):
    value = str(value or "").strip().strip("*.").lower()
    if "://" in value:
        value = urlparse(value).hostname or ""
    if ":" in value:
        value = value.split(":", 1)[0]
    return value.strip(".")


def _normalize_intel(intel, source):
    if not isinstance(intel, dict):
        return None
    item = dict(intel)
    item["source"] = str(item.get("source") or source or "").strip()
    if item.get("ip") is not None:
        item["ip"] = str(item.get("ip") or "").strip()
    if item.get("port") not in (None, ""):
        try:
            item["port"] = int(item["port"])
        except (TypeError, ValueError):
            item["port"] = str(item["port"]).strip()
    if item.get("status_code") not in (None, ""):
        try:
            item["status_code"] = int(item["status_code"])
        except (TypeError, ValueError):
            item["status_code"] = str(item["status_code"]).strip()
    item["source_family"] = str(item.get("source_family") or "").strip()
    item["query_type"] = str(item.get("query_type") or "passive").strip()
    return item


def _intel_key(intel):
    return (
        str(intel.get("source") or ""),
        str(intel.get("ip") or ""),
        str(intel.get("port") or ""),
        str(intel.get("query_type") or ""),
        str(intel.get("url") or ""),
    )


def aggregate_plugin_results(source_results):
    """Aggregate nondeterministic plugin output while preserving all evidence."""
    domain_map = {}
    candidate_map = {}

    for source, results in sorted(source_results, key=lambda item: str(item[0] or "")):
        source = str(source or "").strip()
        for result in results or []:
            if isinstance(result, dict):
                domain = normalize_domain(result.get("domain"))
                intels = result.get("intels") or []
                if result.get("intel"):
                    intels = list(intels) + [result.get("intel")]
                candidate_type = str(result.get("candidate_type") or "").strip()
            else:
                domain = normalize_domain(result)
                intels = []
                candidate_type = ""

            normalized_intels = []
            for intel in intels:
                normalized = _normalize_intel(intel, source)
                if normalized:
                    normalized_intels.append(normalized)

            if domain:
                item = domain_map.setdefault(domain, {
                    "domain": domain,
                    "sources": set(),
                    "intels": {},
                })
                item["sources"].add(source)
                for intel in normalized_intels:
                    item["sources"].add(intel.get("source") or source)
                    item["intels"][_intel_key(intel)] = intel
                continue

            for intel in normalized_intels:
                ip = str(intel.get("ip") or "").strip()
                if not ip:
                    continue
                query_type = str(intel.get("query_type") or "").strip()
                normalized_candidate_type = candidate_type
                if not normalized_candidate_type:
                    normalized_candidate_type = "cert_ip" if query_type == "cert" else "mapping_ip"
                if normalized_candidate_type not in ("cert_ip", "mapping_ip", "mapping"):
                    continue
                if normalized_candidate_type == "mapping":
                    normalized_candidate_type = "mapping_ip"
                # One IP is one candidate. Keep every source/port as evidence
                # and let certificate evidence upgrade the relationship.
                key = ip
                item = candidate_map.setdefault(key, {
                    "domain": "",
                    "candidate_only": True,
                    "candidate_type": normalized_candidate_type,
                    "sources": set(),
                    "intels": {},
                })
                if normalized_candidate_type == "cert_ip":
                    item["candidate_type"] = "cert_ip"
                item["sources"].add(source)
                item["sources"].add(intel.get("source") or source)
                item["intels"][_intel_key(intel)] = intel

    output = []
    for key in sorted(domain_map):
        item = domain_map[key]
        sources = sorted(value for value in item["sources"] if value)
        intels = [item["intels"][value] for value in sorted(item["intels"])]
        payload = {
            "domain": item["domain"],
            "source": sources[0] if sources else "",
            "sources": sources,
        }
        if intels:
            payload["intel"] = intels[0]
            payload["intels"] = intels
        output.append(payload)

    for key in sorted(candidate_map):
        item = candidate_map[key]
        sources = sorted(value for value in item["sources"] if value)
        intels = [item["intels"][value] for value in sorted(item["intels"])]
        payload = {
            "domain": "",
            "source": sources[0] if sources else "",
            "sources": sources,
            "candidate_only": True,
            "candidate_type": item["candidate_type"],
            "intel": intels[0],
            "intels": intels,
        }
        output.append(payload)
    return output
