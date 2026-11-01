import concurrent.futures
from collections import defaultdict

import dns.exception
import dns.query
import dns.rdatatype
import dns.resolver

from app import utils
from app.config import Config
from app.services.resourceBudget import acquire as acquire_resource_budget


logger = utils.get_logger()


DEFAULT_SRV_PREFIXES = (
    "_sip._tcp",
    "_sips._tcp",
    "_xmpp-client._tcp",
    "_xmpp-server._tcp",
    "_ldap._tcp",
    "_ldaps._tcp",
    "_kerberos._tcp",
    "_kpasswd._tcp",
    "_autodiscover._tcp",
    "_caldav._tcp",
    "_carddav._tcp",
    "_imaps._tcp",
    "_submission._tcp",
)


def _normalize_domain(value):
    value = str(value or "").strip().lower().rstrip(".")
    if value.startswith("*."):
        value = value[2:]
    return value


def _domain_in_scope(domain, base_domain):
    domain = _normalize_domain(domain)
    base_domain = _normalize_domain(base_domain)
    return bool(
        domain and base_domain and
        (domain == base_domain or domain.endswith("." + base_domain))
    )


def _valid_asset_domain(domain, base_domain):
    domain = _normalize_domain(domain)
    if domain == _normalize_domain(base_domain):
        return ""
    if not _domain_in_scope(domain, base_domain):
        return ""
    if not utils.is_valid_domain(domain) or utils.check_domain_black(domain):
        return ""
    return domain


def candidate_parent_domains(base_domain, domains, limit=40):
    base_domain = _normalize_domain(base_domain)
    parents = set()
    for value in domains or []:
        domain = _valid_asset_domain(value, base_domain)
        if not domain:
            continue
        prefix = domain[:-(len(base_domain) + 1)]
        labels = [label for label in prefix.split(".") if label]
        if len(labels) == 1:
            parents.add(domain)
        elif len(labels) >= 2:
            parents.add("{}.{}".format(".".join(labels[1:]), base_domain))
    return sorted(parents)[:max(int(limit or 0), 0)]


class DNSAuxiliary(object):
    def __init__(self, base_domain, candidate_domains=None, task_id=""):
        self.base_domain = _normalize_domain(base_domain)
        self.candidate_domains = list(candidate_domains or [])
        self.task_id = str(task_id or "")
        self.timeout = max(float(getattr(Config, "DNS_AUXILIARY_TIMEOUT", 2) or 2), 0.5)
        self.lifetime = max(
            float(getattr(Config, "DNS_AUXILIARY_LIFETIME", 4) or 4),
            self.timeout,
        )

    def _resolver(self):
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.lifetime
        return resolver

    def _resolve(self, name, rdtype):
        return self._resolver().resolve(
            name, rdtype, raise_on_no_answer=False, search=False)

    @staticmethod
    def _expected_empty(error):
        return isinstance(error, (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
        ))

    def _authoritative_nameservers(self):
        try:
            answer = self._resolve(self.base_domain, "NS")
        except Exception as error:
            if not self._expected_empty(error):
                logger.warning("dns auxiliary NS query failed {}: {}".format(
                    self.base_domain, error))
            return []
        return sorted({
            _normalize_domain(getattr(item, "target", item))
            for item in answer
            if _normalize_domain(getattr(item, "target", item))
        })

    def _nameserver_ipv4(self, nameserver):
        try:
            answer = self._resolve(nameserver, "A")
        except Exception:
            return []
        return sorted({str(item).strip() for item in answer if str(item).strip()})

    def _parse_transfer(self, messages):
        domains = set()
        delegated = set()
        srv_evidence = defaultdict(list)
        record_count = 0
        max_records = max(int(getattr(
            Config, "DNS_AXFR_MAX_RECORDS", 5000) or 5000), 1)
        for message in messages:
            for rrset in getattr(message, "answer", []) or []:
                owner = _normalize_domain(getattr(rrset, "name", ""))
                rdtype = dns.rdatatype.to_text(rrset.rdtype)
                owner_asset = _valid_asset_domain(owner, self.base_domain)
                if owner_asset and rdtype in ("A", "CNAME", "MX", "NS"):
                    domains.add(owner_asset)
                if owner_asset and rdtype == "NS":
                    delegated.add(owner_asset)

                for item in rrset:
                    record_count += 1
                    target = ""
                    if hasattr(item, "target"):
                        target = _normalize_domain(item.target)
                    elif hasattr(item, "exchange"):
                        target = _normalize_domain(item.exchange)
                    target = _valid_asset_domain(target, self.base_domain)
                    if target:
                        domains.add(target)
                        if rdtype == "SRV":
                            srv_evidence[target].append({
                                "query": owner,
                                "port": int(getattr(item, "port", 0) or 0),
                                "source": "dns_axfr",
                            })
                    if record_count >= max_records:
                        return domains, delegated, srv_evidence, record_count, True
        return domains, delegated, srv_evidence, record_count, False

    def run_axfr(self):
        result = {
            "domains": set(),
            "delegated_domains": set(),
            "srv_evidence": defaultdict(list),
            "status": "disabled",
            "record_count": 0,
            "nameserver_count": 0,
            "truncated": False,
        }
        if not getattr(Config, "DNS_AXFR_ENABLE", True):
            return result

        nameservers = self._authoritative_nameservers()
        max_ns = max(int(getattr(Config, "DNS_AXFR_MAX_NAMESERVERS", 3) or 3), 1)
        result["nameserver_count"] = min(len(nameservers), max_ns)
        result["status"] = "not_allowed"
        for nameserver in nameservers[:max_ns]:
            for address in self._nameserver_ipv4(nameserver):
                try:
                    messages = dns.query.xfr(
                        address,
                        self.base_domain,
                        timeout=self.timeout,
                        lifetime=max(float(getattr(
                            Config, "DNS_AXFR_LIFETIME", 8) or 8), self.timeout),
                        relativize=False,
                    )
                    parsed = self._parse_transfer(messages)
                except Exception as error:
                    logger.debug("AXFR unavailable {} via {}: {}".format(
                        self.base_domain, nameserver, error))
                    continue
                domains, delegated, srv_evidence, count, truncated = parsed
                result.update({
                    "domains": domains,
                    "delegated_domains": delegated,
                    "srv_evidence": srv_evidence,
                    "status": "done",
                    "record_count": count,
                    "truncated": truncated,
                    "nameserver": nameserver,
                })
                return result
        return result

    def _query_srv(self, prefix):
        query_name = "{}.{}".format(prefix.rstrip("."), self.base_domain)
        output = []
        try:
            answer = self._resolve(query_name, "SRV")
        except Exception as error:
            if self._expected_empty(error):
                return output, "empty"
            if isinstance(error, dns.exception.Timeout):
                return output, "timeout"
            return output, "error"

        for item in answer:
            target = _valid_asset_domain(
                getattr(item, "target", ""), self.base_domain)
            if not target:
                continue
            output.append({
                "domain": target,
                "query": query_name,
                "service": prefix,
                "port": int(getattr(item, "port", 0) or 0),
                "priority": int(getattr(item, "priority", 0) or 0),
                "weight": int(getattr(item, "weight", 0) or 0),
                "source": "dns_srv",
            })
        return output, "done" if output else "empty"

    def run_srv(self):
        if not getattr(Config, "DNS_SRV_ENABLE", True):
            return [], {"status": "disabled", "query_count": 0}
        prefixes = getattr(Config, "DNS_SRV_PREFIXES", DEFAULT_SRV_PREFIXES)
        if isinstance(prefixes, str):
            prefixes = [value.strip() for value in prefixes.split(",") if value.strip()]
        prefixes = list(dict.fromkeys(prefixes or DEFAULT_SRV_PREFIXES))
        workers = min(
            max(int(getattr(Config, "DNS_AUXILIARY_WORKERS", 6) or 1), 1),
            max(len(prefixes), 1),
        )
        records = []
        status_count = defaultdict(int)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(self._query_srv, prefix) for prefix in prefixes]
            for future in concurrent.futures.as_completed(futures):
                values, status = future.result()
                records.extend(values)
                status_count[status] += 1
        return records, {
            "status": "done",
            "query_count": len(prefixes),
            "hit_count": len(records),
            "timeout_count": status_count.get("timeout", 0),
            "error_count": status_count.get("error", 0),
        }

    def _query_delegation(self, domain):
        try:
            answer = self._resolve(domain, "NS")
        except Exception:
            return "", []
        nameservers = sorted({
            _normalize_domain(getattr(item, "target", item))
            for item in answer
            if _normalize_domain(getattr(item, "target", item))
        })
        return (domain, nameservers) if nameservers else ("", [])

    def find_delegated_domains(self):
        limit = max(int(getattr(
            Config, "DNS_DELEGATION_CANDIDATE_LIMIT", 40) or 0), 0)
        candidates = candidate_parent_domains(
            self.base_domain, self.candidate_domains, limit=limit)
        if not candidates:
            return set(), {"query_count": 0, "hit_count": 0}
        workers = min(
            max(int(getattr(Config, "DNS_AUXILIARY_WORKERS", 6) or 1), 1),
            len(candidates),
        )
        delegated = set()
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(self._query_delegation, item) for item in candidates]
            for future in concurrent.futures.as_completed(futures):
                domain, nameservers = future.result()
                if domain and nameservers:
                    delegated.add(domain)
        return delegated, {
            "query_count": len(candidates),
            "hit_count": len(delegated),
        }

    def run(self):
        with acquire_resource_budget(
                "tool:dns_auxiliary", task_id=self.task_id, stage="dns_auxiliary"):
            axfr = self.run_axfr()
            srv_records, srv_meta = self.run_srv()
            delegated, delegation_meta = self.find_delegated_domains()

        domains = set(axfr.get("domains") or [])
        domain_sources = defaultdict(set)
        for domain in domains:
            domain_sources[domain].add("dns_axfr")

        srv_evidence = defaultdict(list)
        for domain, values in (axfr.get("srv_evidence") or {}).items():
            srv_evidence[domain].extend(values)
        for item in srv_records:
            domain = item["domain"]
            domains.add(domain)
            domain_sources[domain].add("dns_srv")
            srv_evidence[domain].append(item)

        delegated.update(axfr.get("delegated_domains") or [])
        return {
            "domains": sorted(domains),
            "domain_sources": {
                domain: sorted(sources)
                for domain, sources in domain_sources.items()
            },
            "delegated_domains": sorted(delegated),
            "srv_evidence": dict(srv_evidence),
            "meta": {
                "axfr_status": axfr.get("status"),
                "axfr_record_count": axfr.get("record_count", 0),
                "axfr_nameserver_count": axfr.get("nameserver_count", 0),
                "axfr_truncated": bool(axfr.get("truncated")),
                "srv_query_count": srv_meta.get("query_count", 0),
                "srv_hit_count": srv_meta.get("hit_count", 0),
                "srv_timeout_count": srv_meta.get("timeout_count", 0),
                "srv_error_count": srv_meta.get("error_count", 0),
                "delegation_query_count": delegation_meta.get("query_count", 0),
                "delegation_hit_count": delegation_meta.get("hit_count", 0),
            },
        }


def dns_auxiliary(base_domain, candidate_domains=None, task_id=""):
    return DNSAuxiliary(
        base_domain,
        candidate_domains=candidate_domains,
        task_id=task_id,
    ).run()
