import hashlib
import ipaddress
from datetime import datetime
from urllib.parse import urlsplit, urlunsplit

from app import utils
from app.config import Config
from app.services.pathDiscovery import redirect_destination_metadata
from app.utils.site_scope import formal_domain_query, formal_site_query


TERMINAL_STATUSES = {
    "alive",
    "http_dead",
    "unresolved",
    "skipped_non_global",
    "probe_error",
    "duplicate_existing",
    "duplicate_batch",
    "external_redirect",
}


def normalize_entry_domain(value):
    value = str(value or "").strip().strip(".").lower()
    if not value or ":" in value:
        return value
    try:
        return value.encode("idna").decode("ascii")
    except UnicodeError:
        return value


def normalize_entry_url(value):
    value = str(value or "").strip()
    if not value:
        return None

    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        host = normalize_entry_domain(parsed.hostname)
        port = parsed.port
    except (TypeError, ValueError):
        return None

    if scheme not in ("http", "https") or not host:
        return None

    default_port = 443 if scheme == "https" else 80
    effective_port = port or default_port
    display_host = "[{}]".format(host) if ":" in host else host
    netloc = display_host
    if effective_port != default_port:
        netloc = "{}:{}".format(display_host, effective_port)

    path = parsed.path or "/"
    normalized = urlunsplit((scheme, netloc, path, parsed.query, parsed.fragment))
    key_material = "{}|{}|{}|{}|{}|{}".format(
        scheme,
        host,
        effective_port,
        path,
        parsed.query,
        parsed.fragment,
    )
    return {
        "normalized": normalized,
        "key_material": key_material,
        "scheme": scheme,
        "host": host,
        "port": effective_port,
        "path": path,
        "query": parsed.query,
        "fragment": parsed.fragment,
    }


def _seed_key(seed_type, normalized_value):
    if seed_type == "domain":
        return "domain:{}".format(normalized_value)
    digest = hashlib.sha256(normalized_value.encode("utf-8")).hexdigest()
    return "url:{}".format(digest)


def _entry_url_type(host):
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return "url"
    return "public_ip_url" if address.is_global else "private_ip_url"


class EntryAssetTracker(object):
    """Track JS-discovered entry candidates without adding another probe pass."""

    URL_COLLECTION_FIELDS = (
        ("site", "site"),
        ("url", "url"),
        ("fileleak", "url"),
        ("asset_seed_alive", "url"),
    )

    def __init__(self, task_id, scope_domains=None):
        self.task_id = str(task_id or "")
        if isinstance(scope_domains, str):
            scope_domains = [scope_domains]
        self.scope_domains = [
            normalize_entry_domain(value)
            for value in (scope_domains or [])
            if normalize_entry_domain(value)
        ]
        self.snapshot_ready = False
        self.baseline_domains = set()
        self.baseline_site_hosts = set()
        self.baseline_urls = set()
        self.baseline_domain_refs = {}
        self.baseline_url_refs = {}
        self.final_url_owners = {}

    def _host_in_scope(self, host, seed_host=""):
        host = normalize_entry_domain(host)
        if not host:
            return False
        scopes = list(self.scope_domains)
        if not scopes:
            seed_host = normalize_entry_domain(seed_host)
            try:
                fallback = normalize_entry_domain(utils.get_fld(seed_host))
            except Exception:
                fallback = seed_host
            if fallback:
                scopes.append(fallback)
        return any(
            host == scope or host.endswith("." + scope)
            for scope in scopes if scope
        )

    @property
    def collection(self):
        return utils.conn_db("entry_asset")

    @staticmethod
    def _ref(collection, item, field, value):
        return {
            "collection": collection,
            "id": item.get("_id"),
            "field": field,
            "value": value,
        }

    @staticmethod
    def _ref_label(ref):
        return "{}:{}".format(ref.get("collection", ""), ref.get("value", ""))

    @staticmethod
    def _append_ref(ref_map, key, ref):
        if not key:
            return
        refs = ref_map.setdefault(key, [])
        marker = (ref.get("collection"), str(ref.get("id")), ref.get("field"))
        if marker not in {
            (item.get("collection"), str(item.get("id")), item.get("field"))
            for item in refs
        }:
            refs.append(ref)

    def snapshot_prior_assets(self):
        if self.snapshot_ready:
            return

        domain_collection = utils.conn_db("domain")
        for item in domain_collection.find(
            formal_domain_query({"task_id": self.task_id}), {"domain": 1}
        ):
            domain = normalize_entry_domain(item.get("domain"))
            if not domain:
                continue
            self.baseline_domains.add(domain)
            self._append_ref(
                self.baseline_domain_refs,
                domain,
                self._ref("domain", item, "domain", domain),
            )

        for collection_name, field in self.URL_COLLECTION_FIELDS:
            query = {"task_id": self.task_id}
            if collection_name == "site":
                query = formal_site_query(query)
            for item in utils.conn_db(collection_name).find(
                query, {field: 1}
            ):
                value = item.get(field)
                normalized = normalize_entry_url(value)
                if not normalized:
                    continue
                url_key = normalized["key_material"]
                self.baseline_urls.add(url_key)
                ref = self._ref(collection_name, item, field, normalized["normalized"])
                self._append_ref(self.baseline_url_refs, url_key, ref)
                host = normalized["host"]
                if host:
                    self.baseline_domains.add(host)
                    if collection_name == "site":
                        self.baseline_site_hosts.add(host)
                    self._append_ref(self.baseline_domain_refs, host, ref)

        for item in self.collection.find(
            {
                "task_id": self.task_id,
                "status": "alive",
                "is_new": True,
                "is_duplicate": False,
            },
            {"seed_key": 1, "final_url": 1, "alive_url": 1},
        ):
            final_url = item.get("final_url") or item.get("alive_url")
            normalized = normalize_entry_url(final_url)
            if normalized and item.get("seed_key"):
                self.final_url_owners[normalized["key_material"]] = item["seed_key"]

        self.snapshot_ready = True

    def _evidence_values(self, *values):
        result = []
        for value in values:
            if isinstance(value, (list, tuple, set)):
                candidates = value
            else:
                candidates = [value]
            for candidate in candidates:
                candidate = str(candidate or "").strip()
                if candidate and candidate not in result:
                    result.append(candidate)
        return result

    def _upsert_candidate(self, base, evidence_sources=None, collectors=None):
        now = utils.curr_date()
        evidence_sources = self._evidence_values(evidence_sources)
        collectors = self._evidence_values(collectors)
        force_reprobe = bool(base.pop("_force_reprobe", False))
        existing = self.collection.find_one(
            {"task_id": self.task_id, "seed_key": base["seed_key"]},
            {"status": 1},
        )
        preserve_terminal = (
            existing and existing.get("status") in TERMINAL_STATUSES
            and not force_reprobe
        )

        set_on_insert = dict(base)
        for field in ("status", "is_new", "is_duplicate", "duplicate_of"):
            set_on_insert.pop(field, None)
        set_on_insert["save_date"] = now
        update = {
            "$setOnInsert": set_on_insert,
            "$set": {"update_date": now},
        }
        if not preserve_terminal:
            update["$set"].update({
                "status": base.get("status", "pending"),
                "is_new": bool(base.get("is_new", True)),
                "is_duplicate": bool(base.get("is_duplicate", False)),
                "duplicate_of": base.get("duplicate_of", []),
            })
        add_to_set = {}
        if evidence_sources:
            add_to_set["evidence_sources"] = {"$each": evidence_sources}
        if collectors:
            add_to_set["collectors"] = {"$each": collectors}
        if add_to_set:
            update["$addToSet"] = add_to_set
        self.collection.update_one(
            {"task_id": self.task_id, "seed_key": base["seed_key"]},
            update,
            upsert=True,
        )
        return self.collection.find_one(
            {"task_id": self.task_id, "seed_key": base["seed_key"]}
        ) or {}

    @staticmethod
    def _absolute_evidence(values):
        for value in values or []:
            try:
                parsed = urlsplit(str(value or "").strip())
            except (TypeError, ValueError):
                continue
            if parsed.scheme in ("http", "https") and parsed.hostname:
                return True
        return False

    def _should_reprobe_existing(self, domain, existing, evidence_sources):
        if not getattr(Config, "ENTRY_REPROBE_EXISTING_NO_SITE", True):
            return False
        if domain in self.baseline_site_hosts:
            return False
        if not self._absolute_evidence(evidence_sources):
            return False
        existing = existing or {}
        status = str(existing.get("status") or "duplicate_existing")
        old_evidence = set(self._evidence_values(existing.get("evidence_sources")))
        new_evidence = set(evidence_sources or []) - old_evidence
        if status == "pending":
            return True
        if status == "duplicate_existing":
            return not existing.get("status") or bool(new_evidence)
        if status not in ("http_dead", "unresolved", "probe_error"):
            return False
        if not new_evidence:
            return False
        ttl = max(int(getattr(Config, "ENTRY_REPROBE_TTL", 1800) or 0), 0)
        if not ttl:
            return True
        try:
            updated_at = datetime.strptime(
                str(existing.get("last_probe_at") or existing.get("update_date") or ""),
                "%Y-%m-%d %H:%M:%S",
            )
            return (datetime.now() - updated_at).total_seconds() >= ttl
        except (TypeError, ValueError):
            return True

    def _enrich_refs(self, refs, evidence_sources, collector):
        evidence_sources = self._evidence_values(evidence_sources)
        now = utils.curr_date()
        for ref in refs or []:
            if not ref.get("id"):
                continue
            update = {
                "$set": {
                    "js_discovered": True,
                    "js_last_seen_at": now,
                },
                "$addToSet": {"js_collectors": collector},
            }
            if evidence_sources:
                update["$addToSet"]["js_evidence_sources"] = {
                    "$each": evidence_sources,
                }
            utils.conn_db(ref["collection"]).update_one(
                {"_id": ref["id"]}, update
            )

    def _enrich_entry_refs(self, refs, evidence_sources, collector, entry_type):
        evidence_sources = self._evidence_values(evidence_sources)
        now = utils.curr_date()
        for ref in refs or []:
            if not ref.get("id"):
                continue
            update = {
                "$set": {
                    "entry_discovered": True,
                    "entry_last_seen_at": now,
                },
                "$addToSet": {
                    "entry_collectors": collector,
                    "entry_types": entry_type,
                },
            }
            if evidence_sources:
                update["$addToSet"]["entry_evidence_sources"] = {
                    "$each": evidence_sources,
                }
            utils.conn_db(ref["collection"]).update_one(
                {"_id": ref["id"]}, update
            )

    def _enrich_live_primary(self, item, evidence_sources, collector):
        if item.get("status") != "alive":
            return

        refs = []
        if item.get("seed_type") == "domain":
            domain = normalize_entry_domain(item.get("domain") or item.get("seed"))
            for collection_name, query, field in (
                ("domain", {"task_id": self.task_id, "domain": domain}, "domain"),
                ("site", {"task_id": self.task_id, "hostname": domain}, "site"),
            ):
                for primary in utils.conn_db(collection_name).find(query, {field: 1}):
                    refs.append(self._ref(
                        collection_name,
                        primary,
                        field,
                        primary.get(field) or domain,
                    ))
        else:
            final_url = str(item.get("final_url") or item.get("alive_url") or "").strip()
            query = {
                "task_id": self.task_id,
                "$or": [
                    {"entry_seed_key": item.get("seed_key")},
                    {"url": final_url},
                ],
            }
            for primary in utils.conn_db("url").find(query, {"url": 1}):
                refs.append(self._ref(
                    "url", primary, "url", primary.get("url") or final_url))
        self._enrich_refs(refs, evidence_sources, collector)

    def register_domain(self, domain, source_url="", discovered_url="", collector="katana"):
        self.snapshot_prior_assets()
        domain = normalize_entry_domain(domain)
        if not domain:
            return {}

        seed_key = _seed_key("domain", domain)
        existing = self.collection.find_one(
            {"task_id": self.task_id, "seed_key": seed_key},
            {"status": 1, "evidence_sources": 1, "update_date": 1, "last_probe_at": 1},
        )
        duplicate = domain in self.baseline_domains
        refs = self.baseline_domain_refs.get(domain, []) if duplicate else []
        evidence_sources = self._evidence_values(source_url, discovered_url)
        reprobe_existing = duplicate and self._should_reprobe_existing(
            domain, existing, evidence_sources)
        base = {
            "task_id": self.task_id,
            "seed_key": seed_key,
            "seed_type": "domain",
            "seed": domain,
            "normalized_seed": domain,
            "domain": domain,
            "source": "{}_js".format(collector),
            "discovered_from": str(source_url or "").strip(),
            "status": "pending" if reprobe_existing or not duplicate else "duplicate_existing",
            "is_new": not duplicate,
            "is_duplicate": duplicate,
            "duplicate_of": [self._ref_label(ref) for ref in refs],
            "reprobe_existing": bool(reprobe_existing),
            "reprobe_reason": "new_js_wih_evidence_without_site" if reprobe_existing else "",
            "_force_reprobe": bool(reprobe_existing),
        }
        item = self._upsert_candidate(
            base, evidence_sources=evidence_sources, collectors=[collector]
        )
        if duplicate:
            self._enrich_refs(refs, evidence_sources, collector)
        else:
            self._enrich_live_primary(item, evidence_sources, collector)
        return item

    def register_url(self, url, source_urls=None, collector="katana", status="pending"):
        self.snapshot_prior_assets()
        normalized = normalize_entry_url(url)
        if not normalized:
            return {}

        seed_type = _entry_url_type(normalized["host"])
        seed_key = _seed_key("url", normalized["key_material"])
        existing = self.collection.find_one(
            {"task_id": self.task_id, "seed_key": seed_key}, {"status": 1}
        )
        duplicate = normalized["key_material"] in self.baseline_urls and (
            not existing or existing.get("status") == "duplicate_existing")
        refs = self.baseline_url_refs.get(normalized["key_material"], []) if duplicate else []
        evidence_sources = self._evidence_values(source_urls)
        base = {
            "task_id": self.task_id,
            "seed_key": seed_key,
            "seed_type": seed_type,
            "seed": normalized["normalized"],
            "normalized_seed": normalized["normalized"],
            "domain": normalized["host"],
            "source": "{}_all_url".format(collector),
            "discovered_from": evidence_sources[0] if evidence_sources else "",
            "status": "duplicate_existing" if duplicate else status,
            "is_new": not duplicate,
            "is_duplicate": duplicate,
            "duplicate_of": [self._ref_label(ref) for ref in refs],
        }
        item = self._upsert_candidate(
            base, evidence_sources=evidence_sources, collectors=[collector]
        )
        if duplicate:
            self._enrich_refs(refs, evidence_sources, collector)
        else:
            self._enrich_live_primary(item, evidence_sources, collector)
        return item

    def register_path_entry(self, page_info, collector="ffuf"):
        self.snapshot_prior_assets()
        page_info = dict(page_info or {})
        if "entry_eligible" in page_info and not page_info.get("entry_eligible"):
            return {}
        normalized = normalize_entry_url(page_info.get("url"))
        if not normalized:
            return {}
        redirect_meta = redirect_destination_metadata(
            page_info.get("redirect_location", ""), normalized["normalized"])

        entry_type = str(page_info.get("entry_type") or "path_entry")
        if entry_type not in {"path_entry", "protected_401_403", "sso_protected"}:
            return {}

        seed_key = _seed_key("url", normalized["key_material"])
        existing = self.collection.find_one(
            {"task_id": self.task_id, "seed_key": seed_key}
        ) or {}
        duplicate = normalized["key_material"] in self.baseline_urls and (
            not existing or existing.get("status") == "duplicate_existing"
        )
        refs = self.baseline_url_refs.get(normalized["key_material"], []) if duplicate else []
        evidence_sources = self._evidence_values(
            page_info.get("site"),
            page_info.get("parent_entry"),
            page_info.get("discovered_from"),
        )
        status = "duplicate_existing" if duplicate else "alive"
        base = {
            "task_id": self.task_id,
            "seed_key": seed_key,
            "seed_type": _entry_url_type(normalized["host"]),
            "seed": normalized["normalized"],
            "normalized_seed": normalized["normalized"],
            "domain": normalized["host"],
            "source": "{}_path_entry".format(collector),
            "discovered_from": evidence_sources[0] if evidence_sources else "",
            "status": status,
            "is_new": not duplicate,
            "is_duplicate": duplicate,
            "duplicate_of": [self._ref_label(ref) for ref in refs],
        }
        item = self._upsert_candidate(
            base,
            evidence_sources=evidence_sources,
            collectors=[collector],
        )
        if duplicate:
            self._enrich_entry_refs(
                refs, evidence_sources, collector, entry_type)
            return item

        preserve_existing = existing.get("status") in {
            "alive", "duplicate_batch", "duplicate_existing",
        }
        evidence_update = {
            "$set": {
                "ffuf_confirmed": True,
                "ffuf_last_seen_at": utils.curr_date(),
                "ffuf_entry_type": entry_type,
                "ffuf_status_code": page_info.get("status_code"),
                "ffuf_redirect_location": page_info.get("redirect_location", ""),
                "ffuf_redirect_url": (
                    page_info.get("redirect_url") or redirect_meta["redirect_url"]),
                "ffuf_scan_depth": int(page_info.get("scan_depth", 1) or 1),
            },
            "$addToSet": {"entry_types": entry_type},
        }
        self.collection.update_one(
            {"task_id": self.task_id, "seed_key": seed_key}, evidence_update
        )
        if preserve_existing:
            result = self.collection.find_one(
                {"task_id": self.task_id, "seed_key": seed_key}
            ) or item
            result["_ffuf_registered_new"] = False
            return result

        update = {
            "status": "alive",
            "is_new": True,
            "is_duplicate": False,
            "duplicate_of": [],
            "entry_type": entry_type,
            "alive_url": normalized["normalized"],
            "alive_urls": [normalized["normalized"]],
            "redirect_location": page_info.get("redirect_location", ""),
            "redirect_url": (
                page_info.get("redirect_url") or redirect_meta["redirect_url"]),
            "redirect_host": (
                page_info.get("redirect_host") or redirect_meta["redirect_host"]),
            "redirect_path": (
                page_info.get("redirect_path") or redirect_meta["redirect_path"]),
            "redirect_type": (
                page_info.get("redirect_type") or redirect_meta["redirect_type"]),
            "redirect_chain": list(page_info.get("redirect_chain", []) or []),
            "redirect_hops": int(page_info.get("redirect_hops", 0) or 0),
            "redirect_system": page_info.get("redirect_system", ""),
            "final_url": (
                page_info.get("final_url")
                or page_info.get("redirect_url")
                or redirect_meta["redirect_url"]
                or normalized["normalized"]),
            "final_status_code": page_info.get("final_status_code"),
            "final_title": page_info.get("final_title", ""),
            "final_http_server": page_info.get("final_http_server", ""),
            "ips": self._domain_ips(normalized["host"]),
            "status_code": page_info.get("status_code"),
            "title": page_info.get("title", ""),
            "content_length": page_info.get("content_length") or 0,
            "redirect_location": page_info.get("redirect_location", ""),
            "scan_depth": int(page_info.get("scan_depth", 1) or 1),
            "parent_entry": page_info.get("parent_entry", ""),
            "verification_status": page_info.get("verification_status", "verified"),
            "update_date": utils.curr_date(),
        }
        self.collection.update_one(
            {"task_id": self.task_id, "seed_key": seed_key}, {"$set": update}
        )
        self.final_url_owners[normalized["key_material"]] = seed_key
        result = self.collection.find_one(
            {"task_id": self.task_id, "seed_key": seed_key}
        ) or item
        result["_ffuf_registered_new"] = True
        return result

    def pending_urls(self, urls):
        result = []
        for url in urls or []:
            normalized = normalize_entry_url(url)
            if not normalized:
                continue
            seed_key = _seed_key("url", normalized["key_material"])
            item = self.collection.find_one(
                {"task_id": self.task_id, "seed_key": seed_key},
                {"status": 1},
            )
            if item and item.get("status") == "pending":
                result.append(normalized["normalized"])
        return result

    def pending_domains(self, domains):
        result = []
        for domain in domains or []:
            domain = normalize_entry_domain(domain)
            if not domain:
                continue
            item = self.collection.find_one(
                {
                    "task_id": self.task_id,
                    "seed_key": _seed_key("domain", domain),
                    "status": "pending",
                },
                {"_id": 1},
            )
            if item:
                result.append(domain)
        return result

    @staticmethod
    def _preserve_fragment(seed_url, final_url):
        seed = normalize_entry_url(seed_url)
        final = normalize_entry_url(final_url)
        if not seed or not final:
            return final_url
        if seed["fragment"] and not final["fragment"]:
            parsed = urlsplit(final["normalized"])
            return urlunsplit((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.query,
                seed["fragment"],
            ))
        return final["normalized"]

    def _merge_into_entry_owner(self, owner_seed_key, item, duplicate_seed=""):
        evidence_sources = self._evidence_values(item.get("evidence_sources"))
        collectors = self._evidence_values(item.get("collectors"))
        add_to_set = {}
        if evidence_sources:
            add_to_set["evidence_sources"] = {"$each": evidence_sources}
        if collectors:
            add_to_set["collectors"] = {"$each": collectors}
        if duplicate_seed:
            add_to_set["duplicate_seeds"] = duplicate_seed
        if not add_to_set:
            return
        self.collection.update_one(
            {"task_id": self.task_id, "seed_key": owner_seed_key},
            {
                "$set": {"update_date": utils.curr_date()},
                "$addToSet": add_to_set,
            },
        )

    def _domain_ips(self, host):
        try:
            address = ipaddress.ip_address(host)
            return [str(address)]
        except ValueError:
            pass
        item = utils.conn_db("domain").find_one(
            formal_domain_query({"task_id": self.task_id, "domain": host}),
            {"ips": 1},
        ) or {}
        return list(item.get("ips") or [])

    def finalize_url(self, seed_url, page_info, collector="katana"):
        seed = normalize_entry_url(seed_url)
        if not seed:
            return None
        seed_key = _seed_key("url", seed["key_material"])
        item = self.collection.find_one(
            {"task_id": self.task_id, "seed_key": seed_key}
        ) or self.register_url(seed_url)
        if item.get("status") != "pending":
            return None

        final_value = page_info.get("final_url") or page_info.get("url") or seed_url
        final_value = self._preserve_fragment(seed_url, final_value)
        final = normalize_entry_url(final_value)
        if not final:
            self.mark_url_probe_error(seed_url, "invalid_final_url")
            return None

        initial_status = self._status_code(page_info.get("status_code"))
        final_status = self._status_code(page_info.get("final_status_code"))
        effective_status = final_status if final_status is not None else initial_status
        probe_status = self._classify_http_status(effective_status)
        if probe_status != "alive":
            update = {
                "status": probe_status,
                "is_new": False,
                "is_duplicate": False,
                "duplicate_of": [],
                "final_url": final["normalized"],
                "domain": final["host"],
                "ips": self._domain_ips(final["host"]),
                "status_code": initial_status,
                "final_status_code": final_status,
                "title": page_info.get("title", ""),
                "final_title": page_info.get("final_title", ""),
                "redirect_location": page_info.get("redirect_location", ""),
                "redirect_chain": list(page_info.get("redirect_chain", []) or []),
                "redirect_hops": int(page_info.get("redirect_hops", 0) or 0),
                "redirect_resolved": bool(page_info.get("redirect_resolved")),
                "update_date": utils.curr_date(),
                "last_probe_at": utils.curr_date(),
            }
            if probe_status == "probe_error":
                update["probe_error"] = "http_status_{}".format(
                    effective_status if effective_status is not None else "unknown")
            self.collection.update_one(
                {"task_id": self.task_id, "seed_key": seed_key},
                {"$set": update},
            )
            return None

        if (
            final["key_material"] != seed["key_material"] and
            not self._host_in_scope(final["host"], seed_host=seed["host"])
        ):
            redirect_meta = redirect_destination_metadata(
                page_info.get("redirect_location", ""), seed["normalized"])
            update = {
                "status": "external_redirect",
                "is_new": False,
                "is_duplicate": False,
                "duplicate_of": [],
                "pipeline_eligible": False,
                "domain": seed["host"],
                "ips": self._domain_ips(seed["host"]),
                "final_url": final["normalized"],
                "external_redirect_url": final["normalized"],
                "external_redirect_host": final["host"],
                "status_code": initial_status,
                "final_status_code": final_status,
                "title": page_info.get("title", ""),
                "final_title": page_info.get("final_title", ""),
                "final_http_server": page_info.get("final_http_server", ""),
                "redirect_location": page_info.get("redirect_location", ""),
                "redirect_url": (
                    page_info.get("redirect_url") or final["normalized"]),
                "redirect_host": (
                    page_info.get("redirect_host") or final["host"]),
                "redirect_path": (
                    page_info.get("redirect_path") or redirect_meta["redirect_path"]),
                "redirect_type": (
                    page_info.get("redirect_type") or redirect_meta["redirect_type"]),
                "redirect_chain": list(page_info.get("redirect_chain", []) or []),
                "redirect_hops": int(page_info.get("redirect_hops", 0) or 0),
                "redirect_resolved": bool(page_info.get("redirect_resolved")),
                "redirect_resolution_error": page_info.get(
                    "redirect_resolution_error", ""),
                "redirect_system": (
                    page_info.get("redirect_system") or
                    page_info.get("final_title") or
                    page_info.get("final_http_server") or
                    final["host"]
                ),
                "update_date": utils.curr_date(),
                "last_probe_at": utils.curr_date(),
            }
            self.collection.update_one(
                {"task_id": self.task_id, "seed_key": seed_key},
                {"$set": update},
            )
            return None

        evidence_sources = self._evidence_values(item.get("evidence_sources"))
        refs = self.baseline_url_refs.get(final["key_material"], [])
        if final["key_material"] in self.baseline_urls:
            self.collection.update_one(
                {"task_id": self.task_id, "seed_key": seed_key},
                {"$set": {
                    "status": "duplicate_existing",
                    "is_new": False,
                    "is_duplicate": True,
                    "duplicate_of": [self._ref_label(ref) for ref in refs],
                    "final_url": final["normalized"],
                    "update_date": utils.curr_date(),
                    "last_probe_at": utils.curr_date(),
                }},
            )
            self._enrich_refs(refs, evidence_sources, collector)
            return None

        owner = self.final_url_owners.get(final["key_material"])
        if owner and owner != seed_key:
            self.collection.update_one(
                {"task_id": self.task_id, "seed_key": seed_key},
                {"$set": {
                    "status": "duplicate_batch",
                    "is_new": False,
                    "is_duplicate": True,
                    "duplicate_of": [owner],
                    "final_url": final["normalized"],
                    "update_date": utils.curr_date(),
                }},
            )
            self._merge_into_entry_owner(owner, item, duplicate_seed=seed["normalized"])
            return None

        status_code = page_info.get("status_code")
        content_length = page_info.get("content_length")
        redirect_meta = redirect_destination_metadata(
            page_info.get("redirect_location", ""), seed["normalized"])
        update = {
            "status": "alive",
            "is_new": True,
            "is_duplicate": False,
            "duplicate_of": [],
            "alive_url": final["normalized"],
            "alive_urls": list(dict.fromkeys([seed["normalized"], final["normalized"]])),
            "final_url": final["normalized"],
            "final_status_code": page_info.get("final_status_code"),
            "final_title": page_info.get("final_title", ""),
            "final_http_server": page_info.get("final_http_server", ""),
            "domain": final["host"],
            "ips": self._domain_ips(final["host"]),
            "status_code": status_code,
            "title": page_info.get("title", ""),
            "content_length": content_length or 0,
            "redirect_location": page_info.get("redirect_location", ""),
            "redirect_url": (
                page_info.get("redirect_url") or redirect_meta["redirect_url"]),
            "redirect_host": (
                page_info.get("redirect_host") or redirect_meta["redirect_host"]),
            "redirect_path": (
                page_info.get("redirect_path") or redirect_meta["redirect_path"]),
            "redirect_type": (
                page_info.get("redirect_type") or redirect_meta["redirect_type"]),
            "redirect_chain": list(page_info.get("redirect_chain", []) or []),
            "redirect_hops": int(page_info.get("redirect_hops", 0) or 0),
            "redirect_resolved": bool(page_info.get("redirect_resolved")),
            "redirect_resolution_error": page_info.get(
                "redirect_resolution_error", ""),
            "redirect_system": (
                page_info.get("redirect_system")
                or page_info.get("final_title")
                or page_info.get("final_http_server")
                or redirect_meta["redirect_host"]
            ),
            "update_date": utils.curr_date(),
        }
        self.collection.update_one(
            {"task_id": self.task_id, "seed_key": seed_key}, {"$set": update}
        )
        self.final_url_owners[final["key_material"]] = seed_key

        page_payload = dict(page_info or {})
        page_payload.update({
            "url": final["normalized"],
            "final_url": final["normalized"],
            "seed_url": seed["normalized"],
            "entry_seed_key": seed_key,
            "js_evidence_sources": evidence_sources,
        })
        if evidence_sources:
            page_payload["discovered_from"] = evidence_sources[0]
            page_payload["discovered_sources"] = evidence_sources
        return final["normalized"], page_payload

    def mark_url_probe_error(self, seed_url, reason="probe_error"):
        normalized = normalize_entry_url(seed_url)
        if not normalized:
            return
        seed_key = _seed_key("url", normalized["key_material"])
        self.collection.update_one(
            {
                "task_id": self.task_id,
                "seed_key": seed_key,
                "status": "pending",
            },
            {"$set": {
                "status": "probe_error",
                "probe_error": str(reason or "probe_error"),
                "update_date": utils.curr_date(),
            }},
        )

    @staticmethod
    def _status_code(value):
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @classmethod
    def _classify_http_status(cls, value):
        status = cls._status_code(value)
        if status is None:
            return "probe_error"
        if 200 <= status < 400 or status in (401, 403, 405):
            return "alive"
        if status in (404, 410) or 400 <= status < 500:
            return "http_dead"
        return "probe_error"

    def finalize_domains(self, domains):
        pending = self.pending_domains(domains)
        if not pending:
            return {"input_count": 0, "alive_count": 0, "failed_count": 0}

        domain_docs = {
            item.get("domain"): item
            for item in utils.conn_db("domain").find(
                formal_domain_query({
                    "task_id": self.task_id,
                    "domain": {"$in": pending},
                }),
                {"domain": 1, "ips": 1, "resolve_status": 1},
            )
            if item.get("domain")
        }
        site_map = {domain: [] for domain in pending}
        for item in utils.conn_db("site").find(
            formal_site_query({
                "task_id": self.task_id,
                "hostname": {"$in": pending},
            }),
            {
                "site": 1,
                "hostname": 1,
                "status": 1,
                "title": 1,
                "body_length": 1,
                "content_length": 1,
                "ip": 1,
            },
        ):
            host = normalize_entry_domain(item.get("hostname"))
            if host in site_map:
                site_map[host].append(item)

        alive_count = 0
        failed_count = 0
        duplicate_count = 0
        for domain in pending:
            seed_key = _seed_key("domain", domain)
            item = self.collection.find_one(
                {"task_id": self.task_id, "seed_key": seed_key}
            ) or {}
            sites = site_map.get(domain) or []
            sites.sort(key=lambda value: (
                0 if self._classify_http_status(value.get("status")) == "alive" else 1,
                str(value.get("site") or ""),
            ))

            viable_sites = [
                site for site in sites
                if self._classify_http_status(site.get("status")) == "alive"
            ]

            unique_sites = []
            duplicate_owner = ""
            for site in viable_sites:
                normalized = normalize_entry_url(site.get("site"))
                if not normalized:
                    continue
                owner = self.final_url_owners.get(normalized["key_material"])
                if owner and owner != seed_key:
                    duplicate_owner = owner
                    continue
                unique_sites.append((normalized, site))

            if unique_sites:
                normalized, site = unique_sites[0]
                alive_urls = [value[0]["normalized"] for value in unique_sites]
                reprobe_existing = bool(item.get("reprobe_existing"))
                update = {
                    "status": "alive",
                    "is_new": not reprobe_existing,
                    "is_duplicate": reprobe_existing,
                    "duplicate_of": [],
                    "alive_url": normalized["normalized"],
                    "alive_urls": alive_urls,
                    "final_url": normalized["normalized"],
                    "ips": list((domain_docs.get(domain) or {}).get("ips") or []),
                    "status_code": site.get("status"),
                    "title": site.get("title", ""),
                    "content_length": site.get("content_length") or site.get("body_length") or 0,
                    "update_date": utils.curr_date(),
                    "last_probe_at": utils.curr_date(),
                    "reprobe_succeeded": reprobe_existing,
                }
                self.collection.update_one(
                    {"task_id": self.task_id, "seed_key": seed_key}, {"$set": update}
                )
                for normalized_site, _ in unique_sites:
                    self.final_url_owners[normalized_site["key_material"]] = seed_key
                alive_count += 1
                continue

            if sites and duplicate_owner:
                self.collection.update_one(
                    {"task_id": self.task_id, "seed_key": seed_key},
                    {"$set": {
                        "status": "duplicate_batch",
                        "is_new": False,
                        "is_duplicate": True,
                        "duplicate_of": [duplicate_owner],
                        "update_date": utils.curr_date(),
                        "last_probe_at": utils.curr_date(),
                    }},
                )
                self._merge_into_entry_owner(duplicate_owner, item, duplicate_seed=domain)
                duplicate_count += 1
                continue

            domain_doc = domain_docs.get(domain) or {}
            ips = list(domain_doc.get("ips") or [])
            if not ips:
                status = "unresolved"
            elif sites and any(
                    self._classify_http_status(site.get("status")) == "probe_error"
                    for site in sites):
                status = "probe_error"
            else:
                status = "http_dead"
            self.collection.update_one(
                {"task_id": self.task_id, "seed_key": seed_key},
                {"$set": {
                    "status": status,
                    "ips": ips,
                    "update_date": utils.curr_date(),
                    "last_probe_at": utils.curr_date(),
                }},
            )
            failed_count += 1

        return {
            "input_count": len(pending),
            "alive_count": alive_count,
            "failed_count": failed_count,
            "duplicate_count": duplicate_count,
        }

    def counts(self):
        base = {
            "task_id": self.task_id,
            "is_new": True,
            "is_duplicate": False,
        }
        return {
            "candidate_count": self.collection.count_documents({"task_id": self.task_id}),
            "alive_count": self.collection.count_documents({**base, "status": "alive"}),
            "pending_count": self.collection.count_documents({
                "task_id": self.task_id, "status": "pending"}),
            "external_redirect_count": self.collection.count_documents({
                "task_id": self.task_id, "status": "external_redirect"}),
        }
