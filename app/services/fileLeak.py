import json
import hashlib
import math
import os
import signal
import shutil
import subprocess
import tempfile
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List
from urllib.parse import urlparse

from app import utils
from app.config import Config
from app.services.assetPolicy import is_transient_block_page
from app.services.resourceBudget import acquire as acquire_resource_budget
from app.services.baseUpdateTask import BaseUpdateTask
from app.services.pathDiscovery import (
    _task_target,
    build_dynamic_path_words,
    build_parent_baselines,
    build_secondary_words,
    build_site_baseline,
    browser_request_headers,
    classify_response,
    normalize_redirect_location,
    ordered_unique,
    probe_response_signature,
    redirect_destination_metadata,
    resolve_redirect_location,
    site_scoped_domain_path_words,
    split_priority_words,
)

logger = utils.get_logger()

FFUF_PROFILE_VERSION = "path-entry-v8-site-scoped-domain"
FFUF_ROUTE_OBSERVATION_VERSION = "route-observation-v1"
ROUTE_ENTRY_TYPES = {
    "path_entry",
    "protected_401_403",
    "sso_protected",
}
ROUTE_PROMOTION_ENTRY_TYPES = {
    "path_entry",
    "sso_protected",
}
FFUF_TARGET_PROFILE_ORDER = {
    "restricted": 0,
    "edge_limited": 1,
    "normal": 2,
    "low_info": 3,
}

# These counters describe completed work and must remain monotonic when an
# acks-late task resumes from per-site checkpoints. Error counters are omitted:
# a successful retry should clear a previously transient failure.
FFUF_RESUME_COUNTER_FIELDS = (
    "site_filtered_count",
    "task_filtered_count",
    "raw_result_count",
    "scan_word_count",
    "verified_result_count",
    "unverified_result_count",
    "baseline_filtered_count",
    "entry_candidate_count",
    "resource_clue_count",
    "redirect_clue_count",
    "redirect_template_count",
    "redirect_group_count",
    "redirect_resolved_count",
    "redirect_resolution_error_count",
    "non_entry_result_count",
    "sso_protected_count",
    "protected_result_count",
    "stale_result_count",
    "second_level_input_count",
    "second_level_result_count",
    "baseline_request_count",
    "baseline_error_count",
    "site_dynamic_word_count",
    "site_scoped_target_count",
    "site_scoped_scan_word_count",
    "site_scoped_result_count",
    "site_scoped_meaningful_result_count",
    "priority_scan_word_count",
    "priority_result_count",
    "priority_meaningful_result_count",
    "low_info_short_scan_count",
    "low_info_escalated_count",
    "low_info_skipped_full_word_count",
    "edge_limited_short_scan_count",
    "edge_limited_escalated_count",
    "edge_limited_skipped_full_word_count",
    "restricted_short_scan_count",
    "restricted_escalated_count",
    "restricted_skipped_full_word_count",
    "batch_emitted_count",
    "retry_site_count",
    "route_dedupe_reused_target_count",
    "route_dedupe_saved_word_count",
    "route_dedupe_split_cluster_count",
    "route_dedupe_fallback_target_count",
)

FFUF_CHECKPOINT_COUNTER_FIELDS = tuple(dict.fromkeys(
    FFUF_RESUME_COUNTER_FIELDS + (
        "timeout_count",
        "failure_count",
        "stopped_count",
        "transient_verify_count",
        "exhausted_site_count",
        "retryable_failure_site_count",
    )
))


def _fair_site_slice(sites, target_profiles, limit):
    sites = list(sites or [])
    limit = max(int(limit or 0), 0)
    if not limit or len(sites) <= limit:
        return sites, []
    queues = {
        profile: [
            site for site in sites
            if target_profiles.get(site.rstrip("/"), "normal") == profile
        ]
        for profile in ("restricted", "edge_limited", "normal", "low_info")
    }
    selected = []
    offsets = {profile: 0 for profile in queues}
    while len(selected) < limit:
        progressed = False
        for profile in ("restricted", "edge_limited", "normal", "low_info"):
            offset = offsets[profile]
            queue = queues[profile]
            if offset >= len(queue):
                continue
            selected.append(queue[offset])
            offsets[profile] += 1
            progressed = True
            if len(selected) >= limit:
                break
        if not progressed:
            break
    selected_set = set(selected)
    return selected, [site for site in sites if site not in selected_set]


def _partition_scan_sites(sites, target_profiles, attempt_states, max_attempts):
    eligible = []
    completed = []
    exhausted = []
    max_attempts = max(int(max_attempts or 1), 1)
    for site in sites or []:
        state = (attempt_states or {}).get(site) or {}
        status = str(state.get("status") or "")
        attempts = max(int(state.get("attempt_count", 0) or 0), 0)
        if status == "done":
            completed.append(site)
        elif attempts >= max_attempts:
            exhausted.append(site)
        else:
            eligible.append(site)
    eligible.sort(key=lambda site: (
        0 if not int(((attempt_states or {}).get(site) or {}).get(
            "attempt_count", 0) or 0) else 1,
        int(((attempt_states or {}).get(site) or {}).get(
            "attempt_count", 0) or 0),
        FFUF_TARGET_PROFILE_ORDER[
            target_profiles.get(site.rstrip("/"), "normal")],
        site,
    ))
    return eligible, completed, exhausted


class FfufResult(list):
    def __init__(self, values=None, meta=None, removed_urls=None):
        super().__init__(values or [])
        self.meta = dict(meta or {})
        self.removed_urls = list(removed_urls or [])


class FfufPage:
    def __init__(self, result, site=""):
        self.result = result
        self.site = site
        self.url = result.get("url", "")
        self.status_code = result.get("status")
        self.content_length = result.get("length", 0)
        self.words = result.get("words", 0)
        self.lines = result.get("lines", 0)
        self.content_type = result.get("content-type", "")
        self.redirect_location = result.get("redirectlocation", "")
        self.redirect_url = result.get("redirect_url", "")
        self.redirect_host = result.get("redirect_host", "")
        self.redirect_path = result.get("redirect_path", "")
        self.redirect_type = result.get("redirect_type", "")
        self.redirect_chain = list(result.get("redirect_chain", []) or [])
        self.redirect_hops = int(result.get("redirect_hops", 0) or 0)
        self.redirect_resolved = bool(result.get("redirect_resolved"))
        self.redirect_resolution_error = result.get("redirect_resolution_error", "")
        self.final_url = result.get("final_url", "")
        self.final_status_code = result.get("final_status_code")
        self.final_title = result.get("final_title", "")
        self.final_http_server = result.get("final_http_server", "")
        self.redirect_system = result.get("redirect_system", "")
        self.input = result.get("input", {})
        self.title = ""
        self.template_detected = bool(result.get("template_detected"))
        self.template_scope = result.get("template_scope", "")
        self.template_duplicate_count = int(result.get("template_duplicate_count", 0) or 0)
        self.entry_type = result.get("entry_type", "")
        self.verification_status = result.get("verification_status", "")
        self.verification_reason = result.get("verification_reason", "")
        self.scan_depth = int(result.get("scan_depth", 1) or 1)
        self.parent_entry = result.get("parent_entry", "")

    def _fetch_title(self):
        if not getattr(Config, "FFUF_ENRICH_TITLE", True):
            return ""
        conn = None
        try:
            timeout = int(getattr(Config, "FFUF_TITLE_TIMEOUT", 5))
            conn = utils.http_req(
                self.url,
                "get",
                timeout=(3, timeout),
                stream=True,
                headers=browser_request_headers(),
            )
            return utils.get_title(conn.content).strip()
        except Exception as e:
            logger.debug("ffuf title fetch failed {} {}".format(self.url, e))
            return ""
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    def enrich_title(self):
        self.title = self._fetch_title()
        return self.title

    def __str__(self):
        return "[{}][{}][{}]{}".format(self.status_code, self.title, self.content_length, self.url)

    def __repr__(self):
        return "<FfufPage> " + self.__str__()

    def dump_json(self):
        redirect_meta = redirect_destination_metadata(
            self.redirect_location, self.url)
        item = {
            "title": self.title,
            "url": self.url,
            "site": self.site,
            "content_length": self.content_length,
            "status_code": self.status_code,
            "ffuf_words": self.words,
            "ffuf_lines": self.lines,
            "content_type": self.content_type,
            "redirect_location": self.redirect_location,
            "redirect_url": self.redirect_url or redirect_meta["redirect_url"],
            "redirect_host": self.redirect_host or redirect_meta["redirect_host"],
            "redirect_path": self.redirect_path or redirect_meta["redirect_path"],
            "redirect_type": self.redirect_type or redirect_meta["redirect_type"],
            "redirect_chain": self.redirect_chain,
            "redirect_hops": self.redirect_hops,
            "redirect_resolved": self.redirect_resolved,
            "redirect_resolution_error": self.redirect_resolution_error,
            "final_url": self.final_url,
            "final_status_code": self.final_status_code,
            "final_title": self.final_title,
            "final_http_server": self.final_http_server,
            "redirect_system": self.redirect_system,
            "scanner": "ffuf",
            "template_detected": self.template_detected,
            "template_scope": self.template_scope,
            "template_duplicate_count": self.template_duplicate_count,
            "entry_type": self.entry_type,
            # Keep protected paths as fileleak evidence, but do not let a
            # uniform response template become an entry candidate.
            "entry_eligible": (
                self.entry_type in ROUTE_ENTRY_TYPES and
                not self.template_detected
            ),
            # Only a verified, non-template HTML/SSO route may upgrade the
            # parent site to route_confirmed.  401/403 remains reviewable
            # evidence without becoming a strong site signal.
            "route_promotion_eligible": (
                self.entry_type in ROUTE_PROMOTION_ENTRY_TYPES and
                self.verification_status == "verified" and
                not self.template_detected
            ),
            "verification_status": self.verification_status,
            "verification_reason": self.verification_reason,
            "scan_depth": self.scan_depth,
            "parent_entry": self.parent_entry,
        }

        fuzz = self.input.get("FUZZ") if isinstance(self.input, dict) else None
        if fuzz:
            item["path"] = fuzz

        return item


def _redirect_chain_item(url, status_code, location="", title="", http_server=""):
    return {
        "url": str(url or ""),
        "status_code": status_code,
        "location": str(location or ""),
        "title": str(title or ""),
        "http_server": str(http_server or ""),
    }


def _resolve_redirect_page(page):
    redirect_meta = redirect_destination_metadata(
        page.redirect_location, page.url)
    page.redirect_url = redirect_meta["redirect_url"]
    page.redirect_host = redirect_meta["redirect_host"]
    page.redirect_path = redirect_meta["redirect_path"]
    page.redirect_type = redirect_meta["redirect_type"]
    if not page.redirect_url:
        return False

    max_hops = max(int(getattr(
        Config, "FFUF_REDIRECT_RESOLVE_MAX_HOPS", 3) or 0), 0)
    timeout = max(int(getattr(
        Config, "FFUF_REDIRECT_RESOLVE_TIMEOUT", 5) or 1), 1)
    chain = [_redirect_chain_item(
        page.url, page.status_code, page.redirect_location, page.title)]
    current_url = page.redirect_url
    seen = {str(page.url or "")}
    response = None
    try:
        for _hop in range(max_hops):
            if not current_url or current_url in seen:
                page.redirect_resolution_error = "redirect_loop"
                break
            seen.add(current_url)
            response = utils.http_req(
                current_url,
                "get",
                timeout=(3, timeout),
                allow_redirects=False,
                headers=browser_request_headers(),
            )
            location = response.headers.get("Location", "")
            title = utils.get_title(response.content).strip()
            http_server = response.headers.get("Server", "")
            chain.append(_redirect_chain_item(
                current_url, response.status_code, location, title, http_server))
            page.final_url = current_url
            page.final_status_code = response.status_code
            page.final_title = title
            page.final_http_server = http_server
            if response.status_code not in (301, 302, 303, 307, 308) or not location:
                page.redirect_resolved = True
                break
            current_url = resolve_redirect_location(location, current_url)
            try:
                response.close()
            except Exception:
                pass
            response = None
        else:
            page.redirect_resolution_error = "redirect_hop_limit"
    except Exception as exc:
        page.redirect_resolution_error = str(exc)[:240]
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass

    page.redirect_chain = chain
    page.redirect_hops = max(len(chain) - 1, 0)
    page.redirect_system = (
        page.final_title or page.final_http_server or page.redirect_host)
    return page.redirect_resolved


def _copy_redirect_resolution(source, target):
    for field in (
        "redirect_url",
        "redirect_host",
        "redirect_path",
        "redirect_type",
        "redirect_hops",
        "redirect_resolved",
        "redirect_resolution_error",
        "final_url",
        "final_status_code",
        "final_title",
        "final_http_server",
        "redirect_system",
    ):
        setattr(target, field, getattr(source, field, None))

    chain = [dict(item) for item in (source.redirect_chain or [])]
    if chain:
        chain[0].update({
            "url": target.url,
            "status_code": target.status_code,
            "location": target.redirect_location,
            "title": target.title,
        })
    else:
        chain = [_redirect_chain_item(
            target.url,
            target.status_code,
            target.redirect_location,
            target.title,
        )]
    target.redirect_chain = chain


def _enrich_redirect_pages(pages):
    pages = [
        page for page in pages or []
        if page.status_code in (301, 302, 303, 307, 308)
        and page.redirect_location
    ]
    for page in pages:
        redirect_meta = redirect_destination_metadata(
            page.redirect_location, page.url)
        page.redirect_url = redirect_meta["redirect_url"]
        page.redirect_host = redirect_meta["redirect_host"]
        page.redirect_path = redirect_meta["redirect_path"]
        page.redirect_type = redirect_meta["redirect_type"]
        page.redirect_system = page.redirect_host

    if not pages or not getattr(Config, "FFUF_REDIRECT_RESOLVE_ENABLE", True):
        return {"redirect_group_count": len(pages)}

    batch_size = max(int(getattr(
        Config, "FFUF_REDIRECT_RESOLVE_MAX_GROUPS", 100) or 0), 0)
    groups = {}
    for page in pages:
        source_host = (urlparse(page.url).netloc or "").lower()
        key = (
            source_host,
            page.status_code,
            normalize_redirect_location(page.redirect_location, page.url),
        )
        groups.setdefault(key, []).append(page)
    group_items = list(groups.items())
    if not group_items:
        return {"redirect_group_count": 0}
    if not batch_size:
        batch_size = len(group_items)

    resolved = 0
    failed = 0
    propagated = 0
    for start in range(0, len(group_items), batch_size):
        batch = group_items[start:start + batch_size]
        workers = min(max(int(getattr(
            Config, "FFUF_REDIRECT_RESOLVE_CONCURRENCY", 4) or 1), 1), len(batch))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(_resolve_redirect_page, grouped_pages[0]):
                (key, grouped_pages)
                for key, grouped_pages in batch
            }
            for future in as_completed(futures):
                _key, grouped_pages = futures[future]
                representative = grouped_pages[0]
                try:
                    if future.result():
                        resolved += 1
                    else:
                        failed += 1
                except Exception as exc:
                    representative.redirect_resolution_error = str(exc)[:240]
                    failed += 1
                for page in grouped_pages[1:]:
                    _copy_redirect_resolution(representative, page)
                    propagated += 1
    return {
        "redirect_page_count": len(pages),
        "redirect_group_count": len(groups),
        "redirect_processed_group_count": len(groups),
        "redirect_resolved_count": resolved,
        "redirect_resolution_error_count": failed,
        "redirect_propagated_page_count": propagated,
    }


def normal_url(url):
    scheme_map = {
        "http": 80,
        "https": 443,
    }
    try:
        o = urlparse(url)
        port = o.port
    except (TypeError, ValueError):
        return ""
    if o.scheme not in scheme_map or not o.hostname:
        return ""

    path = o.path or "/"
    if port == scheme_map[o.scheme] or port is None:
        ret_url = "{}://{}{}".format(o.scheme, o.hostname, path)
    else:
        ret_url = "{}://{}:{}{}".format(o.scheme, o.hostname, port, path)

    if o.query:
        ret_url = ret_url + "?" + o.query

    return ret_url


def _normal_word(word):
    word = str(word or "").strip()
    if not word or word.startswith("#") or "*" in word:
        return ""
    return word.lstrip("/")


def _build_words(dicts):
    words = []
    for word in dicts:
        word = _normal_word(word)
        if word:
            words.append(word)
    return ordered_unique(words)


def _shared_dynamic_words(dynamic_words, dynamic_meta):
    """Remove hostname-only clues from the task-wide FFUF word set."""
    site_scoped = set(
        (dynamic_meta or {}).get("dynamic_selected_domain_words") or [])
    return [word for word in dynamic_words or [] if word not in site_scoped]


def _normalize_target_profile(profile):
    profile = str(profile or "normal").strip().lower()
    if profile not in FFUF_TARGET_PROFILE_ORDER:
        return "normal"
    return profile


def _signature_route_payload(signature):
    if signature is None or signature.status_code is None or not signature.body_hash:
        return None
    return {
        "status": signature.status_code,
        "length": signature.content_length,
        "body_hash": signature.body_hash,
        "content_type": signature.content_type,
        "location": signature.normalized_location,
        "title": str(signature.title or "").strip().lower(),
        "cookies": list(signature.cookie_names or []),
    }


def _baseline_route_observation_key(baseline):
    if not baseline or baseline.stopped or baseline.error_count:
        return ""
    expected_random = max(int(getattr(
        Config, "FFUF_BASELINE_REQUESTS", 3) or 0), 1)
    if baseline.root_signature is None or len(
            baseline.random_signatures or []) < expected_random:
        return ""

    root = _signature_route_payload(baseline.root_signature)
    random_signatures = [
        _signature_route_payload(signature)
        for signature in baseline.random_signatures
    ]
    if root is None or any(item is None for item in random_signatures):
        return ""
    random_signatures.sort(key=lambda item: json.dumps(
        item, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    payload = {
        "version": FFUF_ROUTE_OBSERVATION_VERSION,
        "root": root,
        "random": random_signatures,
    }
    serialized = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "{}:{}".format(
        FFUF_ROUTE_OBSERVATION_VERSION,
        hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
    )


def _route_cluster_sample_sites(route_key, sites):
    sites = sorted(set(sites or []))
    if not sites:
        return []
    minimum = max(int(getattr(
        Config, "FFUF_ROUTE_DEDUPE_SAMPLE_SIZE", 3) or 1), 1)
    maximum = max(int(getattr(
        Config, "FFUF_ROUTE_DEDUPE_MAX_SAMPLE_SIZE", 8) or minimum), minimum)
    adaptive = max(minimum, int(math.ceil(math.log(max(len(sites), 2), 2))))
    sample_count = min(len(sites), maximum, adaptive)

    def rank(site):
        digest = hashlib.sha256(
            (str(route_key) + "\0" + str(site)).encode("utf-8")).hexdigest()
        return digest, site

    return sorted(sites, key=rank)[:sample_count]


def _build_route_cluster_plan(
    sites,
    target_profiles,
    target_route_keys,
    attempted_sites=None,
):
    if not bool(getattr(Config, "FFUF_ROUTE_DEDUPE_ENABLE", True)):
        return {}
    minimum = max(int(getattr(
        Config, "FFUF_ROUTE_DEDUPE_MIN_CLUSTER_SIZE", 4) or 2), 2)
    attempted_sites = set(attempted_sites or [])
    groups = {}
    for site in sites or []:
        site_key = site.rstrip("/")
        if site in attempted_sites:
            continue
        profile = target_profiles.get(site_key, "normal")
        if profile not in (
            "normal", "low_info", "edge_limited", "restricted"
        ):
            continue
        route_key = str(target_route_keys.get(site_key) or "").strip()
        if route_key:
            groups.setdefault((profile, route_key), []).append(site)

    plan = {}
    for (profile, route_key), group_sites in groups.items():
        group_sites = sorted(set(group_sites))
        if len(group_sites) < minimum:
            continue
        samples = _route_cluster_sample_sites(route_key, group_sites)
        sample_set = set(samples)
        cluster_id = "{}:{}".format(profile, route_key)
        plan[cluster_id] = {
            "route_cluster_id": cluster_id,
            "target_profile": profile,
            "sites": group_sites,
            "samples": samples,
            "deferred": [site for site in group_sites if site not in sample_set],
        }
    return plan


def _route_cluster_reuse_observation(
    cluster,
    site_result_meta,
    require_zero_raw=True,
):
    observations = set()
    profile = str((cluster or {}).get("target_profile") or "low_info")
    short_scan_prefix = {
        "low_info": "low_info",
        "edge_limited": "edge_limited",
        "restricted": "restricted",
    }.get(profile, "")
    for site in (cluster or {}).get("samples", []):
        sample = (site_result_meta or {}).get(site) or {}
        if (
            sample.get("state_status") != "done"
            or int(sample.get("completed_site_count", 0) or 0) != 1
            or sample.get("retry_mode")
            or int(sample.get("result_count", 0) or 0) != 0
            or int(sample.get("priority_result_count", 0) or 0) != 0
            or int(sample.get("priority_meaningful_result_count", 0) or 0) != 0
            or (
                short_scan_prefix and
                int(sample.get("{}_short_scan_count".format(
                    short_scan_prefix), 0) or 0) != 1
            )
            or (
                short_scan_prefix and
                int(sample.get("{}_escalated_count".format(
                    short_scan_prefix), 0) or 0) != 0
            )
            or int(sample.get("timeout_count", 0) or 0)
            or int(sample.get("failure_count", 0) or 0)
            or int(sample.get("stopped_count", 0) or 0)
            or int(sample.get("transient_verify_count", 0) or 0)
            or int(sample.get("baseline_error_count", 0) or 0)
            or (require_zero_raw and int(sample.get("raw_result_count", 0) or 0))
        ):
            return ""
        observation = str(sample.get("route_observation_key") or "")
        if not observation:
            return ""
        observations.add(observation)
    return next(iter(observations)) if len(observations) == 1 else ""


def _wordlist_fingerprint(words):
    digest = hashlib.sha256()
    digest.update((FFUF_PROFILE_VERSION + "\n").encode("ascii"))
    profile_values = (
        getattr(Config, "FFUF_MATCH_CODES", ""),
        getattr(Config, "FFUF_BASELINE_ENABLE", True),
        getattr(Config, "FFUF_BASELINE_REQUESTS", 3),
        getattr(Config, "FFUF_BASELINE_SIMILARITY", 0.985),
        getattr(Config, "FFUF_PRIORITY_ENABLE", True),
        getattr(Config, "FFUF_PRIORITY_MAX_WORDS", 240),
        getattr(Config, "FFUF_LOW_INFO_MAX_WORDS", 240),
        getattr(Config, "FFUF_LOW_INFO_ESCALATE_ON_HIT", True),
        getattr(Config, "FFUF_EDGE_MAX_WORDS", 240),
        getattr(Config, "FFUF_EDGE_ESCALATE_ON_HIT", True),
        getattr(Config, "FFUF_RESTRICTED_MAX_WORDS", 240),
        getattr(Config, "FFUF_RESTRICTED_ESCALATE_ON_HIT", True),
        getattr(Config, "FFUF_ROUTE_DEDUPE_ENABLE", True),
        getattr(Config, "FFUF_ROUTE_DEDUPE_MIN_CLUSTER_SIZE", 4),
        getattr(Config, "FFUF_ROUTE_DEDUPE_SAMPLE_SIZE", 3),
        getattr(Config, "FFUF_ROUTE_DEDUPE_MAX_SAMPLE_SIZE", 8),
        getattr(Config, "FFUF_ROUTE_DEDUPE_REQUIRE_ZERO_RAW", True),
        getattr(Config, "FFUF_USER_AGENT", ""),
        getattr(Config, "FFUF_ACCEPT", ""),
        getattr(Config, "FFUF_ACCEPT_LANGUAGE", ""),
        getattr(Config, "FFUF_SECOND_LEVEL_ENABLE", True),
        getattr(Config, "FFUF_SECOND_LEVEL_MAX_ROOTS", 10),
        getattr(Config, "FFUF_SECOND_LEVEL_MAX_WORDS", 140),
        getattr(Config, "FFUF_SECOND_LEVEL_WORDS", ""),
    )
    digest.update("|".join(str(value) for value in profile_values).encode(
        "utf-8", errors="ignore"))
    digest.update(b"\n")
    for word in words:
        digest.update(word.encode("utf-8", errors="ignore"))
        digest.update(b"\n")
    return digest.hexdigest()


def _frozen_wordset_id(task_id):
    return "ffuf_wordset:{}:{}".format(
        str(task_id or ""), FFUF_PROFILE_VERSION)


def _load_frozen_ffuf_wordset(task_id):
    if not task_id:
        return None
    try:
        item = utils.conn_db("fileleak_scan_state").find_one(
            {"_id": _frozen_wordset_id(task_id)},
            {
                "_id": 0,
                "words": 1,
                "dict_fingerprint": 1,
                "dynamic_meta": 1,
            },
        )
    except Exception as exc:
        logger.warning("load frozen ffuf wordset failed task:{} error:{}".format(
            task_id, exc))
        return None
    if not item or not item.get("words") or not item.get("dict_fingerprint"):
        return None
    return {
        "words": _build_words(item.get("words") or []),
        "dict_fingerprint": str(item.get("dict_fingerprint") or ""),
        "dynamic_meta": dict(item.get("dynamic_meta") or {}),
        "reused": True,
        "persisted": True,
    }


def _freeze_ffuf_wordset(task_id, words, dict_fingerprint, dynamic_meta):
    result = {
        "words": list(words or []),
        "dict_fingerprint": dict_fingerprint,
        "dynamic_meta": dict(dynamic_meta or {}),
        "reused": False,
        "persisted": False,
    }
    if not task_id:
        return result

    state_id = _frozen_wordset_id(task_id)
    now = utils.curr_date()
    try:
        collection = utils.conn_db("fileleak_scan_state")
        collection.update_one(
            {"_id": state_id},
            {"$setOnInsert": {
                "_id": state_id,
                "task_id": task_id,
                "site": "__task_wordset__",
                "dict_fingerprint": dict_fingerprint,
                "words": list(words or []),
                "dynamic_meta": dict(dynamic_meta or {}),
                "status": "frozen",
                "profile_version": FFUF_PROFILE_VERSION,
                "created_at": now,
                "updated_at": now,
            }},
            upsert=True,
        )
        frozen = collection.find_one(
            {"_id": state_id},
            {
                "_id": 0,
                "words": 1,
                "dict_fingerprint": 1,
                "dynamic_meta": 1,
            },
        ) or {}
        frozen_words = _build_words(frozen.get("words") or [])
        frozen_fingerprint = str(frozen.get("dict_fingerprint") or "")
        if frozen_words and frozen_fingerprint:
            result.update({
                "words": frozen_words,
                "dict_fingerprint": frozen_fingerprint,
                "dynamic_meta": dict(frozen.get("dynamic_meta") or {}),
                "reused": frozen_fingerprint != dict_fingerprint,
                "persisted": True,
            })
    except Exception as exc:
        logger.warning("freeze ffuf wordset failed task:{} error:{}".format(
            task_id, exc))
    return result


def _completed_scan_sites(task_id, dict_fingerprint):
    if not task_id:
        return set()
    return {
        item.get("site")
        for item in utils.conn_db("fileleak_scan_state").find(
            {
                "task_id": task_id,
                "dict_fingerprint": dict_fingerprint,
                "status": "done",
            },
            {"_id": 0, "site": 1},
        )
        if item.get("site")
    }


def _load_ffuf_resume_counters(task_id, dict_fingerprint):
    if not task_id or not dict_fingerprint:
        return {}
    try:
        item = utils.conn_db("task_stage").find_one(
            {"task_id": task_id, "stage": "file_leak"},
            {"_id": 0, "extra": 1},
        ) or {}
    except Exception as exc:
        logger.warning("load ffuf resume counters failed task:{} error:{}".format(
            task_id, exc))
        return {}

    extra = dict(item.get("extra") or {})
    stored_fingerprint = str(extra.get("dict_fingerprint") or "")
    if stored_fingerprint and stored_fingerprint != dict_fingerprint:
        logger.info(
            "ignore ffuf resume counters for changed fingerprint task:{}".format(
                task_id))
        return {}

    counters = {}
    for key in FFUF_RESUME_COUNTER_FIELDS:
        try:
            value = int(extra.get(key, 0) or 0)
        except (TypeError, ValueError):
            continue
        if value > 0:
            counters[key] = value
    return counters


def _scan_attempt_count(task_id, site, dict_fingerprint):
    if not task_id:
        return 0
    item = utils.conn_db("fileleak_scan_state").find_one(
        {
            "task_id": task_id,
            "site": site,
            "dict_fingerprint": dict_fingerprint,
        },
        {"_id": 0, "attempt_count": 1},
    ) or {}
    return max(int(item.get("attempt_count", 0) or 0), 0)


def _scan_attempt_states(task_id, sites, dict_fingerprint):
    sites = sorted(set(sites or []))
    if not task_id or not sites:
        return {}
    states = {}
    try:
        for start in range(0, len(sites), 500):
            batch = sites[start:start + 500]
            for item in utils.conn_db("fileleak_scan_state").find(
                    {
                        "task_id": task_id,
                        "site": {"$in": batch},
                        "dict_fingerprint": dict_fingerprint,
                    },
                    {"_id": 0, "site": 1, "status": 1, "attempt_count": 1}):
                site = str(item.get("site") or "")
                if site:
                    states[site] = item
    except Exception as exc:
        logger.warning("load ffuf attempt states failed task:{} error:{}".format(
            task_id, exc))
    return states


def _attempted_route_sites(task_id, dict_fingerprint, route_sites):
    route_sites = sorted(set(route_sites or []))
    if not task_id or not dict_fingerprint or not route_sites:
        return set()
    try:
        return {
            item.get("site")
            for item in utils.conn_db("fileleak_scan_state").find(
                {
                    "task_id": task_id,
                    "dict_fingerprint": dict_fingerprint,
                    "site": {"$in": route_sites},
                    "attempt_count": {"$gt": 0},
                },
                {"_id": 0, "site": 1},
            )
            if item.get("site")
        }
    except Exception as exc:
        logger.warning(
            "load attempted ffuf route sites failed task:{} error:{}".format(
                task_id, exc))
        return set(route_sites)


def _mark_scan_state(task_id, site, dict_fingerprint, status, result_meta=None):
    if not task_id:
        return
    result_meta = dict(result_meta or {})
    query = {
        "task_id": task_id,
        "site": site,
        "dict_fingerprint": dict_fingerprint,
    }
    fields = {
        "task_id": task_id,
        "site": site,
        "dict_fingerprint": dict_fingerprint,
        "status": status,
        "profile_version": FFUF_PROFILE_VERSION,
        "target_profile": _normalize_target_profile(
            result_meta.get("target_profile")),
        "updated_at": utils.curr_date(),
        "timeout_count": int(result_meta.get("timeout_count", 0) or 0),
        "failure_count": int(result_meta.get("failure_count", 0) or 0),
        "stopped_count": int(result_meta.get("stopped_count", 0) or 0),
        "result_count": int(result_meta.get("result_count", 0) or 0),
        "transient_verify_count": int(
            result_meta.get("transient_verify_count", 0) or 0),
        "baseline_error_count": int(
            result_meta.get("baseline_error_count", 0) or 0),
        "baseline_filtered_count": int(
            result_meta.get("baseline_filtered_count", 0) or 0),
        "scan_word_count": int(result_meta.get("scan_word_count", 0) or 0),
        "priority_scan_word_count": int(
            result_meta.get("priority_scan_word_count", 0) or 0),
        "priority_result_count": int(
            result_meta.get("priority_result_count", 0) or 0),
        "priority_meaningful_result_count": int(
            result_meta.get("priority_meaningful_result_count", 0) or 0),
        "low_info_short_scan_count": int(
            result_meta.get("low_info_short_scan_count", 0) or 0),
        "low_info_escalated_count": int(
            result_meta.get("low_info_escalated_count", 0) or 0),
        "low_info_skipped_full_word_count": int(
            result_meta.get("low_info_skipped_full_word_count", 0) or 0),
        "edge_limited_short_scan_count": int(
            result_meta.get("edge_limited_short_scan_count", 0) or 0),
        "edge_limited_escalated_count": int(
            result_meta.get("edge_limited_escalated_count", 0) or 0),
        "edge_limited_skipped_full_word_count": int(
            result_meta.get("edge_limited_skipped_full_word_count", 0) or 0),
        "route_cluster_id": str(result_meta.get("route_cluster_id") or ""),
        "route_observation_key": str(
            result_meta.get("route_observation_key") or ""),
        "scan_reused": bool(result_meta.get("scan_reused")),
        "scan_reused_from": str(result_meta.get("scan_reused_from") or ""),
        "route_sample_count": int(result_meta.get("route_sample_count", 0) or 0),
        "route_dedupe_decision": str(
            result_meta.get("route_dedupe_decision") or ""),
        "route_dedupe_reused_target_count": int(
            result_meta.get("route_dedupe_reused_target_count", 0) or 0),
        "route_dedupe_saved_word_count": int(
            result_meta.get("route_dedupe_saved_word_count", 0) or 0),
    }
    for key in FFUF_CHECKPOINT_COUNTER_FIELDS:
        fields[key] = int(result_meta.get(key, 0) or 0)
    update = {"$set": fields}
    if status == "running":
        update["$inc"] = {"attempt_count": 1}
        update["$set"]["started_at"] = utils.curr_date()
    elif status in ("done", "partial", "exhausted", "stopped"):
        update["$set"]["finished_at"] = utils.curr_date()
    utils.conn_db("fileleak_scan_state").update_one(query, update, upsert=True)


def _write_wordlist(words):
    fd, path = tempfile.mkstemp(prefix="arl_ffuf_", suffix=".txt", dir=Config.TMP_PATH)
    with os.fdopen(fd, "w") as f:
        for word in words:
            f.write(word + "\n")
    return path


def _load_ffuf_json(path):
    if not os.path.exists(path):
        return []

    with open(path, "r") as f:
        data = json.load(f)

    if isinstance(data, dict):
        results = data.get("results", [])
        return results if isinstance(results, list) else []

    return []


def _ffuf_noise_key(result):
    tolerance = int(getattr(Config, "FFUF_UNIFORM_LENGTH_TOLERANCE", 128) or 0)
    length = int(result.get("length", 0) or 0)
    length_key = length if tolerance <= 0 else int(length / tolerance)
    return (
        result.get("status"),
        length_key,
        result.get("words", 0),
        result.get("lines", 0),
        normalize_redirect_location(
            result.get("redirectlocation", ""), result.get("url", "")),
    )


def _uniform_status_codes():
    raw = str(getattr(Config, "FFUF_FILTER_UNIFORM_STATUS_CODES", "200,401,403,500") or "")
    codes = set()
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            codes.add(int(item))
        except ValueError:
            continue
    return codes or {403}


def _filter_ffuf_results(results):
    if not getattr(Config, "FFUF_FILTER_UNIFORM_403", True):
        return results, 0

    min_count = int(getattr(Config, "FFUF_UNIFORM_403_MIN_COUNT", 20) or 20)
    noisy_status_codes = _uniform_status_codes()
    group_count = {}
    for item in results:
        if item.get("status") not in noisy_status_codes:
            continue
        key = _ffuf_noise_key(item)
        group_count[key] = group_count.get(key, 0) + 1

    noisy_keys = {key for key, count in group_count.items() if count >= min_count}
    if not noisy_keys:
        return results, 0

    filtered = []
    filtered_count = 0
    representatives = set()
    ordered = sorted(results, key=lambda item: str(item.get("url") or ""))
    for item in ordered:
        key = _ffuf_noise_key(item)
        if item.get("status") in noisy_status_codes and key in noisy_keys:
            if key in representatives:
                filtered_count += 1
                continue
            representatives.add(key)
            item = dict(item)
            item["template_detected"] = True
            item["template_scope"] = "site"
            item["template_duplicate_count"] = max(group_count.get(key, 1) - 1, 0)
        filtered.append(item)

    return filtered, filtered_count


def _task_uniform_status_codes():
    raw = str(getattr(
        Config,
        "FFUF_TASK_UNIFORM_STATUS_CODES",
        "200,301,302,307,308,401,403,500",
    ) or "")
    codes = set()
    for item in raw.split(","):
        try:
            codes.add(int(item.strip()))
        except (TypeError, ValueError):
            continue
    return codes


def _page_noise_key(page):
    tolerance = int(getattr(Config, "FFUF_UNIFORM_LENGTH_TOLERANCE", 128) or 0)
    length = int(getattr(page, "content_length", 0) or 0)
    length_key = length if tolerance <= 0 else int(length / tolerance)
    return (
        getattr(page, "status_code", None),
        length_key,
        int(getattr(page, "words", 0) or 0),
        int(getattr(page, "lines", 0) or 0),
        str(getattr(page, "content_type", "") or "").split(";", 1)[0].strip().lower(),
        normalize_redirect_location(
            getattr(page, "redirect_location", ""), getattr(page, "url", "")),
    )


def _filter_task_uniform_results(pages):
    if not getattr(Config, "FFUF_TASK_UNIFORM_FILTER", True):
        return list(pages), []

    noisy_codes = _task_uniform_status_codes()
    groups = {}
    for page in pages:
        if page.status_code not in noisy_codes:
            continue
        groups.setdefault(_page_noise_key(page), []).append(page)

    noisy_keys = set()
    protected_site_keys = set()
    protected_site_counts = {}
    for key, items in groups.items():
        status_code = key[0]
        hosts = set()
        paths = set()
        host_paths = {}
        for page in items:
            parsed = urlparse(page.url)
            host = parsed.netloc.lower() if parsed.netloc else ""
            if host:
                hosts.add(host)
            if parsed.path:
                paths.add(parsed.path)
                if host:
                    host_paths.setdefault(host, set()).add(parsed.path)

        if status_code == 200:
            min_count = int(getattr(Config, "FFUF_TASK_UNIFORM_200_MIN_COUNT", 40) or 40)
            min_hosts = int(getattr(Config, "FFUF_TASK_UNIFORM_200_MIN_HOSTS", 5) or 5)
            min_paths = int(getattr(Config, "FFUF_TASK_UNIFORM_200_MIN_PATHS", 5) or 5)
        elif status_code in (301, 302, 307, 308):
            min_count = int(getattr(Config, "FFUF_TASK_UNIFORM_REDIRECT_MIN_COUNT", 20) or 20)
            min_hosts = int(getattr(Config, "FFUF_TASK_UNIFORM_REDIRECT_MIN_HOSTS", 2) or 2)
            min_paths = int(getattr(Config, "FFUF_TASK_UNIFORM_REDIRECT_MIN_PATHS", 10) or 10)
        else:
            min_count = int(getattr(Config, "FFUF_TASK_UNIFORM_ERROR_MIN_COUNT", 12) or 12)
            min_hosts = int(getattr(Config, "FFUF_TASK_UNIFORM_ERROR_MIN_HOSTS", 3) or 3)
            min_paths = int(getattr(Config, "FFUF_TASK_UNIFORM_ERROR_MIN_PATHS", 3) or 3)

        if len(items) >= min_count and len(hosts) >= min_hosts and len(paths) >= min_paths:
            noisy_keys.add(key)

        # A single protected host can produce many identical 401/403 pages
        # even when the task-wide host threshold is not met.  Keep one
        # representative after enough distinct paths, while preserving the
        # remaining paths as scan evidence in the raw scanner output.
        if status_code in (401, 403):
            min_site_paths = max(int(getattr(
                Config, "FFUF_SITE_PROTECTED_TEMPLATE_MIN_PATHS", 3) or 3), 2)
            for host, host_path_values in host_paths.items():
                if len(host_path_values) >= min_site_paths:
                    protected_key = (key, host)
                    protected_site_keys.add(protected_key)
                    protected_site_counts[protected_key] = len(host_path_values)

    if not noisy_keys and not protected_site_keys:
        return list(pages), []

    kept = []
    removed = []
    representatives = set()
    ordered = sorted(pages, key=lambda page: str(page.url or ""))
    for page in ordered:
        key = _page_noise_key(page)
        host = (urlparse(page.url).netloc or "").lower()
        protected_key = (key, host)
        if key not in noisy_keys and protected_key not in protected_site_keys:
            kept.append(page)
            continue
        representative_key = (key, host)
        if representative_key in representatives:
            removed.append(page)
            continue
        representatives.add(representative_key)
        page.template_detected = True
        page.template_scope = (
            "task" if key in noisy_keys else "site_protected")
        page.template_duplicate_count = max(
            protected_site_counts.get(protected_key, len(groups.get(key, []))) - 1,
            0,
        )
        kept.append(page)
    return kept, removed


def _enrich_titles(pages):
    if not getattr(Config, "FFUF_ENRICH_TITLE", True):
        return
    max_pages = max(int(getattr(Config, "FFUF_TITLE_MAX_PER_SITE", 40) or 0), 0)
    candidates = []
    for page in pages:
        if page.title or page.verification_status == "verified":
            continue
        content_type = str(page.content_type or "").lower()
        try:
            status_code = int(page.status_code) if page.status_code is not None else None
        except (TypeError, ValueError):
            status_code = None
        if status_code is not None and not (200 <= status_code < 400):
            continue
        if content_type and "html" not in content_type and "xhtml" not in content_type:
            continue
        candidates.append(page)
        if max_pages and len(candidates) >= max_pages:
            break
    if not candidates:
        return
    workers = min(
        max(int(getattr(Config, "FFUF_TITLE_CONCURRENCY", 4) or 1), 1),
        len(candidates),
    )
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(page.enrich_title) for page in candidates]
        for future in futures:
            try:
                future.result()
            except Exception as e:
                logger.debug("ffuf title worker failed: {}".format(e))


def _task_stopped(task_id):
    if not task_id:
        return False
    try:
        return BaseUpdateTask(task_id).is_terminal()
    except Exception as e:
        logger.warning("ffuf check task status failed: {}".format(e))
        return False


def _task_stop_checker(task_id, interval=1.0):
    state = {"checked_at": 0.0, "stopped": False}
    lock = threading.Lock()

    def check():
        if not task_id:
            return False
        now = time.time()
        with lock:
            if now - state["checked_at"] >= interval:
                state["stopped"] = _task_stopped(task_id)
                state["checked_at"] = now
            return state["stopped"]

    return check


def _terminate_process_group(proc, reason):
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return

    try:
        proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.communicate()

    logger.warning("ffuf process terminated: {}".format(reason))


def _ffuf_request_headers():
    return ["{}: {}".format(key, value) for key, value in browser_request_headers().items()]


def _execute_ffuf(
    target,
    words,
    task_id=None,
    rate=None,
    scan_depth=1,
    parent_map=None,
    process_timeout=None,
):
    ffuf_bin = getattr(Config, "FFUF_BIN", "ffuf")
    if not shutil.which(ffuf_bin) and not os.path.exists(ffuf_bin):
        raise RuntimeError("ffuf binary not found: {}".format(ffuf_bin))

    wordlist = _write_wordlist(words)
    out_fd, out_path = tempfile.mkstemp(prefix="arl_ffuf_result_", suffix=".json", dir=Config.TMP_PATH)
    os.close(out_fd)

    url = target.rstrip("/") + "/FUZZ"
    cmd = [
        ffuf_bin,
        "-u", url,
        "-w", wordlist,
        "-ac",
        "-ach",
        "-mc", str(getattr(
            Config,
            "FFUF_MATCH_CODES",
            "200,204,301,302,303,307,308,400,401,403,405,500,501,502,503,504",
        )),
        "-timeout", str(int(getattr(Config, "FFUF_TIMEOUT", 8))),
        "-rate", str(int(rate or getattr(Config, "FFUF_RATE", 30))),
        "-of", "json",
        "-o", out_path,
        "-s",
    ]
    for header in _ffuf_request_headers():
        cmd.extend(["-H", header])

    logger.info(
        "start ffuf fileleak target:{} depth:{} words:{}".format(
            target, scan_depth, len(words)))
    t1 = time.time()
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        process_timeout = int(
            process_timeout
            if process_timeout is not None
            else getattr(Config, "FFUF_PROCESS_TIMEOUT", 600)
        )
        deadline = time.time() + process_timeout
        stdout = ""
        stderr = ""
        while True:
            if proc.poll() is not None:
                stdout, stderr = proc.communicate()
                break

            if _task_stopped(task_id):
                _terminate_process_group(proc, "task stopped {}".format(task_id))
                return FfufResult(meta={"stopped_count": 1})

            if time.time() > deadline:
                _terminate_process_group(proc, "timeout after {}s".format(process_timeout))
                return FfufResult(meta={
                    "timeout_count": 1,
                    "warnings": ["ffuf timeout on {} after {}s".format(target, process_timeout)],
                })

            time.sleep(0.5)

        elapse = time.time() - t1
        if proc.returncode not in (0, 1):
            logger.warning("ffuf failed target:{} code:{} stderr:{}".format(target, proc.returncode, stderr[-1000:]))
            return FfufResult(meta={
                "failure_count": 1,
                "warnings": ["ffuf exit {} on {}".format(proc.returncode, target)],
            })

        raw_results = _load_ffuf_json(out_path)
        results, filtered_count = _filter_ffuf_results(raw_results)
        logger.info(
            "end ffuf fileleak target:{} depth:{} found:{} filtered:{} raw:{} elapse:{}".format(
                target, scan_depth, len(results), filtered_count, len(raw_results), elapse))
        pages = []
        for result in results:
            result = dict(result)
            result["scan_depth"] = scan_depth
            fuzz = result.get("input", {}).get("FUZZ") if isinstance(
                result.get("input"), dict) else ""
            parent = (parent_map or {}).get(str(fuzz or ""), "")
            if parent:
                result["parent_entry"] = target.rstrip("/") + "/" + parent.lstrip("/")
            pages.append(FfufPage(result, site=target))
        return FfufResult(
            pages,
            meta={
                "scan_completed": 1,
                "site_filtered_count": filtered_count,
                "raw_result_count": len(raw_results),
                "scan_word_count": len(words),
            },
        )
    finally:
        for tmp_path in (wordlist, out_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def _verify_pages(pages, baseline, task_id=None, parent_baselines=None):
    pages = list(pages or [])
    if not pages:
        return [], [], {
            "verified_result_count": 0,
            "unverified_result_count": 0,
            "baseline_filtered_count": 0,
            "sso_protected_count": 0,
            "protected_result_count": 0,
            "stale_result_count": 0,
            "transient_verify_count": 0,
        }

    verify_enabled = bool(getattr(Config, "FFUF_BASELINE_ENABLE", True))
    verify_max = max(int(getattr(Config, "FFUF_VERIFY_MAX_RESULTS", 200) or 0), 0)
    candidates = pages[:verify_max] if verify_enabled and verify_max else []
    signatures = {}
    probe_reasons = {}
    if candidates:
        workers = min(
            max(int(getattr(Config, "FFUF_VERIFY_CONCURRENCY", 4) or 1), 1),
            len(candidates),
        )
        timeout = int(getattr(Config, "FFUF_BASELINE_TIMEOUT", 5) or 5)
        stop_cache = {"checked_at": 0.0, "stopped": False}
        stop_lock = threading.Lock()

        def should_stop_cached():
            if not task_id:
                return False
            now = time.time()
            with stop_lock:
                if now - stop_cache["checked_at"] >= 1.0:
                    stop_cache["stopped"] = _task_stopped(task_id)
                    stop_cache["checked_at"] = now
                return stop_cache["stopped"]

        with ThreadPoolExecutor(max_workers=workers) as executor:
            def probe_page(page):
                if should_stop_cached():
                    return None, "task_stopped"
                return probe_response_signature(page.url, timeout), ""

            futures = {executor.submit(probe_page, page): page for page in candidates}
            for future in as_completed(futures):
                page = futures[future]
                try:
                    signature, reason = future.result()
                    signatures[id(page)] = signature
                    probe_reasons[id(page)] = reason
                except Exception as exc:
                    signatures[id(page)] = None
                    probe_reasons[id(page)] = "probe_failed"
                    logger.debug("ffuf verify failed {} {}".format(page.url, exc))

    kept = []
    removed = []
    meta = {
        "verified_result_count": 0,
        "unverified_result_count": 0,
        "baseline_filtered_count": 0,
        "entry_candidate_count": 0,
        "resource_clue_count": 0,
        "redirect_clue_count": 0,
        "redirect_template_count": 0,
        "non_entry_result_count": 0,
        "sso_protected_count": 0,
        "protected_result_count": 0,
        "stale_result_count": 0,
        "transient_verify_count": 0,
    }
    length_tolerance = int(getattr(Config, "FFUF_UNIFORM_LENGTH_TOLERANCE", 128) or 0)
    similarity = float(getattr(Config, "FFUF_BASELINE_SIMILARITY", 0.985) or 0.985)
    result_types = {
        "path_entry",
        "protected_401_403",
        "sso_protected",
        "resource_clue",
        "redirect_clue",
        "redirect_template",
    }
    for page in pages:
        signature = signatures.pop(id(page), None)
        if signature is None:
            page.entry_type = "unverified_path"
            page.verification_status = "unverified"
            page.verification_reason = probe_reasons.get(id(page)) or (
                "verification_not_run" if page not in candidates else "probe_failed")
            meta["unverified_result_count"] += 1
            meta["non_entry_result_count"] += 1
            removed.append(page)
            continue

        page.status_code = signature.status_code
        page.content_length = signature.content_length
        page.content_type = signature.content_type or page.content_type
        page.redirect_location = signature.location or page.redirect_location
        page.title = signature.title
        page.words = signature.word_count
        page.lines = signature.line_count
        page_baseline = (parent_baselines or {}).get(
            str(page.parent_entry or "").rstrip("/"), baseline)
        transient_response = (
            is_transient_block_page({
                "status": signature.status_code,
                "title": signature.title,
            })
            or signature.status_code in (408, 425)
            or (
                signature.status_code is not None
                and 500 <= signature.status_code < 600
            )
        )
        if signature.status_code == 404:
            entry_type, baseline_match, reason = (
                "template_suspect", True, "verification_404")
            meta["stale_result_count"] += 1
        elif transient_response:
            entry_type, baseline_match, reason = (
                "unverified_path", False, "transient_verification_response")
            meta["transient_verify_count"] += 1
        else:
            entry_type, baseline_match, reason = classify_response(
                signature,
                page_baseline,
                length_tolerance=length_tolerance,
                similarity=similarity,
            )
        if page.template_detected and not baseline_match and not transient_response:
            if signature.status_code in (301, 302, 303, 307, 308):
                entry_type = "redirect_template"
                reason = "ffuf_uniform_redirect_template"
            else:
                entry_type = "template_suspect"
                reason = "ffuf_uniform_template"
        page.entry_type = entry_type
        page.verification_status = (
            "unverified" if entry_type == "unverified_path" else "verified")
        page.verification_reason = reason
        meta["verified_result_count"] += 1
        if baseline_match:
            meta["baseline_filtered_count"] += 1
            removed.append(page)
            continue
        if transient_response:
            meta["non_entry_result_count"] += 1
            removed.append(page)
            continue
        if entry_type == "sso_protected":
            meta["sso_protected_count"] += 1
        elif entry_type == "protected_401_403":
            meta["protected_result_count"] += 1
        if entry_type in {"path_entry", "protected_401_403", "sso_protected"}:
            meta["entry_candidate_count"] += 1
        elif entry_type == "resource_clue":
            meta["resource_clue_count"] += 1
        elif entry_type == "redirect_clue":
            meta["redirect_clue_count"] += 1
        elif entry_type == "redirect_template":
            meta["redirect_template_count"] += 1
        elif entry_type not in result_types:
            meta["non_entry_result_count"] += 1
            removed.append(page)
            continue
        kept.append(page)
    return kept, removed, meta


def _merge_scan_meta(destination, source):
    for key in (
        "site_filtered_count", "timeout_count", "failure_count", "stopped_count",
        "raw_result_count", "scan_word_count", "verified_result_count",
        "unverified_result_count", "baseline_filtered_count", "sso_protected_count",
        "protected_result_count", "entry_candidate_count", "resource_clue_count",
        "redirect_clue_count", "non_entry_result_count", "second_level_input_count",
        "redirect_template_count",
        "second_level_result_count", "stale_result_count",
        "transient_verify_count",
        "priority_meaningful_result_count", "low_info_short_scan_count",
        "low_info_escalated_count", "low_info_skipped_full_word_count",
        "edge_limited_short_scan_count", "edge_limited_escalated_count",
        "edge_limited_skipped_full_word_count",
        "restricted_short_scan_count", "restricted_escalated_count",
        "restricted_skipped_full_word_count",
    ):
        destination[key] = int(destination.get(key, 0) or 0) + int(
            (source or {}).get(key, 0) or 0)
    for warning in (source or {}).get("warnings", []) or []:
        if warning and warning not in destination["warnings"]:
            destination["warnings"].append(str(warning))


def _run_ffuf(
    target,
    words,
    task_id=None,
    rate=None,
    enable_dynamic=True,
    on_batch=None,
    retry_mode=False,
    target_profile="normal",
    site_scoped_words=None,
    site_scoped_only=False,
):
    target_profile = _normalize_target_profile(target_profile)
    should_stop = _task_stop_checker(task_id)
    baseline = build_site_baseline(
        target,
        request_count=int(getattr(Config, "FFUF_BASELINE_REQUESTS", 3) or 0),
        timeout=int(getattr(Config, "FFUF_BASELINE_TIMEOUT", 5) or 5),
        should_stop=should_stop,
    )
    if baseline.stopped:
        return FfufResult(meta={
            "stopped_count": 1,
            "target_profile": target_profile,
            "profile_version": FFUF_PROFILE_VERSION,
        })
    expected_baseline_requests = (
        max(int(getattr(Config, "FFUF_BASELINE_REQUESTS", 3) or 0), 0) + 1
    )
    if (
        baseline.root_signature is None and
        baseline.error_count >= expected_baseline_requests
    ):
        # If root and random probes all fail, ffuf cannot get a useful
        # response. Complete this site with a warning instead of waiting for
        # the full process timeout on a dead endpoint.
        warning = (
            "ffuf skipped unreachable target after baseline failures: {}"
        ).format(target)
        logger.info(warning)
        return FfufResult(meta={
            "completed_site_count": 1,
            "baseline_request_count": baseline.request_count,
            "baseline_error_count": baseline.error_count,
            "target_profile": target_profile,
            "profile_version": FFUF_PROFILE_VERSION,
            "warnings": [warning],
        })
    route_observation_key = _baseline_route_observation_key(baseline)
    local_dynamic_limit = max(
        int(getattr(Config, "FFUF_DYNAMIC_SITE_MAX_WORDS", 40) or 0), 0)
    site_scoped_words = _build_words(site_scoped_words or [])
    site_scoped_set = set(site_scoped_words)
    shared_words = _build_words(
        list(baseline.dynamic_words[:local_dynamic_limit] if enable_dynamic else [])
        + ([] if site_scoped_only else list(words or [])))
    shared_words = [word for word in shared_words if word not in site_scoped_set]
    if retry_mode:
        retry_limit = max(int(getattr(
            Config, "FFUF_RETRY_MAX_WORDS", 120) or 0), 0)
        priority_words, remaining_words = split_priority_words(
            shared_words, max_words=retry_limit)
        shared_words = _build_words(
            list(priority_words) + list(remaining_words))[:retry_limit]
    meta = {
        "completed_site_count": 0,
        "site_filtered_count": 0,
        "timeout_count": 0,
        "failure_count": 0,
        "stopped_count": 0,
        "raw_result_count": 0,
        "scan_word_count": 0,
        "verified_result_count": 0,
        "unverified_result_count": 0,
        "baseline_filtered_count": 0,
        "entry_candidate_count": 0,
        "resource_clue_count": 0,
        "redirect_clue_count": 0,
        "redirect_template_count": 0,
        "non_entry_result_count": 0,
        "sso_protected_count": 0,
        "protected_result_count": 0,
        "stale_result_count": 0,
        "transient_verify_count": 0,
        "second_level_input_count": 0,
        "second_level_result_count": 0,
        "priority_scan_word_count": 0,
        "priority_result_count": 0,
        "priority_meaningful_result_count": 0,
        "low_info_short_scan_count": 0,
        "low_info_escalated_count": 0,
        "low_info_skipped_full_word_count": 0,
        "edge_limited_short_scan_count": 0,
        "edge_limited_escalated_count": 0,
        "edge_limited_skipped_full_word_count": 0,
        "restricted_short_scan_count": 0,
        "restricted_escalated_count": 0,
        "restricted_skipped_full_word_count": 0,
        "batch_emitted_count": 0,
        "baseline_request_count": baseline.request_count,
        "baseline_error_count": baseline.error_count,
        "site_dynamic_word_count": len(
            baseline.dynamic_words[:local_dynamic_limit] if enable_dynamic else []),
        "site_scoped_target_count": int(bool(site_scoped_words)),
        "site_scoped_scan_word_count": 0,
        "site_scoped_result_count": 0,
        "site_scoped_meaningful_result_count": 0,
        "warnings": [],
        "retry_mode": bool(retry_mode),
        "target_profile": target_profile,
        "profile_version": FFUF_PROFILE_VERSION,
        "route_observation_key": route_observation_key,
        "scan_reused": False,
    }
    removed_urls = []

    kept = []

    def emit_batch(pages):
        pages = list(pages or [])
        if not pages or not on_batch:
            return
        _enrich_titles(pages)
        try:
            on_batch(pages)
            meta["batch_emitted_count"] += len(pages)
        except Exception as exc:
            warning = "ffuf early result callback failed on {}: {}".format(target, exc)
            logger.exception(warning)
            if warning not in meta["warnings"]:
                meta["warnings"].append(warning)

    short_scan_limits = {
        "low_info": max(int(getattr(
            Config, "FFUF_LOW_INFO_MAX_WORDS", 240) or 0), 0),
        "edge_limited": max(int(getattr(
            Config, "FFUF_EDGE_MAX_WORDS", 240) or 0), 0),
        "restricted": max(int(getattr(
            Config, "FFUF_RESTRICTED_MAX_WORDS", 240) or 0), 0),
    }
    short_scan_prefix = {
        "low_info": "low_info",
        "edge_limited": "edge_limited",
        "restricted": "restricted",
    }.get(target_profile, "")
    short_scan_limit = short_scan_limits.get(target_profile, 0)
    short_scan_strategy = not retry_mode and short_scan_limit > 0
    if retry_mode:
        priority_words, remaining_words = shared_words, []
    elif short_scan_strategy:
        priority_words, remaining_words = split_priority_words(
            shared_words,
            max_words=short_scan_limit,
        )
        if len(priority_words) < short_scan_limit:
            fill_count = short_scan_limit - len(priority_words)
            fill_words = remaining_words[:fill_count]
            priority_words.extend(fill_words)
            fill_set = set(fill_words)
            remaining_words = [
                word for word in remaining_words if word not in fill_set]
    elif getattr(Config, "FFUF_PRIORITY_ENABLE", True):
        priority_words, remaining_words = split_priority_words(
            shared_words,
            max_words=int(getattr(Config, "FFUF_PRIORITY_MAX_WORDS", 240) or 0),
        )
    else:
        priority_words, remaining_words = [], shared_words
    scan_passes = []
    if site_scoped_words:
        scan_passes.append(("site-scoped", site_scoped_words))
    if priority_words:
        scan_passes.append(("priority", priority_words))
    if remaining_words:
        scan_passes.append(("full", remaining_words))

    main_scan_completed = bool(scan_passes)
    for pass_name, pass_words in scan_passes:
        if pass_name == "full" and short_scan_strategy:
            prefix = short_scan_prefix
            escalate_config = {
                "restricted": "FFUF_RESTRICTED_ESCALATE_ON_HIT",
                "edge_limited": "FFUF_EDGE_ESCALATE_ON_HIT",
                "low_info": "FFUF_LOW_INFO_ESCALATE_ON_HIT",
            }[target_profile]
            should_escalate = (
                bool(getattr(Config, escalate_config, True))
                and (
                    meta["priority_meaningful_result_count"]
                    + meta["site_scoped_meaningful_result_count"]
                ) > 0
            )
            if not should_escalate:
                meta["{}_short_scan_count".format(prefix)] = 1
                meta["{}_skipped_full_word_count".format(prefix)] += len(pass_words)
                logger.info(
                    "ffuf {} short scan target:{} priority_hits:{} skipped_words:{}".format(
                        target_profile,
                        target,
                        meta["priority_meaningful_result_count"],
                        len(pass_words),
                    )
                )
                continue
            meta["{}_escalated_count".format(prefix)] = 1
        result = _execute_ffuf(
            target,
            pass_words,
            task_id=task_id,
            rate=rate,
            scan_depth=1,
            process_timeout=(
                int(getattr(Config, "FFUF_RETRY_PROCESS_TIMEOUT", 180) or 180)
                if retry_mode else
                int(getattr(
                    Config, "FFUF_RESTRICTED_PROCESS_TIMEOUT", 180) or 180)
                if target_profile == "restricted" else
                int(getattr(
                    Config, "FFUF_EDGE_PROCESS_TIMEOUT", 180) or 180)
                if target_profile == "edge_limited" else None
            ),
        )
        _merge_scan_meta(meta, result.meta)
        pass_kept, pass_removed, verify_meta = _verify_pages(
            result, baseline, task_id=task_id)
        _merge_scan_meta(meta, verify_meta)
        removed_urls.extend(page.url for page in pass_removed if page.url)
        meaningful_count = sum(
            int(verify_meta.get(key, 0) or 0)
            for key in (
                "entry_candidate_count",
                "resource_clue_count",
                "redirect_clue_count",
                "protected_result_count",
            )
        )
        if pass_name == "site-scoped":
            meta["site_scoped_scan_word_count"] += len(pass_words)
            meta["site_scoped_result_count"] += len(pass_kept)
            meta["site_scoped_meaningful_result_count"] += meaningful_count
        elif pass_name == "priority":
            meta["priority_scan_word_count"] += len(pass_words)
            meta["priority_result_count"] += len(pass_kept)
            meta["priority_meaningful_result_count"] += meaningful_count
        kept.extend(pass_kept)
        emit_batch(pass_kept)
        if not result.meta.get("scan_completed"):
            main_scan_completed = False
            break
    if (
        short_scan_strategy
        and main_scan_completed
        and not meta["{}_escalated_count".format(short_scan_prefix)]
        and not meta["{}_short_scan_count".format(short_scan_prefix)]
    ):
        meta["{}_short_scan_count".format(short_scan_prefix)] = 1
    if main_scan_completed:
        meta["completed_site_count"] = 1

    second_enabled = (
        bool(getattr(Config, "FFUF_SECOND_LEVEL_ENABLE", True))
        and not retry_mode
    )
    if (
        second_enabled
        and kept
        and main_scan_completed
        and (
            not short_scan_strategy
            or (
                meta["priority_meaningful_result_count"]
                + meta["site_scoped_meaningful_result_count"]
            ) > 0
        )
        and not _task_stopped(task_id)
    ):
        child_words = str(getattr(
            Config,
            "FFUF_SECOND_LEVEL_WORDS",
            "login,index,admin,manage,manager,console,portal,workspace,home,main,system,dashboard,web,app",
        ) or "").split(",")
        second_words, parent_map = build_secondary_words(
            kept,
            child_words=child_words,
            max_roots=int(getattr(Config, "FFUF_SECOND_LEVEL_MAX_ROOTS", 10) or 0),
            max_words=int(getattr(Config, "FFUF_SECOND_LEVEL_MAX_WORDS", 140) or 0),
        )
        primary_word_set = set(site_scoped_words) | set(shared_words)
        second_words = [word for word in second_words if word not in primary_word_set]
        if second_words:
            meta["second_level_input_count"] += len(second_words)
            parent_baselines = build_parent_baselines(
                target,
                parent_map.values(),
                timeout=int(getattr(Config, "FFUF_BASELINE_TIMEOUT", 5) or 5),
                should_stop=should_stop,
                concurrency=int(getattr(Config, "FFUF_VERIFY_CONCURRENCY", 4) or 1),
            )
            meta["baseline_request_count"] += parent_baselines.request_count
            meta["baseline_error_count"] += parent_baselines.error_count
            if parent_baselines.stopped:
                meta["stopped_count"] += 1
                return FfufResult(
                    kept,
                    meta=meta,
                    removed_urls=ordered_unique(removed_urls),
                )
            second = _execute_ffuf(
                target,
                second_words,
                task_id=task_id,
                rate=rate,
                scan_depth=2,
                parent_map=parent_map,
            )
            _merge_scan_meta(meta, second.meta)
            second_kept, second_removed, second_verify_meta = _verify_pages(
                second,
                baseline,
                task_id=task_id,
                parent_baselines=parent_baselines,
            )
            _merge_scan_meta(meta, second_verify_meta)
            meta["second_level_result_count"] += len(second_kept)
            removed_urls.extend(page.url for page in second_removed if page.url)
            kept.extend(second_kept)
            emit_batch(second_kept)

    unique_pages = []
    seen_urls = set()
    for page in kept:
        if not page.url or page.url in seen_urls:
            continue
        seen_urls.add(page.url)
        unique_pages.append(page)
    _enrich_titles(unique_pages)
    return FfufResult(
        unique_pages,
        meta=meta,
        removed_urls=ordered_unique(removed_urls),
    )


def _file_leak_single_site(
    site,
    words,
    task_id=None,
    rate=None,
    enable_dynamic=True,
    on_batch=None,
    retry_mode=False,
    target_profile="normal",
    site_scoped_words=None,
    site_scoped_only=False,
):
    target_profile = _normalize_target_profile(target_profile)
    target = normal_url(site.strip())
    if not target:
        return []

    try:
        pages = _run_ffuf(
            target,
            words,
            task_id=task_id,
            rate=rate,
            enable_dynamic=enable_dynamic,
            on_batch=on_batch,
            retry_mode=retry_mode,
            target_profile=target_profile,
            site_scoped_words=site_scoped_words,
            site_scoped_only=site_scoped_only,
        )
        for page in pages:
            logger.info("found => {}".format(page))
        return pages
    except Exception as e:
        logger.info("error on ffuf {}, {}".format(target, e))
        logger.exception(e)
        return FfufResult(meta={
            "failure_count": 1,
            "target_profile": target_profile,
            "profile_version": FFUF_PROFILE_VERSION,
            "warnings": ["ffuf failed on {}: {}".format(target, e)],
        })


def file_leak(
    targets,
    dicts,
    gen_dict=True,
    task_id=None,
    on_result=None,
    target_profiles=None,
    target_route_keys=None,
) -> List[FfufPage]:
    target_profiles = {
        str(site or "").rstrip("/"): _normalize_target_profile(profile)
        for site, profile in (target_profiles or {}).items()
    }
    target_route_keys = {
        str(site or "").rstrip("/"): str(route_key or "").strip()
        for site, route_key in (target_route_keys or {}).items()
        if str(route_key or "").strip()
    }
    site_list = []
    known = set()
    for site in targets:
        site = normal_url(str(site or "").strip())
        if not site:
            continue
        dedupe_key = site.rstrip("/")
        if dedupe_key in known:
            continue
        known.add(dedupe_key)
        site_list.append(site)

    input_site_count = len(site_list)
    base_domain = _task_target(task_id) if gen_dict and task_id else ""
    site_scoped_words_by_site = {
        site: (
            site_scoped_domain_path_words(site, base_domain=base_domain)
            if gen_dict else []
        )
        for site in site_list
    }
    frozen_wordset = _load_frozen_ffuf_wordset(task_id)
    dynamic_words = []
    dynamic_meta = {"dynamic_word_count": 0}
    if frozen_wordset:
        words = frozen_wordset["words"]
        dict_fingerprint = frozen_wordset["dict_fingerprint"]
        dynamic_meta.update(frozen_wordset.get("dynamic_meta") or {})
        wordset_reused = True
        wordset_persisted = True
    else:
        if gen_dict and task_id and site_list:
            dynamic_words, dynamic_meta = build_dynamic_path_words(
                task_id,
                site_list,
                limit=int(getattr(Config, "FFUF_DYNAMIC_MAX_WORDS", 300) or 0),
                source_limit=int(getattr(Config, "FFUF_DYNAMIC_SOURCE_LIMIT", 5000) or 0),
            )
        task_wide_dynamic_words = _shared_dynamic_words(
            dynamic_words, dynamic_meta)
        words = _build_words(
            list(task_wide_dynamic_words) + list(dicts or []))
        dict_fingerprint = _wordlist_fingerprint(words) if words else ""
        frozen_wordset = _freeze_ffuf_wordset(
            task_id, words, dict_fingerprint, dynamic_meta) if words else None
        if frozen_wordset:
            words = frozen_wordset["words"]
            dict_fingerprint = frozen_wordset["dict_fingerprint"]
            dynamic_meta = frozen_wordset.get("dynamic_meta") or dynamic_meta
            wordset_reused = bool(frozen_wordset.get("reused"))
            wordset_persisted = bool(frozen_wordset.get("persisted"))
        else:
            wordset_reused = False
            wordset_persisted = False
    dynamic_meta.update({
        "site_scoped_candidate_target_count": sum(
            int(bool(values)) for values in site_scoped_words_by_site.values()),
        "site_scoped_candidate_word_count": sum(
            len(values) for values in site_scoped_words_by_site.values()),
        "task_wide_domain_word_removed_count": len(
            dynamic_meta.get("dynamic_selected_domain_words") or []),
    })
    if not words and not any(site_scoped_words_by_site.values()):
        return FfufResult(meta={
            "input_site_count": input_site_count,
            "dynamic_word_count": len(dynamic_words),
            "ffuf_wordset_reused": wordset_reused,
            "ffuf_wordset_persisted": wordset_persisted,
        })

    attempt_states = _scan_attempt_states(
        task_id, site_list, dict_fingerprint)
    for completed_site in _completed_scan_sites(task_id, dict_fingerprint):
        state = dict(attempt_states.get(completed_site) or {})
        state["status"] = "done"
        attempt_states[completed_site] = state
    site_list, completed_sites, exhausted_sites = _partition_scan_sites(
        site_list,
        target_profiles,
        attempt_states,
        getattr(Config, "FFUF_SITE_MAX_ATTEMPTS", 2),
    )
    skipped_completed_site_count = len(completed_sites)
    exhausted_site_count = len(exhausted_sites)
    if exhausted_sites and task_id:
        utils.conn_db("fileleak_scan_state").update_many(
            {
                "task_id": task_id,
                "site": {"$in": exhausted_sites},
                "dict_fingerprint": dict_fingerprint,
                "status": {"$ne": "done"},
            },
            {"$set": {
                "status": "exhausted",
                "finished_at": utils.curr_date(),
                "updated_at": utils.curr_date(),
            }},
        )
    pending_site_count = len(site_list)
    site_list, deferred_sites = _fair_site_slice(
        site_list,
        target_profiles,
        getattr(Config, "FFUF_TASK_SLICE_MAX_SITES", 80),
    )
    deferred_site_count = len(deferred_sites)
    resume_counters = _load_ffuf_resume_counters(
        task_id, dict_fingerprint) if wordset_reused else {}
    if not site_list:
        completed_meta = {
            "input_site_count": input_site_count,
            "completed_site_count": skipped_completed_site_count,
            "skipped_completed_site_count": skipped_completed_site_count,
            "exhausted_site_count": exhausted_site_count,
            "retryable_failure_site_count": 0,
            "site_filtered_count": 0,
            "task_filtered_count": 0,
            "timeout_count": 0,
            "failure_count": 0,
            "stopped_count": 0,
            "warnings": ([
                "ffuf exhausted {} site retry limit(s)".format(
                    exhausted_site_count)
            ] if exhausted_site_count else []),
            "dict_fingerprint": dict_fingerprint,
            "ffuf_wordset_reused": wordset_reused,
            "ffuf_wordset_persisted": wordset_persisted,
            "progress_resumed": bool(resume_counters),
            "progress_resume_counter_count": len(resume_counters),
            "pending_site_count": 0,
            "slice_site_count": 0,
            "deferred_site_count": 0,
            "continuation_required": False,
            **dynamic_meta,
        }
        completed_meta.update(resume_counters)
        completed_meta["completed_site_count"] = skipped_completed_site_count
        completed_meta["exhausted_site_count"] = exhausted_site_count
        completed_meta["retryable_failure_site_count"] = 0
        return FfufResult(meta=completed_meta)

    concurrency = max(int(getattr(Config, "FFUF_SITE_CONCURRENCY", 2)), 1)
    concurrency = min(concurrency, len(site_list))
    ret = []
    ret_lock = threading.Lock()
    callback_lock = threading.Lock()
    streamed_urls = set()
    profile_counts = Counter(
        target_profiles.get(site.rstrip("/"), "normal") for site in site_list)
    route_sites = [
        site for site in site_list
        if target_route_keys.get(site.rstrip("/"))
    ]
    attempted_route_sites = _attempted_route_sites(
        task_id, dict_fingerprint, route_sites) if route_sites else set()
    route_clusters = _build_route_cluster_plan(
        site_list,
        target_profiles,
        target_route_keys,
        attempted_sites=attempted_route_sites,
    )
    route_cluster_by_site = {}
    for cluster in route_clusters.values():
        for site in cluster["sites"]:
            route_cluster_by_site[site] = cluster
    deferred_route_sites = {
        site
        for cluster in route_clusters.values()
        for site in cluster["deferred"]
    }
    first_wave_sites = [
        site for site in site_list if site not in deferred_route_sites]
    route_cluster_target_count = sum(
        len(cluster["sites"]) for cluster in route_clusters.values())
    route_sample_target_count = sum(
        len(cluster["samples"]) for cluster in route_clusters.values())
    meta = {
        "input_site_count": input_site_count,
        "completed_site_count": skipped_completed_site_count,
        "skipped_completed_site_count": skipped_completed_site_count,
        "site_filtered_count": 0,
        "task_filtered_count": 0,
        "timeout_count": 0,
        "failure_count": 0,
        "exhausted_site_count": exhausted_site_count,
        "retryable_failure_site_count": 0,
        "stopped_count": 0,
        "raw_result_count": 0,
        "scan_word_count": 0,
        "verified_result_count": 0,
        "unverified_result_count": 0,
        "baseline_filtered_count": 0,
        "entry_candidate_count": 0,
        "resource_clue_count": 0,
        "redirect_clue_count": 0,
        "redirect_template_count": 0,
        "redirect_group_count": 0,
        "redirect_resolved_count": 0,
        "redirect_resolution_error_count": 0,
        "non_entry_result_count": 0,
        "sso_protected_count": 0,
        "protected_result_count": 0,
        "stale_result_count": 0,
        "transient_verify_count": 0,
        "second_level_input_count": 0,
        "second_level_result_count": 0,
        "baseline_request_count": 0,
        "baseline_error_count": 0,
        "site_dynamic_word_count": 0,
        "site_scoped_target_count": 0,
        "site_scoped_scan_word_count": 0,
        "site_scoped_result_count": 0,
        "site_scoped_meaningful_result_count": 0,
        "priority_scan_word_count": 0,
        "priority_result_count": 0,
        "priority_meaningful_result_count": 0,
        "low_info_short_scan_count": 0,
        "low_info_escalated_count": 0,
        "low_info_skipped_full_word_count": 0,
        "edge_limited_short_scan_count": 0,
        "edge_limited_escalated_count": 0,
        "edge_limited_skipped_full_word_count": 0,
        "restricted_short_scan_count": 0,
        "restricted_escalated_count": 0,
        "restricted_skipped_full_word_count": 0,
        "batch_emitted_count": 0,
        "retry_site_count": 0,
        "route_candidate_target_count": len(route_sites),
        "route_cluster_count": len(route_clusters),
        "route_cluster_target_count": route_cluster_target_count,
        "route_sample_target_count": route_sample_target_count,
        "route_dedupe_reused_target_count": 0,
        "route_dedupe_saved_word_count": 0,
        "route_dedupe_split_cluster_count": 0,
        "route_dedupe_fallback_target_count": 0,
        "normal_target_count": profile_counts["normal"],
        "low_info_target_count": profile_counts["low_info"],
        "edge_limited_target_count": profile_counts["edge_limited"],
        "restricted_target_count": profile_counts["restricted"],
        "warnings": [],
        "dict_fingerprint": dict_fingerprint,
        "ffuf_wordset_reused": wordset_reused,
        "ffuf_wordset_persisted": wordset_persisted,
        "profile_version": FFUF_PROFILE_VERSION,
        "progress_resumed": bool(resume_counters),
        "progress_resume_counter_count": len(resume_counters),
        "pending_site_count": pending_site_count,
        "slice_site_count": len(site_list),
        "deferred_site_count": deferred_site_count,
        "continuation_required": bool(deferred_site_count),
    }
    for key, value in resume_counters.items():
        meta[key] = value
    meta["completed_site_count"] = skipped_completed_site_count
    meta["exhausted_site_count"] = exhausted_site_count
    meta["retryable_failure_site_count"] = 0
    if exhausted_site_count:
        meta["warnings"].append(
            "ffuf exhausted {} site retry limit(s)".format(
                exhausted_site_count))
    meta.update(dynamic_meta)
    removed_urls = []

    def refresh_pending_counts():
        terminal_count = (
            int(meta.get("completed_site_count", 0) or 0) +
            int(meta.get("exhausted_site_count", 0) or 0)
        )
        meta["pending_site_count"] = max(input_site_count - terminal_count, 0)
        meta["continuation_required"] = bool(meta["pending_site_count"])

    def merge_meta(result_meta):
        for key in (
            "completed_site_count", "site_filtered_count", "timeout_count",
            "failure_count", "stopped_count", "raw_result_count",
            "exhausted_site_count", "retryable_failure_site_count",
            "scan_word_count", "verified_result_count", "unverified_result_count",
            "baseline_filtered_count", "sso_protected_count",
            "protected_result_count", "entry_candidate_count",
            "resource_clue_count", "redirect_clue_count",
            "redirect_template_count",
            "non_entry_result_count", "stale_result_count",
            "transient_verify_count", "second_level_input_count",
            "second_level_result_count", "baseline_request_count",
            "baseline_error_count", "site_dynamic_word_count",
            "site_scoped_target_count", "site_scoped_scan_word_count",
            "site_scoped_result_count", "site_scoped_meaningful_result_count",
            "priority_scan_word_count", "priority_result_count",
            "priority_meaningful_result_count", "low_info_short_scan_count",
            "low_info_escalated_count", "low_info_skipped_full_word_count",
            "edge_limited_short_scan_count", "edge_limited_escalated_count",
            "edge_limited_skipped_full_word_count",
            "restricted_short_scan_count", "restricted_escalated_count",
            "restricted_skipped_full_word_count",
            "batch_emitted_count",
            "retry_site_count",
            "route_dedupe_reused_target_count",
            "route_dedupe_saved_word_count",
        ):
            meta[key] += int((result_meta or {}).get(key, 0) or 0)
        for warning in (result_meta or {}).get("warnings", []) or []:
            if warning and warning not in meta["warnings"]:
                meta["warnings"].append(str(warning))

    def emit_result(pages):
        pages = list(pages or [])
        if not pages:
            return
        with callback_lock:
            if on_result:
                on_result(pages)
            streamed_urls.update(page.url for page in pages if page.url)

    route_sample_sites = {
        site
        for cluster in route_clusters.values()
        for site in cluster["samples"]
    }
    route_fallback_sites = set()
    site_result_meta = {}

    def target_rate(profile):
        if profile == "restricted":
            return getattr(Config, "FFUF_RESTRICTED_RATE", 12)
        if profile == "edge_limited":
            return getattr(Config, "FFUF_EDGE_RATE", 12)
        if profile == "low_info":
            return getattr(
                Config, "FFUF_LOW_INFO_RATE", getattr(Config, "FFUF_RATE", 80))
        return None

    def run_one(site):
        profile = target_profiles.get(site.rstrip("/"), "normal")
        cluster = route_cluster_by_site.get(site) or {}
        route_meta = {
            "route_cluster_id": cluster.get("route_cluster_id", ""),
            "route_sample_count": len(cluster.get("samples") or []),
            "route_dedupe_decision": (
                "fallback_scan" if site in route_fallback_sites
                else "sample" if site in route_sample_sites else ""
            ),
        }
        if _task_stopped(task_id):
            logger.warning("ffuf stop before target {}".format(site))
            return FfufResult(meta={
                "stopped_count": 1,
                "target_profile": profile,
                "profile_version": FFUF_PROFILE_VERSION,
                **route_meta,
            })
        previous_attempts = _scan_attempt_count(
            task_id, site, dict_fingerprint)
        retry_mode = previous_attempts > 0
        _mark_scan_state(
            task_id,
            site,
            dict_fingerprint,
            "running",
            result_meta={"target_profile": profile, **route_meta},
        )
        pages = _file_leak_single_site(
            site,
            words,
            task_id=task_id,
            rate=target_rate(profile),
            enable_dynamic=gen_dict and not retry_mode,
            on_batch=emit_result,
            retry_mode=retry_mode,
            target_profile=profile,
            site_scoped_words=site_scoped_words_by_site.get(site),
        )
        if hasattr(pages, "meta"):
            pages.meta.update({
                key: value for key, value in route_meta.items() if value not in (None, "")
            })
            pages.meta["attempt_count"] = previous_attempts + 1
        return pages

    def run_site_scoped_only(site):
        """Scan a deferred route target's own hostname words only.

        Route-template de-duplication may reuse the shared dictionary result,
        but it must never reuse another hostname's site-scoped words.
        """
        profile = target_profiles.get(site.rstrip("/"), "normal")
        scoped_words = site_scoped_words_by_site.get(site) or []
        if not scoped_words:
            return FfufResult(meta={
                "completed_site_count": 1,
                "target_profile": profile,
                "profile_version": FFUF_PROFILE_VERSION,
            })
        return _file_leak_single_site(
            site,
            [],
            task_id=task_id,
            rate=target_rate(profile),
            enable_dynamic=False,
            on_batch=emit_result,
            retry_mode=False,
            target_profile=profile,
            site_scoped_words=scoped_words,
            site_scoped_only=True,
        )

    def scan_reused_site_scoped(sites):
        sites = list(sites or [])
        if not sites:
            return {}
        results = {}
        workers = min(concurrency, len(sites))
        logger.info(
            "ffuf site-scoped route wave concurrency:{} targets:{}".format(
                workers, len(sites)))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(run_site_scoped_only, site): site
                for site in sites
            }
            for future in as_completed(futures):
                site = futures[future]
                try:
                    results[site] = future.result()
                except Exception as exc:
                    logger.exception(
                        "ffuf site-scoped route scan failed site:{} task:{}".format(
                            site, task_id))
                    results[site] = FfufResult(meta={
                        "failure_count": 1,
                        "warnings": [
                            "ffuf site-scoped scan failed on {}: {}".format(
                                site, exc)
                        ],
                    })
        return results

    def update_progress():
        if not task_id:
            return
        refresh_pending_counts()
        progress = {
            "input_count": input_site_count,
            "completed_site_count": meta["completed_site_count"],
            "timeout_count": meta["timeout_count"],
            "failure_count": meta["failure_count"],
            "exhausted_site_count": meta["exhausted_site_count"],
            "retryable_failure_site_count": meta[
                "retryable_failure_site_count"],
            "stopped_count": meta["stopped_count"],
            "baseline_filtered_count": meta["baseline_filtered_count"],
            "entry_candidate_count": meta["entry_candidate_count"],
            "resource_clue_count": meta["resource_clue_count"],
            "sso_protected_count": meta["sso_protected_count"],
            "second_level_result_count": meta["second_level_result_count"],
            "retry_site_count": meta["retry_site_count"],
            "scan_word_count": meta["scan_word_count"],
            "site_scoped_target_count": meta["site_scoped_target_count"],
            "site_scoped_scan_word_count": meta[
                "site_scoped_scan_word_count"],
            "site_scoped_result_count": meta["site_scoped_result_count"],
            "site_scoped_meaningful_result_count": meta[
                "site_scoped_meaningful_result_count"],
            "priority_scan_word_count": meta["priority_scan_word_count"],
            "priority_meaningful_result_count": meta[
                "priority_meaningful_result_count"],
            "low_info_short_scan_count": meta["low_info_short_scan_count"],
            "low_info_escalated_count": meta["low_info_escalated_count"],
            "low_info_skipped_full_word_count": meta[
                "low_info_skipped_full_word_count"],
            "edge_limited_short_scan_count": meta[
                "edge_limited_short_scan_count"],
            "edge_limited_escalated_count": meta[
                "edge_limited_escalated_count"],
            "edge_limited_skipped_full_word_count": meta[
                "edge_limited_skipped_full_word_count"],
            "restricted_short_scan_count": meta["restricted_short_scan_count"],
            "restricted_escalated_count": meta["restricted_escalated_count"],
            "restricted_skipped_full_word_count": meta[
                "restricted_skipped_full_word_count"],
            "route_candidate_target_count": meta["route_candidate_target_count"],
            "route_cluster_count": meta["route_cluster_count"],
            "route_cluster_target_count": meta["route_cluster_target_count"],
            "route_sample_target_count": meta["route_sample_target_count"],
            "route_dedupe_reused_target_count": meta[
                "route_dedupe_reused_target_count"],
            "route_dedupe_saved_word_count": meta[
                "route_dedupe_saved_word_count"],
            "route_dedupe_split_cluster_count": meta[
                "route_dedupe_split_cluster_count"],
            "route_dedupe_fallback_target_count": meta[
                "route_dedupe_fallback_target_count"],
            "dict_fingerprint": dict_fingerprint,
            "profile_version": FFUF_PROFILE_VERSION,
            "progress_resumed": meta["progress_resumed"],
            "progress_resume_counter_count": meta[
                "progress_resume_counter_count"],
            "pending_site_count": meta["pending_site_count"],
            "slice_site_count": meta["slice_site_count"],
            "deferred_site_count": meta["deferred_site_count"],
            "continuation_required": meta["continuation_required"],
            "normal_target_count": meta["normal_target_count"],
            "low_info_target_count": meta["low_info_target_count"],
            "edge_limited_target_count": meta["edge_limited_target_count"],
            "restricted_target_count": meta["restricted_target_count"],
        }
        # The persistence callback owns the canonical, de-duplicated output
        # count. Do not replace it with this invocation's in-memory page count.
        if on_result is None:
            progress["output_count"] = max(len(ret), len(streamed_urls))
        BaseUpdateTask(task_id).update_stage_progress("file_leak", progress)

    def process_result(site, pages):
        result_meta = dict(getattr(pages, "meta", {}) or {})
        result_meta.setdefault(
            "target_profile",
            target_profiles.get(site.rstrip("/"), "normal"),
        )
        result_meta.setdefault("profile_version", FFUF_PROFILE_VERSION)
        cluster = route_cluster_by_site.get(site) or {}
        if cluster:
            result_meta.setdefault("route_cluster_id", cluster["route_cluster_id"])
            result_meta.setdefault("route_sample_count", len(cluster["samples"]))
        if result_meta.get("retry_mode"):
            result_meta["retry_site_count"] = 1
        result_meta["result_count"] = len(pages)
        if result_meta.get("stopped_count") or _task_stopped(task_id):
            state_status = "stopped"
        elif (
            result_meta.get("timeout_count")
            or result_meta.get("failure_count")
            or result_meta.get("transient_verify_count")
        ):
            max_attempts = max(int(getattr(
                Config, "FFUF_SITE_MAX_ATTEMPTS", 2) or 1), 1)
            if int(result_meta.get("attempt_count", 1) or 1) >= max_attempts:
                state_status = "exhausted"
                result_meta["exhausted_site_count"] = 1
            else:
                state_status = "partial"
                result_meta["retryable_failure_site_count"] = 1
        else:
            state_status = "done"
        merge_meta(result_meta)
        removed_urls.extend(getattr(pages, "removed_urls", []) or [])
        _mark_scan_state(
            task_id, site, dict_fingerprint, state_status, result_meta=result_meta)
        site_result_meta[site] = {
            **result_meta,
            "state_status": state_status,
        }
        if pages:
            if int(result_meta.get("batch_emitted_count", 0) or 0) < len(pages):
                emit_result(pages)
            with ret_lock:
                ret.extend(pages)
        update_progress()

    def process_wave(wave_sites, label):
        wave_sites = list(wave_sites or [])
        if not wave_sites:
            return
        workers = min(concurrency, len(wave_sites))
        logger.info(
            "ffuf site pool wave:{} concurrency:{} targets:{}".format(
                label, workers, len(wave_sites)))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(run_one, site): site for site in wave_sites}
            for future in as_completed(futures):
                site = futures[future]
                try:
                    pages = future.result()
                except Exception as e:
                    logger.exception("ffuf future failed site:{} task:{}".format(site, task_id))
                    pages = FfufResult(meta={
                        "failure_count": 1,
                        "warnings": ["ffuf future failed on {}: {}".format(site, e)],
                    })
                process_result(site, pages)

    def cluster_reuse_observation(cluster):
        if _task_stopped(task_id):
            return ""
        require_zero_raw = bool(getattr(
            Config, "FFUF_ROUTE_DEDUPE_REQUIRE_ZERO_RAW", True))
        return _route_cluster_reuse_observation(
            cluster,
            site_result_meta,
            require_zero_raw=require_zero_raw,
        )

    def update_sample_decisions(cluster, decision):
        for site in cluster["samples"]:
            sample = site_result_meta.get(site)
            if not sample:
                continue
            sample["route_dedupe_decision"] = decision
            _mark_scan_state(
                task_id,
                site,
                dict_fingerprint,
                sample.get("state_status", "partial"),
                result_meta=sample,
            )

    fallback_sites = []
    with acquire_resource_budget("tool:ffuf", task_id=task_id):
        process_wave(first_wave_sites, "initial")
        for cluster in route_clusters.values():
            observation = cluster_reuse_observation(cluster)
            if observation:
                representative = cluster["samples"][0]
                target_profile = cluster.get("target_profile", "low_info")
                max_words_config = {
                    "low_info": "FFUF_LOW_INFO_MAX_WORDS",
                    "edge_limited": "FFUF_EDGE_MAX_WORDS",
                    "restricted": "FFUF_RESTRICTED_MAX_WORDS",
                }.get(target_profile)
                saved_words = len(words)
                if max_words_config:
                    saved_words = min(
                        saved_words,
                        max(int(getattr(
                            Config, max_words_config, 240) or 0), 0),
                    )
                update_sample_decisions(cluster, "sample_confirmed")
                scoped_results = scan_reused_site_scoped(cluster["deferred"])
                for site in cluster["deferred"]:
                    pages = scoped_results.get(site)
                    if pages is None:
                        pages = FfufResult(meta={
                            "failure_count": 1,
                            "warnings": [
                                "ffuf site-scoped result missing on {}".format(site)
                            ],
                        })
                    scoped_meta = dict(getattr(pages, "meta", {}) or {})
                    if (
                        scoped_meta.get("timeout_count")
                        or scoped_meta.get("failure_count")
                        or scoped_meta.get("stopped_count")
                        or scoped_meta.get("transient_verify_count")
                        or not scoped_meta.get("completed_site_count")
                    ):
                        removed_urls.extend(
                            getattr(pages, "removed_urls", []) or [])
                        if pages:
                            if int(scoped_meta.get(
                                    "batch_emitted_count", 0) or 0) < len(pages):
                                emit_result(pages)
                            with ret_lock:
                                ret.extend(pages)
                        fallback_sites.append(site)
                        meta["route_dedupe_fallback_target_count"] += 1
                        for warning in scoped_meta.get("warnings", []) or []:
                            if warning and warning not in meta["warnings"]:
                                meta["warnings"].append(str(warning))
                        continue

                    merge_meta(scoped_meta)
                    removed_urls.extend(
                        getattr(pages, "removed_urls", []) or [])
                    if pages:
                        if int(scoped_meta.get(
                                "batch_emitted_count", 0) or 0) < len(pages):
                            emit_result(pages)
                        with ret_lock:
                            ret.extend(pages)
                    meta["route_dedupe_reused_target_count"] += 1
                    meta["route_dedupe_saved_word_count"] += saved_words

                    checkpoint_meta = {
                        **scoped_meta,
                        "completed_site_count": 1,
                        "target_profile": target_profile,
                        "profile_version": FFUF_PROFILE_VERSION,
                        "result_count": len(pages),
                        "route_cluster_id": cluster["route_cluster_id"],
                        "route_observation_key": observation,
                        "route_sample_count": len(cluster["samples"]),
                        "route_dedupe_decision": "reused_shared_after_site_scoped",
                        "scan_reused": True,
                        "scan_reused_from": representative,
                        "route_dedupe_reused_target_count": 1,
                        "route_dedupe_saved_word_count": saved_words,
                    }
                    if site_scoped_words_by_site.get(site):
                        _mark_scan_state(
                            task_id,
                            site,
                            dict_fingerprint,
                            "running",
                            result_meta=checkpoint_meta,
                        )
                    site_result_meta[site] = {
                        **checkpoint_meta,
                        "state_status": "done",
                    }
                    _mark_scan_state(
                        task_id,
                        site,
                        dict_fingerprint,
                        "done",
                        result_meta=checkpoint_meta,
                    )
                logger.info(
                    "ffuf route cluster reused cluster:{} samples:{} reused:{} observation:{}".format(
                        cluster["route_cluster_id"],
                        len(cluster["samples"]),
                        sum(
                            1 for site in cluster["deferred"]
                            if site not in fallback_sites
                        ),
                        observation,
                    )
                )
                update_progress()
                continue

            update_sample_decisions(cluster, "sample_split")
            meta["route_dedupe_split_cluster_count"] += 1
            meta["route_dedupe_fallback_target_count"] += len(cluster["deferred"])
            fallback_sites.extend(cluster["deferred"])

        route_fallback_sites.update(fallback_sites)
        fallback_set = set(fallback_sites)
        ordered_fallback = [site for site in site_list if site in fallback_set]
        process_wave(ordered_fallback, "route-fallback")

    kept, removed = _filter_task_uniform_results(ret)
    meta["task_filtered_count"] += len(removed)
    if removed:
        logger.warning(
            "ffuf task-level uniform filter task:{} kept:{} removed:{}".format(
                task_id, len(kept), len(removed)))

    removed_urls.extend(page.url for page in removed if page.url)
    for key, value in _enrich_redirect_pages(kept).items():
        meta[key] = int(meta.get(key, 0) or 0) + int(value or 0)
    refresh_pending_counts()
    return FfufResult(
        kept,
        meta=meta,
        removed_urls=ordered_unique(removed_urls),
    )
