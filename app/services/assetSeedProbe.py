import json
import hashlib
import ipaddress
import os
import signal
import subprocess
from urllib.parse import urlparse

from bson import ObjectId

from app import utils
from app.config import Config
from app.services.baseUpdateTask import BaseUpdateTask
from app.services.edgeAsset import (
    EDGE_TAG,
    WILDCARD_TAG,
    classify_edge_host,
    classify_edge_infrastructure,
    is_ztna_host,
    merge_tags,
)
from app.services.assetPolicy import classify_waf_evidence
from app.services.resourceBudget import acquire as acquire_resource_budget

logger = utils.get_logger()


class HttpxBatchResult(list):
    def __init__(self, values=None, complete=True, error="", timed_out=False):
        super().__init__(values or [])
        self.complete = bool(complete)
        self.error = str(error or "")
        self.timed_out = bool(timed_out)


def _chunked(items, size):
    size = max(int(size or 1), 1)
    for i in range(0, len(items), size):
        yield items[i:i + size]


class AssetSeedProbe(object):
    def __init__(self, task_id, base_domain):
        self.task_id = task_id
        self.base_domain = str(base_domain or "").strip().strip(".").lower()
        if not self.base_domain and task_id:
            try:
                task = utils.conn_db("task").find_one(
                    {"_id": ObjectId(task_id)}, {"_id": 0, "target": 1}) or {}
                target = str(task.get("target") or "").strip().strip(".").lower()
                if target and utils.is_valid_domain(target):
                    self.base_domain = target
            except Exception as exc:
                logger.warning(
                    "asset_seed_probe load task target failed task:{} error:{}".format(
                        task_id, exc))
        self.base_update_task = BaseUpdateTask(task_id) if task_id else None
        self.edge_only_ips = set()
        self.observed_ips = set()
        self.strong_blocked_ips = set()
        self.partial_errors = []
        self.httpx_retry_count = 0
        self.httpx_recovered_batch_count = 0
        self.httpx_failed_target_count = 0
        self.preprobe_cdn_domain_count = 0
        self.preprobe_owned_cdn_domain_count = 0
        self.preprobe_skipped_provider_domain_count = 0
        self.preprobe_external_domain_count = 0
        self.preprobe_domain_evidence = {}

    def _task_stopped(self):
        if not self.base_update_task:
            return False
        try:
            return self.base_update_task.is_terminal()
        except Exception as e:
            logger.warning("asset_seed_probe check task status failed: {}".format(e))
            return False

    def _run_httpx_batch(self, targets, ports=None, timeout=None):
        if not targets:
            return []

        input_text = "\n".join(targets) + "\n"
        command = [
            Config.HTTPX_BIN,
            "-json",
            "-silent",
            "-title",
            "-status-code",
            "-content-length",
            "-content-type",
            "-location",
            "-hash", "sha256",
            "-tech-detect",
            "-favicon",
            "-cdn",
            "-ip",
            "-cname",
            "-web-server",
            "-follow-host-redirects",
            "-include-response-header",
            "-threads", str(Config.ASSET_SEED_HTTPX_THREADS),
            "-rate-limit", str(Config.ASSET_SEED_HTTPX_RATE_LIMIT),
            "-timeout", str(Config.ASSET_SEED_HTTPX_TIMEOUT),
        ]
        if ports:
            command.extend(["-ports", ports])

        timed_out = False
        error = ""
        with acquire_resource_budget("tool:httpx", task_id=self.task_id):
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                start_new_session=True,
                text=True
            )
            timeout = timeout or max(30, min(
                int(getattr(Config, "ASSET_SEED_HTTPX_BATCH_TIMEOUT", 120)),
                Config.ASSET_SEED_HTTPX_TIMEOUT * max(len(targets), 1)
            ))
            try:
                stdout, stderr = proc.communicate(input=input_text, timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    stdout, stderr = proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    stdout, stderr = proc.communicate()
                warning = "asset_seed_probe httpx timeout after {}s".format(timeout)
                timed_out = True
                error = warning
                logger.warning(warning)

        if proc.returncode not in (0, None) and not timed_out:
            warning = "asset_seed_probe httpx exit {}: {}".format(
                proc.returncode, (stderr or "").strip()[-500:])
            error = warning
            logger.warning(warning)

        results = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except ValueError:
                logger.debug("asset_seed_probe httpx bad json: {}".format(line[:200]))
        return HttpxBatchResult(
            results,
            complete=not error,
            error=error,
            timed_out=timed_out,
        )

    @staticmethod
    def _target_key(target):
        return str(target or "").strip().rstrip("/").lower()

    def _observed_targets(self, targets, results):
        target_map = {self._target_key(target): target for target in targets}
        host_map = {}
        for target in targets:
            value = str(target or "").strip()
            try:
                host = urlparse(value if "://" in value else "http://" + value).hostname
            except (TypeError, ValueError):
                host = ""
            if host:
                host_map.setdefault(str(host).lower(), set()).add(target)

        observed = set()
        for item in results or []:
            raw_input = self._target_key(item.get("input"))
            if raw_input in target_map:
                observed.add(target_map[raw_input])
                continue
            values = [item.get("host"), item.get("host_ip"), item.get("ip")]
            try:
                values.append(urlparse(str(item.get("url") or "")).hostname)
            except (TypeError, ValueError):
                pass
            for value in values:
                value = str(value or "").strip().lower()
                observed.update(host_map.get(value, set()))
        return observed

    def _save_batch_state(self, label, targets, ports, status, attempt, error="", result_count=0):
        if not self.task_id:
            return
        material = "{}\n{}\n{}".format(label, ports or "", "\n".join(sorted(targets)))
        fingerprint = hashlib.sha256(material.encode("utf-8")).hexdigest()
        fields = {
            "task_id": self.task_id,
            "label": label,
            "batch_fingerprint": fingerprint,
            "targets": sorted(targets),
            "target_count": len(targets),
            "ports": str(ports or ""),
            "status": status,
            "error": str(error or ""),
            "result_count": int(result_count or 0),
            "updated_at": utils.curr_date(),
        }
        if status == "running":
            fields["started_at"] = utils.curr_date()
        elif status in ("done", "recovered", "partial", "failed"):
            fields["finished_at"] = utils.curr_date()
        try:
            utils.conn_db("asset_seed_probe_state").update_one(
                {
                    "task_id": self.task_id,
                    "label": label,
                    "batch_fingerprint": fingerprint,
                },
                {
                    "$set": fields,
                    "$max": {
                        "attempt": int(attempt),
                        "attempt_count": int(attempt) + 1,
                    },
                },
                upsert=True,
            )
        except Exception as e:
            logger.warning("asset_seed_probe checkpoint failed task:{} label:{} error:{}".format(
                self.task_id, label, e))

    def _run_httpx(self, targets, ports=None, timeout=None, batch_size=None, label="targets"):
        targets = [str(x).strip() for x in targets if str(x or "").strip()]
        targets = sorted(set(targets))
        if not targets:
            return []

        if batch_size is None:
            batch_size = getattr(Config, "ASSET_SEED_HTTPX_BATCH_SIZE", 500)
        batch_size = max(int(batch_size), 1)
        results = []
        max_retries = max(int(getattr(
            Config, "ASSET_SEED_HTTPX_MAX_RETRIES", 2) or 0), 0)
        min_retry_size = max(int(getattr(
            Config, "ASSET_SEED_HTTPX_MIN_RETRY_BATCH_SIZE", 15) or 1), 1)

        def run_batch(batch, attempt=0):
            self._save_batch_state(label, batch, ports, "running", attempt)
            try:
                batch_result = self._run_httpx_batch(
                    batch, ports=ports, timeout=timeout)
            except Exception as e:
                batch_result = HttpxBatchResult(
                    [], complete=False,
                    error="asset_seed_probe httpx {} failed: {}".format(label, e),
                )
                logger.exception(e)

            results.extend(batch_result)
            if getattr(batch_result, "complete", True):
                self._save_batch_state(
                    label, batch, ports, "done", attempt,
                    result_count=len(batch_result))
                return set()

            observed = self._observed_targets(batch, batch_result)
            unresolved = [target for target in batch if target not in observed]
            if not unresolved:
                self.httpx_recovered_batch_count += 1
                self._save_batch_state(
                    label, batch, ports, "recovered", attempt,
                    error=getattr(batch_result, "error", ""),
                    result_count=len(batch_result))
                return set()

            if attempt < max_retries:
                self.httpx_retry_count += 1
                self._save_batch_state(
                    label, batch, ports, "retrying", attempt,
                    error=getattr(batch_result, "error", ""),
                    result_count=len(batch_result))
                next_size = min(
                    len(unresolved),
                    max(min_retry_size, max(len(unresolved) // 2, 1)),
                )
                failed = set()
                for retry_batch in _chunked(unresolved, next_size):
                    failed.update(run_batch(retry_batch, attempt + 1))
                if not failed:
                    self.httpx_recovered_batch_count += 1
                    self._save_batch_state(
                        label, batch, ports, "recovered", attempt,
                        error=getattr(batch_result, "error", ""),
                        result_count=len(batch_result))
                else:
                    self._save_batch_state(
                        label, batch, ports, "partial", attempt,
                        error="{}; unresolved targets:{}".format(
                            getattr(batch_result, "error", "") or
                            "asset_seed_probe httpx retry incomplete",
                            len(failed),
                        ),
                        result_count=len(batch_result))
                return failed

            error = getattr(batch_result, "error", "") or (
                "asset_seed_probe httpx {} exhausted retries".format(label))
            self.partial_errors.append(
                "{} unresolved targets:{}".format(error, len(unresolved)))
            self.httpx_failed_target_count += len(unresolved)
            self._save_batch_state(
                label, unresolved, ports, "failed", attempt,
                error=error, result_count=len(batch_result))
            return set(unresolved)

        total_batches = (len(targets) + batch_size - 1) // batch_size
        for batch_index, batch in enumerate(_chunked(targets, batch_size), 1):
            if self._task_stopped():
                logger.warning("asset_seed_probe stop before httpx batch {}/{}".format(batch_index, total_batches))
                break

            logger.info("asset_seed_probe httpx {} batch {}/{} targets:{}".format(
                label, batch_index, total_batches, len(batch)))
            run_batch(batch)

        return results

    def _extract_ip(self, item):
        ip = item.get("host_ip") or item.get("ip")
        if isinstance(ip, list):
            ip = ip[0] if ip else ""
        if not ip:
            return ""
        ip = str(ip).strip()
        if not utils.not_in_black_ips(ip):
            return ""
        if utils.get_ip_type(ip) != "PUBLIC":
            return ""
        return ip

    def _is_cdn(self, item, ip=""):
        cdn = item.get("cdn")
        if isinstance(cdn, bool) and cdn:
            return True
        cdn_name = item.get("cdn_name") or item.get("cdn_type")
        if cdn_name:
            return True
        cname = item.get("cname")
        if isinstance(cname, list):
            cname = ",".join(cname)
        if cname:
            match = utils.get_cdn_match_by_cname_strict(cname)
            if match.get("kind") == "cdn":
                return True
        if ip and utils.get_cdn_name_by_ip(ip):
            return True
        return False

    def _strict_edge_rule(self, item):
        cname = item.get("cname")
        if not cname:
            return {}
        return utils.get_cdn_match_by_cname_strict(cname)

    def _item_text(self, item, keys=None, include_tech=True):
        values = []
        if keys is None:
            keys = ["cdn_name", "cdn_type", "webserver", "cname"]

        for key in keys:
            value = item.get(key)
            if isinstance(value, list):
                value = " ".join([str(x) for x in value])
            if value:
                values.append(str(value))

        if include_tech:
            tech = item.get("tech") or item.get("technologies") or []
            if isinstance(tech, list):
                values.extend([str(x) for x in tech])
            elif tech:
                values.append(str(tech))

        return " ".join(values).lower()

    def _detect_edge_infrastructure(self, item):
        return classify_edge_infrastructure(self._item_text(item))

    @staticmethod
    def _is_ip_host(host):
        try:
            ipaddress.ip_address(str(host or "").strip("[]"))
            return True
        except ValueError:
            return False

    def _detect_waf(self, item):
        return classify_waf_evidence(item)

    def _build_edge_ip_context(self, domain_info_list):
        ip_domains = {}
        ip_edge_domains = {}
        for info in domain_info_list or []:
            domain = str(getattr(info, "domain", "") or "").strip(".").lower()
            if not domain:
                continue
            edge_info = classify_edge_host(domain, self.base_domain)
            for ip in getattr(info, "ip_list", []) or []:
                ip_domains.setdefault(ip, set()).add(domain)
                if edge_info.get("is_edge"):
                    ip_edge_domains.setdefault(ip, set()).add(domain)

        edge_only_ips = set()
        for ip, domains in ip_domains.items():
            edge_domains = ip_edge_domains.get(ip, set())
            ztna_domains = [domain for domain in domains if is_ztna_host(domain)]
            if len(domains) >= 3 and len(ztna_domains) == len(domains):
                edge_only_ips.add(ip)
                continue
            if not domains or not edge_domains:
                continue
            edge_ratio = float(len(edge_domains)) / float(len(domains))
            if len(domains) == len(edge_domains) or (len(edge_domains) >= 10 and edge_ratio >= 0.8):
                edge_only_ips.add(ip)

        self.edge_only_ips = edge_only_ips
        if edge_only_ips:
            logger.info("asset_seed_probe edge-only ips:{} sample:{}".format(
                len(edge_only_ips), sorted(edge_only_ips)[:5]))

    def _detect_edge_gateway(self, item, host="", ip=""):
        extra_values = []
        for key in ["webserver", "cname", "cdn_name", "cdn_type"]:
            value = item.get(key)
            if isinstance(value, list):
                value = " ".join([str(x) for x in value])
            if value:
                extra_values.append(str(value))
        tech = item.get("tech") or item.get("technologies") or []
        if isinstance(tech, list):
            extra_values.extend([str(x) for x in tech if x])
        elif tech:
            extra_values.append(str(tech))

        edge_info = classify_edge_host(
            host,
            self.base_domain,
            title=item.get("title", ""),
            status_code=item.get("status_code"),
            extra_text=" ".join(extra_values),
        )
        infrastructure = self._detect_edge_infrastructure(item)
        if infrastructure:
            edge_info["is_edge"] = True
            edge_info["edge_name"] = infrastructure
            edge_info["edge_reasons"] = merge_tags(
                edge_info.get("edge_reasons"),
                "edge_infrastructure:{}".format(infrastructure),
            )
            edge_info["tags"] = merge_tags(edge_info.get("tags"), EDGE_TAG)
        if ip and ip in self.edge_only_ips:
            edge_info["is_edge"] = True
            edge_info["edge_name"] = edge_info.get("edge_name") or "edge_only_ip_gateway"
            edge_info["edge_reasons"] = merge_tags(edge_info.get("edge_reasons"), "edge_only_ip_domains")
            edge_info["tags"] = merge_tags(edge_info.get("tags"), EDGE_TAG, WILDCARD_TAG)
        return edge_info

    def _is_blocked_alive_ip_item(self, item, ip, host):
        if not ip:
            return True
        if self._is_cdn(item, ip):
            return True
        if self._strict_edge_rule(item):
            return True
        if self._preprobe_evidence_for_item(item, fallback_host=host):
            return True
        if self._detect_edge_infrastructure(item):
            return True
        waf = self._detect_waf(item)
        edge_info = self._detect_edge_gateway(item, host=host, ip=ip)
        if waf.get("strength") == "strong" or edge_info.get("is_edge"):
            return True
        return False

    def _should_count_alive_ip(self, item, ip, host):
        if not ip:
            return False
        return not self._is_blocked_alive_ip_item(item, ip, host)

    def _save_probe_item(self, item, source="domain"):
        url = item.get("url") or item.get("input")
        if not url:
            return

        parsed = urlparse(url if "://" in url else "http://" + url)
        host = parsed.hostname or item.get("host") or item.get("input")
        if not host:
            return

        ip = self._extract_ip(item)
        is_cdn = self._is_cdn(item, ip)
        cdn_name = item.get("cdn_name") or item.get("cdn_type") or ""
        waf = self._detect_waf(item)
        is_waf = bool(waf.get("detected"))
        waf_name = waf.get("name", "")
        edge_info = self._detect_edge_gateway(item, host=host, ip=ip)
        preprobe = self._preprobe_evidence_for_item(
            item, fallback_host=host)
        preprobe_kind = preprobe.get("kind", "")
        if preprobe_kind == "cdn":
            is_cdn = True
            cdn_name = preprobe.get("provider", "") or cdn_name
        elif preprobe_kind == "waf":
            is_waf = True
            waf_name = preprobe.get("provider", "") or waf_name
            waf["strength"] = "strong"
            waf["reason"] = "dns_cname_suffix"
        if preprobe:
            edge_info["is_edge"] = True
            edge_info["edge_name"] = (
                preprobe.get("provider", "") or edge_info.get("edge_name", ""))
            edge_info["edge_reasons"] = merge_tags(
                edge_info.get("edge_reasons"),
                "dns_preprobe:{}".format(preprobe_kind or "edge"),
            )
            edge_info["tags"] = merge_tags(
                edge_info.get("tags"), EDGE_TAG)
        hashes = item.get("hash") or item.get("hashes") or {}
        if not isinstance(hashes, dict):
            hashes = {}
        resolved_ips = item.get("a") or []
        if not isinstance(resolved_ips, (list, tuple, set)):
            resolved_ips = [resolved_ips]
        resolved_ips = sorted(set(
            [str(value).strip() for value in resolved_ips if str(value or "").strip()]
            + ([ip] if ip else [])
        ))
        if edge_info.get("is_edge"):
            if is_waf:
                waf_name = waf_name or edge_info.get("edge_name", "")
                waf["strength"] = "strong"
                waf["reason"] = waf.get("reason") or "edge_gateway"

        save_item = {
            "task_id": self.task_id,
            "target": self.base_domain,
            "source": source,
            "url": url,
            "host": host,
            "ip": ip,
            "resolved_ips": resolved_ips,
            "status_code": item.get("status_code"),
            "title": item.get("title", ""),
            "webserver": item.get("webserver", ""),
            "content_length": item.get("content_length") or item.get("body_length") or 0,
            "content_type": item.get("content_type") or "",
            "location": item.get("location") or "",
            "body_hash": str(hashes.get("body_sha256") or "").strip().lower(),
            "header_hash": str(hashes.get("header_sha256") or "").strip().lower(),
            "header": item.get("header") or item.get("response_header") or {},
            "favicon": item.get("favicon"),
            "tech": item.get("tech") or item.get("technologies") or [],
            "cdn": is_cdn,
            "cdn_name": cdn_name,
            "waf": is_waf,
            "waf_name": waf_name,
            "waf_strength": waf.get("strength", "none"),
            "waf_reason": waf.get("reason", ""),
            "edge": bool(edge_info.get("is_edge")),
            "edge_name": edge_info.get("edge_name", ""),
            "edge_reasons": edge_info.get("edge_reasons", []),
            "tag": edge_info.get("tags", []),
            "cname": item.get("cname") or "",
            "save_date": utils.curr_date(),
        }
        if preprobe:
            save_item.update({
                "edge_preclassified": True,
                "edge_kind": preprobe_kind,
                "edge_provider": preprobe.get("provider", ""),
                "edge_record": preprobe.get("record", ""),
                "edge_matched_suffix": preprobe.get("matched_suffix", ""),
                "edge_pipeline_eligible": bool(
                    preprobe.get("pipeline_eligible", True)),
            })
            if not preprobe.get("pipeline_eligible", True):
                save_item.update({
                    "pipeline_eligible": False,
                    "candidate_disposition": "external_edge",
                })
        query = {
            "task_id": self.task_id,
            "url": url,
            "source": source,
        }
        utils.conn_db("asset_seed_alive").update_one(query, {"$set": save_item}, upsert=True)

    @staticmethod
    def _normalize_domain(value):
        return str(value or "").strip().strip(".").lower()

    def _target_host(self, value):
        value = str(value or "").strip()
        if not value:
            return ""
        try:
            parsed = urlparse(value if "://" in value else "http://" + value)
            return self._normalize_domain(parsed.hostname)
        except (TypeError, ValueError):
            return ""

    def _preprobe_evidence_for_item(self, item, fallback_host=""):
        """Resolve DNS evidence by original input before redirect/final URL."""
        candidates = [
            self._target_host(item.get("input")),
            self._normalize_domain(fallback_host),
            self._target_host(item.get("url")),
            self._target_host(item.get("final_url") or item.get("final-url")),
            self._normalize_domain(item.get("host")),
        ]
        for host in candidates:
            if host and host in self.preprobe_domain_evidence:
                return self.preprobe_domain_evidence[host]
        return {}

    def _domain_in_scope(self, domain):
        domain = self._normalize_domain(domain)
        base_domain = self._normalize_domain(self.base_domain)
        return bool(base_domain and (
            domain == base_domain or domain.endswith("." + base_domain)
        ))

    def _preprobe_cdn_evidence_values(self, domain, records=None):
        """Classify strict DNS evidence before spending an HTTP request."""
        if not getattr(Config, "CDN_PREPROBE_ENABLE", True):
            return {}

        domain = self._normalize_domain(domain)
        if not domain:
            return {}

        in_scope = self._domain_in_scope(domain)
        # A broad provider root (for example ksyun.com) is useful as CNAME
        # evidence, but must not label every host when that provider itself is
        # the scan target. Domain-self matching is therefore external-only.
        if not in_scope:
            match = utils.get_cdn_match_by_cname_strict(domain)
            if match and match.get("match_scope") != "record_only":
                return {
                    "domain": domain,
                    "provider": match.get("name", ""),
                    "kind": match.get("kind", "cdn"),
                    "matched_suffix": match.get("suffix", ""),
                    "record": domain,
                    "reason": "provider_tail_domain",
                    "in_scope": False,
                }

        for record in records or []:
            record = self._normalize_domain(record)
            if not record:
                continue
            match = utils.get_cdn_match_by_cname_strict(record)
            if match:
                return {
                    "domain": domain,
                    "provider": match.get("name", ""),
                    "kind": match.get("kind", "cdn"),
                    "matched_suffix": match.get("suffix", ""),
                    "record": record,
                    "reason": "dns_cname_suffix",
                    "in_scope": in_scope,
                }
        return {}

    def _preprobe_cdn_evidence(self, info):
        return self._preprobe_cdn_evidence_values(
            getattr(info, "domain", ""),
            getattr(info, "record_list", []) or [],
        )

    def _preprobe_policy(self, evidence):
        external_provider_tail = bool(
            evidence and
            evidence.get("reason") == "provider_tail_domain" and
            not evidence.get("in_scope")
        )
        probe_eligible = bool(
            not external_provider_tail or
            getattr(Config, "CDN_PREPROBE_EXTERNAL_EDGE_HTTP", False)
        )
        return {
            "external_provider_tail": external_provider_tail,
            "probe_eligible": probe_eligible,
            "pipeline_eligible": not external_provider_tail,
        }

    def _register_preprobe_evidence(self, evidence, existing=None):
        if not evidence:
            return {}
        domain = evidence.get("domain", "")
        if domain in self.preprobe_domain_evidence:
            return self.preprobe_domain_evidence[domain]

        evidence = dict(evidence)
        evidence.update(self._preprobe_policy(evidence))
        self.preprobe_domain_evidence[domain] = evidence
        self.preprobe_cdn_domain_count += 1
        if evidence.get("in_scope"):
            self.preprobe_owned_cdn_domain_count += 1
        else:
            self.preprobe_external_domain_count += 1
        if not evidence.get("probe_eligible"):
            self.preprobe_skipped_provider_domain_count += 1
        self._record_preprobe_cdn_evidence(evidence, existing=existing)
        return evidence

    def _record_preprobe_cdn_evidence(self, evidence, existing=None):
        if not self.task_id or not evidence:
            return False
        query = {
            "task_id": self.task_id,
            "domain": evidence["domain"],
        }
        try:
            collection = utils.conn_db("domain")
            if existing is None:
                existing = collection.find_one(query, {
                    "_id": 0, "cdn_source": 1, "waf_source": 1,
                    "edge_source": 1, "candidate_disposition": 1,
                }) or {}
            kind = evidence.get("kind") or "cdn"
            provider = evidence.get("provider") or ""
            now = utils.curr_date()
            fields = {
                "edge_preclassified": True,
                "edge_kind": kind,
                "edge_provider": provider,
                "edge_record": evidence.get("record", ""),
                "edge_matched_suffix": evidence.get("matched_suffix", ""),
                "asset_seed_probe_eligible": bool(
                    evidence.get("probe_eligible")),
                "asset_seed_probe_skip_reason": (
                    evidence.get("reason", "")
                    if not evidence.get("probe_eligible") else ""
                ),
                "edge_pipeline_eligible": bool(
                    evidence.get("pipeline_eligible")),
            }
            unset_fields = {}
            if existing.get("edge_source") in (None, "", "dns_preprobe"):
                fields.update({
                    "edge": True,
                    "edge_name": provider,
                    "edge_source": "dns_preprobe",
                    "edge_checked_at": now,
                })
            if kind == "cdn":
                if existing.get("cdn_source") in (None, "", "dns_preprobe"):
                    fields.update({
                        "cdn": True,
                        "cdn_name": provider,
                        "cdn_source": "dns_preprobe",
                        "cdn_record": evidence.get("record", ""),
                        "cdn_preclassified": True,
                        "cdn_checked_at": now,
                    })
            elif existing.get("cdn_source") == "dns_preprobe":
                unset_fields.update({
                    "cdn": "", "cdn_name": "", "cdn_source": "",
                    "cdn_record": "", "cdn_preclassified": "",
                    "cdn_checked_at": "",
                })

            if kind == "waf":
                if existing.get("waf_source") in (None, "", "dns_preprobe"):
                    fields.update({
                        "waf": True,
                        "waf_name": provider,
                        "waf_strength": "strong",
                        "waf_source": "dns_preprobe",
                        "waf_record": evidence.get("record", ""),
                        "waf_preclassified": True,
                        "waf_checked_at": now,
                    })
            elif existing.get("waf_source") == "dns_preprobe":
                unset_fields.update({
                    "waf": "", "waf_name": "", "waf_strength": "",
                    "waf_source": "", "waf_record": "",
                    "waf_preclassified": "", "waf_checked_at": "",
                })

            if not evidence.get("pipeline_eligible"):
                fields.update({
                    "pipeline_eligible": False,
                    "candidate_disposition": "external_edge",
                })
            elif existing.get("candidate_disposition") == "external_edge":
                unset_fields.update({
                    "pipeline_eligible": "", "candidate_disposition": "",
                })

            update = {"$set": fields}
            if unset_fields:
                update["$unset"] = unset_fields
            result = collection.update_one(query, update, upsert=False)
            if not int(getattr(result, "matched_count", 0) or 0):
                logger.warning(
                    "asset_seed_probe preprobe evidence unmatched task:{} domain:{}".format(
                        self.task_id, evidence.get("domain")))
                return False
            return True
        except Exception as exc:
            logger.warning(
                "asset_seed_probe persist preprobe CDN evidence failed "
                "task:{} domain:{} error:{}".format(
                    self.task_id, evidence.get("domain"), exc))
            return False

    def _clear_preprobe_cdn_evidence(self, domain, existing=None):
        if not self.task_id or not domain:
            return False
        query = {"task_id": self.task_id, "domain": domain}
        try:
            collection = utils.conn_db("domain")
            if existing is None:
                existing = collection.find_one(query, {
                    "_id": 0, "cdn_source": 1, "waf_source": 1,
                    "edge_source": 1, "candidate_disposition": 1,
                }) or {}
            if not any(existing.get(field) == "dns_preprobe" for field in (
                    "edge_source", "cdn_source", "waf_source")):
                return False
            unset_fields = {
                "edge_preclassified": "", "edge_kind": "",
                "edge_provider": "", "edge_record": "",
                "edge_matched_suffix": "", "edge_pipeline_eligible": "",
                "asset_seed_probe_eligible": "", "asset_seed_probe_skip_reason": "",
            }
            if existing.get("edge_source") == "dns_preprobe":
                unset_fields.update({
                    "edge": "", "edge_name": "", "edge_source": "",
                    "edge_checked_at": "",
                })
            if existing.get("cdn_source") == "dns_preprobe":
                unset_fields.update({
                    "cdn": "", "cdn_name": "", "cdn_source": "",
                    "cdn_record": "", "cdn_preclassified": "",
                    "cdn_checked_at": "",
                })
            if existing.get("waf_source") == "dns_preprobe":
                unset_fields.update({
                    "waf": "", "waf_name": "", "waf_strength": "",
                    "waf_source": "", "waf_record": "",
                    "waf_preclassified": "", "waf_checked_at": "",
                })
            if existing.get("candidate_disposition") == "external_edge":
                unset_fields.update({
                    "pipeline_eligible": "", "candidate_disposition": "",
                })
            collection.update_one(query, {"$unset": unset_fields})
            return True
        except Exception as exc:
            logger.warning(
                "asset_seed_probe clear stale preprobe evidence failed "
                "task:{} domain:{} error:{}".format(
                    self.task_id, domain, exc))
            return False

    def _domain_preprobe_rows(self, domains):
        if not self.task_id or not domains:
            return {}
        try:
            rows = utils.conn_db("domain").find(
                {"task_id": self.task_id, "domain": {"$in": sorted(domains)}},
                {"_id": 0, "domain": 1, "record": 1,
                 "cdn_source": 1, "waf_source": 1, "edge_source": 1,
                 "candidate_disposition": 1},
            )
            return {
                self._normalize_domain(row.get("domain")): row
                for row in rows if self._normalize_domain(row.get("domain"))
            }
        except Exception as exc:
            logger.warning(
                "asset_seed_probe load DNS preprobe rows failed task:{} error:{}".format(
                    self.task_id, exc))
            return {}

    def _prepare_http_probe_targets(self, targets):
        targets = [str(value).strip() for value in targets or []
                   if str(value or "").strip()]
        if not getattr(Config, "CDN_PREPROBE_ENABLE", True) or not targets:
            return targets

        target_hosts = {}
        for target in targets:
            try:
                parsed = urlparse(target if "://" in target else "http://" + target)
                host = self._normalize_domain(parsed.hostname)
            except (TypeError, ValueError):
                host = ""
            if not host or self._is_ip_host(host):
                continue
            target_hosts.setdefault(host, []).append(target)

        rows = self._domain_preprobe_rows(set(target_hosts))
        blocked_hosts = set()
        for host in target_hosts:
            row = rows.get(host) or {}
            records = row.get("record") or []
            if not isinstance(records, (list, tuple, set)):
                records = [records]
            evidence = self._preprobe_cdn_evidence_values(host, records)
            if not evidence:
                self._clear_preprobe_cdn_evidence(host, existing=row)
                continue
            evidence = self._register_preprobe_evidence(
                evidence, existing=row)
            if not evidence.get("probe_eligible"):
                blocked_hosts.add(host)

        if not blocked_hosts:
            return targets
        filtered = []
        for target in targets:
            try:
                parsed = urlparse(target if "://" in target else "http://" + target)
                host = self._normalize_domain(parsed.hostname)
            except (TypeError, ValueError):
                host = ""
            if host not in blocked_hosts:
                filtered.append(target)
        logger.info(
            "asset_seed_probe DNS prefilter targets:{} kept:{} blocked_hosts:{}".format(
                len(targets), len(filtered), len(blocked_hosts)))
        return filtered

    def probe_domains(self, domain_info_list):
        domains = []
        skipped_edge = 0
        domain_names = {
            self._normalize_domain(getattr(info, "domain", ""))
            for info in domain_info_list or []
            if self._normalize_domain(getattr(info, "domain", ""))
        }
        preprobe_rows = self._domain_preprobe_rows(domain_names)
        for info in domain_info_list:
            domain = self._normalize_domain(getattr(info, "domain", ""))
            if domain:
                existing = preprobe_rows.get(domain) or {}
                cdn_evidence = self._preprobe_cdn_evidence(info)
                if cdn_evidence:
                    cdn_evidence = self._register_preprobe_evidence(
                        cdn_evidence, existing=existing)
                    if not cdn_evidence.get("probe_eligible"):
                        continue
                else:
                    self._clear_preprobe_cdn_evidence(
                        domain, existing=existing)
                if classify_edge_host(domain, self.base_domain).get("is_edge"):
                    skipped_edge += 1
                    continue
                domains.append(domain)

        results = self._run_httpx(
            domains,
            batch_size=getattr(Config, "ASSET_SEED_HTTPX_DOMAIN_BATCH_SIZE", Config.ASSET_SEED_HTTPX_BATCH_SIZE),
            timeout=getattr(Config, "ASSET_SEED_HTTPX_BATCH_TIMEOUT", 120),
            label="domains"
        )
        alive_sites = []
        alive_ips = set()
        blocked_ips = set()
        for item in results:
            self._save_probe_item(item, source="domain")
            url = item.get("url")
            host = urlparse(
                url if url and "://" in url
                else "http://" + str(item.get("input") or "")
            ).hostname or ""
            evidence = self._preprobe_evidence_for_item(
                item, fallback_host=host)
            if url and evidence.get("pipeline_eligible", True):
                alive_sites.append(url)
            ip = self._extract_ip(item)
            if ip:
                self.observed_ips.add(ip)
            if self._is_blocked_alive_ip_item(item, ip, host):
                if ip:
                    blocked_ips.add(ip)
                    self.strong_blocked_ips.add(ip)
                continue
            if ip:
                alive_ips.add(ip)

        if getattr(Config, "ASSET_SEED_STRICT_EDGE_IP_EXCLUDE", True):
            alive_ips -= blocked_ips

        logger.info(
            "asset_seed_probe domains:{} alive_sites:{} alive_ips:{} blocked_ips:{} "
            "skipped_edge:{} preprobe_cdn:{} preprobe_owned_cdn:{} "
            "preprobe_external:{} preprobe_skipped_provider:{}".format(
                len(set(domains)), len(set(alive_sites)), len(alive_ips),
                len(blocked_ips), skipped_edge,
                self.preprobe_cdn_domain_count,
                self.preprobe_owned_cdn_domain_count,
                self.preprobe_external_domain_count,
                self.preprobe_skipped_provider_domain_count,
            ))
        return list(set(alive_sites)), list(alive_ips)

    def probe_ips(self, ips):
        raw_count = len(set(ips or []))
        ips = [ip for ip in ips or [] if ip not in self.edge_only_ips]
        skipped_edge = raw_count - len(set(ips))
        results = self._run_httpx(
            ips,
            ports=Config.ASSET_SEED_WEB_PORTS,
            batch_size=getattr(Config, "ASSET_SEED_HTTPX_IP_BATCH_SIZE", 120),
            timeout=getattr(Config, "ASSET_SEED_HTTPX_IP_BATCH_TIMEOUT", 90),
            label="ips"
        )
        alive_ips = set()
        blocked_ips = set()
        alive_sites = []
        for item in results:
            self._save_probe_item(item, source="ip")
            url = item.get("url")
            ip = self._extract_ip(item)
            if ip:
                self.observed_ips.add(ip)
            host = urlparse(url if url and "://" in url else "http://" + str(item.get("input") or "")).hostname or ""
            if self._is_blocked_alive_ip_item(item, ip, host):
                if ip:
                    blocked_ips.add(ip)
                    self.strong_blocked_ips.add(ip)
                continue
            if url:
                alive_sites.append(url)
            if ip:
                alive_ips.add(ip)

        if getattr(Config, "ASSET_SEED_STRICT_EDGE_IP_EXCLUDE", True):
            alive_ips -= blocked_ips

        logger.info("asset_seed_probe ips:{} alive_sites:{} alive_ips:{} blocked_ips:{} skipped_edge:{}".format(
            len(set(ips)), len(set(alive_sites)), len(alive_ips), len(blocked_ips), skipped_edge))
        return list(set(alive_sites)), list(alive_ips)

    def run(self, domain_info_list, ips=None):
        self._build_edge_ip_context(domain_info_list)
        domain_sites, domain_ips = self.probe_domains(domain_info_list)
        requested_ips = {
            str(ip).strip() for ip in (ips or [])
            if str(ip or "").strip() and utils.not_in_black_ips(str(ip).strip())
            and utils.get_ip_type(str(ip).strip()) == "PUBLIC"
            and str(ip).strip() not in self.edge_only_ips
        }
        ip_sites, ip_alive = self.probe_ips(requested_ips)
        alive_ips = set(domain_ips + ip_alive)
        unknown_ips = requested_ips - self.observed_ips - self.strong_blocked_ips
        scan_ips = (requested_ips | alive_ips) - self.strong_blocked_ips
        return {
            "alive_sites": list(set(domain_sites + ip_sites)),
            "alive_ips": sorted(alive_ips),
            "unknown_ips": sorted(unknown_ips),
            "blocked_ips": sorted(self.strong_blocked_ips),
            "scan_ips": sorted(scan_ips),
            "partial_errors": list(dict.fromkeys(self.partial_errors)),
            "httpx_retry_count": self.httpx_retry_count,
            "httpx_recovered_batch_count": self.httpx_recovered_batch_count,
            "httpx_failed_target_count": self.httpx_failed_target_count,
            "preprobe_cdn_domain_count": self.preprobe_cdn_domain_count,
            "preprobe_owned_cdn_domain_count": self.preprobe_owned_cdn_domain_count,
            "preprobe_external_domain_count": self.preprobe_external_domain_count,
            "preprobe_skipped_provider_domain_count": (
                self.preprobe_skipped_provider_domain_count),
        }


def asset_seed_probe(task_id, base_domain, domain_info_list, ips=None):
    probe = AssetSeedProbe(task_id=task_id, base_domain=base_domain)
    return probe.run(domain_info_list, ips=ips)


def httpx_probe_urls(
    urls,
    task_id=None,
    base_domain="",
    source="find_site",
    accepted_status_ranges=None,
    ports=None,
):
    probe = AssetSeedProbe(task_id=task_id or "", base_domain=base_domain or "")
    raw_urls = [str(value).strip() for value in urls or []
                if str(value or "").strip()]
    probe_urls = probe._prepare_http_probe_targets(raw_urls)
    results = probe._run_httpx(probe_urls, ports=ports)
    alive_sites = []
    skip_status = {410, 422, 501, 502, 504}
    for item in results:
        url = item.get("url")
        if not url:
            continue
        status_code = item.get("status_code")
        if status_code in skip_status:
            continue
        if accepted_status_ranges:
            try:
                status_code = int(status_code)
            except (TypeError, ValueError):
                continue
            if not any(start <= status_code <= end for start, end in accepted_status_ranges):
                continue
        if task_id:
            probe._save_probe_item(item, source=source)
        evidence = probe._preprobe_evidence_for_item(item)
        if evidence.get("pipeline_eligible", True):
            alive_sites.append(url)

    logger.info("httpx_probe_urls input:{} probe:{} alive:{} preprobe:{} blocked:{}".format(
        len(set(raw_urls)), len(set(probe_urls)), len(set(alive_sites)),
        probe.preprobe_cdn_domain_count,
        probe.preprobe_skipped_provider_domain_count))
    return list(set(alive_sites))
