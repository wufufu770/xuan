import json
import hashlib
import os
import signal
import shutil
import subprocess
import re
from collections import Counter

from app import utils
from app.config import Config

logger = utils.get_logger()


class DomainBrutePlusError(Exception):
    pass


DNSX_METRIC_DEFAULTS = {
    "dnsx_submitted_count": 0,
    "dnsx_response_count": 0,
    "dnsx_no_response_count": 0,
    "dnsx_noerror_count": 0,
    "dnsx_nxdomain_count": 0,
    "dnsx_servfail_count": 0,
    "dnsx_other_rcode_count": 0,
    "dnsx_a_hit_count": 0,
    "dnsx_a_record_count": 0,
    "dnsx_cname_hit_count": 0,
    "dnsx_cname_record_count": 0,
    "dnsx_no_record_response_count": 0,
    "dnsx_invalid_response_count": 0,
}


class DomainBrutePlus:
    def __init__(
            self, base_domain, word_file, tmp_dir=None,
            priority_word_file=None, task_id="", progress_callback=None):
        self.base_domain = base_domain.strip().strip(".")
        self.word_file = word_file
        if priority_word_file is None:
            use_priority = (
                bool(getattr(Config, "DOMAIN_DICT_PRIORITY_ENABLE", True)) and
                word_file and
                os.path.abspath(word_file) == os.path.abspath(Config.DOMAIN_DICT_2W)
            )
            priority_word_file = (
                getattr(Config, "DOMAIN_DICT_PRIORITY", "")
                if use_priority else ""
            )
        self.priority_word_file = priority_word_file or ""
        self.tmp_dir = tmp_dir or Config.TMP_PATH
        self.run_id = utils.random_choices()
        self.candidates_path = os.path.join(self.tmp_dir, "domain_plus_candidates_{}".format(self.run_id))
        self.alterx_path = os.path.join(self.tmp_dir, "domain_plus_alterx_{}".format(self.run_id))
        self.puredns_path = os.path.join(self.tmp_dir, "domain_plus_puredns_{}".format(self.run_id))
        self.dnsx_path = os.path.join(self.tmp_dir, "domain_plus_dnsx_{}".format(self.run_id))
        self.candidate_families = {}
        self.task_id = str(task_id or "")
        self.progress_callback = progress_callback

    def _check_tools(self, required=None):
        tools = {
            "alterx": Config.ALTERX_BIN,
            "puredns": Config.PUREDNS_BIN,
            "dnsx": Config.DNSX_BIN,
            "massdns": Config.MASSDNS_BIN,
        }
        required = set(required or tools)
        missing = []
        for name, path in tools.items():
            if name not in required:
                continue
            if not path:
                missing.append(name)
                continue
            if os.path.isabs(path):
                if not os.path.isfile(path):
                    missing.append(name)
            elif shutil.which(path) is None:
                missing.append(name)

        if missing:
            raise DomainBrutePlusError("missing tools: {}".format(",".join(missing)))

    def _run_cmd(self, command, timeout=60 * 60, input_text=None):
        logger.info("domain_brute_plus command: {}".format(" ".join(command)))
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                stdin=subprocess.PIPE if input_text is not None else None,
                                start_new_session=True, text=True)
        try:
            stdout, stderr = proc.communicate(input=input_text, timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                stdout, stderr = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                stdout, stderr = proc.communicate()
            raise DomainBrutePlusError("{} timeout after {}s".format(command[0], timeout))
        except BaseException:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            raise
        if proc.returncode != 0:
            stderr = stderr.strip()[-1000:]
            raise DomainBrutePlusError("{} failed: {}".format(command[0], stderr))
        if stderr.strip():
            logger.debug(stderr.strip()[-1000:])
        return stdout

    @staticmethod
    def _normalize_dictionary_word(value):
        value = str(value or "").strip().lower().strip(".")
        if not re.match(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", value):
            return ""
        return value

    def _write_base_candidates(self, meta=None):
        is_fuzz_domain = "{fuzz}" in self.base_domain
        words = []
        seen_words = set()
        family_counts = Counter()
        duplicate_count = 0
        invalid_count = 0

        def append_file(path, family, limit=0):
            nonlocal duplicate_count, invalid_count
            if not path or not os.path.isfile(path):
                return
            selected = 0
            with open(path, "r", encoding="utf-8", errors="ignore") as source:
                for line in source:
                    word = self._normalize_dictionary_word(line)
                    if not word:
                        if line.strip():
                            invalid_count += 1
                        continue
                    if word in seen_words:
                        duplicate_count += 1
                        continue
                    seen_words.add(word)
                    words.append((word, family))
                    family_counts[family] += 1
                    selected += 1
                    if limit and selected >= limit:
                        break

        priority_limit = max(int(getattr(
            Config, "DOMAIN_DICT_PRIORITY_LIMIT", 1000) or 0), 0)
        append_file(self.priority_word_file, "priority", priority_limit)
        append_file(self.word_file, "base")

        candidate_lines = []
        self.candidate_families = {}
        for word, family in words:
            if is_fuzz_domain:
                domain = self.base_domain.replace("{fuzz}", word)
            else:
                domain = "{}.{}".format(word, self.base_domain)
            candidate_lines.append(domain)
            self.candidate_families[domain] = family

        if not is_fuzz_domain:
            candidate_lines.append(self.base_domain)
            self.candidate_families[self.base_domain] = "root"
            family_counts["root"] += 1

        with open(self.candidates_path, "w", encoding="utf-8") as out:
            for domain in candidate_lines:
                out.write(domain + "\n")

        digest = hashlib.sha256(
            "\n".join(domain for domain in candidate_lines).encode("utf-8")
        ).hexdigest()
        if meta is not None:
            meta.update({
                "input_count": len(candidate_lines),
                "candidate_count": len(candidate_lines),
                "dictionary_word_count": len(words),
                "dictionary_priority_count": family_counts.get("priority", 0),
                "dictionary_base_count": family_counts.get("base", 0),
                "dictionary_duplicate_count": duplicate_count,
                "dictionary_invalid_count": invalid_count,
                "dictionary_candidate_counts": dict(family_counts),
                "dictionary_version": digest,
                "dictionary_files": [
                    os.path.basename(path) for path in (
                        self.priority_word_file, self.word_file)
                    if path and os.path.isfile(path)
                ],
            })
        logger.info(
            "domain_brute_plus candidates:{} priority:{} base:{} duplicate:{} invalid:{}".format(
                len(candidate_lines), family_counts.get("priority", 0),
                family_counts.get("base", 0), duplicate_count, invalid_count))

    def _write_candidates(self, domains):
        cnt = 0
        unique_domains = set()
        with open(self.candidates_path, "w", encoding="utf-8") as out:
            for domain in domains:
                domain = domain.strip().lower().strip(".")
                if not domain:
                    continue
                if domain in unique_domains:
                    continue
                if utils.check_domain_black(domain):
                    continue
                unique_domains.add(domain)
                out.write(domain + "\n")
                cnt += 1
        logger.info("domain_brute_plus custom candidates: {}".format(cnt))

    def _run_alterx(self, input_path=None):
        command = [
            Config.ALTERX_BIN,
            "-l", "stdin",
            "-en",
            "-silent",
            "-limit", str(Config.ALTERX_LIMIT),
            "-o", self.alterx_path,
        ]
        input_path = input_path or self.candidates_path
        with open(input_path, "r", encoding="utf-8", errors="ignore") as f:
            self._run_cmd(command, timeout=Config.ALTERX_TIMEOUT, input_text=f.read())

    def _merge_candidates(self):
        domains = set()
        for path in [self.candidates_path, self.alterx_path]:
            if not os.path.exists(path):
                continue
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    domain = line.strip().lower().strip(".")
                    if not domain:
                        continue
                    if utils.check_domain_black(domain):
                        continue
                    domains.add(domain)

        with open(self.candidates_path, "w", encoding="utf-8") as out:
            for domain in sorted(domains):
                out.write(domain + "\n")
        logger.info("domain_brute_plus merged candidates: {}".format(len(domains)))

    def _run_puredns(self, timeout=None, skip_validation=False):
        if timeout is None:
            timeout = int(getattr(Config, "DOMAIN_BRUTE_PLUS_PUREDNS_TIMEOUT", 90) or 90)
        command = [
            Config.PUREDNS_BIN,
            "resolve",
            self.candidates_path,
            "--resolvers", Config.PUREDNS_RESOLVERS,
            "--resolvers-trusted", Config.PUREDNS_TRUSTED_RESOLVERS,
            "--bin", Config.MASSDNS_BIN,
            "--rate-limit", str(Config.PUREDNS_RATE_LIMIT),
            "--rate-limit-trusted", str(Config.PUREDNS_TRUSTED_RATE_LIMIT),
            "--write", self.puredns_path,
            "-q",
        ]
        if skip_validation:
            # dnsx immediately validates the puredns output with the trusted
            # resolver pool. Avoid puredns' duplicate trusted pass, which can
            # spin massdns on an all-empty public result set.
            command.append("--skip-validation")
        self._run_cmd(command, timeout=timeout)

    def _run_dnsx(self, timeout=None, input_path=None, output_path=None):
        if timeout is None:
            timeout = int(getattr(Config, "DOMAIN_BRUTE_PLUS_DNSX_TIMEOUT", 3 * 60) or 3 * 60)
        input_path = input_path or self.puredns_path
        output_path = output_path or self.dnsx_path
        command = [
            Config.DNSX_BIN,
            "-l", input_path,
            "-a",
            "-cname",
            "-rcode", "noerror,nxdomain,servfail,refused",
            "-json",
            "-silent",
            "-r", Config.DNSX_RESOLVERS,
            "-t", str(Config.DNSX_THREADS),
            "-rl", str(Config.DNSX_RATE_LIMIT),
            "-o", output_path,
        ]
        self._run_cmd(command, timeout=timeout)

    def _has_non_empty_lines(self, path):
        if not os.path.exists(path):
            return False

        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.strip():
                    return True
        return False

    def _count_non_empty_lines(self, path):
        if not os.path.exists(path):
            return 0
        count = 0
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.strip():
                    count += 1
        return count

    def _read_non_empty_lines(self, path):
        if not os.path.exists(path):
            return []
        values = []
        with open(path, "r", encoding="utf-8", errors="ignore") as source:
            for line in source:
                value = line.strip().lower().strip(".")
                if value:
                    values.append(value)
        return values

    @staticmethod
    def _dedupe_records(records):
        output = []
        seen = set()
        for item in records or []:
            marker = (
                item.get("domain"),
                item.get("type"),
                item.get("record"),
            )
            if marker in seen:
                continue
            seen.add(marker)
            output.append(item)
        return output

    @staticmethod
    def _merge_batch_meta(items):
        items = [dict(item or {}) for item in items or []]
        merged = {key: 0 for key in DNSX_METRIC_DEFAULTS}
        numeric_fields = set(DNSX_METRIC_DEFAULTS) | {
            "candidate_count",
            "resolved_candidate_count",
            "resolver_leaf_batch_count",
            "resolver_split_count",
        }
        for item in items:
            for key in numeric_fields:
                merged[key] = merged.get(key, 0) + int(item.get(key, 0) or 0)
        merged["fallback_used"] = any(
            bool(item.get("fallback_used")) for item in items)
        merged["puredns_status_counts"] = dict(Counter(
            str(item.get("puredns_status") or "unknown") for item in items
        ))
        merged["dnsx_status_counts"] = dict(Counter(
            str(item.get("dnsx_status") or "unknown") for item in items
        ))
        merged["puredns_status"] = (
            "done" if all(
                item.get("puredns_status") in ("done", "no_resolved_records")
                for item in items
            ) else "done_with_warnings"
        )
        merged["dnsx_status"] = (
            "done" if all(item.get("dnsx_status") == "done" for item in items)
            else "done_with_warnings"
        )
        merged["resolver_status"] = "done"
        merged["resolver_engine"] = "batched_puredns+dnsx_trusted"
        merged["resolver_leaf_batch_count"] = max(
            merged.get("resolver_leaf_batch_count", 0), len(items))
        return merged

    def _checkpoint_query(self, fingerprint, batch_key, batch_hash):
        return {
            "task_id": self.task_id,
            "profile": "domain_brute",
            "candidate_fingerprint": fingerprint,
            "batch_key": batch_key,
            "batch_hash": batch_hash,
        }

    def _resolve_batch_with_checkpoint(
            self, domains, fingerprint, batch_key, runtime, depth=0):
        domains = list(domains or [])
        batch_hash = hashlib.sha256(
            "\n".join(domains).encode("utf-8")).hexdigest()
        collection = utils.conn_db("domain_brute_batch_state") if self.task_id else None
        query = self._checkpoint_query(fingerprint, batch_key, batch_hash)
        if collection is not None:
            checkpoint = collection.find_one(
                query, {"_id": 0, "status": 1, "output": 1, "meta": 1})
            if checkpoint and checkpoint.get("status") == "done":
                runtime["reused"] += 1
                return list(checkpoint.get("output") or []), dict(checkpoint.get("meta") or {})
            collection.update_one(
                query,
                {
                    "$set": {
                        "status": "running",
                        "input_count": len(domains),
                        "depth": depth,
                        "updated_at": utils.curr_date(),
                    },
                    "$setOnInsert": {
                        "created_at": utils.curr_date(),
                    },
                    "$inc": {"attempt_count": 1},
                },
                upsert=True,
            )

        batch_meta = {}
        try:
            output = resolve_candidates_plus(
                self.base_domain,
                domains,
                puredns_timeout=int(getattr(
                    Config, "DOMAIN_BRUTE_BATCH_PUREDNS_TIMEOUT", 90) or 90),
                dnsx_timeout=int(getattr(
                    Config, "DOMAIN_BRUTE_BATCH_DNSX_TIMEOUT", 180) or 180),
                meta=batch_meta,
            )
            batch_meta["resolver_leaf_batch_count"] = 1
        except DomainBrutePlusError as exc:
            min_size = max(int(getattr(
                Config, "DOMAIN_BRUTE_BATCH_MIN_SIZE", 250) or 250), 1)
            max_depth = max(int(getattr(
                Config, "DOMAIN_BRUTE_BATCH_SPLIT_DEPTH", 4) or 4), 0)
            if len(domains) > min_size and depth < max_depth:
                runtime["split"] += 1
                midpoint = max(len(domains) // 2, 1)
                child_results = []
                child_meta = []
                for suffix, child_domains in (
                    ("0", domains[:midpoint]),
                    ("1", domains[midpoint:]),
                ):
                    if not child_domains:
                        continue
                    result, meta = self._resolve_batch_with_checkpoint(
                        child_domains,
                        fingerprint,
                        "{}.{}".format(batch_key, suffix),
                        runtime,
                        depth=depth + 1,
                    )
                    child_results.extend(result)
                    child_meta.append(meta)
                output = self._dedupe_records(child_results)
                batch_meta = self._merge_batch_meta(child_meta)
                batch_meta["resolver_split_count"] = (
                    int(batch_meta.get("resolver_split_count", 0) or 0) + 1)
            else:
                if collection is not None:
                    collection.update_one(query, {"$set": {
                        "status": "failed",
                        "error": str(exc)[:1000],
                        "updated_at": utils.curr_date(),
                    }})
                raise

        if collection is not None:
            collection.update_one(query, {
                "$set": {
                    "status": "done",
                    "output_count": len(output),
                    "output": output,
                    "meta": batch_meta,
                    "updated_at": utils.curr_date(),
                    "completed_at": utils.curr_date(),
                },
                "$unset": {"error": ""},
            })
        return output, batch_meta

    def _run_batched(self, meta):
        domains = self._read_non_empty_lines(self.candidates_path)
        batch_size = max(int(getattr(
            Config, "DOMAIN_BRUTE_BATCH_SIZE", 2500) or 2500), 1)
        batches = [
            domains[start:start + batch_size]
            for start in range(0, len(domains), batch_size)
        ]
        fingerprint = str(meta.get("dictionary_version") or hashlib.sha256(
            "\n".join(domains).encode("utf-8")).hexdigest())
        if self.task_id:
            utils.conn_db("domain_brute_batch_state").update_many(
                {
                    "task_id": self.task_id,
                    "profile": "domain_brute",
                    "candidate_fingerprint": fingerprint,
                    "status": "running",
                },
                {"$set": {
                    "status": "interrupted",
                    "updated_at": utils.curr_date(),
                }},
            )

        runtime = {"reused": 0, "split": 0}
        all_output = []
        batch_meta = []
        for index, domains_batch in enumerate(batches):
            output, item_meta = self._resolve_batch_with_checkpoint(
                domains_batch,
                fingerprint,
                "{:05d}".format(index),
                runtime,
            )
            all_output.extend(output)
            batch_meta.append(item_meta)
            if callable(self.progress_callback):
                self.progress_callback({
                    "completed_batches": index + 1,
                    "total_batches": len(batches),
                    "output_count": len({
                        item.get("domain") for item in all_output
                        if item.get("domain")
                    }),
                    "checkpoint_reused_batches": runtime["reused"],
                    "split_batch_count": runtime["split"],
                })

        output = self._dedupe_records(all_output)
        merged = self._merge_batch_meta(batch_meta)
        resolved_count = len({
            item.get("domain") for item in output if item.get("domain")
        })
        merged.update({
            "candidate_count": len(domains),
            "resolved_candidate_count": resolved_count,
            "total_batches": len(batches),
            "completed_batches": len(batches),
            "checkpoint_reused_batches": runtime["reused"],
            "split_batch_count": runtime["split"],
            "resolved_per_10k": round(
                resolved_count * 10000.0 / max(len(domains), 1), 2),
        })
        if runtime["split"] or any(
                item.get("fallback_used") for item in batch_meta):
            merged.update({
                "warning": "resolver batches completed with fallback or adaptive split",
                "_stage_status": "done_with_warnings",
                "completion_state": "done_with_warnings",
            })
        meta.update(merged)
        return output

    def _parse_dnsx(self, meta=None):
        output = []
        seen = set()
        family_responses = Counter()
        family_hits = Counter()
        metrics = {
            key: 0 for key in DNSX_METRIC_DEFAULTS
            if key != "dnsx_submitted_count"
        }
        if not os.path.exists(self.dnsx_path):
            if meta is not None:
                metrics["dnsx_no_response_count"] = int(
                    meta.get("dnsx_submitted_count", 0) or 0)
                meta.update(metrics)
            return output

        with open(self.dnsx_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    metrics["dnsx_invalid_response_count"] += 1
                    logger.warning("domain_brute_plus dnsx json decode failed: {}".format(line[:200]))
                    continue

                if not isinstance(item, dict):
                    metrics["dnsx_invalid_response_count"] += 1
                    continue
                host = str(item.get("host") or "").lower().strip(".")
                if not host or host in seen:
                    if not host:
                        metrics["dnsx_invalid_response_count"] += 1
                    continue
                seen.add(host)
                metrics["dnsx_response_count"] += 1
                family = self.candidate_families.get(host, "unknown")
                family_responses[family] += 1

                cnames = item.get("cname") or item.get("cname_raw") or []
                if isinstance(cnames, str):
                    cnames = [cnames]
                cnames = _ordered_unique([
                    str(x).strip().strip(".") for x in cnames if x
                ])
                records = item.get("a") or []
                if isinstance(records, str):
                    records = [records]
                records = _ordered_unique([
                    str(x).strip() for x in records if x
                ])

                status_code = str(item.get("status_code") or "").upper()
                if not status_code and (cnames or records):
                    status_code = "NOERROR"
                metric_key = {
                    "NOERROR": "dnsx_noerror_count",
                    "NXDOMAIN": "dnsx_nxdomain_count",
                    "SERVFAIL": "dnsx_servfail_count",
                }.get(status_code, "dnsx_other_rcode_count")
                metrics[metric_key] += 1

                if records:
                    metrics["dnsx_a_hit_count"] += 1
                    metrics["dnsx_a_record_count"] += len(records)
                if cnames:
                    metrics["dnsx_cname_hit_count"] += 1
                    metrics["dnsx_cname_record_count"] += len(cnames)
                if not records and not cnames:
                    metrics["dnsx_no_record_response_count"] += 1
                else:
                    family_hits[family] += 1

                if cnames:
                    output.append({
                        "domain": host,
                        "type": "CNAME",
                        "record": cnames[0],
                    })
                for record in records:
                    output.append({
                        "domain": host,
                        "type": "A",
                        "record": record,
                    })
        if meta is not None:
            submitted_count = int(meta.get("dnsx_submitted_count", 0) or 0)
            metrics["dnsx_no_response_count"] = max(
                submitted_count - metrics["dnsx_response_count"], 0)
            meta.update(metrics)
            meta["dnsx_family_response_counts"] = dict(family_responses)
            meta["dnsx_family_hit_counts"] = dict(family_hits)
        return output

    def _cleanup(self):
        if Config.DOMAIN_BRUTE_PLUS_KEEP_TMP:
            return
        for path in [self.candidates_path, self.alterx_path, self.puredns_path, self.dnsx_path]:
            try:
                if os.path.exists(path):
                    os.unlink(path)
            except OSError as e:
                logger.warning(e)

    def run(self, meta=None):
        if meta is None:
            meta = {}
        meta.update({
            "puredns_status": "pending",
            "dnsx_status": "pending",
            "fallback_used": False,
            "resolver_engine": "puredns+dnsx_trusted",
        })
        meta.update(DNSX_METRIC_DEFAULTS)
        self._check_tools(required=("puredns", "dnsx", "massdns"))
        try:
            self._write_base_candidates(meta=meta)
            candidate_count = int(meta.get("candidate_count", 0) or 0)
            batch_size = max(int(getattr(
                Config, "DOMAIN_BRUTE_BATCH_SIZE", 2500) or 2500), 1)
            if self.task_id or candidate_count > batch_size:
                output = self._run_batched(meta)
                logger.info(
                    "domain_brute_plus batched result records:{} domains:{} batches:{} reused:{}".format(
                        len(output), meta.get("resolved_candidate_count", 0),
                        meta.get("total_batches", 0),
                        meta.get("checkpoint_reused_batches", 0)))
                return output
            dnsx_input_path = None
            dnsx_output_path = None
            try:
                self._run_puredns()
            except DomainBrutePlusError as e:
                error_text = str(e)
                meta.update({
                    "puredns_status": (
                        "timeout" if "timeout" in error_text.lower() else "failed"),
                    "puredns_error": error_text,
                    "fallback_used": True,
                    "fallback_reason": (
                        "puredns_timeout" if "timeout" in error_text.lower()
                        else "puredns_failed"),
                    "resolver_engine": "dnsx_candidates",
                })
                logger.warning(
                    "domain_brute_plus puredns failed on {}, fallback dnsx candidates: {}".format(
                    self.base_domain, e))
                dnsx_input_path = self.candidates_path
                dnsx_output_path = self.dnsx_path

            if meta["puredns_status"] == "pending":
                if self._has_non_empty_lines(self.puredns_path):
                    meta["puredns_status"] = "done"
                else:
                    meta.update({
                        "puredns_status": "no_resolved_records",
                        "fallback_used": True,
                        "fallback_reason": "puredns_no_resolved_records",
                        "resolver_engine": "dnsx_candidates",
                    })
                    dnsx_input_path = self.candidates_path
                    dnsx_output_path = self.dnsx_path

            actual_dnsx_input = dnsx_input_path or self.puredns_path
            meta["dnsx_submitted_count"] = self._count_non_empty_lines(
                actual_dnsx_input)
            try:
                self._run_dnsx(
                    input_path=dnsx_input_path,
                    output_path=dnsx_output_path,
                )
                meta["dnsx_status"] = "done"
            except DomainBrutePlusError as e:
                error_text = str(e)
                meta.update({
                    "dnsx_status": (
                        "timeout" if "timeout" in error_text.lower() else "failed"),
                    "dnsx_error": error_text,
                    "resolver_status": "failed",
                })
                raise

            output = self._parse_dnsx(meta=meta)
            resolved_count = len({
                item.get("domain") for item in output if item.get("domain")
            })
            meta.update({
                "resolved_candidate_count": resolved_count,
                "resolver_status": "done",
                "resolved_per_10k": round(
                    resolved_count * 10000.0 /
                    max(int(meta.get("candidate_count", 0) or 0), 1), 2),
            })
            logger.info(
                "domain_brute_plus base result records:{} domains:{} submitted:{} "
                "responses:{} noerror:{} nxdomain:{} servfail:{}".format(
                    len(output), resolved_count, meta["dnsx_submitted_count"],
                    meta["dnsx_response_count"], meta["dnsx_noerror_count"],
                    meta["dnsx_nxdomain_count"], meta["dnsx_servfail_count"]))
            return output
        finally:
            self._cleanup()


def domain_brute_plus(
        base_domain, word_file, meta=None, task_id="", progress_callback=None):
    runner = DomainBrutePlus(
        base_domain=base_domain,
        word_file=word_file,
        task_id=task_id,
        progress_callback=progress_callback,
    )
    return runner.run(meta=meta)


def alterx_candidates_plus(base_domain, domains, alterx_timeout=None):
    runner = DomainBrutePlus(base_domain=base_domain, word_file="")
    runner._check_tools(required=("alterx",))
    seed_path = runner.candidates_path
    seen = set()
    try:
        with open(seed_path, "w", encoding="utf-8") as out:
            for domain in domains:
                domain = domain.strip().lower().strip(".")
                if not domain or domain in seen:
                    continue
                if utils.check_domain_black(domain):
                    continue
                seen.add(domain)
                out.write(domain + "\n")
                if len(seen) >= Config.ALTERX_SEED_LIMIT:
                    break

        if not seen:
            return []

        old_timeout = Config.ALTERX_TIMEOUT
        if alterx_timeout:
            Config.ALTERX_TIMEOUT = alterx_timeout

        try:
            runner._run_alterx(input_path=seed_path)
        finally:
            Config.ALTERX_TIMEOUT = old_timeout

        output = []
        if os.path.exists(runner.alterx_path):
            with open(runner.alterx_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    domain = line.strip().lower().strip(".")
                    if not domain:
                        continue
                    output.append(domain)

        logger.info("alterx_candidates_plus seeds:{} candidates:{}".format(len(seen), len(output)))
        return output
    finally:
        runner._cleanup()


def _clean_label(label):
    label = label.strip().lower()
    if not re.match(r"^[a-z0-9-]{1,30}$", label):
        return ""
    return label.strip("-")


COMMON_MUTATION_LABELS = {
    "www", "m", "h5", "wap", "api", "app", "web", "admin", "manage",
    "manager", "portal", "test", "dev", "uat", "pre", "prod", "stage",
    "stg", "qa", "sit", "int", "internal", "inner", "intra", "sandbox",
    "gray", "beta", "demo", "static", "cdn", "img",
    "file", "download", "mail", "vpn", "sso", "oa", "open", "mobile",
    "wx", "wechat", "weixin", "mini", "miniapp", "mp", "ios", "android",
    "apk", "ipa", "client", "hybrid", "rn", "flutter",
}

EDGE_SEED_LABELS = {
    "ztna", "waf", "edge", "gateway", "firewall", "sase", "proxy",
    "shield", "access",
}

SHORT_MUTATION_TOKENS = {
    "oa", "hr", "bi", "ai", "id", "sso", "crm", "erp", "api", "gw",
    "h5", "m", "im", "pj", "wx", "mp", "rn",
}

MUTATION_ENV_WORDS = [
    "dev", "test", "uat", "pre", "stg", "qa", "sit", "prod",
    "gray", "beta", "stage", "demo",
]

MUTATION_CHANNEL_WORDS = [
    "api", "admin", "manage", "portal", "app", "mobile", "web",
    "h5", "wap", "wx", "wechat", "weixin", "mini", "miniapp",
    "mp", "ios", "android", "client",
]

MUTATION_ROLE_WORDS = [
    "api", "app", "web", "gw", "gateway", "front", "admin", "manage",
    "portal", "sso", "oa", "open", "trade", "quote", "market", "user",
    "auth", "login", "mobile", "h5", "wap", "wx", "wechat", "weixin",
    "mini", "miniapp", "mp", "client", "ios", "android", "download",
    "apk", "ipa", "push", "im", "job", "task", "data", "report",
]

MUTATION_SUFFIX_WORDS = [
    "dev", "test", "uat", "pre", "stg", "qa", "sit", "pj", "bak",
    "old", "new", "m", "h5", "wap", "app", "mobile", "wx",
    "miniapp", "mp", "ios", "android",
]

MUTATION_FAMILY_WEIGHTS = (
    ("environment", 1),
    ("role", 3),
    ("channel", 3),
    ("concatenation", 2),
    ("structure", 3),
)

COMPOUND_SUFFIXES = sorted(
    set(MUTATION_ENV_WORDS + MUTATION_CHANNEL_WORDS + MUTATION_ROLE_WORDS),
    key=len,
    reverse=True,
)

COMPOUND_PREFIXES = sorted(
    set(MUTATION_ENV_WORDS + MUTATION_CHANNEL_WORDS),
    key=len,
    reverse=True,
)

RECURSIVE_PARENT_LABELS = {
    "dev", "test", "uat", "pre", "stg", "stage", "qa", "sit", "prod",
    "gray", "beta", "demo", "internal", "inner", "intra", "corp", "cloud",
    "app", "mobile", "h5", "wap", "wx", "mini", "miniapp", "mp", "api",
    "open", "partner", "vendor", "staff", "ops", "sre", "lab", "sandbox",
}

RECURSIVE_PARENT_SKIP_LABELS = EDGE_SEED_LABELS | {
    "www", "cdn", "static", "img", "image", "images", "download", "file",
}


def _is_random_label(label):
    try:
        from app.services.edgeAsset import is_random_long_label
        return is_random_long_label(label)
    except Exception:
        compact = re.sub(r"[^a-z0-9]", "", str(label or "").lower())
        return len(compact) >= 12 and bool(re.search(r"[a-z]", compact)) and bool(re.search(r"\d", compact))


def _is_edge_seed_domain(domain, base_domain):
    try:
        from app.services.edgeAsset import classify_edge_host
        if classify_edge_host(domain, base_domain).get("is_edge"):
            return True
    except Exception:
        pass

    labels = _domain_labels(base_domain, domain)
    if any(label in EDGE_SEED_LABELS for label in labels):
        return True
    return bool(labels) and all(_is_random_label(label) for label in labels)


def _domain_labels(base_domain, domain):
    domain = str(domain or "").strip().lower().strip(".")
    base_domain = str(base_domain or "").strip().lower().strip(".")
    if domain == base_domain:
        return []
    if not domain.endswith("." + base_domain):
        return []
    prefix = domain[:-(len(base_domain) + 1)]
    labels = [_clean_label(x) for x in prefix.split(".")]
    return [x for x in labels if x]


def select_mutation_seed_domains(base_domain, domains, seed_scores=None):
    """Select bounded, high-signal seeds without alphabetical truncation."""
    limit = max(int(getattr(Config, "LIGHT_MUTATION_SEED_LIMIT", 160) or 0), 0)
    if not limit:
        return []

    seed_scores = seed_scores or {}
    candidates = []
    seen_domains = set()
    for input_index, raw_domain in enumerate(domains or []):
        domain = str(raw_domain or "").strip().lower().strip(".")
        if not domain or domain in seen_domains:
            continue
        seen_domains.add(domain)
        if not domain.endswith("." + base_domain) or _is_edge_seed_domain(domain, base_domain):
            continue
        labels = _domain_labels(base_domain, domain)
        useful_labels = [
            label for label in labels
            if label not in COMMON_MUTATION_LABELS
            and label not in EDGE_SEED_LABELS
            and not _is_random_label(label)
        ]
        if not useful_labels:
            continue
        tokens = []
        for label in useful_labels:
            values = _label_tokens(label) or [label]
            for token in values:
                if token not in tokens:
                    tokens.append(token)
        if not tokens:
            continue

        external_score = int(seed_scores.get(domain, 0) or 0)
        intrinsic_score = min(len(tokens), 3) * 4 + min(len(labels), 3)
        candidates.append({
            "domain": domain,
            "tokens": tokens,
            "score": external_score + intrinsic_score,
            "input_index": input_index,
        })

    candidates.sort(key=lambda item: (
        -item["score"], item["input_index"], item["domain"]))
    selected = []
    selected_domains = set()
    covered_tokens = set()

    # First preserve business-label diversity, then fill remaining capacity by
    # score. This prevents many aliases of one application from crowding out
    # unrelated labels discovered later in the source list.
    for item in candidates:
        if not (set(item["tokens"]) - covered_tokens):
            continue
        selected.append(item["domain"])
        selected_domains.add(item["domain"])
        covered_tokens.update(item["tokens"])
        if len(selected) >= limit:
            return selected

    for item in candidates:
        if item["domain"] in selected_domains:
            continue
        selected.append(item["domain"])
        if len(selected) >= limit:
            break
    return selected


def _split_compound_part(part):
    part = _clean_label(part)
    if not part:
        return []

    # Suffixes are the most reliable signal in real enterprise labels:
    # amsuat -> ams + uat, eaigateway -> eai + gateway.
    for suffix in COMPOUND_SUFFIXES:
        if not part.endswith(suffix) or part == suffix:
            continue
        stem = part[:-len(suffix)].strip("-")
        if len(stem) < 3:
            continue
        return [stem, suffix]

    # Prefix splitting is deliberately conservative to avoid treating words
    # such as "application" as app + lication. A compact prefix is split only
    # when the remainder is itself a known infrastructure label.
    for prefix in COMPOUND_PREFIXES:
        if not part.startswith(prefix) or part == prefix:
            continue
        remainder = part[len(prefix):].strip("-")
        if remainder in COMMON_MUTATION_LABELS or remainder in MUTATION_ROLE_WORDS:
            return [prefix, remainder]

    return [part]


def _label_tokens(label):
    tokens = []
    raw_parts = [x for x in re.split(r"[-_]+", label) if x]
    for raw_part in raw_parts or [label]:
        alpha_num_parts = re.findall(r"[a-z]+[0-9]*|[0-9]+[a-z]+", raw_part)
        if not alpha_num_parts:
            alpha_num_parts = [raw_part]
        for part in alpha_num_parts:
            tokens.extend(_split_compound_part(part))

    clean_tokens = []
    for token in tokens:
        token = _clean_label(token)
        if not token:
            continue
        if len(token) < 2 or len(token) > 24:
            continue
        if len(token) == 2 and token not in SHORT_MUTATION_TOKENS:
            continue
        if token.isdigit():
            continue
        if re.match(r"^(?:cdn|waf|edge|static|img|image|dev|test|uat|pre|stg|qa|sit|int)\d*$", token):
            continue
        if token in COMMON_MUTATION_LABELS or token in EDGE_SEED_LABELS:
            continue
        if _is_random_label(token):
            continue
        if token not in clean_tokens:
            clean_tokens.append(token)
    return clean_tokens


def _ordered_unique(values):
    output = []
    seen = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output


def _round_robin_values(*groups):
    groups = [_ordered_unique(group) for group in groups if group]
    output = []
    seen = set()
    for index in range(max([len(group) for group in groups] or [0])):
        for group in groups:
            if index >= len(group):
                continue
            value = group[index]
            if value in seen:
                continue
            seen.add(value)
            output.append(value)
    return output


def _learn_mutation_profile(label_groups):
    concat_prefix = Counter()
    concat_suffix = Counter()
    structure_prefix = Counter()
    structure_suffix = Counter()
    learned_stems = []
    seen_stems = set()
    affix_words = sorted(
        set(MUTATION_ENV_WORDS + MUTATION_CHANNEL_WORDS +
            MUTATION_ROLE_WORDS + MUTATION_SUFFIX_WORDS),
        key=lambda value: (-len(value), value),
    )

    for labels in label_groups:
        useful_labels = [
            label for label in labels
            if label not in COMMON_MUTATION_LABELS
            and label not in EDGE_SEED_LABELS
            and not _is_random_label(label)
        ]
        for label in labels:
            compact_label = label.replace("-", "")
            for stem in _label_tokens(label):
                compact_stem = stem.replace("-", "")
                if compact_stem == compact_label:
                    continue
                if stem not in seen_stems:
                    seen_stems.add(stem)
                    learned_stems.append(stem)
                if "-" in label:
                    continue
                for affix in affix_words:
                    if compact_label == affix + compact_stem:
                        concat_prefix[affix] += 1
                    if compact_label == compact_stem + affix:
                        concat_suffix[affix] += 1

        if not useful_labels or len(labels) < 2:
            continue
        for index, label in enumerate(labels):
            if label not in COMMON_MUTATION_LABELS:
                continue
            if index == 0:
                structure_prefix[label] += 1
            if index == len(labels) - 1:
                structure_suffix[label] += 1

    def ranked(counter):
        return [value for value, _ in sorted(
            counter.items(), key=lambda item: (-item[1], item[0]))]

    return {
        "concat_prefix": ranked(concat_prefix),
        "concat_suffix": ranked(concat_suffix),
        "structure_prefix": ranked(structure_prefix),
        "structure_suffix": ranked(structure_suffix),
        "learned_stems": learned_stems,
    }


def _mutation_pattern_families(base_domain, seed, mutation_profile=None):
    mutation_profile = mutation_profile or {}
    family_names = [name for name, _ in MUTATION_FAMILY_WEIGHTS]
    families = {name: [] for name in family_names}
    family_seen = {name: set() for name in family_names}
    role_words = [
        word for word in MUTATION_ROLE_WORDS
        if word not in MUTATION_CHANNEL_WORDS
    ]

    def add(family, prefix):
        name = "{}.{}".format(prefix, base_domain)
        if name in family_seen[family]:
            return
        family_seen[family].add(name)
        families[family].append(name)

    for word in MUTATION_ENV_WORDS:
        add("environment", "{}-{}".format(seed, word))
        add("environment", "{}-{}".format(word, seed))

    for word in role_words:
        add("role", "{}-{}".format(seed, word))
        add("role", "{}-{}".format(word, seed))

    for word in MUTATION_CHANNEL_WORDS:
        add("channel", "{}-{}".format(seed, word))
        add("channel", "{}-{}".format(word, seed))

    learned_concat_prefix = mutation_profile.get("concat_prefix") or []
    learned_concat_suffix = mutation_profile.get("concat_suffix") or []
    for word in learned_concat_prefix:
        add("concatenation", "{}{}".format(word, seed))
    for word in learned_concat_suffix:
        add("concatenation", "{}{}".format(seed, word))
    concat_words = _round_robin_values(
        learned_concat_prefix,
        learned_concat_suffix,
        MUTATION_CHANNEL_WORDS,
        MUTATION_ENV_WORDS,
        role_words,
        MUTATION_SUFFIX_WORDS,
    )
    for word in concat_words:
        add("concatenation", "{}{}".format(word, seed))
        add("concatenation", "{}{}".format(seed, word))

    learned_structure_prefix = mutation_profile.get("structure_prefix") or []
    learned_structure_suffix = mutation_profile.get("structure_suffix") or []
    for word in learned_structure_prefix:
        add("structure", "{}.{}".format(word, seed))
    for word in learned_structure_suffix:
        add("structure", "{}.{}".format(seed, word))
    structure_words = _round_robin_values(
        learned_structure_prefix,
        learned_structure_suffix,
        MUTATION_ENV_WORDS,
        role_words,
        MUTATION_CHANNEL_WORDS,
    )
    for word in structure_words:
        add("structure", "{}.{}".format(seed, word))
        add("structure", "{}.{}".format(word, seed))

    return families


def _mutation_patterns(base_domain, seed, mutation_profile=None):
    families = _mutation_pattern_families(
        base_domain, seed, mutation_profile=mutation_profile)
    patterns = []
    family_names = [name for name, _ in MUTATION_FAMILY_WEIGHTS]
    max_patterns = max([len(families[name]) for name in family_names] or [0])
    for index in range(max_patterns):
        for family in family_names:
            values = families[family]
            if index < len(values):
                patterns.append(values[index])
    return patterns


def _family_quotas(capacity):
    total_weight = sum(weight for _, weight in MUTATION_FAMILY_WEIGHTS)
    quotas = {}
    allocated = 0
    for family, weight in MUTATION_FAMILY_WEIGHTS:
        quota = capacity * weight // total_weight if total_weight else 0
        quotas[family] = quota
        allocated += quota
    for family, _ in MUTATION_FAMILY_WEIGHTS:
        if allocated >= capacity:
            break
        quotas[family] += 1
        allocated += 1
    return quotas


def light_mutation_candidates(
        base_domain, domains, seed_scores=None, candidate_limit=None,
        seed_limit=None, per_seed_limit=None, meta=None, family_map=None,
        known_domains=None):
    base_domain = base_domain.strip().lower().strip(".")
    domain_values = list(domains or [])
    if candidate_limit is None:
        candidate_limit = getattr(Config, "LIGHT_MUTATION_LIMIT", 1500)
    candidate_limit = max(int(candidate_limit or 0), 0)
    if meta is None:
        meta = {}
    if family_map is None:
        family_map = {}
    if not base_domain or not candidate_limit:
        meta.update({
            "input_seed_count": len(set(domain_values)),
            "selected_seed_count": 0,
            "candidate_count": 0,
            "family_candidate_counts": {},
        })
        return []
    known_domains = {
        str(domain or "").strip().lower().strip(".")
        for domain in list(domain_values) + list(known_domains or [])
        if str(domain or "").strip()
    }
    root_entries = [
        "www", "m", "app", "api", "admin", "manage", "portal", "sso",
        "oa", "mail", "vpn", "download", "file", "static", "cdn",
        "test", "uat", "dev", "pre", "stg", "demo", "h5", "wap",
        "mobile", "client", "ios", "android", "wx", "wechat", "weixin",
        "mini", "miniapp", "mp", "app-api", "api-app", "appgw", "app-gw",
        "app-gateway", "mobile-api", "api-mobile", "h5-api", "api-h5",
        "wap-api", "api-wap", "wx-api", "api-wx", "miniapp-api",
        "api-miniapp", "mp-api", "api-mp", "app-download", "download-app",
        "appdownload", "downloadapp", "ios-app", "android-app",
        "app-ios", "app-android", "app-server", "app-service",
        "mobile-gw", "h5-gw", "wx-gw", "miniapp-gw"
    ]

    candidates = []
    seen = set()
    seed_domains = []
    skipped_edge = 0
    label_counter = Counter()
    token_counter = Counter()
    prefix_labels = []
    skipped_known = 0

    selected_seed_domains = select_mutation_seed_domains(
        base_domain, domain_values, seed_scores=seed_scores)
    for domain in selected_seed_domains:
        domain = domain.strip().lower().strip(".")
        if not domain.endswith("." + base_domain):
            continue
        if _is_edge_seed_domain(domain, base_domain):
            skipped_edge += 1
            continue
        labels = _domain_labels(base_domain, domain)
        if not labels:
            continue
        useful_labels = [
            label for label in labels
            if label not in COMMON_MUTATION_LABELS and label not in EDGE_SEED_LABELS and not _is_random_label(label)
        ]
        if not useful_labels:
            continue
        seed_domains.append(domain)
        prefix_labels.append(labels)
        for label in useful_labels:
            label_counter[label] += 1
            for token in _label_tokens(label):
                token_counter[token] += 1

    mutation_profile = _learn_mutation_profile(prefix_labels)
    for stem in mutation_profile["learned_stems"]:
        token_counter[stem] += 1

    def add(name, family="target_label"):
        nonlocal skipped_known
        if len(candidates) >= candidate_limit:
            return False
        name = name.strip().lower().strip(".")
        if not name or name in seen:
            return False
        if name in known_domains:
            skipped_known += 1
            return False
        if utils.check_domain_black(name):
            return False
        seen.add(name)
        candidates.append(name)
        family_map[name] = family
        return True

    if seed_limit is None:
        seed_limit = getattr(Config, "LIGHT_MUTATION_SEED_LIMIT", 160)
    seed_limit = max(int(seed_limit or 0), 0)
    top_labels = [x for x, _ in label_counter.most_common(seed_limit)]
    top_tokens = [x for x, _ in token_counter.most_common(seed_limit)]
    seeds = []
    label_seeds = [
        label for label in top_labels
        if ("-" not in label or label_counter.get(label, 0) >= 2)
        and label in _label_tokens(label)
    ]
    for value in top_tokens + label_seeds:
        if value not in seeds:
            seeds.append(value)

    direct_seed_count = 0
    for seed in seeds:
        if add("{}.{}".format(seed, base_domain), family="target_label"):
            direct_seed_count += 1

    baseline_limit = min(candidate_limit, max(
        len(candidates), int(candidate_limit * 0.20)))
    deferred_root_entries = []
    for entry in root_entries:
        candidate = "{}.{}".format(entry, base_domain)
        if len(candidates) < baseline_limit:
            add(candidate, family="root_priority")
        else:
            deferred_root_entries.append(candidate)

    if per_seed_limit is None:
        per_seed_limit = getattr(Config, "LIGHT_MUTATION_PER_SEED_LIMIT", 50)
    per_seed_limit = max(int(per_seed_limit or 0), 0)
    family_names = [name for name, _ in MUTATION_FAMILY_WEIGHTS]
    per_family_seed_limits = {}
    total_family_weight = sum(weight for _, weight in MUTATION_FAMILY_WEIGHTS)
    allocated_per_seed = 0
    for family, weight in MUTATION_FAMILY_WEIGHTS:
        value = (
            per_seed_limit * weight // total_family_weight
            if total_family_weight else 0)
        per_family_seed_limits[family] = value
        allocated_per_seed += value
    for family in family_names:
        if allocated_per_seed >= per_seed_limit:
            break
        per_family_seed_limits[family] += 1
        allocated_per_seed += 1

    seed_families = {
        seed: _mutation_pattern_families(
            base_domain, seed, mutation_profile=mutation_profile)
        for seed in seeds
    }
    family_queues = {family: [] for family in family_names}
    family_queue_seen = {family: set() for family in family_names}

    def queue_candidate(family, name, seed=None):
        if name in family_queue_seen[family]:
            return
        family_queue_seen[family].add(name)
        family_queues[family].append((name, seed))

    for family in family_names:
        family_seed_limit = per_family_seed_limits[family]
        for pattern_index in range(family_seed_limit):
            for seed in seeds:
                patterns = seed_families[seed][family]
                if pattern_index < len(patterns):
                    queue_candidate(family, patterns[pattern_index], seed=seed)

    structural_replacements = _round_robin_values(
        mutation_profile.get("structure_prefix") or [],
        mutation_profile.get("structure_suffix") or [],
        MUTATION_ENV_WORDS,
        [word for word in MUTATION_ROLE_WORDS
         if word not in MUTATION_CHANNEL_WORDS],
        MUTATION_CHANNEL_WORDS,
    )
    for labels in prefix_labels:
        for index, label in enumerate(labels):
            if label not in COMMON_MUTATION_LABELS:
                continue
            for replacement in structural_replacements:
                mutated = list(labels)
                mutated[index] = replacement
                queue_candidate(
                    "structure",
                    "{}.{}".format(".".join(mutated), base_domain),
                )

    quotas = _family_quotas(candidate_limit - len(candidates))
    family_counts = {family: 0 for family in family_names}
    family_offsets = {family: 0 for family in family_names}
    variant_seed_names = set()

    def add_from_family(family):
        queue = family_queues[family]
        while family_offsets[family] < len(queue):
            name, seed = queue[family_offsets[family]]
            family_offsets[family] += 1
            if add(name, family=family):
                family_counts[family] += 1
                if seed:
                    variant_seed_names.add(seed)
                return True
        return False

    for family in family_names:
        while family_counts[family] < quotas[family]:
            if not add_from_family(family):
                break

    while len(candidates) < candidate_limit:
        progress = False
        for family in family_names:
            if add_from_family(family):
                progress = True
            if len(candidates) >= candidate_limit:
                break
        if not progress:
            break

    for candidate in deferred_root_entries:
        if len(candidates) >= candidate_limit:
            break
        add(candidate, family="root_priority")

    candidate_family_counts = dict(Counter(
        family_map.get(candidate, "unknown") for candidate in candidates))
    meta.update({
        "input_seed_count": len(set(domain_values)),
        "selected_seed_count": len(seed_domains),
        "skipped_edge_seed_count": skipped_edge,
        "skipped_known_candidate_count": skipped_known,
        "learned_label_count": len(label_counter),
        "learned_token_count": len(token_counter),
        "direct_seed_candidate_count": direct_seed_count,
        "variant_seed_coverage": len(variant_seed_names),
        "candidate_count": len(candidates),
        "family_quotas": quotas,
        "family_candidate_counts": candidate_family_counts,
        "learned_concat_prefix": mutation_profile["concat_prefix"][:8],
        "learned_concat_suffix": mutation_profile["concat_suffix"][:8],
        "learned_structure_prefix": mutation_profile["structure_prefix"][:8],
        "learned_structure_suffix": mutation_profile["structure_suffix"][:8],
        "top_tokens": top_tokens[:12],
    })

    logger.info(
        "light_mutation_candidates input_seeds:{} selected_seeds:{} skipped_edge:{} "
        "skipped_known:{} labels:{} tokens:{} direct_seeds:{} variant_seed_coverage:{} "
        "candidates:{} family_quotas:{} family_counts:{} learned_concat_prefix:{} "
        "learned_concat_suffix:{} learned_structure_prefix:{} "
        "learned_structure_suffix:{} top_tokens:{}".format(
            len(set(domain_values)), len(seed_domains), skipped_edge, skipped_known,
            len(label_counter), len(token_counter), direct_seed_count,
            len(variant_seed_names), len(candidates), quotas, family_counts,
            mutation_profile["concat_prefix"][:8],
            mutation_profile["concat_suffix"][:8],
            mutation_profile["structure_prefix"][:8],
            mutation_profile["structure_suffix"][:8],
            top_tokens[:12],
        ))
    return candidates


def recursive_brute_candidates(
        base_domain, domains, word_file=None, delegated_parents=None):
    base_domain = str(base_domain or "").strip().lower().strip(".")
    if not base_domain or not getattr(Config, "RECURSIVE_BRUTE_ENABLE", True):
        return []

    parent_limit = max(int(getattr(Config, "RECURSIVE_BRUTE_PARENT_LIMIT", 8) or 0), 0)
    word_limit = max(int(getattr(Config, "RECURSIVE_BRUTE_WORD_LIMIT", 200) or 0), 0)
    candidate_limit = max(int(getattr(Config, "RECURSIVE_BRUTE_LIMIT", 1200) or 0), 0)
    min_children = max(int(getattr(Config, "RECURSIVE_BRUTE_MIN_CHILDREN", 2) or 1), 1)
    if not parent_limit or not word_limit or not candidate_limit:
        return []

    known_domains = set()
    parent_children = {}
    direct_parents = set()
    observed_direct_parents = set()
    delegated_parents = {
        str(value or "").strip().lower().strip(".")
        for value in (delegated_parents or [])
        if str(value or "").strip()
    }
    skipped_edge = 0
    for raw_domain in domains or []:
        domain = str(raw_domain or "").strip().lower().strip(".")
        labels = _domain_labels(base_domain, domain)
        if not labels:
            continue
        known_domains.add(domain)
        if _is_edge_seed_domain(domain, base_domain):
            skipped_edge += 1
            continue

        if len(labels) == 1:
            observed_direct_parents.add(domain)
            if labels[0] in RECURSIVE_PARENT_LABELS:
                direct_parents.add(domain)

        if len(labels) < 2:
            continue
        parent_labels = labels[1:]
        if any(label in RECURSIVE_PARENT_SKIP_LABELS or _is_random_label(label)
               for label in parent_labels):
            continue
        parent = "{}.{}".format(".".join(parent_labels), base_domain)
        parent_children.setdefault(parent, set()).add(labels[0])

    scored_parents = []
    all_parents = set(parent_children) | direct_parents | delegated_parents
    for parent in all_parents:
        labels = _domain_labels(base_domain, parent)
        if not labels or len(labels) > 2:
            continue
        if _is_edge_seed_domain(parent, base_domain):
            continue
        child_count = len(parent_children.get(parent, set()))
        direct_score = 20 if (
            child_count and parent in observed_direct_parents) else 0
        high_value_score = 30 if labels[0] in RECURSIVE_PARENT_LABELS else 0
        delegated_score = 60 if parent in delegated_parents else 0
        if (child_count < min_children and not direct_score
                and not high_value_score and not delegated_score):
            continue
        scored_parents.append((
            child_count * 10 + direct_score + high_value_score + delegated_score,
            parent,
        ))

    scored_parents.sort(key=lambda item: (-item[0], item[1]))
    selected_parents = [parent for _, parent in scored_parents[:parent_limit]]
    if not selected_parents:
        logger.info("recursive_brute_candidates no promising parent {}".format(base_domain))
        return []

    word_file = word_file or Config.altdns_dict_path
    words = []
    seen_words = set()
    try:
        raw_words = utils.load_file(word_file)
    except Exception as e:
        logger.warning("recursive brute dictionary load failed {}: {}".format(word_file, e))
        return []
    for raw_word in raw_words:
        word = _clean_label(str(raw_word or "").strip())
        if not word or word in seen_words or word in RECURSIVE_PARENT_SKIP_LABELS:
            continue
        seen_words.add(word)
        words.append(word)
        if len(words) >= word_limit:
            break

    candidates = []
    seen_candidates = set()
    child_frequency = Counter()
    for children in parent_children.values():
        for child in children:
            if (child not in RECURSIVE_PARENT_SKIP_LABELS
                    and not _is_random_label(child)):
                child_frequency[child] += 1
    mirrored_words = [value for value, _ in sorted(
        child_frequency.items(), key=lambda item: (-item[1], item[0]))]
    parent_words = {}
    parent_mirrored_words = {}
    for parent in selected_parents:
        own_children = parent_children.get(parent, set())
        transferable = [
            word for word in mirrored_words if word not in own_children
        ]
        parent_mirrored_words[parent] = set(transferable)
        parent_words[parent] = _ordered_unique(transferable + words)

    mirrored_candidate_count = 0
    max_parent_words = max(
        [len(parent_words[parent]) for parent in selected_parents] or [0])
    for word_index in range(max_parent_words):
        for parent in selected_parents:
            values = parent_words[parent]
            if word_index >= len(values):
                continue
            word = values[word_index]
            candidate = "{}.{}".format(word, parent)
            if candidate in known_domains or candidate in seen_candidates:
                continue
            if utils.check_domain_black(candidate):
                continue
            seen_candidates.add(candidate)
            candidates.append(candidate)
            if word in parent_mirrored_words[parent]:
                mirrored_candidate_count += 1
            if len(candidates) >= candidate_limit:
                break
        if len(candidates) >= candidate_limit:
            break

    logger.info(
        "recursive_brute_candidates parents:{} words:{} mirrored_words:{} "
        "mirrored_candidates:{} candidates:{} skipped_edge:{} selected:{}".format(
            len(all_parents), len(words), len(mirrored_words),
            mirrored_candidate_count, len(candidates), skipped_edge,
            selected_parents))
    return candidates


def resolve_candidates_plus(
        base_domain, domains, puredns_timeout=3 * 60,
        dnsx_timeout=3 * 60, meta=None, candidate_families=None):
    if meta is None:
        meta = {}
    meta.update({
        "candidate_count": len(domains),
        "puredns_status": "pending",
        "dnsx_status": "pending",
        "fallback_used": False,
        "resolver_engine": "puredns_wildcard+dnsx_trusted",
        "puredns_validation_engine": "dnsx",
    })
    meta.update(DNSX_METRIC_DEFAULTS)
    runner = DomainBrutePlus(base_domain=base_domain, word_file="")
    runner._check_tools(required=("puredns", "dnsx", "massdns"))
    try:
        runner._write_candidates(domains)
        runner.candidate_families = {
            str(domain or "").strip().lower().strip("."): str(family or "unknown")
            for domain, family in (candidate_families or {}).items()
            if str(domain or "").strip()
        }
        dnsx_input_path = None
        dnsx_output_path = None
        try:
            runner._run_puredns(
                timeout=puredns_timeout,
                skip_validation=True,
            )
        except DomainBrutePlusError as e:
            error_text = str(e)
            meta.update({
                "puredns_status": "timeout" if "timeout" in error_text.lower() else "failed",
                "puredns_error": error_text,
                "fallback_used": True,
                "fallback_reason": "puredns_timeout" if "timeout" in error_text.lower() else "puredns_failed",
                "resolver_engine": "dnsx_candidates",
            })
            logger.warning("resolve_candidates_plus puredns failed on {}, fallback dnsx candidates: {}".format(
                base_domain, e))
            dnsx_input_path = runner.candidates_path
            dnsx_output_path = runner.dnsx_path

        if meta["puredns_status"] == "pending":
            if runner._has_non_empty_lines(runner.puredns_path):
                meta["puredns_status"] = "done"
            else:
                meta.update({
                    "puredns_status": "no_resolved_records",
                    "fallback_used": True,
                    "fallback_reason": "puredns_no_resolved_records",
                    "resolver_engine": "dnsx_candidates",
                })
                logger.warning(
                    "resolve_candidates_plus puredns returned no resolved records on {}, "
                    "fallback dnsx candidates".format(base_domain))
                dnsx_input_path = runner.candidates_path
                dnsx_output_path = runner.dnsx_path

        actual_dnsx_input_path = dnsx_input_path or runner.puredns_path
        meta["dnsx_submitted_count"] = runner._count_non_empty_lines(
            actual_dnsx_input_path)
        try:
            runner._run_dnsx(
                timeout=dnsx_timeout,
                input_path=dnsx_input_path,
                output_path=dnsx_output_path,
            )
            meta["dnsx_status"] = "done"
        except DomainBrutePlusError as e:
            error_text = str(e)
            meta.update({
                "dnsx_status": "timeout" if "timeout" in error_text.lower() else "failed",
                "dnsx_error": error_text,
            })
            raise
        output = runner._parse_dnsx(meta=meta)
        meta["resolved_candidate_count"] = len({
            item.get("domain") for item in output if item.get("domain")
        })
        logger.info(
            "resolve_candidates_plus result records:{} domains:{} dnsx_submitted:{} "
            "dnsx_responses:{} noerror:{} nxdomain:{} servfail:{} "
            "a_hits:{} cname_hits:{}".format(
                len(output), meta["resolved_candidate_count"],
                meta["dnsx_submitted_count"], meta["dnsx_response_count"],
                meta["dnsx_noerror_count"], meta["dnsx_nxdomain_count"],
                meta["dnsx_servfail_count"], meta["dnsx_a_hit_count"],
                meta["dnsx_cname_hit_count"],
            ))
        return output
    finally:
        runner._cleanup()


def resolve_candidates_dnsx_plus(
        base_domain, domains, dnsx_timeout=60, meta=None,
        candidate_families=None):
    if meta is None:
        meta = {}
    meta.update({
        "candidate_count": len(domains),
        "dnsx_status": "pending",
        "resolver_engine": "dnsx_candidates",
        "fallback_used": False,
    })
    meta.update(DNSX_METRIC_DEFAULTS)
    runner = DomainBrutePlus(base_domain=base_domain, word_file="")
    runner._check_tools(required=("dnsx",))
    try:
        runner._write_candidates(domains)
        runner.candidate_families = {
            str(domain or "").strip().lower().strip("."): str(family or "unknown")
            for domain, family in (candidate_families or {}).items()
            if str(domain or "").strip()
        }
        meta["dnsx_submitted_count"] = runner._count_non_empty_lines(
            runner.candidates_path)
        try:
            runner._run_dnsx(
                timeout=dnsx_timeout,
                input_path=runner.candidates_path,
                output_path=runner.dnsx_path,
            )
        except DomainBrutePlusError as e:
            error_text = str(e)
            meta.update({
                "dnsx_status": "timeout" if "timeout" in error_text.lower() else "failed",
                "dnsx_error": error_text,
            })
            raise
        output = runner._parse_dnsx(meta=meta)
        meta["dnsx_status"] = "done"
        meta["resolved_candidate_count"] = len({
            item.get("domain") for item in output if item.get("domain")
        })
        logger.info("resolve_candidates_dnsx_plus result records:{} domains:{}".format(
            len(output), meta["resolved_candidate_count"]))
        return output
    finally:
        runner._cleanup()
