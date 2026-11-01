from typing import List
import subprocess
from app import utils
from app.config import Config
import os
import json
import signal
import shutil
import tempfile
import time
from app.modules import WihRecord
from app.services.baseUpdateTask import BaseUpdateTask

logger = utils.get_logger()


class WihResult(list):
    def __init__(self, values=None, meta=None):
        super().__init__(values or [])
        self.meta = dict(meta or {})


class InfoHunter(object):
    # 从JS中收集，子域名，AK SK 等信息
    def __init__(self, sites: list, task_id=""):
        self.sites = set(sites)
        self.task_id = task_id or ""
        self.base_update_task = BaseUpdateTask(self.task_id) if self.task_id else None
        self.meta = {}

        tmp_path = Config.TMP_PATH
        rand_str = utils.random_choices()

        # wih 目标文件
        self.wih_target_path = os.path.join(tmp_path, "wih_target_{}.txt".format(rand_str))

        # wih 结果文件
        self.wih_result_path = os.path.join(tmp_path, "wih_result_{}.json".format(rand_str))

        self.wih_bin_path = "wih"

    def _get_target_file(self):
        with open(self.wih_target_path, "w", encoding="utf-8") as f:
            for site in sorted(self.sites):
                f.write(site + "\n")

    def _delete_file(self):
        for path in (self.wih_target_path, self.wih_result_path):
            try:
                if os.path.exists(path):
                    os.unlink(path)
            except OSError as e:
                logger.warning(e)

    def _task_stopped(self):
        if not self.base_update_task:
            return False
        try:
            return self.base_update_task.is_terminal()
        except Exception as e:
            logger.warning("wih task status check failed: {}".format(e))
            return False

    @staticmethod
    def _terminate_process(proc):
        if proc.poll() is not None:
            return
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                return
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                logger.warning("wih child did not exit after SIGKILL pid:{}".format(proc.pid))

    def exec_wih(self):
        command = [
            self.wih_bin_path,
            "-r", Config.WIH_RULE_PATH,
            "-J",
            "-o", self.wih_result_path,
            "--concurrency", "3",
            "--log-level", "zero",
            "--concurrency-per-site", "1",
            "--disable-ak-sk-output",
            "-t", self.wih_target_path,
        ]

        if Config.PROXY_URL:
            command.extend(["--proxy", Config.PROXY_URL])

        logger.info(" ".join(command))
        if self._task_stopped():
            self.meta.update({"error": "wih skipped for terminal task", "stopped": True})
            return False

        timeout = max(int(getattr(Config, "WIH_BATCH_TIMEOUT", 900) or 900), 60)
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as process_log:
            proc = subprocess.Popen(
                command,
                stdout=process_log,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )
            start_time = time.time()
            while proc.poll() is None:
                if self._task_stopped():
                    self._terminate_process(proc)
                    self.meta.update({"error": "wih stopped with terminal task", "stopped": True})
                    break
                if time.time() - start_time > timeout:
                    self._terminate_process(proc)
                    self.meta.update({"error": "wih timeout after {}s".format(timeout), "timeout": True})
                    break
                time.sleep(1)

            if proc.poll() is None:
                self._terminate_process(proc)
            try:
                return_code = proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                return_code = proc.poll()
                self.meta.setdefault("error", "wih child did not exit after termination")
            if return_code is None:
                return_code = -9
            process_log.seek(0)
            output_tail = process_log.read()[-500:].strip()

        self.meta["return_code"] = return_code
        if return_code != 0 and not self.meta.get("error"):
            self.meta["error"] = "wih exit {}: {}".format(return_code, output_tail)
        return return_code == 0

    def check_have_wih(self) -> bool:
        return bool(shutil.which(self.wih_bin_path) or os.path.exists(self.wih_bin_path))

    def dump_result(self) -> list:
        results = []

        # 检查结果文件是否存在
        if not os.path.exists(self.wih_result_path):
            return results

        parse_error_count = 0
        malformed_record_count = 0
        with open(self.wih_result_path, "r", encoding="utf-8") as f:
            while True:
                line = f.readline()
                if not line:
                    break

                try:
                    data = json.loads(line)
                except ValueError:
                    parse_error_count += 1
                    logger.warning("skip malformed wih json line: {}".format(line[:200]))
                    continue
                if not isinstance(data, dict):
                    parse_error_count += 1
                    continue
                site = str(data.get("target") or "").strip()
                records = data.get("records", [])
                if not site or not isinstance(records, list):
                    parse_error_count += 1
                    continue
                for item in records:
                    if not isinstance(item, dict):
                        malformed_record_count += 1
                        continue
                    record_type = str(item.get("id") or "").strip()
                    content = str(item.get("content") or "").strip()
                    source = str(item.get("source") or "").strip()
                    fnv_hash = item.get("hash")
                    if not record_type or not content or fnv_hash is None:
                        malformed_record_count += 1
                        continue
                    tag = str(item.get("tag") or "").strip()
                    if tag:
                        content = "{} ({})".format(content, tag)

                    record_dict = {
                        "record_type": record_type,
                        "content": content,
                        "source": source,
                        "site": site,
                        "fnv_hash": fnv_hash,
                    }

                    results.append(WihRecord(**record_dict))

        if parse_error_count:
            self.meta["parse_error_count"] = parse_error_count
        if malformed_record_count:
            self.meta["malformed_record_count"] = malformed_record_count
        malformed_count = parse_error_count + malformed_record_count
        if malformed_count and not self.meta.get("error"):
            self.meta["error"] = "wih malformed output items: {}".format(malformed_count)
        return results

    def run(self):
        if not self.check_have_wih():
            logger.warning("not found webInfoHunter binary")
            return WihResult(meta={"error": "webInfoHunter binary not found"})

        results = []
        try:
            self._get_target_file()
            self.exec_wih()
            results = self.dump_result()
        except Exception as e:
            logger.exception(e)
            self.meta["error"] = "wih execution failed: {}".format(e)
        finally:
            self._delete_file()

        return WihResult(results, meta=self.meta)


def run_wih(sites: List[str], task_id="") -> List[WihRecord]:
    logger.info("run webInfoHunter, sites: {}".format(len(sites)))
    hunter = InfoHunter(sites, task_id=task_id)
    results = hunter.run()

    logger.info("webInfoHunter result: {}".format(len(results)))

    return results
