import os
import re
import shutil
import subprocess
import tempfile
import threading
import time

from app import utils
from app.config import Config
from .baseThread import BaseThread


logger = utils.get_logger()


class SiteScreenshot(BaseThread):
    def __init__(self, sites, concurrency=3, capture_dir="./"):
        configured_concurrency = max(int(getattr(
            Config, "SCREENSHOT_CONCURRENCY", 2) or 2), 1)
        super().__init__(
            sites,
            concurrency=max(1, min(int(concurrency or 1), configured_concurrency)),
        )
        self.capture_dir = capture_dir
        self.screenshot_map = {}
        self.failure_map = {}
        self._result_lock = threading.Lock()
        os.makedirs(self.capture_dir, 0o777, True)

    def _record_failure(self, site, reason):
        with self._result_lock:
            self.failure_map[site] = str(reason or "screenshot_failed")[:500]

    def work(self, site):
        chrome_path = str(getattr(Config, "KATANA_CHROME_PATH", "") or "").strip()
        if not chrome_path or not os.path.isfile(chrome_path):
            self._record_failure(site, "chromium_not_found")
            return

        file_name = os.path.join(
            self.capture_dir, "{}.png".format(self.gen_filename(site)))
        profile_dir = tempfile.mkdtemp(prefix="arl-screenshot-")
        timeout = max(int(getattr(Config, "SCREENSHOT_TIMEOUT", 45) or 45), 5)
        cmd_parameters = [
            chrome_path,
            "--headless=new",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--disable-extensions",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-default-apps",
            "--disable-sync",
            "--hide-scrollbars",
            "--ignore-certificate-errors",
            "--window-size=1440,900",
            "--virtual-time-budget=10000",
            "--user-data-dir={}".format(profile_dir),
            "--screenshot={}".format(file_name),
            site,
        ]
        logger.debug("screenshot {}".format(site))
        try:
            result = subprocess.run(
                cmd_parameters,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
            if (
                result.returncode != 0 or
                not os.path.isfile(file_name) or
                os.path.getsize(file_name) <= 0
            ):
                stderr = result.stderr.decode("utf-8", errors="replace").strip()
                reason = "chromium_exit_{}".format(result.returncode)
                if stderr:
                    reason = "{}: {}".format(reason, stderr[-300:])
                self._record_failure(site, reason)
                try:
                    os.remove(file_name)
                except OSError:
                    pass
                return
            with self._result_lock:
                self.screenshot_map[site] = file_name
        except subprocess.TimeoutExpired:
            self._record_failure(site, "chromium_timeout_{}s".format(timeout))
        except OSError as exc:
            self._record_failure(site, exc)
        finally:
            shutil.rmtree(profile_dir, ignore_errors=True)

    def gen_filename(self, site):
        filename = site.replace("://", "_")
        return re.sub(r"[^\w\-_. ]", "_", filename)

    def run(self):
        started_at = time.time()
        logger.info("start screenshot targets:{} concurrency:{}".format(
            len(self.targets), self.concurrency))
        self._run()
        elapsed = time.time() - started_at
        logger.info(
            "end screenshot success:{} failed:{} elapsed:{:.2f}".format(
                len(self.screenshot_map), len(self.failure_map), elapsed))
        return {
            "input_count": len(self.targets),
            "output_count": len(self.screenshot_map),
            "failed_count": len(self.failure_map),
            "failed_sites": sorted(self.failure_map)[:20],
            "elapsed": elapsed,
        }


def site_screenshot(sites, concurrency=3, capture_dir="./"):
    screenshot = SiteScreenshot(
        sites,
        concurrency=concurrency,
        capture_dir=capture_dir,
    )
    return screenshot.run()
