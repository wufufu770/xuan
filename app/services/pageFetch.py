import time
import threading

from app import utils
from app.config import Config
from app.services.pathDiscovery import (
    browser_request_headers,
    redirect_destination_metadata,
    resolve_redirect_location,
)
from .baseUpdateTask import BaseUpdateTask
from .baseThread import BaseThread

logger = utils.get_logger()

REDIRECT_STATUS_CODES = (301, 302, 303, 307, 308)


def _redirect_chain_item(url, status_code, location="", title="", http_server=""):
    return {
        "url": str(url or ""),
        "status_code": status_code,
        "location": str(location or ""),
        "title": str(title or ""),
        "http_server": str(http_server or ""),
    }


class PageFetch(BaseThread):
    def __init__(self, sites, concurrency=None, batch_size=None, task_id=""):
        self.targets = self._normalize_targets(sites)
        if concurrency is None:
            concurrency = getattr(Config, "PAGE_FETCH_CONCURRENCY", 8)
        super().__init__(self.targets, concurrency=concurrency)
        self.batch_size = max(1, int(batch_size or getattr(Config, "PAGE_FETCH_BATCH_SIZE", 200)))
        self.task_id = task_id
        self.base_update_task = BaseUpdateTask(task_id) if task_id else None
        self.page_map = {}
        self._lock = threading.Lock()

    @staticmethod
    def _normalize_targets(sites):
        ordered = []
        seen = set()
        for site in sites or []:
            site = str(site or "").strip()
            if not site or site in seen:
                continue
            seen.add(site)
            ordered.append(site)
        return ordered

    def work(self, site):
        conn = None
        try:
            conn = utils.http_req(
                site,
                "get",
                timeout=(3, 6),
                stream=True,
                headers=browser_request_headers(),
            )
            body = conn.content
            title = utils.get_title(body).strip()
            item = {
                "title": title,
                "url": site,
                "final_url": str(getattr(conn, "url", "") or site),
                "content_length": len(body),
                "status_code": conn.status_code,
            }
            headers = getattr(conn, "headers", {}) or {}
            location = headers.get("Location", "")
            if conn.status_code in REDIRECT_STATUS_CODES and location:
                item.update(self._resolve_redirect(site, conn.status_code, location, title))
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
        with self._lock:
            self.page_map[site] = item

    @staticmethod
    def _redirect_resolve_config():
        enabled = getattr(
            Config,
            "ENTRY_REDIRECT_RESOLVE_ENABLE",
            getattr(Config, "FFUF_REDIRECT_RESOLVE_ENABLE", True),
        )
        max_hops = getattr(
            Config,
            "ENTRY_REDIRECT_RESOLVE_MAX_HOPS",
            getattr(Config, "FFUF_REDIRECT_RESOLVE_MAX_HOPS", 3),
        )
        timeout = getattr(
            Config,
            "ENTRY_REDIRECT_RESOLVE_TIMEOUT",
            getattr(Config, "FFUF_REDIRECT_RESOLVE_TIMEOUT", 5),
        )
        return bool(enabled), max(int(max_hops or 0), 0), max(int(timeout or 1), 1)

    def _resolve_redirect(self, site, status_code, location, title=""):
        redirect_meta = redirect_destination_metadata(location, site)
        item = {
            "redirect_location": str(location or ""),
            "redirect_url": redirect_meta["redirect_url"],
            "redirect_host": redirect_meta["redirect_host"],
            "redirect_path": redirect_meta["redirect_path"],
            "redirect_type": redirect_meta["redirect_type"],
            "redirect_chain": [
                _redirect_chain_item(site, status_code, location, title)
            ],
            "redirect_hops": 0,
            "redirect_resolved": False,
            "redirect_resolution_error": "",
            "redirect_system": redirect_meta["redirect_host"],
            "final_url": redirect_meta["redirect_url"] or site,
            "final_status_code": None,
            "final_title": "",
            "final_http_server": "",
        }
        if not redirect_meta["redirect_url"]:
            item["redirect_resolution_error"] = "invalid_redirect_location"
            return item

        enabled, max_hops, timeout = self._redirect_resolve_config()
        if not enabled or max_hops <= 0:
            return item

        current_url = redirect_meta["redirect_url"]
        seen = {str(site or "")}
        response = None
        try:
            for _hop in range(max_hops):
                if not current_url or current_url in seen:
                    item["redirect_resolution_error"] = "redirect_loop"
                    break
                seen.add(current_url)
                response = utils.http_req(
                    current_url,
                    "get",
                    timeout=(3, timeout),
                    allow_redirects=False,
                    headers=browser_request_headers(),
                )
                response_headers = getattr(response, "headers", {}) or {}
                next_location = response_headers.get("Location", "")
                final_title = utils.get_title(response.content).strip()
                final_http_server = response_headers.get("Server", "")
                item["redirect_chain"].append(_redirect_chain_item(
                    current_url,
                    response.status_code,
                    next_location,
                    final_title,
                    final_http_server,
                ))
                item["redirect_hops"] = len(item["redirect_chain"]) - 1
                item["final_url"] = current_url
                item["final_status_code"] = response.status_code
                item["final_title"] = final_title
                item["final_http_server"] = final_http_server
                if response.status_code not in REDIRECT_STATUS_CODES or not next_location:
                    item["redirect_resolved"] = True
                    break

                next_url = resolve_redirect_location(next_location, current_url)
                try:
                    response.close()
                except Exception:
                    pass
                response = None
                if not next_url:
                    item["redirect_resolution_error"] = "invalid_redirect_location"
                    break
                current_url = next_url
            else:
                item["redirect_resolution_error"] = "redirect_hop_limit"
        except Exception as exc:
            item["redirect_resolution_error"] = str(exc)[:240]
        finally:
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass

        item["redirect_system"] = (
            item["final_title"]
            or item["final_http_server"]
            or item["redirect_host"]
        )
        return item

    def _batched_targets(self, targets):
        for start in range(0, len(targets), self.batch_size):
            yield targets[start:start + self.batch_size]

    def _should_stop(self):
        if not self.base_update_task:
            return False
        return self.base_update_task.is_terminal()

    def run(self):
        t1 = time.time()
        logger.info("start PageFetch {}".format(len(self.targets)))
        original_targets = list(self.targets)
        for index, batch in enumerate(self._batched_targets(original_targets), start=1):
            if self._should_stop():
                logger.info("stop PageFetch early on terminal task status, task_id:{}".format(self.task_id))
                break
            logger.info("PageFetch batch {}/{} size:{} task_id:{}".format(
                index,
                (len(original_targets) + self.batch_size - 1) // self.batch_size,
                len(batch),
                self.task_id,
            ))
            self.targets = batch
            self._run()
        self.targets = original_targets
        elapse = time.time() - t1
        logger.info("end PageFetch elapse {} result:{}".format(elapse, len(self.page_map)))
        return self.page_map


def page_fetch(sites, concurrency=None, batch_size=None, task_id=""):
    s = PageFetch(sites, concurrency=concurrency, batch_size=batch_size, task_id=task_id)
    return s.run()
