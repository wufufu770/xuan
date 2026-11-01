import hashlib
import os
import random
import re
import time
from datetime import datetime
from urllib.parse import urlparse

from app import utils
from app.config import Config

logger = utils.get_logger()

BING_SEARCH_URL = "https://www.bing.com/search?q={query}&first={first}"
BING_BASE_URL = "https://www.bing.com"

CHECKPOINT_COLLECTION = "bing_deep_checkpoint"
RESULT_URL_LIMIT = 50

CAPTCHA_MARKERS = (
    "异常流量", "验证您是真人", "人机验证", "verify you are human",
    "unusual traffic", "captcha", "blocked",
)

URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.I)


class BingBlocked(Exception):
    """Bing 风控命中：验证码/封锁，需要冷却 profile。"""


class BingDeepSearch(object):
    def __init__(self, task_id, root_domain, max_pages=None, path_urls=None):
        self.task_id = str(task_id)
        self.root_domain = str(root_domain or "").strip(".").lower()
        self.max_pages = max_pages or int(
            getattr(Config, "BING_MAX_PAGES", 10) or 10)
        self.path_keyword_queries = list(
            getattr(Config, "BING_PATH_QUERIES", []) or [])
        self.delay_min = float(getattr(Config, "BING_DELAY_MIN", 3) or 3)
        self.delay_max = float(getattr(Config, "BING_DELAY_MAX", 9) or 9)
        self.daily_query_limit = int(
            getattr(Config, "BING_DAILY_QUERY_LIMIT", 40) or 40)
        self.cooldown_seconds = int(
            getattr(Config, "BING_COOLDOWN_SECONDS", 1800) or 1800)
        self.max_path_urls = int(
            getattr(Config, "BING_MAX_PATH_URLS", 300) or 300)

        self.proxy_pool = [
            str(item).strip() for item in
            (getattr(Config, "BING_PROXY_POOL", []) or [])
            if str(item).strip()
        ]
        self.proxy_attempt = 0

        self.discovered_domains = set()
        self.path_records = {}
        self.captcha_hit_count = 0
        self.query_count = 0
        self.profile_dir = os.path.join(
            str(getattr(Config, "BING_PROFILE_DIR", "/opt/ARL/data/bing_profiles")
                or "/opt/ARL/data/bing_profiles"),
            re.sub(r"[^a-z0-9.\-]", "_", self.root_domain),
        )

    # ---------- checkpoint ----------

    def _checkpoint_query(self):
        return "site:{}".format(self.root_domain)

    def load_checkpoint(self):
        doc = utils.conn_db(CHECKPOINT_COLLECTION).find_one({
            "task_id": self.task_id,
            "root_domain": self.root_domain,
        })
        return doc or {}

    def save_checkpoint(self, completed_page, query_states=None):
        now = utils.curr_date()
        update = {
            "$set": {
                "task_id": self.task_id,
                "root_domain": self.root_domain,
                "completed_page": int(completed_page),
                "query_states": query_states or {},
                "updated_at": now,
            },
        }
        utils.conn_db(CHECKPOINT_COLLECTION).update_one(
            {"task_id": self.task_id, "root_domain": self.root_domain},
            update, upsert=True)

    def _daily_quota_doc(self):
        today = datetime.now().strftime("%Y-%m-%d")
        doc = utils.conn_db(CHECKPOINT_COLLECTION).find_one({
            "task_id": self.task_id,
            "root_domain": self.root_domain,
        }) or {}
        quota = doc.get("daily_quota") or {}
        if quota.get("date") != today:
            return {"date": today, "count": 0}
        return quota

    def _record_query_usage(self, quota):
        quota["count"] = int(quota.get("count") or 0) + 1
        utils.conn_db(CHECKPOINT_COLLECTION).update_one(
            {"task_id": self.task_id, "root_domain": self.root_domain},
            {"$set": {"daily_quota": quota}}, upsert=True)
        return quota

    # ---------- proxy ----------

    def _current_proxy(self):
        if not self.proxy_pool:
            return ""
        index = (self._profile_hash() + self.proxy_attempt) % len(self.proxy_pool)
        return self.proxy_pool[index]

    def _profile_hash(self):
        return int(hashlib.md5(
            self.root_domain.encode("utf-8")).hexdigest(), 16)

    def _rotate_proxy(self, reason):
        if not self.proxy_pool:
            return ""
        self.proxy_attempt += 1
        proxy = self._current_proxy()
        logger.info("bing proxy rotated {} -> attempt:{} reason:{}".format(
            self.root_domain, self.proxy_attempt, reason))
        return proxy

    # ---------- browser ----------

    def _launch_context(self, playwright):
        from playwright.sync_api import Error as PlaywrightError

        chrome_path = str(getattr(Config, "KATANA_CHROME_PATH", "") or "").strip()
        if not chrome_path or not os.path.isfile(chrome_path):
            raise RuntimeError("chrome binary not found: {}".format(chrome_path))

        os.makedirs(self.profile_dir, 0o755, True)

        proxy = self._current_proxy()
        kwargs = {
            "user_data_dir": self.profile_dir,
            "headless": True,
            "executable_path": chrome_path,
            "args": [
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--disable-blink-features=AutomationControlled",
                "--window-size=1440,900",
                "--lang=zh-CN",
            ],
            "viewport": {"width": 1440, "height": 900},
            "locale": "zh-CN",
            "timezone_id": "Asia/Shanghai",
        }
        if proxy:
            kwargs["proxy"] = {"server": proxy}

        try:
            return playwright.chromium.launch_persistent_context(**kwargs)
        except PlaywrightError as e:
            if proxy and self.proxy_pool:
                # 代理不可用：轮换一个再试
                logger.warning("bing proxy launch failed, rotating: {}".format(
                    str(e)[:200]))
                proxy = self._rotate_proxy("launch_failed")
                kwargs["proxy"] = {"server": proxy}
                return playwright.chromium.launch_persistent_context(**kwargs)
            raise

    @staticmethod
    def _human_pause(page, extra=0.0):
        delay = random.uniform(0.8, 2.2) + extra
        page.wait_for_timeout(int(delay * 1000))

    @staticmethod
    def _human_scroll(page):
        for _ in range(random.randint(2, 4)):
            page.mouse.wheel(0, random.randint(300, 900))
            page.wait_for_timeout(random.randint(300, 900))

    @staticmethod
    def _assert_not_blocked(page):
        try:
            content = page.content()[:20000].lower()
        except Exception:
            return
        for marker in CAPTCHA_MARKERS:
            if marker in content:
                raise BingBlocked(marker)

    def _sleep_between_pages(self):
        time.sleep(random.uniform(self.delay_min, self.delay_max))

    # ---------- extraction ----------

    def _extract_result_urls(self, page):
        urls = []
        try:
            anchors = page.query_selector_all("a[href]")
            for anchor in anchors:
                href = (anchor.get_attribute("href") or "").strip()
                if href.startswith(("http://", "https://")):
                    urls.append(href)
                if len(urls) >= RESULT_URL_LIMIT * 2:
                    break
        except Exception as e:
            logger.debug("bing anchor extract failed: {}".format(e))
        return urls

    def _collect_domain(self, url):
        try:
            host = (urlparse(url).hostname or "").strip(".").lower()
        except ValueError:
            return
        if not host:
            return
        if host == self.root_domain or host.endswith("." + self.root_domain):
            self.discovered_domains.add(host)

    def _collect_path(self, url):
        try:
            parsed = urlparse(url)
        except ValueError:
            return
        host = (parsed.hostname or "").strip(".").lower()
        if not host or not (
                host == self.root_domain or host.endswith("." + self.root_domain)):
            return
        path = parsed.path or "/"
        if path in ("/", ""):
            return
        if re.search(r"\.(jpg|jpeg|png|gif|css|ico|svg|js|woff2?)(\?|$)",
                     path, re.I):
            return
        dedupe_key = host + path
        if dedupe_key in self.path_records:
            return
        if len(self.path_records) >= self.max_path_urls:
            return
        self.path_records[dedupe_key] = {
            "host": host,
            "path": path,
            "url": url,
        }

    # ---------- main ----------

    def _search_http(self, query, first=1):
        """HTTP 直连抓取 Bing 结果页（无浏览器），返回结果 URL 列表。"""
        import requests

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Referer": "https://cn.bing.com/",
        }
        proxies = None
        if self.proxy_pool:
            proxy = self.proxy_pool[self.proxy_attempt % len(self.proxy_pool)]
            proxies = {"http": proxy, "https": proxy}
        resp = requests.get(
            "https://cn.bing.com/search",
            params={"q": query, "first": first, "count": 10},
            headers=headers, proxies=proxies, timeout=20)
        if resp.status_code != 200:
            self.proxy_attempt += 1
            raise BingBlocked("http status {}".format(resp.status_code))
        html = resp.text
        if re.search(r"(captcha|人机验证|异常流量|verify you are)", html, re.I):
            self.proxy_attempt += 1
            raise BingBlocked("bing captcha detected (http mode)")
        urls = re.findall(
            r'<li class="b_algo".*?<h2>\s*<a[^>]+href="(https?://[^"]+)"', html, re.S)
        if not urls:
            urls = re.findall(r'<h2>\s*<a[^>]+href="(https?://[^"]+)"', html)
        return urls

    def _run_http(self):
        """HTTP 模式：无 Playwright，纯 requests + 限速/配额/断点。"""
        checkpoint = self.load_checkpoint()
        quota = self._daily_quota_doc()
        completed_page = int(checkpoint.get("completed_page") or 0)
        query_states = dict(checkpoint.get("query_states") or {})

        summary = {
            "root_domain": self.root_domain,
            "mode": "http",
            "query_count": 0,
            "captcha_hits": 0,
            "completed_pages": 0,
            "resumed_from_page": completed_page,
            "blocked": False,
        }

        # 阶段一：site:根域 子域撒网（断点续跑）
        for page_index in range(completed_page + 1, self.max_pages + 1):
            if quota.get("count", 0) >= self.daily_query_limit:
                summary["daily_limit_reached"] = True
                break
            try:
                urls = self._search_http(self._checkpoint_query(), page_index * 10 + 1)
            except BingBlocked:
                self.captcha_hit_count += 1
                summary["captcha_hits"] += 1
                summary["blocked"] = True
                break
            quota = self._record_query_usage(quota)
            self.query_count += 1
            summary["query_count"] += 1
            before = len(self.discovered_domains)
            for url in urls:
                self._collect_domain(url)
            summary["completed_pages"] = page_index
            self.save_checkpoint(page_index, query_states)
            if len(urls) < 5:
                break
            if len(self.discovered_domains) == before and page_index >= 3:
                break
            self._sleep_between_pages()

        # 阶段二：目录型查询 -> 路径回流
        for keyword in self.path_keyword_queries:
            key = "path:{}".format(keyword)
            if query_states.get(key):
                continue
            if quota.get("count", 0) >= self.daily_query_limit:
                summary["daily_limit_reached"] = True
                break
            try:
                urls = self._search_http(
                    "site:{} {}".format(self.root_domain, keyword), 1)
            except BingBlocked:
                self.captcha_hit_count += 1
                summary["captcha_hits"] += 1
                summary["blocked"] = True
                break
            quota = self._record_query_usage(quota)
            self.query_count += 1
            summary["query_count"] += 1
            for url in urls:
                self._collect_path(url)
            query_states[key] = 1
            self.save_checkpoint(summary.get("completed_pages", 0), query_states)
            self._sleep_between_pages()

        summary["domain_count"] = len(self.discovered_domains)
        summary["path_count"] = len(self.path_records)
        logger.info("bing deep(http) {} done queries:{} domains:{} paths:{} blocked:{}".format(
            self.root_domain, self.query_count, len(self.discovered_domains),
            len(self.path_records), summary.get("blocked")))
        return summary

    def run(self):
        """返回 summary；域名/路径结果由调用方取属性回流。"""
        if not bool(getattr(Config, "BING_ENABLE", False)):
            return {"skipped": True, "reason": "BING.ENABLE is false"}

        if str(getattr(Config, "BING_MODE", "") or "").strip().lower() == "http":
            return self._run_http()

        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return {"error": "playwright 未安装，无法执行 Bing 深度搜索"}

        checkpoint = self.load_checkpoint()
        quota = self._daily_quota_doc()
        completed_page = int(checkpoint.get("completed_page") or 0)
        query_states = dict(checkpoint.get("query_states") or {})

        summary = {
            "root_domain": self.root_domain,
            "query_count": 0,
            "captcha_hits": 0,
            "completed_pages": 0,
            "resumed_from_page": completed_page,
            "blocked": False,
        }

        with sync_playwright() as playwright:
            context = self._launch_context(playwright)
            try:
                page = context.pages[0] if context.pages else context.new_page()
                page.set_default_timeout(20000)

                # 阶段一：site:根域 子域撒网（断点续跑）
                start_page = completed_page + 1
                for page_index in range(start_page, self.max_pages + 1):
                    if quota.get("count", 0) >= self.daily_query_limit:
                        logger.warning("bing daily query limit reached {}".format(
                            self.root_domain))
                        summary["daily_limit_reached"] = True
                        break

                    first_result = page_index * 10 + 1
                    query = self._checkpoint_query()
                    try:
                        urls = self._search(page, query, first_result)
                    except BingBlocked as e:
                        self.captcha_hit_count += 1
                        summary["captcha_hits"] += 1
                        summary["blocked"] = True
                        self._handle_blocked(e)
                        break

                    quota = self._record_query_usage(quota)
                    self.query_count += 1
                    summary["query_count"] += 1

                    before = len(self.discovered_domains)
                    for url in urls:
                        self._collect_domain(url)
                    summary["completed_pages"] = page_index

                    self.save_checkpoint(page_index, query_states)
                    if len(urls) < 5:
                        # 结果页不足，后续页大概率无新结果
                        break
                    if len(self.discovered_domains) == before and page_index >= 3:
                        break
                    self._sleep_between_pages()

                # 阶段二：目录型查询 → 路径回流
                for keyword in self.path_keyword_queries:
                    key = "path:{}".format(keyword)
                    if query_states.get(key):
                        continue
                    if quota.get("count", 0) >= self.daily_query_limit:
                        summary["daily_limit_reached"] = True
                        break

                    query = "site:{} {}".format(self.root_domain, keyword)
                    try:
                        urls = self._search(page, query, 1)
                    except BingBlocked as e:
                        self.captcha_hit_count += 1
                        summary["captcha_hits"] += 1
                        summary["blocked"] = True
                        self._handle_blocked(e)
                        break

                    quota = self._record_query_usage(quota)
                    self.query_count += 1
                    summary["query_count"] += 1

                    for url in urls:
                        self._collect_path(url)
                    query_states[key] = 1
                    self.save_checkpoint(
                        summary.get("completed_pages", 0), query_states)
                    self._sleep_between_pages()
            finally:
                try:
                    context.close()
                except Exception:
                    pass

        summary["domain_count"] = len(self.discovered_domains)
        summary["path_count"] = len(self.path_records)
        logger.info("bing deep {} done queries:{} domains:{} paths:{} blocked:{}".format(
            self.root_domain, self.query_count, len(self.discovered_domains),
            len(self.path_records), summary.get("blocked")))
        return summary

    def _search(self, page, query, first_result):
        url = BING_SEARCH_URL.format(
            query=_url_quote(query), first=first_result)
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=25000)
        except Exception as e:
            # 网络类错误只轮换代理，不当作风控冷却处理
            message = str(e)
            if ("net::ERR" in message or "Timeout" in message) and self.proxy_pool:
                self._rotate_proxy("network_error")
            raise

        self._human_pause(page)
        self._human_scroll(page)
        self._assert_not_blocked(page)
        return self._extract_result_urls(page)

    def _handle_blocked(self, error):
        """风控命中：profile 冷却 + 轮换代理，绝不自动解验证码。"""
        cooldown_until = time.time() + self.cooldown_seconds
        utils.conn_db(CHECKPOINT_COLLECTION).update_one(
            {"task_id": self.task_id, "root_domain": self.root_domain},
            {"$set": {
                "cooldown_until": cooldown_until,
                "cooldown_reason": str(error)[:200],
                "cooldown_at": utils.curr_date(),
            }}, upsert=True)
        self._rotate_proxy("blocked")
        logger.warning("bing blocked {} reason:{} cooldown:{}s".format(
            self.root_domain, error, self.cooldown_seconds))


def _url_quote(value):
    from urllib.parse import quote
    return quote(str(value), safe="")


def check_profile_cooldown(task_id, root_domain):
    doc = utils.conn_db(CHECKPOINT_COLLECTION).find_one({
        "task_id": str(task_id), "root_domain": str(root_domain or "").lower(),
    }, {"_id": 0, "cooldown_until": 1, "cooldown_reason": 1}) or {}
    cooldown_until = float(doc.get("cooldown_until") or 0)
    if cooldown_until > time.time():
        return {
            "cooling": True,
            "remaining_seconds": int(cooldown_until - time.time()),
            "reason": doc.get("cooldown_reason") or "",
        }
    return {"cooling": False}


def save_bing_results(task_id, base_domain, domains, path_records):
    """Bing 结果回流：域名进任务管线，路径进 fileleak(source=bing)。"""
    from app.services.domainSiteUpdate import domain_site_update

    now = utils.curr_date()
    saved_path_count = 0
    if path_records:
        conn = utils.conn_db("fileleak")
        existing = {
            item.get("url")
            for item in conn.find(
                {"task_id": task_id, "scanner": "bing"}, {"_id": 0, "url": 1})
            if item.get("url")
        }
        docs = []
        for record in path_records.values():
            if record["url"] in existing:
                continue
            docs.append({
                "task_id": task_id,
                "site": record["host"],
                "url": record["url"],
                "path": record["path"],
                "title": "",
                "status_code": 0,
                "content_length": 0,
                "content_type": "",
                "scanner": "bing",
                "source": "bing",
                "sources": ["bing"],
                "base_domain": base_domain,
                "save_date": now,
                "update_date": now,
            })
        if docs:
            conn.insert_many(docs)
        saved_path_count = len(docs)

    domain_summary = {}
    alive_domains = [d for d in (domains or []) if d]
    if alive_domains:
        try:
            domain_summary = domain_site_update(
                task_id, alive_domains, "bing", run_file_leak=False) or {}
        except Exception as e:
            logger.warning("bing domain_site_update failed: {}".format(e))

    return saved_path_count, domain_summary
