"""会话池端到端自检（本地假站点，全程 127.0.0.1，不访问外部主机）。

验证链路：真实 Chrome 持久化上下文登录捕获 cookie -> storage_state 加密入池
-> 解密取 cookie -> 注入全新上下文复用登录态。

用法：.venv/bin/python scripts/session_e2e_check.py
前提：发行包内 Chrome for Testing（tools/chrome-for-testing）存在。
"""

import http.server
import json
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import Config                    # noqa: E402
from app.services import session_pool            # noqa: E402

SID = "e2e-session-12345"


def _find_chrome():
    explicit = os.environ.get("CHROME_PATH")
    if explicit and os.path.exists(explicit):
        return explicit
    base = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(base)
    for entry in sorted(os.listdir(os.path.join(root, "tools", "chrome-for-testing"))):
        candidate = os.path.join(root, "tools", "chrome-for-testing", entry,
                                 "chrome-linux64", "chrome")
        if os.path.exists(candidate):
            return candidate
    raise SystemExit("未找到包内 Chrome，请设置 CHROME_PATH")


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/login":
            self.send_response(302)
            self.send_header("Set-Cookie", "sid={}; Path=/".format(SID))
            self.send_header("Location", "/whoami")
            self.end_headers()
        elif self.path == "/whoami":
            cookie = self.headers.get("Cookie", "")
            body = json.dumps({"sid": cookie}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args):
        pass


def main():
    chrome = _find_chrome()
    Config.KATANA_CHROME_PATH = chrome
    import tempfile
    Config.SESSION_POOL_ROOT = tempfile.mkdtemp(prefix="e2e-pool-")

    # 本地无 MongoDB：池的存储层替换为内存实现（加密/解密链路不变）
    memory_collections = {}

    def memory_conn(name):
        if name not in memory_collections:
            docs = []

            class Coll:
                def find_one(self, query):
                    for d in docs:
                        if all(d.get(k) == v for k, v in query.items()):
                            return dict(d)
                    return None

                def update_one(self, query, update, upsert=False):
                    set_data = update.get("$set", {})
                    for d in docs:
                        if all(d.get(k) == v for k, v in query.items()):
                            d.update(set_data)
                            return
                    new_doc = dict(query)
                    new_doc.update(set_data)
                    docs.append(new_doc)

            memory_collections[name] = Coll()
        return memory_collections[name]

    session_pool.utils.conn_db = memory_conn

    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:{}".format(port)
    print("[1] 本地假站点: {}".format(base))

    from playwright.sync_api import sync_playwright

    pw = sync_playwright().start()
    try:
        # 阶段一：持久化上下文登录（模拟人工登录后 cookie 落在 profile）
        context, handle = session_pool.launch_context(
            "local-e2e", "main", headless=True, owner="e2e", playwright=pw)
        try:
            page = context.new_page()
            page.goto(base + "/login", wait_until="domcontentloaded")
            page.wait_for_url("**/whoami")
            state = context.storage_state()
        finally:
            session_pool.close_context(context, handle)

        sid_in_state = None
        for cookie in state.get("cookies") or []:
            if cookie.get("name") == "sid":
                sid_in_state = cookie.get("value")
        assert sid_in_state == SID, "storage_state 未捕获登录 cookie"
        print("[2] 登录捕获 OK: sid={} ({})".format(sid_in_state[:12], "..."))

        # 入池 -> 解密取回
        session_pool.save_state("local-e2e", "main", state)
        assert session_pool.get_cookie("local-e2e", "main", "sid") == SID
        ok, detail = session_pool.run_health_check(
            "local-e2e", "main",
            probe=lambda source, state: (bool(state.get("cookies")), "e2e"))
        assert ok, detail
        print("[3] 加密入池/解密/探活 OK")

        # 阶段二：全新无痕上下文注入 storage_state，复用登录态
        fresh = pw.chromium.launch(headless=True,
                                   executable_path=chrome,
                                   args=["--no-sandbox"])
        try:
            injected = fresh.new_context(storage_state=state)
            page2 = injected.new_page()
            page2.goto(base + "/whoami", wait_until="domcontentloaded")
            body = json.loads(page2.content().split("<pre>")[1].split("</pre>")[0])
            assert SID in body.get("sid", ""), "注入后 cookie 未生效: {}".format(body)
            print("[4] 注入复用 OK: 新上下文携带登录 cookie")
        finally:
            fresh.close()
    finally:
        pw.stop()

    server.shutdown()
    print("E2E_OK: 捕获->加密入池->解密->注入复用 全链路通过")


if __name__ == "__main__":
    main()
