"""会话窗口网关：会话池页内嵌 noVNC 窗口登录 + 静默抓取 + 无头续期。

每个 (source, account) 一个驱动线程：
  Xvfb(display) + x11vnc(rfb) + websockify(noVNC web+ws 同端口)
  + Chromium 有头持久化 profile（session_pool.profile_dir，卷持久化）
抓取/关闭经命令队列发到驱动线程执行（Playwright sync API 线程绑定）；
无头续期（refresher）直接走 session_pool.launch_context（headless），
受租约保护：窗口占用时自动跳过。

noVNC iframe 直连 websockify 端口（compose 暴露 6100-6102），不走 nginx。
"""

import os
import queue
import subprocess
import threading
import time

from app import utils
from app.config import Config
from app.services import session_pool

logger = utils.get_logger()

MAX_WINDOWS = 3
DISPLAY_BASE = 90
VNC_BASE = 5910
WS_BASE = 6100
NOVNC_WEB = "/usr/share/novnc"

LOGIN_URLS = {
    "fengniao": "https://www.riskbird.com/",
    "aqc": "https://aiqicha.baidu.com/",
    "tyc": "https://www.tianyancha.com/",
    "kc": "https://www.qcc.com/",
}

_lock = threading.Lock()
_windows = {}   # (source, account) -> WindowSession


class WindowError(RuntimeError):
    pass


def _proc(cmd):
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)


class WindowSession(threading.Thread):
    """驱动线程：拥有 Playwright 实例与浏览器子进程，串行处理命令。"""

    def __init__(self, source, account, login_url, slot):
        super().__init__(daemon=True, name="session-window-{}-{}".format(source, account))
        self.source, self.account = source, account
        self.login_url = login_url
        self.display = DISPLAY_BASE + slot
        self.vnc_port = VNC_BASE + slot
        self.ws_port = WS_BASE + slot
        self.cmds = queue.Queue()
        self.ready = threading.Event()
        self.error = ""
        self.started_ts = time.time()
        self._procs = []

    # -- 子进程 --
    def _spawn(self):
        self._procs.append(_proc(["Xvfb", ":{}".format(self.display),
                                  "-screen", "0", "1366x900x24", "-nolisten", "tcp"]))
        self._procs.append(_proc(["x11vnc", "-display", ":{}".format(self.display),
                                  "-rfbport", str(self.vnc_port), "-forever",
                                  "-shared", "-nopw", "-quiet"]))
        self._procs.append(_proc(["websockify", "--web", NOVNC_WEB,
                                  str(self.ws_port),
                                  "localhost:{}".format(self.vnc_port)]))

    def _kill_procs(self):
        for p in self._procs:
            try:
                p.terminate()
            except Exception:
                pass
        for p in self._procs:
            try:
                p.wait(timeout=5)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass

    # -- 线程体 --
    def run(self):
        env_display = str(self.display)
        old_display = os.environ.get("DISPLAY")
        os.environ["DISPLAY"] = ":" + env_display
        pw = None
        context = None
        try:
            self._spawn()
            time.sleep(1.2)   # Xvfb 就绪
            from playwright.sync_api import sync_playwright
            pw = sync_playwright().start()
            context = pw.chromium.launch_persistent_context(
                session_pool.profile_dir(self.source, self.account),
                headless=False,
                executable_path=session_pool._chrome_path(),
                args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
                      "--window-size=1360,880", "--start-maximized"],
                viewport=None)
            page = context.pages[0] if context.pages else context.new_page()
            try:
                page.goto(self.login_url, wait_until="domcontentloaded", timeout=30000)
            except Exception as exc:
                logger.warning("window login_url load failed: %s", exc)
            self.ready.set()

            while True:
                try:
                    cmd, payload, resp_q = self.cmds.get(timeout=600)
                except queue.Empty:
                    break   # 10 分钟无指令自动收窗（profile 已持久化）
                if cmd == "capture":
                    state = context.storage_state()
                    resp_q.put(("ok", state))
                elif cmd == "goto":
                    page = context.pages[0] if context.pages else context.new_page()
                    page.goto(payload, wait_until="domcontentloaded", timeout=30000)
                    resp_q.put(("ok", True))
                elif cmd == "close":
                    break
        except Exception as exc:
            self.error = str(exc)
            logger.warning("window session %s:%s failed: %s",
                           self.source, self.account, exc)
            self.ready.set()
        finally:
            try:
                if context:
                    context.close()
            except Exception:
                pass
            try:
                if pw:
                    pw.stop()
            except Exception:
                pass
            self._kill_procs()
            if old_display is not None:
                os.environ["DISPLAY"] = old_display
            session_pool.release_lease(self.source, self.account, "window")

    # -- 对外命令 --
    def capture(self, timeout=30):
        resp_q = queue.Queue()
        self.cmds.put(("capture", None, resp_q))
        try:
            status, state = resp_q.get(timeout=timeout)
        except queue.Empty:
            return None
        return state if status == "ok" else None

    def stop(self):
        self.cmds.put(("close", None, None))
        self.join(timeout=15)


def _login_url(source, override):
    return str(override or "").strip() or LOGIN_URLS.get(source, "about:blank")


def open_window(source, account, login_url=None):
    """打开（或复用）窗口登录会话。返回给前端的 noVNC 信息。"""
    key = (source, account)
    with _lock:
        existing = _windows.get(key)
        if existing and existing.is_alive():
            return {"ws_port": existing.ws_port,
                    "vnc_port": existing.vnc_port,
                    "login_url": existing.login_url,
                    "reused": True}
        if sum(1 for w in _windows.values() if w.is_alive()) >= MAX_WINDOWS:
            raise WindowError("并发窗口已达上限（{}），请先关闭不用的窗口".format(MAX_WINDOWS))
        session_pool.acquire_lease(source, account, "window")
        slot = _free_slot()
        win = WindowSession(source, account, _login_url(source, login_url), slot)
        _windows[key] = win
        win.start()
    if not win.ready.wait(timeout=30):
        _pop(key)
        raise WindowError("窗口启动超时")
    if win.error:
        _pop(key)
        raise WindowError("窗口启动失败: {}".format(win.error))
    return {"ws_port": win.ws_port, "vnc_port": win.vnc_port,
            "login_url": win.login_url, "reused": False}


def _free_slot():
    used = {w.ws_port - WS_BASE for w in _windows.values() if w.is_alive()}
    for slot in range(MAX_WINDOWS):
        if slot not in used:
            return slot
    raise WindowError("无空闲窗口槽位")


def _pop(key):
    with _lock:
        _windows.pop(key, None)


def capture_window(source, account):
    """从打开的窗口抓取 storage_state；窗口未开返回 None。"""
    win = _windows.get((source, account))
    if not win or not win.is_alive():
        return None
    return win.capture()


def close_window(source, account):
    win = _windows.pop((source, account), None)
    if not win:
        return False
    win.stop()
    return True


def window_status():
    alive = []
    for (source, account), win in list(_windows.items()):
        if win.is_alive():
            alive.append({"source": source, "account": account,
                          "ws_port": win.ws_port,
                          "login_url": win.login_url,
                          "started_ts": int(win.started_ts)})
        else:
            _pop((source, account))
    return alive


# --------------------------------------------------- 无头静默续期 ----

def refresh_account(source, account, stay_url=None):
    """无头打开同 profile 访问数据源首页刷新 cookie → 入池 → 探活。

    返回 (ok, detail)；窗口占用（租约冲突）时返回 (None, "busy")。
    """
    try:
        context, handle = session_pool.launch_context(
            source, account, headless=True, owner="refresher")
    except session_pool.SessionBusy as exc:
        return None, "busy: {}".format(exc)
    except Exception as exc:
        return False, "浏览器启动失败: {}".format(exc)

    pw, _source, _account, _owner, owns = handle
    try:
        page = context.pages[0] if context.pages else context.new_page()
        url = stay_url or _login_url(source, None)
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            time.sleep(5)   # 等待站点侧可能的 token 滑续
        except Exception as exc:
            logger.warning("refresh goto %s failed: %s", url, exc)
        state = context.storage_state()
        session_pool.save_state(source, account, state)
        ok, detail = session_pool.run_health_check(source, account)
        return ok, detail
    finally:
        session_pool.close_context(context, handle)


def refresh_all(max_accounts=20):
    """遍历会话池全部账号做静默续期 + 探活（供调度循环周期调用）。

    返回 [{source, account, ok, detail}]；窗口占用跳过（None ok）。
    """
    results = []
    for doc in session_pool.pool_status()[:max_accounts]:
        source, account = doc.get("source"), doc.get("account")
        if not source or not account:
            continue
        try:
            ok, detail = refresh_account(source, account)
            results.append({"source": source, "account": account,
                            "ok": ok, "detail": detail})
        except Exception as exc:
            results.append({"source": source, "account": account,
                            "ok": False, "detail": str(exc)})
    return results
