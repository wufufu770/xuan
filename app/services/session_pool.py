"""会话池原型：cookie 会话型数据源（凤鸟等）的登录态托管。

设计对应方案书 5.3-5.4：
- 每个 (source, account) 一个持久化 Chrome profile（user-data-dir），
  Chrome 复用发行包内的 Chrome for Testing（Config.KATANA_CHROME_PATH）
- operator 登录一次 -> storage_state 导出 -> Fernet 加密存 session_account
  集合（密钥派生自 ARL_SESSION_KEY 环境变量，缺省用 ARL_API_KEY）
- 探活：按 source 注册的必需 cookie 名做完整性检查（凤鸟要求 token），
  网络级探活由数据源消费方自行承担
- 消费：resolve_fengniao_token 优先读池，config.yaml 为过渡兼容回退
- 租约：同一浏览器单元（profile）同时只允许一个持有者（Playwright 限制）

原型边界（诚实声明）：
- 登录交互走 scripts/session_login.py 有头浏览器人工登录；
  玄览内嵌 CDP screencast 登录属前端联调范围
- 同 profile 串行使用；分布式部署时租约表需外置（当前进程内）
"""

import base64
import hashlib
import json
import os
import threading
import time

from cryptography.fernet import Fernet, InvalidToken

from app import utils
from app.config import Config

logger = utils.get_logger()

STATE_COLLECTION = "session_account"
REQUIRED_COOKIES = {
    "fengniao": ["token"],
}


# ----------------------------------------------------------- 加密 ----

def _key_material():
    return os.environ.get("ARL_SESSION_KEY") or str(getattr(Config, "API_KEY", "") or "arl-session-pool")


def _fernet():
    digest = hashlib.sha256(_key_material().encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_state(state):
    return _fernet().encrypt(json.dumps(state).encode()).decode()


def decrypt_state(blob):
    try:
        return json.loads(_fernet().decrypt(blob.encode()).decode())
    except InvalidToken:
        raise ValueError("storage_state 解密失败：密钥不匹配（ARL_SESSION_KEY/API_KEY 变更？）")


# ----------------------------------------------------------- 租约 ----

_lease_lock = threading.Lock()
_leases = {}


def acquire_lease(source, account, owner):
    key = (source, account)
    with _lease_lock:
        lease = _leases.get(key)
        if lease and lease["owner"] != owner and time.time() < lease["expires_ts"]:
            raise SessionBusy("{}:{} 正被 {} 占用".format(source, account, lease["owner"]))
        _leases[key] = {"owner": owner, "expires_ts": time.time() + 3600}
        return key


def release_lease(source, account, owner):
    key = (source, account)
    with _lease_lock:
        lease = _leases.get(key)
        if lease and lease["owner"] == owner:
            _leases.pop(key, None)


class SessionBusy(RuntimeError):
    pass


# ------------------------------------------------------ profile ----

def _sanitize(name):
    return "".join(c for c in str(name or "") if c.isalnum() or c in "-_.") or "default"


def pool_root():
    return str(getattr(Config, "SESSION_POOL_ROOT", "") or "/opt/ARL/data/session_pool")


def profile_dir(source, account):
    return os.path.join(pool_root(), _sanitize(source), _sanitize(account))


def _chrome_path():
    return str(getattr(Config, "KATANA_CHROME_PATH", "") or "") or None


def launch_context(source, account, headless=True, owner="pool", playwright=None):
    """启动该账号的持久化浏览器（登录/补登录用）。返回 (context, handle)。

    playwright 可传入外部已启动的实例（同进程嵌套多个同步 Playwright
    实例会互相报 asyncio 冲突）；此时 close_context 不会停止它。
    """
    from playwright.sync_api import sync_playwright

    acquire_lease(source, account, owner)
    profile = profile_dir(source, account)
    os.makedirs(profile, exist_ok=True)
    owns = playwright is None
    pw = playwright or sync_playwright().start()
    try:
        context = pw.chromium.launch_persistent_context(
            profile, headless=headless, executable_path=_chrome_path(),
            args=["--no-sandbox"])
        return context, (pw, source, account, owner, owns)
    except Exception:
        release_lease(source, account, owner)
        if owns:
            pw.stop()
        raise


def close_context(context, handle):
    pw, source, account, owner, owns = handle
    try:
        context.close()
    finally:
        release_lease(source, account, owner)
        if owns:
            pw.stop()


# ---------------------------------------------------- 存取与健康 ----

def save_state(source, account, state, expires_hint=0):
    doc = {
        "source": source, "account": account,
        "state_enc": encrypt_state(state),
        "status": "ok", "last_error": "",
        "cookie_names": sorted(c.get("name", "") for c in state.get("cookies") or []),
        "expires_hint": int(expires_hint or 0),
        "updated_ts": time.time(),
        "updated_date": utils.curr_date(),
        "last_check_ts": 0,
    }
    try:
        utils.conn_db(STATE_COLLECTION).update_one(
            {"source": source, "account": account}, {"$set": doc}, upsert=True)
    except Exception as exc:
        logger.warning("session_pool save_state db failed: %s", exc)
        raise


def load_doc(source, account):
    try:
        return utils.conn_db(STATE_COLLECTION).find_one(
            {"source": source, "account": account})
    except Exception as exc:
        logger.warning("session_pool load db failed: %s", exc)
        return None


def load_state(source, account):
    doc = load_doc(source, account)
    if not doc or not doc.get("state_enc"):
        return None
    return decrypt_state(doc["state_enc"])


def get_cookie(source, account, name):
    """从池中取指定 cookie 值；无记录/DB 不可用返回 None（调用方回退）。"""
    state = load_state(source, account)
    if not state:
        return None
    for cookie in state.get("cookies") or []:
        if cookie.get("name") == name:
            return cookie.get("value")
    return None


def default_health_check(source, state):
    """默认探活：必需 cookie 是否齐全（网络级探活由消费方承担）。"""
    required = REQUIRED_COOKIES.get(source, [])
    names = {c.get("name") for c in state.get("cookies") or []}
    missing = [name for name in required if name not in names]
    if missing:
        return False, "缺少必需 cookie: {}".format(",".join(missing))
    if required:
        return True, "required cookies present"
    if state.get("cookies"):
        return True, "cookies present"
    return False, "storage_state 为空"


def run_health_check(source, account, probe=None):
    """探活并更新状态；返回 (ok, detail)。DB 不可用时不抛异常。"""
    probe = probe or default_health_check
    doc = load_doc(source, account)
    if not doc:
        return False, "pool 中无该账号记录"
    try:
        state = decrypt_state(doc["state_enc"])
        ok, detail = probe(source, state)
    except ValueError as exc:
        ok, detail = False, str(exc)
    except Exception as exc:
        ok, detail = False, "探活异常: {}".format(exc)
    try:
        utils.conn_db(STATE_COLLECTION).update_one(
            {"source": source, "account": account},
            {"$set": {"status": "ok" if ok else "expired",
                      "last_error": "" if ok else detail,
                      "last_check_ts": time.time()}})
    except Exception as exc:
        logger.warning("session_pool health db failed: %s", exc)
    return ok, detail


def pool_status():
    """账号池状态列表（不返回敏感 state 本体与内部 _id）。"""
    try:
        docs = list(utils.conn_db(STATE_COLLECTION).find(
            {}, {"_id": 0, "state_enc": 0}))
    except Exception as exc:
        logger.warning("session_pool status db failed: %s", exc)
        return []
    return docs


# ----------------------------------------------- fengniao 供给 ----

def resolve_fengniao_token():
    """凤鸟 token 供给顺序：会话池（真源）-> config.yaml（过渡兼容）。

    任何池侧异常都回退到 config，绝不影响采集主流程。
    """
    try:
        token = get_cookie("fengniao", "default", "token")
        if token:
            return token
    except Exception as exc:
        logger.warning("session_pool resolve failed: %s", exc)
    return getattr(Config, "FENGNIAR_TOKEN", "") or ""


def sync_fengniao_to_config(config_path, account="default"):
    """把池内 token 同步写回 config.yaml（过渡期双写；池仍为真源）。

    供"重新登录完成"后立即让旧版读取路径生效。返回是否写入。
    """
    token = get_cookie("fengniao", account, "token")
    if not token:
        return False
    from app.utils.yamlconf import locked_update
    with locked_update(config_path) as data:
        data["FENGNIAR_TOKEN"] = token
    return True
