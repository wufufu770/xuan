"""会话池 REST：账号状态 / 登录态录入 / 探活 / 删除 / 同步 config。

录入两种形态：
- /set_token/  直贴 token 或 cookie 串（推荐，用户实际拿到的东西）
- /import_state/  Playwright storage_state 对象（高级，或由 session_login.py 产出）

登录交互亦可由 scripts/session_login.py（有头浏览器人工登录）完成。
"""

import re

from flask_restx import fields, Namespace

from app import utils
from app.utils import auth
from . import ARLResource
from .engines import CONFIG_PATH
from app.services import session_pool
from app.services.fengniao import token_expire_time as fengniao_token_exp

ns = Namespace('session_pool', description="cookie 会话池（数据源登录态托管）")

logger = utils.get_logger()

# source -> 目标站域名（storage_state 的 cookie domain）
SOURCE_DOMAINS = {
    "fengniao": "www.riskbird.com",
    "aqc": "aiqicha.baidu.com",
    "tyc": "www.tianyancha.com",
    "kc": "www.kuaicha365.com",
}

_COOKIE_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,40}$")


def _ret(data=None, message="success", code=200):
    return {"code": code, "message": message, "data": data or {}}


def parse_token_to_state(source, raw):
    """token 字符串 -> storage_state dict。支持三种形态：

    1) 纯 token 值（JWT 或任意会话值）：存为名为 token 的 cookie
    2) 单个 cookie：token=xxx / sid=yyy
    3) 完整 cookie 串：token=xxx; app-uuid=WEB-...; app-device=WEB

    返回 storage_state dict；输入为空返回 None。
    """
    raw = str(raw or "").strip()
    if not raw:
        return None
    domain = SOURCE_DOMAINS.get(source, "")
    pairs = []
    if ";" in raw:                                   # 形态 3：cookie 串
        for part in raw.split(";"):
            part = part.strip()
            if "=" not in part:
                continue
            name, value = part.split("=", 1)
            pairs.append((name.strip(), value.strip()))
    elif "=" in raw:                                 # 可能是形态 2
        name, value = raw.split("=", 1)
        if _COOKIE_NAME_RE.match(name.strip()):
            pairs.append((name.strip(), value.strip()))
        else:
            pairs = [("token", raw)]                  # 形态 1 的兜底
    else:                                            # 形态 1：纯 token
        pairs = [("token", raw)]
    if not pairs:
        return None
    cookies = [{"name": name, "value": value, "domain": domain, "path": "/"}
               for name, value in pairs if name and value]
    return {"cookies": cookies, "origins": []}


def _state_expires_hint(state):
    """从 storage_state 的 cookie 里解析最大 JWT exp（无则 0）。"""
    expires = 0
    for cookie in (state or {}).get("cookies") or []:
        try:
            expires = max(expires, fengniao_token_exp(cookie.get("value")))
        except Exception:
            continue
    return expires


import_model = ns.model('SessionStateImport', {
    'source': fields.String(required=True, description="数据源（fengniao 等）"),
    'account': fields.String(required=True, description="账号标识"),
    'state': fields.Raw(required=True,
                        description="storage_state 对象，或 token/cookie 字符串"),
})

token_model = ns.model('SessionTokenSet', {
    'source': fields.String(required=True, description="数据源（fengniao 等）"),
    'account': fields.String(required=True, description="账号标识"),
    'token': fields.String(required=True,
                           description="token 值 / cookie 串 / token=xxx"),
})

account_model = ns.model('SessionAccount', {
    'source': fields.String(required=True, description="数据源"),
    'account': fields.String(required=True, description="账号标识"),
})


@ns.route('/import_state/')
class SessionImport(ARLResource):
    @auth
    @ns.expect(import_model)
    def post(self):
        """导入 storage_state（对象）或 token/cookie 串（字符串，自动封装）"""
        args = self.parse_args(import_model)
        source = str(args.get("source") or "").strip()
        account = str(args.get("account") or "").strip()
        state = args.get("state")
        if not source or not account or not state:
            return _ret({"error": "参数缺失"}, message="参数缺失", code=400)

        if isinstance(state, str):
            state = parse_token_to_state(source, state)
            if not state:
                return _ret({"error": "token 解析为空"}, message="token 解析为空", code=400)
        if not isinstance(state, dict):
            return _ret({"error": "state 需为对象或字符串"},
                        message="参数格式错误", code=400)

        expires_hint = _state_expires_hint(state)

        session_pool.save_state(source, account, state, expires_hint=expires_hint)
        ok, detail = session_pool.run_health_check(source, account)

        synced = False
        if source == "fengniao":
            try:
                synced = session_pool.sync_fengniao_to_config(CONFIG_PATH, account=account)
            except Exception as exc:
                logger.warning("session_pool sync config failed: %s", exc)

        from app.utils.audit import audit
        audit("session_pool_import", detail={"source": source, "account": account,
                                             "health": detail, "config_synced": synced})
        return _ret({"health": detail, "ok": ok, "config_synced": synced},
                    message="登录态已入池" if ok else "已入池但探活未通过")


@ns.route('/set_token/')
class SessionSetToken(ARLResource):
    @auth
    @ns.expect(token_model)
    def post(self):
        """直贴 token / cookie 串入池（推荐路径）：解析→入池→探活→凤鸟同步 config"""
        args = self.parse_args(token_model)
        source = str(args.get("source") or "").strip()
        account = str(args.get("account") or "").strip()
        raw_token = args.get("token")
        if not source or not account or not str(raw_token or "").strip():
            return _ret({"error": "source/account/token 不能为空"},
                        message="参数缺失", code=400)

        state = parse_token_to_state(source, raw_token)
        if not state:
            return _ret({"error": "token 解析为空"}, message="token 解析为空", code=400)

        expires_hint = _state_expires_hint(state)
        session_pool.save_state(source, account, state, expires_hint=expires_hint)
        ok, detail = session_pool.run_health_check(source, account)

        synced = False
        if source == "fengniao":
            try:
                synced = session_pool.sync_fengniao_to_config(CONFIG_PATH, account=account)
            except Exception as exc:
                logger.warning("session_pool sync config failed: %s", exc)

        from app.utils.audit import audit
        audit("session_pool_set_token",
              detail={"source": source, "account": account,
                      "health": detail, "config_synced": synced})
        return _ret({"ok": ok, "detail": detail, "config_synced": synced,
                     "expires_hint": expires_hint,
                     "cookie_names": [c.get("name") for c in state["cookies"]]},
                    message="登录态已入池" if ok else "已入池但探活未通过")


@ns.route('/probe/')
class SessionProbe(ARLResource):
    @auth
    @ns.expect(account_model)
    def post(self):
        """一键探活：返回 {ok, detail, status, expires_hint}"""
        args = self.parse_args(account_model)
        source = str(args.get("source") or "").strip()
        account = str(args.get("account") or "").strip()
        if not source or not account:
            return _ret({"error": "source/account 不能为空"},
                        message="参数缺失", code=400)
        doc = session_pool.load_doc(source, account)
        if not doc:
            return _ret({"error": "账号不存在"}, message="未找到", code=404)

        ok, detail = session_pool.run_health_check(source, account)
        doc = session_pool.load_doc(source, account) or {}
        return _ret({"ok": ok, "detail": detail,
                     "status": doc.get("status"),
                     "expires_hint": doc.get("expires_hint") or 0})


@ns.route('/accounts/')
class SessionAccounts(ARLResource):
    @auth
    def get(self):
        """账号池状态列表"""
        return _ret({"accounts": session_pool.pool_status()})

    @auth
    @ns.expect(account_model)
    def post(self):
        """登记账号（探活前状态 unknown，等登录后 import_state）"""
        args = self.parse_args(account_model)
        source = str(args.get("source") or "").strip()
        account = str(args.get("account") or "").strip()
        if not source or not account:
            return _ret({"error": "source/account 不能为空"}, message="参数缺失", code=400)
        session_pool.save_state(source, account, {"cookies": [], "origins": []})
        session_pool.run_health_check(source, account)
        return _ret({"source": source, "account": account}, message="账号已登记")

    @auth
    @ns.expect(account_model)
    def delete(self):
        """删除账号（保留浏览器 profile，仅移除池内记录）"""
        args = self.parse_args(account_model)
        source = str(args.get("source") or "").strip()
        account = str(args.get("account") or "").strip()
        if not source or not account:
            return _ret({"error": "source/account 不能为空"}, message="参数缺失", code=400)
        result = utils.conn_db(session_pool.STATE_COLLECTION).delete_one(
            {"source": source, "account": account})
        from app.utils.audit import audit
        audit("session_pool_delete", detail={"source": source, "account": account})
        if not result.deleted_count:
            return _ret({"error": "账号不存在"}, message="未找到", code=404)
        return _ret({"source": source, "account": account}, message="已删除")


# ------------------------------------------------- 窗口登录（M3 网关） ----

window_model = ns.model('SessionWindow', {
    'source': fields.String(required=True, description="数据源"),
    'account': fields.String(required=True, description="账号名"),
    'login_url': fields.String(required=False, description="登录页地址（缺省按源映射）"),
})


@ns.route('/window/')
class SessionPoolWindow(ARLResource):

    @auth
    @ns.expect(window_model)
    def post(self):
        """打开窗口登录会话（noVNC iframe 直连 websockify 端口）"""
        args = self.parse_args(window_model)
        source = str(args.get("source") or "").strip()
        account = str(args.get("account") or "").strip()
        if not source or not account:
            return _ret({"error": "source/account 不能为空"}, message="参数缺失", code=400)
        try:
            from app.services import session_window
            info = session_window.open_window(source, account,
                                              login_url=args.get("login_url"))
        except session_pool.SessionBusy as exc:
            return _ret({"error": str(exc)}, message="会话被占用", code=409)
        except Exception as exc:
            return _ret({"error": str(exc)}, message="窗口打开失败", code=500)
        from app.utils.audit import audit
        audit("session_window_open", detail={"source": source, "account": account})
        return _ret(info, message="窗口已打开")


@ns.route('/capture/')
class SessionPoolCapture(ARLResource):

    @auth
    @ns.expect(window_model)
    def post(self):
        """从打开的窗口抓取 storage_state → 入池 → 探活"""
        args = self.parse_args(window_model)
        source = str(args.get("source") or "").strip()
        account = str(args.get("account") or "").strip()
        if not source or not account:
            return _ret({"error": "source/account 不能为空"}, message="参数缺失", code=400)
        from app.services import session_window
        state = session_window.capture_window(source, account)
        if state is None:
            return _ret({"error": "该账号没有打开中的窗口"}, message="未找到窗口", code=404)
        session_pool.save_state(source, account, state)
        ok, detail = session_pool.run_health_check(source, account)
        from app.utils.audit import audit
        audit("session_window_capture", detail={"source": source, "account": account, "ok": ok})
        return _ret({"source": source, "account": account, "ok": ok,
                     "detail": detail,
                     "cookie_names": sorted(c.get("name", "")
                                            for c in state.get("cookies") or [])},
                    message="已抓取并探活" if ok else "已抓取，探活未通过")


@ns.route('/window/close/')
class SessionPoolWindowClose(ARLResource):

    @auth
    @ns.expect(window_model)
    def post(self):
        """关闭窗口登录会话（profile 保留在盘）"""
        args = self.parse_args(window_model)
        source = str(args.get("source") or "").strip()
        account = str(args.get("account") or "").strip()
        if not source or not account:
            return _ret({"error": "source/account 不能为空"}, message="参数缺失", code=400)
        from app.services import session_window
        closed = session_window.close_window(source, account)
        return _ret({"source": source, "account": account, "closed": closed},
                    message="已关闭" if closed else "该账号没有打开中的窗口")


@ns.route('/window/status/')
class SessionPoolWindowStatus(ARLResource):

    @auth
    def get(self):
        """当前打开中的窗口列表"""
        from app.services import session_window
        return _ret({"items": session_window.window_status()})
