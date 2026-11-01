import functools
import time

from flask import request
from argon2 import PasswordHasher
from argon2.exceptions import Argon2Error

from app import modules
from app.config import Config
from . import gen_md5, random_choices, curr_date
from .audit import audit
from .conn import conn_db

salt = 'arlsalt!@#'

# 存量口令为 md5(salt+password)；argon2 登录验证通过后透明升级
_hasher = PasswordHasher()


def hash_password(password):
    """新口令一律 argon2id。"""
    return _hasher.hash(password)


def verify_and_upgrade(user_doc, password):
    """校验口令；存量 md5 验证通过时透明升级为 argon2。"""
    stored = str(user_doc.get("password") or "")
    if stored.startswith("$argon2"):
        try:
            _hasher.verify(stored, password)
            return True
        except Argon2Error:
            return False
        except Exception:
            return False
    if stored and stored == gen_md5(salt + password):
        try:
            conn_db('user').update_one(
                {"_id": user_doc["_id"]},
                {"$set": {"password": _hasher.hash(password)}})
        except Exception:
            pass
        return True
    return False


def _token_doc_valid(doc, now=None):
    """token 文档有效性判定（纯函数，便于单测）。"""
    if doc is None or doc.get("revoked"):
        return False
    now = time.time() if now is None else now
    expires = float(doc.get("expires_ts") or 0)
    return expires <= 0 or expires > now


def new_user_token(username, days=None):
    """签发登录 token：api_token 集合为真源（过期/吊销/last_seen），
    user.token 同步写入以兼容旧校验逻辑，过渡期后移除。"""
    if days is None:
        days = int(getattr(Config, "TOKEN_EXPIRE_DAYS", 7) or 7)
    now = time.time()
    token = gen_md5(random_choices(50))
    doc = {
        "token": token,
        "username": username,
        "type": "login",
        "create_time": curr_date(),
        "create_ts": now,
        "expires_ts": now + days * 86400,
        "last_seen": now,
        "revoked": False,
    }
    conn_db('api_token').insert_one(doc)
    conn_db('user').update_one({"username": username},
                               {"$set": {"token": token}})
    return doc


def user_login(username=None, password=None):
    if not username or not password:
        return

    user_doc = conn_db('user').find_one({"username": username})
    if not user_doc or user_doc.get("disabled"):
        audit("login_failed", username=username)
        return
    if not verify_and_upgrade(user_doc, password):
        audit("login_failed", username=username)
        return

    doc = new_user_token(username)
    audit("login_success", username=username)
    return {"username": username, "token": doc["token"], "type": "login",
            "role": _user_role(username)}


def user_login_header():
    token = request.headers.get("Token") or request.args.get("token")

    if not Config.AUTH:
        return True

    if not token:
        return False

    if token == Config.API_KEY:
        return {
            "username": "ARL-API",
            "token": token,
            "type": "api",
            "role": "admin",
        }

    # 新 token 表：未吊销且未过期
    doc = conn_db('api_token').find_one(
        {"token": token, "revoked": {"$ne": True}})
    if doc is not None:
        if not _token_doc_valid(doc):
            return False
        now = time.time()
        try:
            if now - float(doc.get("last_seen") or 0) > 60:
                conn_db('api_token').update_one(
                    {"_id": doc["_id"]}, {"$set": {"last_seen": now}})
        except Exception:
            pass
        return {
            "username": doc.get("username"),
            "token": token,
            "type": "login",
            "role": _user_role(doc.get("username")),
        }

    # 兼容存量会话：仅当该 token 在 api_token 无记录时按旧版 user.token 放行
    # （api_token 中存在但被吊销/过期的，走上面的分支已被拒绝，不得从这里绕过）
    data = conn_db('user').find_one({"token": token})
    if data and conn_db('api_token').find_one({"token": token}) is None:
        return {
            "username": data.get("username"),
            "token": token,
            "type": "login",
            "role": _user_role(data.get("username")),
        }

    return False


def _user_role(username):
    """查用户角色；缺省 admin（存量单管理员账号平滑兼容 RBAC）。"""
    doc = conn_db('user').find_one({"username": username}, {"role": 1})
    return doc.get("role") if doc and doc.get("role") else "admin"


def get_user_role(username):
    return _user_role(username)


VALID_ROLES = ("admin", "operator", "auditor")


def user_logout(token):
    if user_login_header():
        try:
            conn_db('api_token').update_one(
                {"token": token},
                {"$set": {"revoked": True, "revoke_ts": time.time()}})
        except Exception:
            pass
        conn_db('user').update_one({"token": token}, {"$set": {"token": None}})
        audit("logout")


def change_pass(token, old_password, new_password):
    data = conn_db('user').find_one({"token": token})
    if not data or not verify_and_upgrade(data, old_password):
        audit("change_pass_failed", username=data.get("username") if data else "")
        return False
    conn_db('user').update_one({"token": token},
                               {"$set": {"password": hash_password(new_password)}})
    audit("change_pass_success", username=data.get("username"))
    return True


def auth(func):
    ret = {
        "message": "not login",
        "code": 401,
        "data": {}
    }
    forbidden = {
        "message": "auditor role is read-only",
        "code": 403,
        "data": {}
    }

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if Config.AUTH:
            info = user_login_header()
            if not info:
                return ret
            # RBAC：auditor 只读——非 GET 请求全局拒绝（登录/登出/改密不经本装饰器）
            if request.method != "GET" and info.get("role") == "auditor":
                audit("rbac_denied", username=info.get("username"),
                      detail={"method": request.method, "path": request.path})
                return forbidden

        return func(*args, **kwargs)

    return wrapper
