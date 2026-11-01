"""RBAC 三角色测试：auditor 全局只读、operator 可写、admin 用户管理。"""

import time

import pytest
from flask import Flask
from flask_restx import Api

from app.config import Config
from app.utils import user as user_mod
from app.utils import audit as audit_mod
from tests.fake_db import FakeDB


@pytest.fixture
def env(monkeypatch, tmp_path):
    fake = FakeDB()
    monkeypatch.setattr(user_mod, "conn_db", fake.conn_db)
    monkeypatch.setattr(audit_mod, "conn_db", fake.conn_db)
    monkeypatch.setattr(Config, "AUTH", True, raising=False)
    monkeypatch.setattr(Config, "API_KEY", "static-api-key", raising=False)

    import app.routes.stats as stats_mod
    monkeypatch.setattr(stats_mod, "conn", fake.conn_db)

    # 一个受 @auth 保护的写端点做拦截验证（session_pool 登记）
    import app.routes.session_pool as session_pool_routes
    import app.services.session_pool as session_pool
    import app.utils as utils_pkg
    monkeypatch.setattr(utils_pkg, "conn_db", fake.conn_db)
    monkeypatch.setattr(session_pool, "utils", utils_pkg)
    monkeypatch.setattr(session_pool_routes, "CONFIG_PATH", str(tmp_path / "c.yaml"))

    app = Flask(__name__)
    api = Api(app, prefix="/api", doc=False)
    from app.routes import user_ns, stats_ns, session_pool_ns
    for ns in (user_ns, stats_ns, session_pool_ns):
        api.add_namespace(ns)
    client = app.test_client()
    return {"client": client, "db": fake}


def _mk_user(env, username, role, password="password1"):
    from app.utils.user import hash_password
    env["db"].conn_db("user").insert_one(
        {"username": username, "password": hash_password(password), "role": role})
    return username, password


def _login(env, username, password):
    resp = env["client"].post("/api/user/login",
                              json={"username": username, "password": password})
    body = resp.get_json()
    assert body["code"] == 200, body
    return body["data"]["token"], body["data"]["role"]


# ------------------------------------------------------------ 角色 ----

def test_roles_on_login(env):
    _mk_user(env, "boss", "admin")
    _mk_user(env, "ops", "operator")
    _mk_user(env, "watcher", "auditor")
    assert _login(env, "boss", "password1")[1] == "admin"
    assert _login(env, "ops", "password1")[1] == "operator"
    assert _login(env, "watcher", "password1")[1] == "auditor"


def test_missing_role_defaults_admin(env):
    """存量账号（无 role 字段）平滑兼容为 admin。"""
    from app.utils.user import hash_password
    env["db"].conn_db("user").insert_one(
        {"username": "legacy", "password": hash_password("password1")})
    token, role = _login(env, "legacy", "password1")
    assert role == "admin"


# --------------------------------------------------- auditor 只读 ----

def test_auditor_write_denied_read_allowed(env):
    _mk_user(env, "watcher", "auditor")
    token, _ = _login(env, "watcher", "password1")
    headers = {"Token": token}

    resp = env["client"].post("/api/session_pool/accounts/",
                              json={"source": "fengniao", "account": "x"},
                              headers=headers)
    assert resp.get_json()["code"] == 403
    assert "read-only" in resp.get_json()["message"]

    # 审计留痕
    deny = [d for d in env["db"].conn_db("audit_log").docs
            if d.get("action") == "rbac_denied"]
    assert deny and deny[0]["detail"]["method"] == "POST"

    # GET 正常
    resp = env["client"].get("/api/session_pool/accounts/", headers=headers)
    assert resp.get_json()["code"] == 200


def test_operator_write_allowed(env):
    _mk_user(env, "ops", "operator")
    token, _ = _login(env, "ops", "password1")
    resp = env["client"].post("/api/session_pool/accounts/",
                              json={"source": "fengniao", "account": "x"},
                              headers={"Token": token})
    assert resp.get_json()["code"] == 200


# -------------------------------------------------- 用户管理接口 ----

def test_admin_user_management_lifecycle(env):
    _mk_user(env, "boss", "admin")
    admin_token, _ = _login(env, "boss", "password1")
    h = {"Token": admin_token}

    # 创建 operator 与 auditor
    resp = env["client"].post("/api/user/add/",
                              json={"username": "ops1", "password": "password9",
                                    "role": "operator"}, headers=h)
    assert resp.get_json()["code"] == 200

    # 列表
    items = env["client"].get("/api/user/list/", headers=h).get_json()["data"]["items"]
    names = {i["username"]: i for i in items}
    assert names["ops1"]["role"] == "operator"
    assert all("password" not in i and "token" not in i for i in items)

    # 改角色
    resp = env["client"].post("/api/user/set_role/",
                              json={"username": "ops1", "role": "auditor"}, headers=h)
    assert resp.get_json()["code"] == 200

    # 非 admin 不可管理
    ops_token, _ = _login(env, "ops1", "password9")
    resp = env["client"].get("/api/user/list/", headers={"Token": ops_token})
    assert resp.get_json()["code"] == 403

    # 禁用 → 在线会话吊销 + 登录拒绝
    resp = env["client"].post("/api/user/disable/",
                              json={"username": "ops1", "disabled": True}, headers=h)
    assert resp.get_json()["code"] == 200
    resp = env["client"].post("/api/user/login",
                              json={"username": "ops1", "password": "password9"})
    assert resp.get_json()["code"] == 401


def test_admin_cannot_disable_self(env):
    _mk_user(env, "boss", "admin")
    token, _ = _login(env, "boss", "password1")
    resp = env["client"].post("/api/user/disable/",
                              json={"username": "boss", "disabled": True},
                              headers={"Token": token})
    assert resp.get_json()["code"] == 400


def test_short_password_rejected(env):
    _mk_user(env, "boss", "admin")
    token, _ = _login(env, "boss", "password1")
    resp = env["client"].post("/api/user/add/",
                              json={"username": "weak", "password": "123",
                                    "role": "operator"},
                              headers={"Token": token})
    assert resp.get_json()["code"] == 400
