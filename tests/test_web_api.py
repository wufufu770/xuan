"""Web 层 API 集成测试（Flask test client + 假 DB，升级安全网）。

覆盖认证流、鉴权拦截、stats/summary 响应契约、session_pool 入池流程、
fengniao/engines 凭据配置读写。不连真实 Mongo/不出网。

conn_db 打桩策略：动态引用（utils.conn_db）patch app.utils 模块属性；
导入期绑定（from app.utils import conn_db）逐模块 patch。
"""

import base64
import json
import time

import pytest
import yaml
from flask import Flask
from flask_restx import Api

from app.config import Config
from app.utils import user as user_mod
from app.utils import audit as audit_mod
from tests.fake_db import FakeDB


@pytest.fixture
def web(monkeypatch, tmp_path):
    """组装被测最小 API + 假 DB + tmp 配置文件。"""
    fake = FakeDB()
    monkeypatch.setattr(user_mod, "conn_db", fake.conn_db)
    monkeypatch.setattr(audit_mod, "conn_db", fake.conn_db)
    monkeypatch.setattr(Config, "AUTH", True, raising=False)
    monkeypatch.setattr(Config, "API_KEY", "static-api-key", raising=False)

    # stats.py 以 `from app.utils import conn_db as conn` 导入期绑定，需逐模块 patch
    import app.routes.stats as stats_mod
    monkeypatch.setattr(stats_mod, "conn", fake.conn_db)

    # 会话池服务动态引用 utils.conn_db —— patch 模块属性即可全覆盖
    import app.utils as utils_pkg
    monkeypatch.setattr(utils_pkg, "conn_db", fake.conn_db)
    import app.services.session_pool as session_pool
    monkeypatch.setattr(session_pool, "utils", utils_pkg)
    monkeypatch.setenv("ARL_SESSION_KEY", "web-test-key")

    # 凤鸟/引擎配置指向 tmp yaml（避免污染测试用 app/config.yaml）
    import app.routes.engines as engines_mod
    import app.routes.fengniao as fengniao_mod
    import app.routes.session_pool as session_pool_routes
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump({
        "FENGNIAR_TOKEN": "", "FOFA": {"KEY": "fofa-secret-key-0001", "EMAIL": ""},
        "QUERY_PLUGIN": {"hunter_qax": {"api_key": "", "enable": False},
                         "quake_360": {"quake_token": "", "enable": False}},
    }))
    # session_pool 路由同样 `from .engines import CONFIG_PATH` 导入期绑定
    monkeypatch.setattr(session_pool_routes, "CONFIG_PATH", str(config_path))
    monkeypatch.setattr(engines_mod, "CONFIG_PATH", str(config_path))
    monkeypatch.setattr(fengniao_mod, "CONFIG_PATH", str(config_path))
    monkeypatch.setattr(fengniao_mod.Config, "FENGNIAR_TOKEN", "", raising=False)

    app = Flask(__name__)
    api = Api(app, prefix="/api", doc=False)
    from app.routes import (user_ns, stats_ns, session_pool_ns,
                            fengniao_ns, engines_ns)
    for ns in (user_ns, stats_ns, session_pool_ns, fengniao_ns, engines_ns):
        api.add_namespace(ns)

    client = app.test_client()
    return {"client": client, "db": fake, "config_path": str(config_path)}


def _login(client, username="admin", password="pw"):
    return client.post("/api/user/login",
                       json={"username": username, "password": password})


@pytest.fixture
def admin_user(web):
    from app.utils.user import hash_password
    web["db"].conn_db("user").insert_one(
        {"_id": 1, "username": "admin", "password": hash_password("pw")})
    return web


def _jwt(exp):
    header = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        json.dumps({"exp": exp}).encode()).rstrip(b"=").decode()
    return "{}.{}.{}".format(header, payload, "sig")


# ------------------------------------------------------------ 认证流 ----

def test_login_and_authenticated_request(admin_user):
    client = admin_user["client"]
    resp = client.post("/api/user/login", json={"username": "admin", "password": "pw"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["code"] == 200
    token = body["data"]["token"]
    assert token

    resp = client.get("/api/session_pool/accounts/", headers={"Token": token})
    assert resp.status_code == 200
    assert resp.get_json()["code"] == 200


def test_wrong_password_rejected(admin_user):
    resp = admin_user["client"].post(
        "/api/user/login", json={"username": "admin", "password": "bad"})
    assert resp.get_json()["code"] == 401


def test_missing_token_returns_401(web):
    resp = web["client"].get("/api/session_pool/accounts/")
    assert resp.get_json()["code"] == 401


def test_static_api_key_accepted(web):
    resp = web["client"].get("/api/session_pool/accounts/",
                             headers={"Token": "static-api-key"})
    assert resp.status_code == 200


def test_expired_token_rejected(admin_user):
    client = admin_user["client"]
    token = client.post("/api/user/login",
                        json={"username": "admin", "password": "pw"}).get_json()["data"]["token"]
    admin_user["db"].conn_db("api_token").update_one(
        {"token": token}, {"$set": {"expires_ts": time.time() - 5}})
    resp = client.get("/api/session_pool/accounts/", headers={"Token": token})
    assert resp.get_json()["code"] == 401


# --------------------------------------------------- stats/summary ----

def test_stats_summary_shape(web):
    web["db"].conn_db("domain").insert_one({"resolve_status": "resolved"})
    web["db"].conn_db("domain").insert_one({})
    resp = web["client"].get("/api/stats/summary/",
                             headers={"Token": "static-api-key"})
    assert resp.status_code == 200
    data = resp.get_json()["data"]
    assert data["domains"] == 2
    assert data["resolved_domains"] == 1
    assert "health" in data and "tasks_recent" in data["health"]
    assert "fengniao_token" in data["health"]


# ------------------------------------------------------ session_pool ----

def test_session_pool_register_import_status(web):
    client = web["client"]
    headers = {"Token": "static-api-key"}

    # 登记
    resp = client.post("/api/session_pool/accounts/",
                       json={"source": "fengniao", "account": "ops1"}, headers=headers)
    assert resp.get_json()["code"] == 200

    # 导入登录态（凤鸟：带 token cookie）
    state = {"cookies": [{"name": "token", "value": _jwt(time.time() + 86400)}],
             "origins": []}
    resp = client.post("/api/session_pool/import_state/",
                       json={"source": "fengniao", "account": "ops1", "state": state},
                       headers=headers)
    body = resp.get_json()
    assert body["code"] == 200
    assert body["data"]["ok"] is True
    assert body["data"]["config_synced"] is True

    # config.yaml 已同步 token（过渡双写）
    with open(web["config_path"]) as f:
        assert yaml.safe_load(f)["FENGNIAR_TOKEN"] == state["cookies"][0]["value"]

    # 列表不泄漏密文与明文 cookie
    resp = client.get("/api/session_pool/accounts/", headers=headers)
    doc = resp.get_json()["data"]["accounts"][0]
    assert "state_enc" not in doc
    assert "secret" not in json.dumps(doc)

    # 池内 cookie 可被消费方取到
    from app.services.session_pool import get_cookie
    assert get_cookie("fengniao", "ops1", "token") == state["cookies"][0]["value"]


def test_session_pool_import_rejects_bad_payload(web):
    # state 为数字（既非对象也非可解析字符串）→ 400
    resp = web["client"].post("/api/session_pool/import_state/",
                              json={"source": "fengniao", "account": "x", "state": 123},
                              headers={"Token": "static-api-key"})
    assert resp.get_json()["code"] == 400
    # 空字符串 → 400
    resp = web["client"].post("/api/session_pool/import_state/",
                              json={"source": "fengniao", "account": "x", "state": "  "},
                              headers={"Token": "static-api-key"})
    assert resp.get_json()["code"] == 400


# ------------------------------------------- fengniao/engines 配置 ----

def test_engines_get_masks_keys(web):
    resp = web["client"].get("/api/engines/", headers={"Token": "static-api-key"})
    data = resp.get_json()["data"]
    assert data["fofa"]["configured"] is True
    assert "fofa-secret-key-0001" not in json.dumps(data)   # 明文不出现在响应
    assert data["fofa"]["key_masked"]


def test_fengniao_config_round_trip(web):
    client = web["client"]
    headers = {"Token": "static-api-key"}

    token = _jwt(time.time() + 3600)
    resp = client.post("/api/fengniao/config/",
                       json={"token": "token=" + token}, headers=headers)
    body = resp.get_json()
    assert body["code"] == 200
    assert body["data"]["configured"] is True
    assert body["data"]["exp_text"]                     # JWT 过期时间已解析
    assert token not in json.dumps(body)                # 响应只含掩码

    # 落到了 tmp config.yaml（真实测试配置未被污染）
    with open(web["config_path"]) as f:
        assert yaml.safe_load(f)["FENGNIAR_TOKEN"] == token

    # 清除
    resp = client.post("/api/fengniao/config/", json={"clear": True}, headers=headers)
    assert resp.get_json()["code"] == 200
    with open(web["config_path"]) as f:
        assert yaml.safe_load(f)["FENGNIAR_TOKEN"] == ""


def test_fengniao_config_empty_token_rejected(web):
    resp = web["client"].post("/api/fengniao/config/",
                              json={"token": "  "},
                              headers={"Token": "static-api-key"})
    assert resp.get_json()["code"] == 400
