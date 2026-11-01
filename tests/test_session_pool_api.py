"""会话池 API 层测试（P1 修复：set_token / probe / delete / 字符串导入）。"""

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
from app.utils import notify as notify_mod
from tests.fake_db import FakeDB


def _jwt(exp=None):
    exp = exp if exp is not None else int(time.time()) + 86400
    header = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        json.dumps({"exp": exp}).encode()).rstrip(b"=").decode()
    return "{}.{}.{}".format(header, payload, "sig")


@pytest.fixture
def env(monkeypatch, tmp_path):
    fake = FakeDB()
    monkeypatch.setattr(user_mod, "conn_db", fake.conn_db)
    monkeypatch.setattr(audit_mod, "conn_db", fake.conn_db)
    monkeypatch.setattr(Config, "AUTH", True, raising=False)
    monkeypatch.setattr(Config, "API_KEY", "static-api-key", raising=False)

    import app.utils as utils_pkg
    import app.services.session_pool as session_pool
    monkeypatch.setattr(utils_pkg, "conn_db", fake.conn_db)
    monkeypatch.setattr(session_pool, "utils", utils_pkg)
    monkeypatch.setenv("ARL_SESSION_KEY", "web-test-key")

    import app.routes.session_pool as session_pool_routes
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump({"FENGNIAR_TOKEN": ""}))
    monkeypatch.setattr(session_pool_routes, "CONFIG_PATH", str(config_path))

    app = Flask(__name__)
    api = Api(app, prefix="/api", doc=False)
    from app.routes import session_pool_ns
    api.add_namespace(session_pool_ns)
    return {"client": app.test_client(), "db": fake,
            "h": {"Token": "static-api-key"}, "config_path": str(config_path)}


# ------------------------------------------------------- 解析函数 ----

def test_parse_pure_jwt():
    from app.routes.session_pool import parse_token_to_state
    state = parse_token_to_state("fengniao", _jwt())
    assert state["cookies"][0]["name"] == "token"
    assert state["cookies"][0]["domain"] == "www.riskbird.com"
    assert state["origins"] == []


def test_parse_single_cookie():
    from app.routes.session_pool import parse_token_to_state
    state = parse_token_to_state("aqc", "sid=abc123")
    assert state["cookies"][0]["name"] == "sid"
    assert state["cookies"][0]["value"] == "abc123"
    assert state["cookies"][0]["domain"] == "aiqicha.baidu.com"


def test_parse_cookie_string():
    from app.routes.session_pool import parse_token_to_state
    raw = "token=" + _jwt() + "; app-uuid=WEB-XYZ; app-device=WEB"
    state = parse_token_to_state("fengniao", raw)
    names = [c["name"] for c in state["cookies"]]
    assert names == ["token", "app-uuid", "app-device"]


def test_parse_empty_returns_none():
    from app.routes.session_pool import parse_token_to_state
    assert parse_token_to_state("fengniao", "  ") is None


# --------------------------------------------------------- set_token ----

def test_set_token_pure_jwt_fengniao(env):
    token = _jwt(int(time.time()) + 7200)
    resp = env["client"].post("/api/session_pool/set_token/",
                              json={"source": "fengniao", "account": "default",
                                    "token": token},
                              headers=env["h"])
    body = resp.get_json()
    assert body["code"] == 200
    assert body["data"]["ok"] is True                    # 探活通过（token cookie 存在）
    assert body["data"]["config_synced"] is True         # 凤鸟同步 config.yaml
    assert body["data"]["expires_hint"] > time.time() + 7000
    assert body["data"]["cookie_names"] == ["token"]

    # config.yaml 已写入 token（过渡双写）
    with open(env["config_path"]) as f:
        assert yaml.safe_load(f)["FENGNIAR_TOKEN"] == token


def test_set_token_cookie_string(env):
    raw = "token=" + _jwt() + "; app-uuid=WEB-ABC; app-device=WEB"
    resp = env["client"].post("/api/session_pool/set_token/",
                              json={"source": "fengniao", "account": "ops",
                                    "token": raw},
                              headers=env["h"])
    body = resp.get_json()
    assert body["code"] == 200
    assert sorted(body["data"]["cookie_names"]) == ["app-device", "app-uuid", "token"]
    assert body["data"]["config_synced"] is True


def test_set_token_empty_rejected(env):
    resp = env["client"].post("/api/session_pool/set_token/",
                              json={"source": "fengniao", "account": "x",
                                    "token": "   "},
                              headers=env["h"])
    assert resp.get_json()["code"] == 400


def test_set_token_overwrites_existing(env):
    env["client"].post("/api/session_pool/set_token/",
                       json={"source": "fengniao", "account": "default",
                             "token": "first-value"},
                       headers=env["h"])
    resp = env["client"].post("/api/session_pool/set_token/",
                              json={"source": "fengniao", "account": "default",
                                    "token": "second-value"},
                              headers=env["h"])
    assert resp.get_json()["code"] == 200
    from app.services.session_pool import get_cookie
    assert get_cookie("fengniao", "default", "token") == "second-value"


# ------------------------------------------------------------ probe ----

def test_probe_after_set_token(env):
    env["client"].post("/api/session_pool/set_token/",
                       json={"source": "fengniao", "account": "default",
                             "token": "tok-value"},
                       headers=env["h"])
    resp = env["client"].post("/api/session_pool/probe/",
                              json={"source": "fengniao", "account": "default"},
                              headers=env["h"])
    body = resp.get_json()
    assert body["code"] == 200
    assert body["data"]["ok"] is True
    assert body["data"]["status"] == "ok"


def test_probe_missing_account(env):
    resp = env["client"].post("/api/session_pool/probe/",
                              json={"source": "fengniao", "account": "ghost"},
                              headers=env["h"])
    assert resp.get_json()["code"] == 404


# --------------------------------------------------------- accounts ----

def test_accounts_lifecycle_register_set_delete(env):
    client, h = env["client"], env["h"]

    # 登记
    resp = client.post("/api/session_pool/accounts/",
                       json={"source": "fengniao", "account": "main"}, headers=h)
    assert resp.get_json()["code"] == 200

    # 列表可见
    accounts = client.get("/api/session_pool/accounts/", headers=h).get_json()["data"]["accounts"]
    assert any(a["source"] == "fengniao" and a["account"] == "main" for a in accounts)

    # 删除
    resp = client.delete("/api/session_pool/accounts/",
                         json={"source": "fengniao", "account": "main"}, headers=h)
    assert resp.get_json()["code"] == 200

    accounts = client.get("/api/session_pool/accounts/", headers=h).get_json()["data"]["accounts"]
    assert not any(a["account"] == "main" for a in accounts)


def test_accounts_delete_missing(env):
    resp = env["client"].delete("/api/session_pool/accounts/",
                                json={"source": "fengniao", "account": "nope"},
                                headers=env["h"])
    assert resp.get_json()["code"] == 404


# ------------------------------------------------------ import 兼容 ----

def test_import_state_accepts_token_string(env):
    resp = env["client"].post("/api/session_pool/import_state/",
                              json={"source": "fengniao", "account": "default",
                                    "state": _jwt()},
                              headers=env["h"])
    body = resp.get_json()
    assert body["code"] == 200 and body["data"]["ok"] is True


def test_import_state_still_accepts_object(env):
    state = {"cookies": [{"name": "token", "value": "abc"}], "origins": []}
    resp = env["client"].post("/api/session_pool/import_state/",
                              json={"source": "fengniao", "account": "default",
                                    "state": state},
                              headers=env["h"])
    assert resp.get_json()["code"] == 200
