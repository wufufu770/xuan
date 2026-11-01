"""会话池单测（假 DB + 真实 Fernet，不出网、不启动浏览器）。"""

import os
import time

import pytest

from app.config import Config
from app.services import session_pool
from tests.fake_db import FakeDB


@pytest.fixture
def db(monkeypatch):
    fake = FakeDB()
    monkeypatch.setattr(session_pool.utils, "conn_db", fake.conn_db)
    return fake


@pytest.fixture(autouse=True)
def _stable_key(monkeypatch):
    monkeypatch.setenv("ARL_SESSION_KEY", "unit-test-key")


# ----------------------------------------------------------- 加密 ----

def test_encrypt_decrypt_round_trip():
    state = {"cookies": [{"name": "token", "value": "t"}], "origins": []}
    blob = session_pool.encrypt_state(state)
    assert blob != str(state)
    assert session_pool.decrypt_state(blob) == state


def test_wrong_key_fails_cleanly(monkeypatch):
    blob = session_pool.encrypt_state({"cookies": []})
    monkeypatch.setenv("ARL_SESSION_KEY", "another-key")
    with pytest.raises(ValueError, match="密钥不匹配"):
        session_pool.decrypt_state(blob)


# ------------------------------------------------------- 存取 ----

def test_save_load_get_cookie(db):
    state = {"cookies": [{"name": "token", "value": "tok123"}], "origins": []}
    session_pool.save_state("fengniao", "default", state, expires_hint=123)

    doc = db.conn_db("session_account").find_one({"source": "fengniao"})
    assert doc["state_enc"] and "tok123" not in doc["state_enc"]  # 密文不含明文
    assert doc["expires_hint"] == 123
    assert session_pool.get_cookie("fengniao", "default", "token") == "tok123"
    assert session_pool.get_cookie("fengniao", "default", "nope") is None


def test_get_cookie_db_failure_returns_none(db, monkeypatch):
    def boom(name):
        raise RuntimeError("db down")
    monkeypatch.setattr(session_pool.utils, "conn_db", boom)
    assert session_pool.get_cookie("fengniao", "default", "token") is None


def test_missing_account_returns_none(db):
    assert session_pool.load_state("fengniao", "ghost") is None
    assert session_pool.get_cookie("fengniao", "ghost", "token") is None


# ------------------------------------------------------- 租约 ----

def test_lease_serializes_owners():
    session_pool.acquire_lease("src", "acc", owner="A")
    with pytest.raises(session_pool.SessionBusy):
        session_pool.acquire_lease("src", "acc", owner="B")
    session_pool.release_lease("src", "acc", owner="A")
    session_pool.acquire_lease("src", "acc", owner="B")   # 释放后可获取
    session_pool.release_lease("src", "acc", owner="B")


def test_lease_same_owner_reacquire_ok():
    session_pool.acquire_lease("s2", "a2", owner="A")
    session_pool.acquire_lease("s2", "a2", owner="A")     # 续租合法
    session_pool.release_lease("s2", "a2", owner="A")


# ------------------------------------------------------- 探活 ----

def test_health_check_fengniao_requires_token_cookie(db):
    missing = {"cookies": [{"name": "other", "value": "x"}]}
    session_pool.save_state("fengniao", "default", missing)
    ok, detail = session_pool.run_health_check("fengniao", "default")
    assert not ok and "token" in detail
    assert db.conn_db("session_account").find_one(
        {"source": "fengniao"})["status"] == "expired"

    good = {"cookies": [{"name": "token", "value": "t"}]}
    session_pool.save_state("fengniao", "default", good)
    ok, detail = session_pool.run_health_check("fengniao", "default")
    assert ok
    assert db.conn_db("session_account").find_one(
        {"source": "fengniao"})["status"] == "ok"


def test_health_check_unknown_account(db):
    ok, detail = session_pool.run_health_check("fengniao", "ghost")
    assert not ok and "无该账号" in detail


# ------------------------------------------------- fengniao 供给 ----

def test_resolve_prefers_pool_over_config(db, monkeypatch):
    state = {"cookies": [{"name": "token", "value": "from-pool"}]}
    session_pool.save_state("fengniao", "default", state)
    monkeypatch.setattr(Config, "FENGNIAR_TOKEN", "from-config", raising=False)

    from app.services.fengniao import resolve_fengniao_token
    assert resolve_fengniao_token() == "from-pool"


def test_resolve_falls_back_to_config(db, monkeypatch):
    monkeypatch.setattr(Config, "FENGNIAR_TOKEN", "from-config", raising=False)
    from app.services.fengniao import resolve_fengniao_token
    assert resolve_fengniao_token() == "from-config"


def test_resolve_survives_db_outage(db, monkeypatch):
    def boom(name):
        raise RuntimeError("db down")
    monkeypatch.setattr(session_pool.utils, "conn_db", boom)
    monkeypatch.setattr(Config, "FENGNIAR_TOKEN", "from-config", raising=False)
    from app.services.fengniao import resolve_fengniao_token
    assert resolve_fengniao_token() == "from-config"


def test_sync_fengniao_to_config(db, tmp_path):
    import yaml
    config_path = str(tmp_path / "config.yaml")
    with open(config_path, "w") as f:
        yaml.safe_dump({"FENGNIAR_TOKEN": "old", "FOFA": {"KEY": "keep"}}, f)

    state = {"cookies": [{"name": "token", "value": "fresh-token"}]}
    session_pool.save_state("fengniao", "default", state)

    assert session_pool.sync_fengniao_to_config(config_path) is True
    with open(config_path) as f:
        data = yaml.safe_load(f)
    assert data["FENGNIAR_TOKEN"] == "fresh-token"
    assert data["FOFA"]["KEY"] == "keep"          # 兄弟键保留（锁内覆盖语义）


def test_sync_fengniao_to_config_no_account(db, tmp_path):
    import yaml
    config_path = str(tmp_path / "config.yaml")
    with open(config_path, "w") as f:
        yaml.safe_dump({}, f)
    assert session_pool.sync_fengniao_to_config(config_path) is False


def test_pool_status_hides_state(db):
    state = {"cookies": [{"name": "token", "value": "secret"}]}
    session_pool.save_state("fengniao", "default", state)
    docs = session_pool.pool_status()
    assert len(docs) == 1
    assert "state_enc" not in docs[0]
    assert "secret" not in str(docs[0])
