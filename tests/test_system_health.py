"""system_health 健康指标测试（假 DB + 凤鸟解析 Mock）。"""

import time

import pytest

from app.services import system_health
from tests.fake_db import FakeDB


@pytest.fixture
def db(monkeypatch):
    fake = FakeDB()
    monkeypatch.setattr(system_health.utils, "conn_db", fake.conn_db)
    return fake


@pytest.fixture
def fengniao_state(monkeypatch):
    holder = {"token": "", "exp": 0}
    import app.routes.fengniao as routes_fengniao
    import app.services.fengniao as services_fengniao
    monkeypatch.setattr(routes_fengniao, "_token_from_yaml",
                        lambda: holder["token"])
    monkeypatch.setattr(services_fengniao, "token_expire_time",
                        lambda token=None: holder["exp"] if holder["token"] else 0)
    return holder


def test_tasks_recent_counts_and_success_rate(db):
    tasks = db.conn_db("task")
    for _ in range(7):
        tasks.insert_one({"status": "done"})
    for _ in range(3):
        tasks.insert_one({"status": "error"})
    tasks.insert_one({"status": "running"})

    health = system_health.collect_health()
    recent = health["tasks_recent"]
    assert recent["sample"] == 11
    assert recent["done"] == 7 and recent["error"] == 3
    assert recent["success_rate"] == round(7 / 10, 4)


def test_tasks_recent_empty_is_none_rate(db):
    health = system_health.collect_health()
    assert health["tasks_recent"]["success_rate"] is None


def test_api_token_active_excludes_revoked_and_expired(db):
    now = time.time()
    tokens = db.conn_db("api_token")
    tokens.insert_one({"revoked": False, "expires_ts": now + 999})
    tokens.insert_one({"expires_ts": now + 999})                 # 无 revoked 视为有效
    tokens.insert_one({"revoked": True, "expires_ts": now + 999})
    tokens.insert_one({"revoked": False, "expires_ts": now - 1})  # 已过期

    health = system_health.collect_health()
    assert health["api_token_active"] == 2


def test_fengniao_token_fields(db, fengniao_state):
    now = time.time()
    fengniao_state.update({"token": "jwt", "exp": now + 3600})
    health = system_health.collect_health()
    assert health["fengniao_token"]["configured"] is True
    assert health["fengniao_token"]["expires_in_hours"] == 1.0


def test_fengniao_token_unconfigured(db, fengniao_state):
    health = system_health.collect_health()
    assert health["fengniao_token"]["configured"] is False
    assert health["fengniao_token"]["expires_in_hours"] is None


def test_subsystem_failure_does_not_break_overall(db, monkeypatch):
    def boom(name):
        raise RuntimeError("task collection gone")
    monkeypatch.setattr(system_health.utils, "conn_db", boom)
    health = system_health.collect_health()
    assert health["tasks_recent"] == {}
    assert health["api_token_active"] is None
