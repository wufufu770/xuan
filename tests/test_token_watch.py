"""凤鸟 token 到期看门测试（状态机：新鲜/临期/冷却/已过期/无 token）。"""

import time

import pytest

from app.utils import notify as notify_mod
from app.utils import token_watch
from tests.fake_db import FakeDB


@pytest.fixture
def db(monkeypatch):
    fake = FakeDB()
    monkeypatch.setattr(token_watch, "conn_db", fake.conn_db)
    return fake


@pytest.fixture
def yaml_token(monkeypatch):
    """patch 路由层的 yaml 读取与服务的过期解析（看门内部延迟导入）。"""
    holder = {"token": "", "exp": 0}
    import app.routes.fengniao as routes_fengniao
    import app.services.fengniao as services_fengniao
    monkeypatch.setattr(routes_fengniao, "_token_from_yaml",
                        lambda: holder["token"])
    monkeypatch.setattr(services_fengniao, "token_expire_time",
                        lambda token=None: holder["exp"] if holder["token"] else 0)
    return holder


def test_no_token_returns_none(db, yaml_token):
    assert token_watch.check_fengniao_token() is None
    assert db.conn_db("alert_state").docs == []


def test_fresh_token_no_alert(db, yaml_token):
    now = time.time()
    yaml_token.update({"token": "jwt", "exp": now + 7 * 86400})
    assert token_watch.check_fengniao_token(now=now) is None


def test_expiring_token_alerts_once_then_cooldown(db, yaml_token, monkeypatch):
    now = time.time()
    yaml_token.update({"token": "jwt", "exp": now + 10 * 3600})
    sent = []
    monkeypatch.setattr(notify_mod, "send_alert",
                        lambda title, body: sent.append(title) or "sent")

    text = token_watch.check_fengniao_token(now=now)
    assert text and "10.0 小时" in text
    assert sent == ["凤鸟 token 即将过期"]
    assert db.conn_db("alert_state").find_one({"key": token_watch.STATE_KEY})

    # 冷却期内同状态不再发送
    assert token_watch.check_fengniao_token(now=now + 3600) is None
    assert len(sent) == 1

    # 冷却期过后再次提醒
    assert token_watch.check_fengniao_token(now=now + token_watch.COOLDOWN_SECONDS + 60)
    assert len(sent) == 2


def test_expired_token_still_alerts(db, yaml_token, monkeypatch):
    now = time.time()
    yaml_token.update({"token": "jwt", "exp": now - 3600})
    sent = []
    monkeypatch.setattr(notify_mod, "send_alert",
                        lambda title, body: sent.append(title) or "sent")
    text = token_watch.check_fengniao_token(now=now)
    assert text and "剩余 -1.0 小时" in text
    assert sent


def test_unparseable_token_no_alert(db, yaml_token):
    now = time.time()
    yaml_token.update({"token": "jwt", "exp": 0})
    assert token_watch.check_fengniao_token(now=now) is None


def test_db_failure_never_raises(db, yaml_token, monkeypatch):
    now = time.time()
    yaml_token.update({"token": "jwt", "exp": now + 3600})

    def boom(name):
        raise RuntimeError("db down")
    monkeypatch.setattr(token_watch, "conn_db", boom)
    # 看门自身吞掉一切异常（旁路能力），调度循环无需为它兜底
    assert token_watch.check_fengniao_token(now=now) is None
