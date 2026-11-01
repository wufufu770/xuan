"""统一告警分发测试（全部渠道 Mock，不出网）。"""

import pytest

from app.utils import notify as notify_mod
from app.utils.notify import send_alert


@pytest.fixture
def cfg(monkeypatch):
    from app.config import Config
    values = {
        "DINGDING_ACCESS_TOKEN": "", "DINGDING_SECRET": "",
        "FEISHU_WEBHOOK": "", "FEISHU_SECRET": "",
        "WX_WORK_WEBHOOK": "", "WEB_HOOK_URL": "", "WEB_HOOK_TOKEN": "",
        "EMAIL_HOST": "", "EMAIL_PORT": "", "EMAIL_USERNAME": "",
        "EMAIL_PASSWORD": "", "EMAIL_TO": "",
    }
    for key, value in values.items():
        monkeypatch.setattr(Config, key, value, raising=False)
    return Config


def test_no_channels_all_skipped(cfg):
    results = send_alert("标题", "内容")
    assert set(results.values()) == {"skipped"}


def test_dingding_success_and_failure_isolated(cfg, monkeypatch):
    cfg.DINGDING_ACCESS_TOKEN = "tok"
    cfg.DINGDING_SECRET = "sec"
    cfg.FEISHU_WEBHOOK = "https://feishu/hook"

    calls = []

    def boom(**kwargs):
        calls.append("dingding")
        raise RuntimeError("网络故障")

    feishu_calls = []

    def feishu_ok(**kwargs):
        calls.append("feishu")
        feishu_calls.append(kwargs)
        return {"code": 0}

    monkeypatch.setattr(notify_mod.push, "dingding_send", boom)
    monkeypatch.setattr(notify_mod.push, "feishu_send", feishu_ok)

    results = send_alert("标题", "正文")
    assert results["dingding"] is False          # 失败被隔离为 False
    assert results["feishu"] is True             # 其他渠道照常
    assert calls == ["dingding", "feishu"]       # 两个渠道都被尝试
    assert feishu_calls[0]["webhook_url"] == "https://feishu/hook"


def test_webhook_payload_and_token_header(cfg, monkeypatch):
    cfg.WEB_HOOK_URL = "https://ops.internal/hook"
    cfg.WEB_HOOK_TOKEN = "t0ken"
    captured = {}

    class Resp:
        status_code = 200

    def fake_post(url, timeout=None, json=None, headers=None):
        captured.update({"url": url, "json": json, "headers": headers})
        return Resp()

    monkeypatch.setattr(notify_mod.requests, "post", fake_post)
    results = send_alert("标题", "正文")
    assert results["webhook"] is True
    assert captured["url"] == "https://ops.internal/hook"
    assert captured["json"] == {"title": "标题", "content": "正文"}
    assert captured["headers"]["Token"] == "t0ken"


def test_email_requires_full_config(cfg):
    cfg.EMAIL_HOST = "smtp.example.com"
    results = send_alert("标题")
    assert results["email"] == "skipped"   # 缺用户名/密码不发送
