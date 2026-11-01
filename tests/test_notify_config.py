"""通知渠道配置 API 测试（假 DB + tmp yaml）。"""

import pytest
import yaml
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

    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump({
        "DINGDING": {"ACCESS_TOKEN": "", "SECRET": ""},
        "FEISHU": {"WEBHOOK_URL": "", "SECRET": ""},
        "WX_WORK_WEBHOOK": "",
        "WEBHOOK": {"URL": "", "TOKEN": ""},
        "EMAIL": {"HOST": "", "PORT": "", "USERNAME": "", "PASSWORD": "", "TO": ""},
    }))
    import app.routes.notify_config as notify_mod
    import app.routes.engines as engines_mod
    monkeypatch.setattr(notify_mod, "CONFIG_PATH", str(config_path))
    monkeypatch.setattr(notify_mod, "_load_config",
                        lambda: yaml.safe_load(open(str(config_path))))
    monkeypatch.setattr(engines_mod, "CONFIG_PATH", str(config_path))
    monkeypatch.setattr(engines_mod, "_load_config",
                        lambda: yaml.safe_load(open(str(config_path))))

    app = Flask(__name__)
    api = Api(app, prefix="/api", doc=False)
    from app.routes import notify_config_ns
    api.add_namespace(notify_config_ns)
    return {"client": app.test_client(), "db": fake,
            "h": {"Token": "static-api-key"},
            "config_path": str(config_path)}


def test_get_masks_and_configured(env):
    with open(env["config_path"], "a") as f:
        f.write("DINGDING_EXTRA_MARK: keep\n")  # 确保文件可重读
    # 写入两个渠道再读取
    env["client"].post("/api/notify_config/",
                       json={"channel": "dingding",
                             "fields": {"AccessToken": "tok-123456789",
                                        "加签 Secret": "sec-abcdefg"}},
                       headers=env["h"])
    resp = env["client"].get("/api/notify_config/", headers=env["h"])
    data = resp.get_json()["data"]
    assert data["dingding"]["configured"] is True
    assert "tok-123456789" not in resp.text            # 明文不泄漏
    assert data["dingding"]["values"]["AccessToken"].startswith("tok-")


def test_save_writes_yaml_section(env):
    env["client"].post("/api/notify_config/",
                       json={"channel": "feishu",
                             "fields": {"Webhook 地址": "https://open.feishu.cn/hook/x"}},
                       headers=env["h"])
    data = yaml.safe_load(open(env["config_path"]))
    assert data["FEISHU"]["WEBHOOK_URL"] == "https://open.feishu.cn/hook/x"
    assert data["FEISHU"]["SECRET"] == ""              # 未填字段清空但保留兄弟段
    assert "DINGDING" in data                          # 其他渠道段不受影响


def test_clear_channel(env):
    env["client"].post("/api/notify_config/",
                       json={"channel": "wxwork",
                             "fields": {"Webhook 地址": "https://qy/w"}},
                       headers=env["h"])
    resp = env["client"].post("/api/notify_config/",
                              json={"channel": "wxwork", "clear": True,
                                    "fields": {}},
                              headers=env["h"])
    assert resp.get_json()["code"] == 200
    assert yaml.safe_load(open(env["config_path"]))["WX_WORK_WEBHOOK"] == ""


def test_unknown_channel_rejected(env):
    resp = env["client"].post("/api/notify_config/",
                              json={"channel": "sms", "fields": {}},
                              headers=env["h"])
    assert resp.get_json()["code"] == 400
