"""数据源接入（integration）测试：注册表读写/掩码/热更新/路由往返。

不连真实 Mongo、不出网（探活函数 monkeypatch）。
"""

import json

import pytest
import yaml
from flask import Flask
from flask_restx import Api

from app.config import Config
from app.utils import user as user_mod
from app.utils import audit as audit_mod
from tests.fake_db import FakeDB


BASE_YAML = {
    "FOFA": {"KEY": "fofa-key-abcdef123456", "EMAIL": ""},
    "GITHUB": {"TOKEN": ""},
    "QUERY_PLUGIN": {
        "hunter_qax": {"api_key": "", "enable": False},
        "quake_360": {"quake_token": "", "enable": False},
        "zoomeye": {"api_key": "", "enable": False},
        "virustotal": {"api_key": "", "enable": False},
        "crtsh": {"enable": True},
    },
}


@pytest.fixture
def web(monkeypatch, tmp_path):
    fake = FakeDB()
    monkeypatch.setattr(user_mod, "conn_db", fake.conn_db)
    monkeypatch.setattr(audit_mod, "conn_db", fake.conn_db)
    monkeypatch.setattr(Config, "AUTH", True, raising=False)
    monkeypatch.setattr(Config, "API_KEY", "static-api-key", raising=False)

    import app.utils as utils_pkg
    monkeypatch.setattr(utils_pkg, "conn_db", fake.conn_db)

    import app.services.integration as integration_mod
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(BASE_YAML))
    monkeypatch.setattr(integration_mod, "CONFIG_PATH", str(config_path))
    integration_mod._mtime_cache["ts"] = None   # 失效热更新缓存
    monkeypatch.setattr(Config, "FOFA_KEY", "", raising=False)
    monkeypatch.setattr(Config, "GITHUB_TOKEN", "", raising=False)
    monkeypatch.setattr(Config, "QUERY_PLUGIN_CONFIG", {}, raising=False)

    from app.routes import integration_ns

    app = Flask(__name__)
    api = Api(app, prefix="/api", doc=False)
    api.add_namespace(integration_ns)
    return {"client": app.test_client(), "db": fake,
            "config_path": str(config_path),
            "integration": integration_mod}


H = {"Token": "static-api-key"}


# ------------------------------------------------------------ 视图 ----
def test_view_masks_sensitive_values(web):
    resp = web["client"].get("/api/integration/", headers=H)
    body = resp.get_json()
    assert body["code"] == 200
    data = body["data"]
    groups = {g["group"]: g for g in data["groups"]}
    fofa = next(i for i in groups["mapping"]["items"] if i["vendor"] == "fofa")
    assert fofa["configured"] is True
    assert fofa["values"]["key"].startswith("fofa")
    assert "****" in fofa["values"]["key"]
    assert "fofa-key-abcdef123456" not in json.dumps(body)
    # 鹰图未配置 + 带被动收集开关
    hunter = next(i for i in groups["mapping"]["items"] if i["vendor"] == "hunter_qax")
    assert hunter["configured"] is False
    assert hunter["enabled"] is False
    # 免密来源清单
    assert any(s["vendor"] == "crtsh" for s in data["keyless_sources"])


def test_view_has_field_display_names(web):
    resp = web["client"].get("/api/integration/", headers=H)
    fofa = next(i for g in resp.get_json()["data"]["groups"]
                for i in g["items"] if i["vendor"] == "fofa")
    assert {"key": "key", "label": "API Key"} in fofa["field_defs"]


# ------------------------------------------------------------ 保存 ----
def test_save_vendor_updates_yaml_and_process_config(web):
    resp = web["client"].post("/api/integration/", headers=H, json={
        "vendor": "hunter_qax",
        "fields": {"api_key": "hunter-key-9876543210"},
        "enable": True})
    body = resp.get_json()
    assert body["code"] == 200 and body["data"]["updated"] == ["api_key"]

    saved = yaml.safe_load(open(web["config_path"]))
    assert saved["QUERY_PLUGIN"]["hunter_qax"]["api_key"] == "hunter-key-9876543210"
    assert saved["QUERY_PLUGIN"]["hunter_qax"]["enable"] is True

    view = web["client"].get("/api/integration/", headers=H).get_json()["data"]
    hunter = next(i for g in view["groups"] for i in g["items"]
                  if i["vendor"] == "hunter_qax")
    assert hunter["configured"] is True and hunter["enabled"] is True


def test_save_keeps_other_sections_and_masked_fields(web):
    """留空字段不改动（掩码回显语义），且不覆盖并发保存的其他段。"""
    resp = web["client"].post("/api/integration/", headers=H, json={
        "vendor": "fofa", "fields": {}})   # 空 fields：不改
    assert resp.get_json()["data"]["updated"] == []
    saved = yaml.safe_load(open(web["config_path"]))
    assert saved["FOFA"]["KEY"] == "fofa-key-abcdef123456"


def test_save_unknown_vendor_rejected(web):
    resp = web["client"].post("/api/integration/", headers=H, json={
        "vendor": "not_a_vendor", "fields": {"key": "x"}})
    assert resp.get_json()["code"] == 400


def test_clear_vendor_wipes_and_disables(web):
    web["client"].post("/api/integration/", headers=H, json={
        "vendor": "fofa", "fields": {"key": "k"}})
    resp = web["client"].post("/api/integration/", headers=H, json={
        "vendor": "fofa", "clear": True, "fields": {}})
    assert resp.get_json()["data"]["cleared"] == ["key"]
    saved = yaml.safe_load(open(web["config_path"]))
    assert saved["FOFA"]["KEY"] == ""
    assert saved["QUERY_PLUGIN"]["fofa"]["enable"] is False


# ------------------------------------------------------------ 热更新 ----
def test_reload_runtime_syncs_config_from_yaml(web):
    integration = web["integration"]
    assert Config.FOFA_KEY == ""          # 初始内存为空
    assert integration.reload_runtime() is True
    assert Config.FOFA_KEY == "fofa-key-abcdef123456"
    assert Config.QUERY_PLUGIN_CONFIG["crtsh"]["enable"] is True

    # mtime 未变 → 零开销短路
    assert integration.reload_runtime() is False

    # 改 yaml 后再次触发 → 同步（含 GITHUB_TOKEN）
    data = yaml.safe_load(open(web["config_path"]))
    data["GITHUB"] = {"TOKEN": "gh-token-123"}
    open(web["config_path"], "w").write(yaml.safe_dump(data))
    integration._mtime_cache["ts"] = None
    integration.reload_runtime()
    assert Config.GITHUB_TOKEN == "gh-token-123"


# ------------------------------------------------------------ 探活 ----
def test_test_vendor_dispatches_to_probe(web, monkeypatch):
    integration = web["integration"]
    web["client"].post("/api/integration/", headers=H, json={
        "vendor": "github", "fields": {"token": "gh-token-123"}})
    monkeypatch.setattr(integration, "_test_github",
                        lambda token: {"ok": True, "message": "鉴权成功：octocat"})
    resp = web["client"].post("/api/integration/test/", headers=H,
                              json={"vendor": "github"})
    body = resp.get_json()
    assert body["code"] == 200
    assert body["data"]["ok"] is True
    assert "octocat" in body["data"]["message"]


def test_test_vendor_unconfigured(web):
    resp = web["client"].post("/api/integration/test/", headers=H,
                              json={"vendor": "quake_360"})
    assert resp.get_json()["data"]["ok"] is False


def test_test_vendor_without_probe_reports_untested(web):
    web["client"].post("/api/integration/", headers=H, json={
        "vendor": "chaos", "fields": {"api_key": "chaos-key-001"}})
    resp = web["client"].post("/api/integration/test/", headers=H,
                              json={"vendor": "chaos"})
    data = resp.get_json()["data"]
    assert data["ok"] is True and data["tested"] is False
