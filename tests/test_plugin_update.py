"""插件在线更新服务测试（假 DB + 假 fetcher，不出网）。

覆盖：索引校验、SSRF 拒绝、sha256 防篡改、fingerprint/poc 两种载荷的
语义校验与落地、版本比对与安装记录。
"""

import hashlib
import json

import pytest

from app.config import Config
from app.services import plugin_update
from tests.fake_db import FakeDB


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _entry(payload: bytes, **kw):
    base = {"plugin": "finger-community", "version": "1.0.0",
            "kind": "fingerprint", "sha256": _sha(payload),
            "payload_url": "https://93.184.216.34/payload.json"}
    base.update(kw)
    return base


@pytest.fixture
def db(monkeypatch):
    fake = FakeDB()
    monkeypatch.setattr(plugin_update.utils, "conn_db", fake.conn_db)
    monkeypatch.setattr(Config, "PLUGIN_REGISTRY_URL", "https://93.184.216.34/index.json",
                        raising=False)
    return fake


# ------------------------------- 索引与 SSRF -------------------------------

def test_parse_index_valid():
    raw = json.dumps({"plugins": [{
        "plugin": "fp", "version": "1.2.0", "kind": "fingerprint",
        "sha256": "a" * 64, "payload_url": "https://x/y"}]}).encode()
    entries = plugin_update.parse_index(raw)
    assert entries[0]["plugin"] == "fp" and entries[0]["kind"] == "fingerprint"


def test_parse_index_rejects_bad_entries():
    for bad in (
        {"plugins": {}},
        {"plugins": [{"plugin": "", "version": "1", "kind": "fingerprint", "sha256": "a" * 64}]},
        {"plugins": [{"plugin": "x", "version": "1", "kind": "evil", "sha256": "a" * 64}]},
        {"plugins": [{"plugin": "x", "version": "1", "kind": "poc", "sha256": "zz"}]},
    ):
        with pytest.raises(ValueError):
            plugin_update.parse_index(json.dumps(bad).encode())


def test_validate_fetch_url_rejects_ssrf():
    for url in ("file:///etc/passwd", "http://127.0.0.1/x", "http://10.0.0.1/x",
                "http://169.254.169.254/latest/meta-data/", "ftp://93.184.216.34/x"):
        with pytest.raises(ValueError):
            plugin_update.validate_fetch_url(url)


def test_validate_fetch_url_accepts_public():
    assert plugin_update.validate_fetch_url("https://93.184.216.34/index.json")


# ------------------------------- 检查与安装 -------------------------------

def test_check_update_status_kinds(db):
    db.conn_db(plugin_update.PLUGIN_INSTALL_COLLECTION).insert_one(
        {"plugin": "fp", "version": "1.0.0"})
    index = json.dumps({"plugins": [
        {"plugin": "fp", "version": "1.1.0", "kind": "fingerprint",
         "sha256": "a" * 64, "payload_url": "https://93.184.216.34/fp.json"},
        {"plugin": "brand-new", "version": "0.1.0", "kind": "poc",
         "sha256": "b" * 64, "payload_url": "https://93.184.216.34/poc.json"},
    ]}).encode()
    items = plugin_update.check_update(fetcher=lambda u: index)
    status = {i["plugin"]: i["status"] for i in items}
    assert status == {"fp": "update", "brand-new": "new"}
    assert items[0]["installed_version"] == "1.0.0"


def test_check_update_requires_registry(db):
    Config.PLUGIN_REGISTRY_URL = ""
    with pytest.raises(ValueError):
        plugin_update.check_update(fetcher=lambda u: b"{}")


def test_install_rejects_checksum_mismatch(db):
    payload = json.dumps([{"name": "A", "rule": 'body="x"'}]).encode()
    entry = _entry(payload)
    entry["sha256"] = "0" * 64
    with pytest.raises(ValueError):
        plugin_update.install_plugin(entry, fetcher=lambda u: payload)
    assert db.conn_db(plugin_update.PLUGIN_INSTALL_COLLECTION).find({}) == []


def test_install_fingerprint_upserts_rules(db):
    payload = json.dumps([
        {"name": "FP-A", "rule": 'body="hello-world"'},
        {"name": "FP-BAD", "rule": 'body=='},
    ]).encode()
    result = plugin_update.install_plugin(_entry(payload), fetcher=lambda u: payload)
    assert result["result"] == {"inserted": 1, "updated": 0, "invalid": 1}
    docs = db.conn_db("fingerprint").find({})
    assert [d["name"] for d in docs] == ["FP-A"]

    # 同名再装不同版本 = updated
    payload2 = json.dumps([{"name": "FP-A", "rule": 'title="x"'}]).encode()
    entry2 = _entry(payload2, version="1.1.0")
    result2 = plugin_update.install_plugin(entry2, fetcher=lambda u: payload2)
    assert result2["result"]["updated"] == 1
    rec = db.conn_db(plugin_update.PLUGIN_INSTALL_COLLECTION).find_one({"plugin": "finger-community"})
    assert rec["version"] == "1.1.0"


def test_install_poc_file_rules(db, tmp_path):
    good = json.dumps({"file": "my_poc.py", "code": "VALUE = 1\n"}).encode()
    entry = _entry(good, kind="poc", plugin="poc-pack")
    result = plugin_update.install_plugin(entry, fetcher=lambda u: good,
                                          plugins_dir=str(tmp_path))
    assert result["result"]["file"] == "my_poc.py"
    assert (tmp_path / "my_poc.py").read_text() == "VALUE = 1\n"

    # 文件名白名单
    bad_name = json.dumps({"file": "../evil.py", "code": "x=1"}).encode()
    with pytest.raises(ValueError):
        plugin_update.install_plugin(
            _entry(bad_name, kind="poc", plugin="evil"), fetcher=lambda u: bad_name,
            plugins_dir=str(tmp_path))

    # 语法错误拒绝
    bad_code = json.dumps({"file": "broken.py", "code": "def (:\n"}).encode()
    with pytest.raises(ValueError):
        plugin_update.install_plugin(
            _entry(bad_code, kind="poc", plugin="broken"), fetcher=lambda u: bad_code,
            plugins_dir=str(tmp_path))
    assert not (tmp_path / "broken.py").exists()
