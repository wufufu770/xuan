"""扫描引擎 YAML 导出/导入/克隆测试（假 DB，不出网）。"""

import time
from bson import ObjectId

import pytest
from flask import Flask
from flask_restx import Api

from app.config import Config
from app.utils import user as user_mod
from app.utils import audit as audit_mod
from tests.fake_db import FakeDB

POLICY_DOC = {
    "name": "base-engine",
    "desc": "基准引擎",
    "policy": {
        "domain_config": {"domain_brute": True, "domain_dict": ""} if False else {},
        "ip_config": {"port_scan_type": "test"},
        "site_config": {},
        "poc_config": [],
        "brute_config": [],
        "file_leak": False,
        "npoc_service_detection": False,
        "scope_config": {},
    },
}


@pytest.fixture
def env(monkeypatch):
    fake = FakeDB()
    monkeypatch.setattr(user_mod, "conn_db", fake.conn_db)
    monkeypatch.setattr(audit_mod, "conn_db", fake.conn_db)
    monkeypatch.setattr(Config, "AUTH", True, raising=False)
    monkeypatch.setattr(Config, "API_KEY", "static-api-key", raising=False)

    import app.routes.policy_yaml as policy_yaml_mod
    monkeypatch.setattr(policy_yaml_mod.utils, "conn_db", fake.conn_db)

    app = Flask(__name__)
    api = Api(app, prefix="/api", doc=False)
    from app.routes import policy_yaml_ns
    api.add_namespace(policy_yaml_ns)
    return {"client": app.test_client(), "db": fake,
            "h": {"Token": "static-api-key"}}


def _insert_policy(env):
    oid = ObjectId()
    doc = dict(POLICY_DOC)
    doc["_id"] = oid
    env["db"].conn_db("policy").insert_one(doc)
    return oid


def test_yaml_export_round_trip(env):
    oid = _insert_policy(env)

    resp = env["client"].get("/api/policy_yaml/yaml_export/?policy_id={}".format(oid), headers=env["h"])
    body = resp.get_json()
    assert body["code"] == 200, body
    text = body["data"]["yaml"]
    assert "base-engine" in text and "policy:" in text

    # 导入 → 新策略入库
    resp = env["client"].post("/api/policy_yaml/yaml_import/",
                              json={"name": "imported-engine", "yaml": text}, headers=env["h"])
    body = resp.get_json()
    assert body["code"] == 200, body
    new_id = body["data"]["policy_id"]
    imported = env["db"].conn_db("policy").find_one({"_id": ObjectId(new_id)})
    assert imported["name"] == "imported-engine"
    assert imported["policy"]["ip_config"]["port_scan_type"] == "test"


def test_yaml_import_rejects_missing_policy_node(env):
    resp = env["client"].post("/api/policy_yaml/yaml_import/",
                              json={"name": "x", "yaml": "name: only"}, headers=env["h"])
    body = resp.get_json()
    assert body["code"] != 200
    assert "policy 节点" in body["data"]["error"]


def test_yaml_import_rejects_bad_yaml(env):
    resp = env["client"].post("/api/policy_yaml/yaml_import/",
                              json={"name": "x", "yaml": "a: [unclosed"}, headers=env["h"])
    body = resp.get_json()
    assert body["code"] != 200
    assert "YAML 解析失败" in body["data"]["error"]


def test_yaml_import_rejects_empty_name(env):
    resp = env["client"].post("/api/policy_yaml/yaml_import/",
                              json={"name": "  ",
                                    "yaml": "policy: {}"}, headers=env["h"])
    assert resp.get_json()["code"] != 200


def test_clone_copies_policy(env):
    oid = _insert_policy(env)
    resp = env["client"].post("/api/policy_yaml/clone/",
                              json={"policy_id": str(oid), "name": "cloned"}, headers=env["h"])
    body = resp.get_json()
    assert body["code"] == 200, body
    cloned = env["db"].conn_db("policy").find_one({"_id": ObjectId(body["data"]["policy_id"])})
    assert cloned["name"] == "cloned"
    assert cloned["policy"] == POLICY_DOC["policy"]
    assert "clone of: base-engine" in cloned["desc"]


def test_clone_unknown_policy(env):
    resp = env["client"].post("/api/policy_yaml/clone/",
                              json={"policy_id": str(ObjectId()), "name": "x"}, headers=env["h"])
    assert resp.get_json()["code"] != 200
