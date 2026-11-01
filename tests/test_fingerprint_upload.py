"""指纹上传增强测试：去重/覆盖更新/非法表达式（ADD-ARL-Finger 兼容格式）。"""

import io

import pytest
from flask import Flask
from flask_restx import Api

from app.config import Config
from app.utils import user as user_mod
from app.utils import audit as audit_mod
from tests.fake_db import FakeDB


@pytest.fixture
def env(monkeypatch):
    fake = FakeDB()
    monkeypatch.setattr(user_mod, "conn_db", fake.conn_db)
    monkeypatch.setattr(audit_mod, "conn_db", fake.conn_db)
    monkeypatch.setattr(Config, "AUTH", True, raising=False)
    monkeypatch.setattr(Config, "API_KEY", "static-api-key", raising=False)

    import app.routes.fingerprint as fingerprint_mod
    monkeypatch.setattr(fingerprint_mod.utils, "conn_db", fake.conn_db)

    app = Flask(__name__)
    api = Api(app, prefix="/api", doc=False)
    from app.routes import fingerprint_ns
    api.add_namespace(fingerprint_ns)
    return {"client": app.test_client(), "db": fake,
            "h": {"Token": "static-api-key"}}


def _upload(client, rules, headers, update=False):
    import yaml
    data = {"file": (io.BytesIO(yaml.safe_dump(rules).encode()), "fp.yml"),
            "update": "true" if update else "false"}
    return client.post("/api/fingerprint/upload/", data=data,
                       content_type="multipart/form-data",
                       headers=headers)


def test_upload_new_rules(env):
    rules = [{"name": "TestFp1", "rule": 'body="hello-world"'},
             {"name": "TestFp2", "rule": 'title="管理后台"'}]
    resp = _upload(env["client"], rules, env["h"])
    body = resp.get_json()
    assert body["code"] == 200
    assert body["data"]["success_cnt"] == 2
    assert len(env["db"].conn_db("fingerprint").docs) == 2


def test_upload_repeat_skipped_by_default(env):
    rules = [{"name": "TestFp1", "rule": 'body="hello-world"'}]
    _upload(env["client"], rules, env["h"])
    resp = _upload(env["client"], rules, env["h"])
    body = resp.get_json()
    assert body["data"]["repeat_cnt"] == 1
    assert body["data"]["success_cnt"] == 0
    # 名称未被覆盖
    doc = env["db"].conn_db("fingerprint").docs[0]
    assert doc["name"] == "TestFp1"


def test_upload_update_overwrites_name(env):
    rules = [{"name": "TestFp1", "rule": 'body="hello-world"'}]
    _upload(env["client"], rules, env["h"])
    renamed = [{"name": "TestFp1-v2", "rule": 'body="hello-world"'}]
    resp = _upload(env["client"], renamed, env["h"], update=True)
    body = resp.get_json()
    assert body["data"]["update_cnt"] == 1
    doc = env["db"].conn_db("fingerprint").docs[0]
    assert doc["name"] == "TestFp1-v2"


def test_upload_invalid_expression_counted(env):
    rules = [{"name": "Bad", "rule": "not a valid ((( expression"}]
    resp = _upload(env["client"], rules, env["h"])
    body = resp.get_json()
    assert body["data"]["error_cnt"] == 1
    assert len(env["db"].conn_db("fingerprint").docs) == 0
