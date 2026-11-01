"""企业情报资产检索 /asset_ext/ 测试（APP/小程序/ICP 展平 + 关键字 + 分页）。"""

import pytest
from flask import Flask
from flask_restx import Api

from app.config import Config
from app.utils import user as user_mod
from app.utils import audit as audit_mod
from tests.fake_db import FakeDB


def _intel_doc(ent, **kw):
    doc = {"ent_name": ent, "group_id": "g1", "path": ent,
           "icp": [], "app": [], "miniprogram": [], "error": ""}
    doc.update(kw)
    return doc


@pytest.fixture
def web(monkeypatch):
    fake = FakeDB()
    monkeypatch.setattr(user_mod, "conn_db", fake.conn_db)
    monkeypatch.setattr(audit_mod, "conn_db", fake.conn_db)
    monkeypatch.setattr(Config, "AUTH", True, raising=False)
    monkeypatch.setattr(Config, "API_KEY", "static-api-key", raising=False)

    import app.utils as utils_pkg
    monkeypatch.setattr(utils_pkg, "conn_db", fake.conn_db)

    coll = fake.conn_db("fengniao_intel")
    coll.insert_one(_intel_doc(
        "科大讯飞",
        app=[{"appname": "讯飞输入法", "downloadCountLevel": "亿级",
              "updateDateAndroid": "2026-09-01"},
             {"appname": "讯飞星火", "downloadCountLevel": "千万级"}],
        miniprogram=[{"name": "讯飞小程序", "cate": "工具"}],
        icp=[{"hostname": "iflytek.com", "icpnum": "皖ICP备05001217",
              "webname": "科大讯飞", "shdate": "2026-01-01"}]))
    coll.insert_one(_intel_doc(
        "另一家",
        app=[{"appname": "云盘", "downloadCountLevel": "百万级"}]))

    from app.routes import asset_ext_ns

    app = Flask(__name__)
    api = Api(app, prefix="/api", doc=False)
    api.add_namespace(asset_ext_ns)
    return {"client": app.test_client()}


H = {"Token": "static-api-key"}


def test_app_kind_flattens_and_pages(web):
    resp = web["client"].get("/api/asset_ext/?kind=app", headers=H)
    body = resp.get_json()
    assert body["code"] == 200
    data = body["data"]
    assert data["total"] == 3
    names = [i["appname"] for i in data["items"]]
    assert names == ["云盘", "讯飞输入法", "讯飞星火"]      # 企业 _id 倒序，组内保持采集序
    assert data["items"][0]["ent_name"] == "另一家"


def test_keyword_matches_ent_and_item(web):
    resp = web["client"].get("/api/asset_ext/?kind=app&keyword=讯飞", headers=H)
    data = resp.get_json()["data"]
    assert data["total"] == 2 and all("讯飞" in i["appname"] or "讯飞" in i["ent_name"]
                                      for i in data["items"])
    resp = web["client"].get("/api/asset_ext/?kind=app&keyword=云盘", headers=H)
    assert resp.get_json()["data"]["total"] == 1


def test_miniprogram_and_icp_kinds(web):
    r1 = web["client"].get("/api/asset_ext/?kind=miniprogram", headers=H)
    assert r1.get_json()["data"]["items"][0]["cate"] == "工具"
    r2 = web["client"].get("/api/asset_ext/?kind=icp", headers=H)
    items = r2.get_json()["data"]["items"]
    assert items[0]["hostname"] == "iflytek.com"
    assert items[0]["icpnum"] == "皖ICP备05001217"


def test_invalid_kind_rejected(web):
    resp = web["client"].get("/api/asset_ext/?kind=nope", headers=H)
    assert resp.get_json()["code"] != 200


def test_pagination(web):
    resp = web["client"].get("/api/asset_ext/?kind=app&page=2&size=2", headers=H)
    data = resp.get_json()["data"]
    assert data["total"] == 3 and len(data["items"]) == 1
