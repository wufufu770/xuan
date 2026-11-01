"""统一控制台 API 面测试：/ai/judge 批量研判下发与 /github_scheduler/ 添加。

前端融合重构后（console 原生 17 页，无 bundle iframe），REST 面去冗余：
  POST /api/ai/judge            {site_ids, collection, scope}  → celery 异步研判
  POST /api/github_scheduler/   {name, keyword, cron}          → 泄露监控计划
"""

import pytest
from flask import Flask
from flask_restx import Api

from app.config import Config
from app.modules import CeleryAction
from app.utils import user as user_mod
from app.utils import audit as audit_mod
from tests.fake_db import FakeDB


@pytest.fixture
def web(monkeypatch, tmp_path):
    fake = FakeDB()
    monkeypatch.setattr(user_mod, "conn_db", fake.conn_db)
    monkeypatch.setattr(audit_mod, "conn_db", fake.conn_db)
    monkeypatch.setattr(Config, "AUTH", True, raising=False)
    monkeypatch.setattr(Config, "API_KEY", "static-api-key", raising=False)

    # 路由经 `from app import utils` 动态引用 utils.conn_db —— patch 模块属性
    import app.utils as utils_pkg
    monkeypatch.setattr(utils_pkg, "conn_db", fake.conn_db)

    from app.routes import ai_judge_ns, github_scheduler_ns

    app = Flask(__name__)
    api = Api(app, prefix="/api", doc=False)
    for ns in (ai_judge_ns, github_scheduler_ns):
        api.add_namespace(ns)
    return {"client": app.test_client(), "db": fake}


H = {"Token": "static-api-key"}


def test_ai_judge_dispatches_celery_task(web, monkeypatch):
    """POST /ai/judge 走 celery 异步队列（arl_post.AI_JUDGE_TASK）。"""
    import app.celerytask as celerytask_mod

    called = {}

    class FakeAsyncResult:
        def __str__(self):
            return "celery-id-123"

    def fake_apply_async(kwargs=None, **_kw):
        called["options"] = (kwargs or {}).get("options")
        return FakeAsyncResult()

    monkeypatch.setattr(celerytask_mod.arl_post, "apply_async", fake_apply_async)

    resp = web["client"].post(
        "/api/ai/judge",
        json={"site_ids": ["a1", "b2"], "collection": "site", "scope": "批量研判"},
        headers=H)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["code"] == 200
    assert body["data"]["ok"] is True
    assert body["data"]["site_count"] == 2
    assert body["data"]["celery_id"] == "celery-id-123"
    assert called["options"]["celery_action"] == CeleryAction.AI_JUDGE_TASK
    assert called["options"]["data"]["site_ids"] == ["a1", "b2"]


def test_ai_judge_rejects_empty_site_ids(web):
    resp = web["client"].post(
        "/api/ai/judge", json={"site_ids": []}, headers=H)
    body = resp.get_json()
    assert body["code"] == 200
    assert body["data"]["ok"] is False


def test_ai_judge_rejects_oversize_batch(web):
    resp = web["client"].post(
        "/api/ai/judge",
        json={"site_ids": ["x{}".format(i) for i in range(51)]},
        headers=H)
    body = resp.get_json()
    assert body["data"]["ok"] is False
    assert "上限 50" in body["data"]["message"]


def test_github_scheduler_add_creates_task(web):
    resp = web["client"].post(
        "/api/github_scheduler/",
        json={"name": "监控A", "keyword": "wufufu770", "cron": "0 0 * * *"},
        headers=H)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["code"] == 200
    doc = web["db"].conn_db("github_scheduler").find_one({"keyword": "wufufu770"})
    assert doc and doc["name"] == "监控A" and doc["status"] == "running"


def test_github_scheduler_add_rejects_bad_cron(web):
    resp = web["client"].post(
        "/api/github_scheduler/",
        json={"name": "监控B", "keyword": "kw", "cron": "not-a-cron"},
        headers=H)
    body = resp.get_json()
    assert body["code"] != 200
    assert web["db"].conn_db("github_scheduler").find_one({"keyword": "kw"}) is None
