"""执行图编译与监控 diff 历史路由测试。"""

from bson import ObjectId

import pytest
from flask import Flask
from flask_restx import Api

from app.config import Config
from app.services import engine_graph
from app.utils import user as user_mod
from app.utils import audit as audit_mod
from tests.fake_db import FakeDB

POLICY_FULL = {
    "domain_config": {"domain_brute": True, "dns_query_plugin": True},
    "ip_config": {"port_scan": True, "port_scan_type": "test",
                  "ssl_cert": False, "site_identify": True},
    "site_config": {"site_capture": False},
    "poc_config": [],
    "brute_config": [],
}


# ------------------------------------------------------- 执行图 ----

def test_graph_phases_and_states():
    graph = engine_graph.build_engine_graph(POLICY_FULL)
    phases = {p["phase"] for p in graph["phases"]}
    assert phases == {"light", "heavy_top", "heavy_full", "post", "post_finalize"}

    nodes = {n["stage"]: n for p in graph["phases"] for n in p["nodes"]}
    assert nodes["domain_brute"]["state"] == "enabled"
    assert nodes["port_scan_top1000"]["state"] == "enabled"
    assert nodes["port_scan_full"]["state"] == "disabled"      # test 档无全端口
    assert nodes["ssl_cert"]["state"] == "disabled"
    assert nodes["find_site"]["state"] == "enabled"
    assert nodes["site_capture"]["state"] == "disabled"
    assert nodes["poc_run"]["state"] == "disabled"             # poc_config 为空
    assert nodes["weak_brute"]["state"] == "disabled"
    assert nodes["ai_judge"]["state"] == "auto"                # 无显式选项键

    # 边：阶段内顺序 + 阶段间衔接
    edges = {(e["from"], e["to"]) for e in graph["edges"]}
    assert ("domain_brute", "dns_query_plugin") in edges
    assert ("asset_seed_prefill", "port_scan_top1000") in edges  # light→heavy_top
    assert graph["summary"]["total_stages"] == len(engine_graph.TASK_STAGE_ORDER)


def test_graph_full_port_scan_enables_full_stage():
    policy = {"ip_config": {"port_scan": True, "port_scan_type": "custom",
                            "port_custom": "1-65535"}}
    graph = engine_graph.build_engine_graph(policy)
    nodes = {n["stage"]: n for p in graph["phases"] for n in p["nodes"]}
    assert nodes["port_scan_full"]["state"] == "enabled"


def test_graph_unknown_options_ignored():
    graph = engine_graph.build_engine_graph({"domain_config": {"totally_unknown": True}})
    assert graph["summary"]["auto"] > 0


# --------------------------------------------------- diff 历史路由 ----

@pytest.fixture
def env(monkeypatch):
    fake = FakeDB()
    monkeypatch.setattr(user_mod, "conn_db", fake.conn_db)
    monkeypatch.setattr(audit_mod, "conn_db", fake.conn_db)
    monkeypatch.setattr(Config, "AUTH", True, raising=False)
    monkeypatch.setattr(Config, "API_KEY", "static-api-key", raising=False)

    import app.routes.monitor_diff as monitor_diff_mod
    monkeypatch.setattr(monitor_diff_mod.utils, "conn_db", fake.conn_db)

    app = Flask(__name__)
    api = Api(app, prefix="/api", doc=False)
    from app.routes import monitor_diff_ns
    api.add_namespace(monitor_diff_ns)
    return {"client": app.test_client(), "db": fake,
            "h": {"Token": "static-api-key"}}


def test_diff_list_and_detail(env):
    diff_doc = {
        "job_id": "job-1", "scope_id": "scope-1", "source": "domain",
        "target": "example.com", "run_date": "2026-10-30 00:00:00",
        "run_number": 2,
        "diff": {"domains": {"added": ["new.com"], "removed": [],
                             "added_total": 1, "removed_total": 0},
                 "ports": {"added": [], "removed": [],
                           "added_total": 0, "removed_total": 0},
                 "sites": {"added": [], "removed": [], "changed": [],
                           "added_total": 0, "removed_total": 0,
                           "changed_total": 0}},
    }
    env["db"].conn_db("monitor_diff").insert_one(diff_doc)

    resp = env["client"].get("/api/monitor_diff/list/?job_id=job-1",
                             headers=env["h"])
    body = resp.get_json()
    assert body["code"] == 200 and body["data"]["total"] == 1
    item = body["data"]["items"][0]
    assert item["target"] == "example.com"
    assert item["summary"]["domains"]["added_total"] == 1

    resp = env["client"].get("/api/monitor_diff/detail/?diff_id={}".format(item["_id"]),
                             headers=env["h"])
    detail = resp.get_json()["data"]["diff"]
    assert detail["diff"]["domains"]["added"] == ["new.com"]


def test_diff_list_filters(env):
    for job in ("job-a", "job-b"):
        env["db"].conn_db("monitor_diff").insert_one(
            {"job_id": job, "scope_id": "scope-1"})
    resp = env["client"].get("/api/monitor_diff/list/?job_id=job-a",
                             headers=env["h"])
    items = resp.get_json()["data"]["items"]
    assert len(items) == 1 and items[0]["job_id"] == "job-a"


def test_diff_detail_rejects_bad_id(env):
    resp = env["client"].get("/api/monitor_diff/detail/?diff_id=not-an-objectid",
                             headers=env["h"])
    assert resp.get_json()["code"] == 400


def test_diff_detail_404(env):
    resp = env["client"].get("/api/monitor_diff/detail/?diff_id={}".format(ObjectId()),
                             headers=env["h"])
    assert resp.get_json()["code"] == 404


# ------------------------------------------------- 执行图 REST ----

@pytest.fixture
def graph_env(monkeypatch):
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


def test_graph_endpoint(graph_env):
    oid = ObjectId()
    graph_env["db"].conn_db("policy").insert_one(
        {"_id": oid, "name": "eng", "policy": POLICY_FULL})
    resp = graph_env["client"].get("/api/policy_yaml/graph/?policy_id={}".format(oid),
                                   headers=graph_env["h"])
    body = resp.get_json()
    assert body["code"] == 200
    assert body["data"]["name"] == "eng"
    assert body["data"]["graph"]["summary"]["enabled"] >= 4
