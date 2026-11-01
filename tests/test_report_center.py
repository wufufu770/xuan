"""报告中心测试：xlsx 真实生成 / 统计摘要 / job 生命周期 / REST。"""

import os
import time
from bson import ObjectId

import pytest
from flask import Flask
from flask_restx import Api

from app.config import Config
from app.services import report_center
from tests.fake_db import FakeDB

SCOPE = "scope-r1"


@pytest.fixture
def env(monkeypatch, tmp_path):
    fake = FakeDB()
    monkeypatch.setattr(report_center.utils, "conn_db", fake.conn_db)
    # auth 链（user/audit 模块）也必须打桩，否则真连 Mongo 30s 超时
    import app.utils as utils_pkg
    from app.utils import user as user_mod
    from app.utils import audit as audit_mod
    monkeypatch.setattr(utils_pkg, "conn_db", fake.conn_db)
    monkeypatch.setattr(user_mod, "conn_db", fake.conn_db)
    monkeypatch.setattr(audit_mod, "conn_db", fake.conn_db)
    monkeypatch.setattr(Config, "AUTH", True, raising=False)
    monkeypatch.setattr(Config, "API_KEY", "static-api-key", raising=False)
    monkeypatch.setattr(Config, "REPORT_ROOT", str(tmp_path / "reports"))

    # 资产组数据
    fake.conn_db("task").insert_one({"_id": ObjectId(), "scope_id": SCOPE})
    fake.conn_db("domain").insert_one(
        {"scope_id": SCOPE, "domain": "a.com", "resolve_status": "resolved"})
    fake.conn_db("ip").insert_one(
        {"scope_id": SCOPE, "ip": "1.2.3.4",
         "port_info": [{"port_id": 80}, {"port_id": 443}]})
    fake.conn_db("site").insert_one(
        {"scope_id": SCOPE, "site": "http://a.com", "title": "首页", "status": 200,
         "finger": [{"name": "Nginx"}]})
    fake.conn_db("vulnerability").insert_one(
        {"scope_id": SCOPE, "vul_name": "SQLi", "severity": "high", "url": "http://a.com/x"})
    fake.conn_db("nuclei_vul").insert_one(
        {"scope_id": SCOPE, "vul_name": "CVE-2024-0001", "severity": "critical"})

    app = Flask(__name__)
    api = Api(app, prefix="/api", doc=False)
    from app.routes import report_ns
    api.add_namespace(report_ns)
    return {"client": app.test_client(), "db": fake,
            "h": {"Token": "static-api-key"}, "tmp": tmp_path}


def test_build_xlsx_real_file(env):
    data = report_center.collect_scope_data(SCOPE)
    path = os.path.join(str(env["tmp"]), "out.xlsx")
    counts = report_center.build_xlsx(data, path)

    assert os.path.exists(path) and os.path.getsize(path) > 0
    assert counts["域名"] == 1 and counts["站点"] == 1
    assert counts["漏洞"] == 2  # vulnerability + nuclei_vul

    from openpyxl import load_workbook
    wb = load_workbook(path)
    assert set(wb.sheetnames) == {"域名", "IP", "站点", "漏洞"}
    vuln_rows = list(wb["漏洞"].iter_rows(values_only=True))
    assert ["漏洞名", "严重程度", "URL"] == list(vuln_rows[0])
    assert any("CVE-2024-0001" in (r[0] or "") for r in vuln_rows[1:])


def test_summary_stats_aggregation(env):
    stats = report_center.build_summary_stats(report_center.collect_scope_data(SCOPE))
    assert stats["domains"] == 1 and stats["sites"] == 1
    assert stats["vuln_by_severity"].get("high") == 1
    assert stats["vuln_by_severity"].get("critical") == 1
    assert stats["top_fingerprints"] == [("Nginx", 1)]


def test_llm_summary_disabled_is_empty(env, monkeypatch):
    monkeypatch.setattr(report_center, "llm_summary", lambda stats: "")
    assert report_center.llm_summary({}) == ""


def test_job_lifecycle_sync_run(env, monkeypatch):
    sent = []
    job_oid = ObjectId()
    monkeypatch.setattr(report_center, "llm_summary",
                        lambda stats: "摘要：1 高危 1 严重")
    report_center.run_report_job(job_oid, SCOPE, "测试资产组", use_llm=True)

    job = env["db"].conn_db("report_job").docs[0]
    assert job["status"] == "done" and job["progress_done"] == 100

    reports = env["db"].conn_db("report").docs
    assert len(reports) == 1
    doc = reports[0]
    assert doc["summary"].startswith("摘要")
    assert doc["llm_used"] is True
    assert os.path.exists(doc["path"]) and doc["path"].startswith(str(env["tmp"]))

    # get_report 可回查
    fetched = report_center.get_report(str(doc["_id"]))
    assert fetched["filename"] == doc["filename"]


def test_job_error_captured(env, monkeypatch):
    job_oid = ObjectId()

    def boom(scope_id):
        raise RuntimeError("采集失败")
    monkeypatch.setattr(report_center, "collect_scope_data", boom)
    report_center.run_report_job(job_oid, SCOPE, "x", use_llm=False)

    job = env["db"].conn_db("report_job").docs[0]
    assert job["status"] == "error" and "采集失败" in job["error"]


# ------------------------------------------------------------- REST ----

def test_rest_generate_job_flow(env, monkeypatch):
    client, h = env["client"], env["h"]

    resp = client.post("/api/report/generate/",
                       json={"scope_id": SCOPE, "scope_name": "组A", "use_llm": False},
                       headers=h)
    assert resp.get_json()["code"] == 200
    job_id = resp.get_json()["data"]["job_id"]

    # 等线程完成
    for _ in range(50):
        job = report_center.get_job(job_id)
        if job and job.get("status") in ("done", "error"):
            break
        time.sleep(0.1)
    assert job["status"] == "done"
    report_id = job["report_id"]

    # 进度接口
    resp = client.get("/api/report/job/?job_id={}".format(job_id), headers=h)
    assert resp.get_json()["data"]["job"]["status"] == "done"

    # 下载
    resp = client.get("/api/report/download/?report_id={}".format(report_id), headers=h)
    assert resp.status_code == 200
    assert resp.data[:2] == b"PK"  # xlsx zip 魔数

    # 列表
    resp = client.get("/api/report/list/?scope_id={}".format(SCOPE), headers=h)
    items = resp.get_json()["data"]["items"]
    assert len(items) == 1 and "path" not in items[0]


def test_rest_generate_requires_scope_id(env):
    resp = env["client"].post("/api/report/generate/", json={},
                              headers=env["h"])
    body = resp.get_json() or {}
    # @ns.expect 的 required 校验（flask-restx 400 结构）或路由内校验（code=400）均可
    assert resp.status_code == 400 or body.get("code") == 400


def test_rest_download_rejects_path_escape(env, monkeypatch):
    # 伪造 report 记录指向 REPORT_ROOT 之外 → 拒绝下载
    env["db"].conn_db("report").insert_one(
        {"path": "/etc/passwd", "filename": "evil.xlsx"})
    evil_id = env["db"].conn_db("report").docs[-1]["_id"]
    resp = env["client"].get("/api/report/download/?report_id={}".format(evil_id),
                             headers=env["h"])
    assert resp.get_json()["code"] == 404
