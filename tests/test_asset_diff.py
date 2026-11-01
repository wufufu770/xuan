"""监控资产 diff 引擎测试（假 DB + 告警 Mock，不出网）。"""

import pytest

from app.config import Config
from app.services import asset_diff
from tests.fake_db import FakeDB

SCOPE = "scope-1"
JOB = "job-1"


@pytest.fixture
def db(monkeypatch):
    fake = FakeDB()
    monkeypatch.setattr(asset_diff.utils, "conn_db", fake.conn_db)
    return fake


@pytest.fixture
def scope_assets(db, monkeypatch):
    """资产组当前状态：domains / asset_ip / asset_site / fengniao_group。

    asset_ip/asset_site 用本地假集合；其余集合（asset_snapshot/monitor_diff）
    委托给 db 的 FakeDB。sites 元组为 (site, finger[, title])。
    """
    state = {
        "domains": [],
        "ip_ports": [],
        "sites": [],
        "groups": [],
    }

    def fake_get_domains(scope_id):
        return state["domains"] if scope_id == SCOPE else []

    class FakeColl:
        def __init__(self, rows):
            self.rows = rows

        def find(self, query, projection=None):
            return [r for r in self.rows
                    if r.get("scope_id") == query.get("scope_id")]

    class FakeGroupColl:
        def find(self, query, projection=None):
            want = query.get("companies.asset_scope_id")
            return [g for g in state["groups"]
                    if any(str(n.get("asset_scope_id") or "") == str(want)
                           for n in g.get("companies") or [])]

    def fake_conn(name):
        if name == "asset_ip":
            return FakeColl([{"scope_id": SCOPE, "ip": ip, "port_info":
                              [{"port_id": p} for p in ports]}
                             for ip, ports in state["ip_ports"]])
        if name == "asset_site":
            rows = []
            for entry in state["sites"]:
                site, fingers = entry[0], entry[1]
                title = entry[2] if len(entry) > 2 else ""
                rows.append({"scope_id": SCOPE, "site": site,
                             "finger": fingers, "title": title})
            return FakeColl(rows)
        if name == "fengniao_group":
            return FakeGroupColl()
        return db.conn_db(name)

    monkeypatch.setattr(asset_diff.utils, "get_asset_domain_by_id", fake_get_domains)
    monkeypatch.setattr(asset_diff.utils, "conn_db", fake_conn)
    return state


@pytest.fixture(autouse=True)
def _enable(monkeypatch):
    monkeypatch.setattr(Config, "MONITOR_DIFF_ENABLE", True, raising=False)
    # 单测不出网：默认证书采集器返回 None（各用例自行注入假采集器）
    monkeypatch.setattr(asset_diff, "_default_cert_end_date", lambda target: None)


def test_capped_dedupes_sorts_and_flags():
    values = ["b", "a", "b", "c"]
    items, total, truncated = asset_diff._capped(values, limit=2)
    assert items == ["a", "b"]
    assert total == 3 and truncated is True
    items, total, truncated = asset_diff._capped(["a"], limit=5)
    assert (items, total, truncated) == (["a"], 1, False)


def test_diff_snapshots_dimensions():
    prev = {
        "domains": ["a.com", "b.com"],
        "ports": ["1.1.1.1:80"],
        "sites": ["http://a.com|Nginx", "http://gone.com|Tomcat"],
    }
    curr = {
        "domains": ["b.com", "c.com"],
        "ports": ["1.1.1.1:80", "1.1.1.1:443"],
        "sites": ["http://a.com|Nginx,PHP", "http://new.com|Apache"],
    }
    diff = asset_diff.diff_snapshots(prev, curr)
    assert diff["domains"]["added"] == ["c.com"]
    assert diff["domains"]["removed"] == ["a.com"]
    assert diff["ports"]["added"] == ["1.1.1.1:443"]
    assert diff["ports"]["removed_total"] == 0
    assert diff["sites"]["added"] == ["http://new.com"]
    assert diff["sites"]["removed"] == ["http://gone.com"]
    assert diff["sites"]["changed"] == ["http://a.com"]   # 指纹 Nginx -> Nginx,PHP
    assert asset_diff.has_changes(diff)


def test_diff_snapshots_no_changes():
    same = {"domains": ["a.com"], "ports": ["1.1.1.1:80"],
            "sites": ["http://a.com|Nginx"]}
    diff = asset_diff.diff_snapshots(same, same)
    assert not asset_diff.has_changes(diff)


def test_first_run_only_snapshot(db, scope_assets):
    scope_assets["domains"] = ["a.com"]
    sent = []

    result = asset_diff.run_scope_diff(job_id=JOB, scope_id=SCOPE, source="domain",
                                       notify=lambda t, m: sent.append(t))
    assert result is None                       # 首次运行不告警
    assert sent == []
    snap = db.conn_db(asset_diff.SNAPSHOT_COLLECTION).find_one({"job_id": JOB})
    assert snap and snap["domains"] == ["a.com"] and snap["run_number"] == 1
    assert db.conn_db(asset_diff.DIFF_COLLECTION).docs == []


def test_second_run_change_alerts(db, scope_assets, monkeypatch):
    scope_assets["domains"] = ["a.com"]
    sent = []
    asset_diff.run_scope_diff(job_id=JOB, scope_id=SCOPE, source="domain",
                              notify=lambda t, m: sent.append((t, m)))

    scope_assets["domains"] = ["a.com", "new.com"]
    scope_assets["ip_ports"] = [("1.2.3.4", [80, 443])]
    scope_assets["sites"] = [("http://a.com", [{"name": "Nginx"}])]
    diff_id = asset_diff.run_scope_diff(job_id=JOB, scope_id=SCOPE,
                                        source="domain", task_id="t9",
                                        target="example.com",
                                        notify=lambda t, m: sent.append((t, m)))
    assert diff_id
    assert len(sent) == 1
    title, body = sent[0]
    assert "example.com" in title
    assert "new.com" in body and "443" in body and "http://a.com" in body

    doc = db.conn_db(asset_diff.DIFF_COLLECTION).docs[0]
    assert doc["diff"]["domains"]["added"] == ["new.com"]
    assert doc["diff"]["ports"]["added_total"] == 2
    assert doc["run_number"] == 2
    snap = db.conn_db(asset_diff.SNAPSHOT_COLLECTION).find_one({"job_id": JOB})
    assert snap["run_number"] == 2 and "1.2.3.4:443" in snap["ports"]


def test_second_run_no_change_no_alert(db, scope_assets, monkeypatch):
    scope_assets["domains"] = ["a.com"]
    asset_diff.run_scope_diff(job_id=JOB, scope_id=SCOPE, source="domain",
                              notify=lambda t, m: None)
    sent = []
    asset_diff.run_scope_diff(job_id=JOB, scope_id=SCOPE, source="domain",
                              notify=lambda t, m: sent.append(t))
    assert sent == []
    assert db.conn_db(asset_diff.DIFF_COLLECTION).docs == []


def test_disabled_flag_skips_everything(db, scope_assets, monkeypatch):
    monkeypatch.setattr(Config, "MONITOR_DIFF_ENABLE", False, raising=False)
    scope_assets["domains"] = ["a.com"]
    result = asset_diff.run_scope_diff(job_id=JOB, scope_id=SCOPE, source="domain",
                                       notify=lambda t, m: None)
    assert result is None
    assert db.conn_db(asset_diff.SNAPSHOT_COLLECTION).docs == []


def test_db_failure_swallowed(db, scope_assets, monkeypatch):
    scope_assets["domains"] = ["a.com"]

    def boom(name):
        raise RuntimeError("db down")
    monkeypatch.setattr(asset_diff.utils, "conn_db", boom)
    assert asset_diff.run_scope_diff(job_id=JOB, scope_id=SCOPE, source="domain",
                                     notify=lambda t, m: None) is None


# ------------------------- 页面标题 / 证书到期 / 新增 APP（方案书369:6） ----

def test_titles_changed_detected():
    prev = {"titles": ["http://a.com|旧标题"]}
    curr = {"titles": ["http://a.com|新标题", "http://b.com|B"]}
    diff = asset_diff.diff_snapshots(prev, curr)
    assert diff["titles"]["changed"] == ["http://a.com"]
    assert diff["titles"]["added"] == ["http://b.com"]
    assert asset_diff.has_changes(diff)


def test_titles_baseline_upgrade_quiet():
    """旧格式快照（无 titles 键）首轮只补基线，标题不告警。"""
    prev = {"domains": ["a.com"]}
    curr = {"domains": ["a.com"], "titles": ["http://a.com|标题X"]}
    diff = asset_diff.diff_snapshots(prev, curr)
    assert diff["titles"]["added_total"] == 0
    assert not asset_diff.has_changes(diff)


def test_certs_renewal_and_newly_expiring():
    prev = {"certs": ["1.1.1.1:443|2026-06-01 00:00:00"], "certs_expiring": []}
    curr = {"certs": ["1.1.1.1:443|2027-06-01 00:00:00", "2.2.2.2:443|2026-01-05 00:00:00"],
            "certs_expiring": ["2.2.2.2:443|2026-01-05 00:00:00|5天后到期"]}
    diff = asset_diff.diff_snapshots(prev, curr)
    assert diff["certs"]["changed"] == ["1.1.1.1:443"]        # 续期
    assert diff["certs"]["expiring"] == ["2.2.2.2:443|2026-01-05 00:00:00|5天后到期"]
    assert diff["certs"]["expiring_total"] == 1
    assert asset_diff.has_changes(diff)


def test_certs_expiring_repeat_quiet():
    """同一批证书持续临期只在进入窗口那一轮告警。"""
    expiring = ["2.2.2.2:443|2026-01-05 00:00:00|3天后到期"]
    prev = {"certs": ["2.2.2.2:443|2026-01-05 00:00:00"], "certs_expiring": expiring}
    curr = {"certs": ["2.2.2.2:443|2026-01-05 00:00:00"], "certs_expiring": expiring}
    diff = asset_diff.diff_snapshots(prev, curr)
    assert diff["certs"]["expiring_total"] == 0
    assert not asset_diff.has_changes(diff)


def test_apps_added_removed():
    prev = {"apps": ["企业微信"]}
    curr = {"apps": ["企业微信", "掌上银行"]}
    diff = asset_diff.diff_snapshots(prev, curr)
    assert diff["apps"]["added"] == ["掌上银行"]
    assert asset_diff.has_changes(diff)
    diff2 = asset_diff.diff_snapshots(curr, prev)
    assert diff2["apps"]["removed"] == ["掌上银行"]


def test_collect_includes_new_dimensions(scope_assets, monkeypatch):
    scope_assets["domains"] = ["a.com"]
    scope_assets["ip_ports"] = [("1.2.3.4", [443])]
    scope_assets["sites"] = [("http://a.com", [{"name": "Nginx"}], "门户首页")]
    scope_assets["groups"] = [{"companies": [
        {"asset_scope_id": SCOPE, "app": [{"appname": "掌上银行"}, {"name": "企业版"}]},
        {"asset_scope_id": "other", "app": [{"appname": "不该出现"}]},
    ]}]
    monkeypatch.setattr(asset_diff, "_default_cert_end_date",
                        lambda t: "2027-01-01 00:00:00" if t == "1.2.3.4:443" else None)
    fp = asset_diff.collect_scope_fingerprint(SCOPE)
    assert fp["titles"] == {"http://a.com|门户首页"}
    assert fp["certs"] == {"1.2.3.4:443|2027-01-01 00:00:00"}
    assert fp["apps"] == {"企业版", "掌上银行"}


def test_end_to_end_new_signals_alert(db, scope_assets, monkeypatch):
    """标题变化 + 证书临期 + 新增 APP 一并推送（含快照持久化核对）。"""
    scope_assets["domains"] = ["a.com"]
    scope_assets["ip_ports"] = [("1.2.3.4", [443])]
    scope_assets["sites"] = [("http://a.com", [], "旧标题")]
    scope_assets["groups"] = [{"companies": [
        {"asset_scope_id": SCOPE, "app": [{"appname": "掌上银行"}]}]}]
    monkeypatch.setattr(asset_diff, "_default_cert_end_date",
                        lambda t: "2099-01-01 00:00:00")
    asset_diff.run_scope_diff(job_id=JOB, scope_id=SCOPE, source="domain",
                              notify=lambda t, m: None)   # 首轮建基线

    now = 1_800_000_000
    scope_assets["sites"] = [("http://a.com", [], "新标题")]
    scope_assets["groups"] = [{"companies": [
        {"asset_scope_id": SCOPE, "app": [{"appname": "掌上银行"}, {"appname": "企业版"}]}]}]
    monkeypatch.setattr(asset_diff, "_default_cert_end_date",
                        lambda t: "2027-01-25 00:00:00")   # 落在默认 15 天窗口附近
    sent = []
    diff_id = asset_diff.run_scope_diff(
        job_id=JOB, scope_id=SCOPE, source="domain", target="example.com",
        notify=lambda t, m: sent.append((t, m)), now=now)
    assert diff_id and len(sent) == 1
    body = sent[0][1]
    assert "页面标题变化" in body and "证书临期" in body and "企业版" in body

    snap = db.conn_db(asset_diff.SNAPSHOT_COLLECTION).find_one({"job_id": JOB})
    assert snap["titles"] == ["http://a.com|新标题"]
    assert snap["apps"] == ["企业版", "掌上银行"]
    expiring = snap["certs_expiring"]
    assert len(expiring) == 1 and expiring[0].startswith("1.2.3.4:443|2027-01-25 00:00:00|")
    assert "到期" in expiring[0] or "过期" in expiring[0]
