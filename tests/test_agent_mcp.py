"""M2 测试：Agent 工具注册表 / MCP JSON-RPC / 会话 CRUD / SSE 工具循环。"""

import json

import pytest
from flask import Flask
from flask_restx import Api

from app.config import Config
from app.utils import user as user_mod
from app.utils import audit as audit_mod
from tests.fake_db import FakeDB


@pytest.fixture
def web(monkeypatch):
    fake = FakeDB()
    monkeypatch.setattr(user_mod, "conn_db", fake.conn_db)
    monkeypatch.setattr(audit_mod, "conn_db", fake.conn_db)
    monkeypatch.setattr(Config, "AUTH", True, raising=False)
    monkeypatch.setattr(Config, "API_KEY", "static-api-key", raising=False)

    import app.utils as utils_pkg
    monkeypatch.setattr(utils_pkg, "conn_db", fake.conn_db)

    from app.routes import agent_ns, mcp_ns

    app = Flask(__name__)
    api = Api(app, prefix="/api", doc=False)
    for ns in (agent_ns, mcp_ns):
        api.add_namespace(ns)
    return {"client": app.test_client(), "db": fake}


H = {"Token": "static-api-key"}


# ------------------------------------------------------ 工具注册表 ----
def test_tool_registry_shape():
    from app.services.agent_tools import TOOLS, TOOLS_BY_NAME, MCP_BLOCKED
    assert len(TOOLS) >= 10
    assert all(set(t) >= {"name", "description", "parameters", "handler", "danger"}
               for t in TOOLS)
    assert MCP_BLOCKED == ["submit_task", "schedule_scan"]
    assert "platform_overview" in TOOLS_BY_NAME


def test_call_tool_danger_blocked_for_mcp():
    from app.services.agent_tools import call_tool
    r = call_tool("submit_task", {"target": "example.com", "name": "x"},
                  allow_danger=False)
    assert r["ok"] is False and "禁用" in r["error"]
    r2 = call_tool("nope", allow_danger=True)
    assert r2["ok"] is False and "未知工具" in r2["error"]


def test_call_tool_platform_overview(web):
    db = web["db"]
    db.conn_db("task").insert_one({"name": "t1", "status": "done"})
    from app.services.agent_tools import call_tool
    r = call_tool("platform_overview", {})
    assert r["ok"] is True
    assert r["result"]["tasks"] >= 1


def test_call_tool_search_assets(web):
    db = web["db"]
    db.conn_db("site").insert_one({"site": "http://demo.example.com", "title": "Demo"})
    from app.services.agent_tools import call_tool
    r = call_tool("search_assets", {"kind": "site", "keyword": "demo"})
    assert r["ok"] is True and r["result"]["count"] == 1


def test_call_tool_schedule_scan_uses_first_policy(web):
    db = web["db"]
    db.conn_db("policy").insert_one({"name": "默认策略", "policy": {}})
    from app.services.agent_tools import call_tool
    r = call_tool("schedule_scan", {"target": "example.com", "cron": "0 */6 * * *"},
                  allow_danger=True)
    assert r["ok"] is True and r["result"]["policy_name"] == "默认策略"
    doc = db.conn_db("task_schedule").find_one({"target": "example.com"})
    assert doc and doc["status"] == "scheduled"


def test_call_tool_bad_cron(web):
    from app.services.agent_tools import call_tool
    db = web["db"]
    db.conn_db("policy").insert_one({"name": "p", "policy": {}})
    r = call_tool("schedule_scan", {"target": "example.com", "cron": "bad"})
    assert r["ok"] is False


# -------------------------------------------------------- MCP 面 ----
def test_mcp_initialize_and_tools_list(web):
    resp = web["client"].post("/api/mcp", json={
        "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}, headers=H)
    body = resp.get_json()
    assert body["result"]["serverInfo"]["name"] == "xuanlan-mcp"

    resp = web["client"].post("/api/mcp", json={
        "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, headers=H)
    tools = resp.get_json()["result"]["tools"]
    names = {t["name"] for t in tools}
    assert "search_assets" in names and "submit_task" not in names   # danger 不暴露


def test_mcp_tools_call_roundtrip(web):
    web["db"].conn_db("vuln").insert_one(
        {"vul_name": "RCE", "severity": "high", "target": "demo.com"})
    resp = web["client"].post("/api/mcp", json={
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "list_risks", "arguments": {"severity": "high"}}}, headers=H)
    result = resp.get_json()["result"]
    assert result["isError"] is False
    payload = json.loads(result["content"][0]["text"])
    assert payload["vuln_count"] == 1


def test_mcp_danger_call_rejected(web):
    resp = web["client"].post("/api/mcp", json={
        "jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": {"name": "submit_task", "arguments": {}}}, headers=H)
    result = resp.get_json()["result"]
    assert result["isError"] is True
    assert "禁用" in result["content"][0]["text"]


def test_mcp_unknown_method(web):
    resp = web["client"].post("/api/mcp", json={
        "jsonrpc": "2.0", "id": 5, "method": "nope/method"}, headers=H)
    assert resp.get_json()["error"]["code"] == -32601


# ---------------------------------------------------- 会话与聊天 ----
def test_conversation_crud_and_messages(web, monkeypatch):
    import app.routes.agent as agent_mod

    scripted = [
        (True, {"role": "assistant", "content": "",
                "tool_calls": [{"id": "c1", "name": "platform_overview",
                                "arguments": {}}]}, ""),
        (True, {"role": "assistant",
                "content": "平台当前共 1 个任务，一切正常。", "tool_calls": []}, ""),
    ]
    monkeypatch.setattr(agent_mod, "chat_messages",
                        lambda messages, tools=None, **kw:
                        scripted.pop(0) if scripted else scripted and None)

    resp = web["client"].post("/api/agent/chat", json={"message": "看看平台现状"},
                              headers=H)
    assert resp.status_code == 200
    raw = resp.get_data(as_text=True)
    events = [json.loads(line[len("data: "):]) for line in raw.splitlines()
              if line.startswith("data: ")]
    types = [e["type"] for e in events]
    assert types[0] == "start" and "tool" in types and "tool_result" in types
    assert types[-1] == "done"
    conv_id = events[0]["conversation_id"]

    # 会话列表 + 消息历史
    convs = web["client"].get("/api/agent/conversations/", headers=H).get_json()
    assert convs["data"]["items"][0]["_id"] == conv_id
    msgs = web["client"].get(
        "/api/agent/conversations/messages/?conversation_id=" + conv_id,
        headers=H).get_json()["data"]["items"]
    roles = [m["role"] for m in msgs]
    assert roles == ["user", "assistant", "tool", "assistant"]

    # 重命名 + 删除
    web["client"].post("/api/agent/conversations/rename/",
                       json={"conversation_id": conv_id, "title": "巡检"},
                       headers=H)
    convs = web["client"].get("/api/agent/conversations/", headers=H).get_json()
    assert convs["data"]["items"][0]["title"] == "巡检"
    web["client"].post("/api/agent/conversations/delete/",
                       json={"conversation_id": conv_id}, headers=H)
    convs = web["client"].get("/api/agent/conversations/", headers=H).get_json()
    assert all(c["_id"] != conv_id for c in convs["data"]["items"])


def test_agent_chat_requires_message(web):
    resp = web["client"].post("/api/agent/chat", json={"message": " "}, headers=H)
    assert resp.get_json()["code"] == 400


def test_session_refresh_watch(web):
    """续期看门：空池无动作；失败账号触发通知回调。"""
    import app.utils.session_refresh as sr

    sent = {}
    base = time.time() + 10**9
    r = sr.check_sessions(now=base, refresh_all=lambda: [],
                          notify=lambda t, m: sent.update(t=t))
    assert r is None
    r = sr.check_sessions(now=base + 6 * 3600 + 1,
                          refresh_all=lambda: [{"source": "fengniao", "account": "default",
                                                "ok": False, "detail": "expired"}],
                          notify=lambda t, m: sent.update(t=t, m=m))
    assert "失败 1" in r and "fengniao:default" in r and sent["t"]


import time  # noqa: E402
