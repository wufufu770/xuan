"""MCP Server 测试：协议握手/工具清单/工具调用/错误处理 + stdio 端到端。"""

import io
import json
import subprocess
import sys
import os

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.mcp_server import handle_request, serve


def _rpc(method, params=None, msg_id=1):
    message = {"jsonrpc": "2.0", "id": msg_id, "method": method}
    if params is not None:
        message["params"] = params
    return message


# ---------------------------------------------------------- 协议层 ----

def test_initialize_handshake():
    resp = handle_request(_rpc("initialize"))
    assert resp["result"]["protocolVersion"] == "2024-11-05"
    assert resp["result"]["serverInfo"]["name"] == "arl-platform"
    assert "tools" in resp["result"]["capabilities"]


def test_notification_returns_none():
    assert handle_request({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_tools_list_contains_expected_tools():
    resp = handle_request(_rpc("tools/list"))
    names = {t["name"] for t in resp["result"]["tools"]}
    assert {"arl_stats", "arl_task_submit", "arl_task_status",
            "arl_asset_query", "arl_report_generate"} <= names
    for tool in resp["result"]["tools"]:
        assert "inputSchema" in tool and "description" in tool


def test_unknown_method():
    resp = handle_request(_rpc("bogus/method"))
    assert resp["error"]["code"] == -32601


def test_unknown_tool():
    resp = handle_request(_rpc("tools/call", {"name": "nope", "args": {}}))
    assert resp["error"]["code"] == -32602


def test_invalid_json_message_shape():
    resp = handle_request("not-a-dict")
    assert resp["error"]["code"] == -32600


# ---------------------------------------------------------- 工具层 ----

@pytest.fixture
def fake_db(monkeypatch):
    from tests.fake_db import FakeDB
    fake = FakeDB()
    import app.utils as utils_pkg
    monkeypatch.setattr(utils_pkg, "conn_db", fake.conn_db)
    return fake


def test_tool_arl_stats(fake_db):
    fake_db.conn_db("site").insert_one({"site": "http://a.com"})
    resp = handle_request(_rpc("tools/call", {"name": "arl_stats", "args": {}}))
    assert "isError" not in resp["result"]
    data = json.loads(resp["result"]["content"][0]["text"])
    assert data["site"] == 1 and "health" in data


def test_tool_arl_asset_query_keyword(fake_db):
    fake_db.conn_db("site").insert_one({"site": "http://a.com", "title": "首页"})
    fake_db.conn_db("site").insert_one({"site": "http://b.com", "title": "x"})
    resp = handle_request(_rpc("tools/call", {
        "name": "arl_asset_query",
        "args": {"collection": "site", "keyword": "a\\.com"}}))
    rows = json.loads(resp["result"]["content"][0]["text"])
    assert len(rows) == 1 and rows[0]["site"] == "http://a.com"


def test_tool_arl_asset_query_rejects_bad_collection():
    resp = handle_request(_rpc("tools/call", {
        "name": "arl_asset_query", "args": {"collection": "user"}}))
    assert resp["result"].get("isError") is True
    assert "site/domain/ip" in resp["result"]["content"][0]["text"]


def test_tool_arl_task_status_recent(fake_db):
    fake_db.conn_db("task").insert_one({"name": "t1", "target": "a.com",
                                        "status": "done"})
    resp = handle_request(_rpc("tools/call", {"name": "arl_task_status",
                                              "args": {}}))
    rows = json.loads(resp["result"]["content"][0]["text"])
    assert rows[0]["target"] == "a.com"


def test_tool_arl_task_status_bad_id():
    resp = handle_request(_rpc("tools/call", {"name": "arl_task_status",
                                              "args": {"task_id": "../../etc"}}))
    assert resp["result"].get("isError") is True


def test_tool_submit_requires_fields(fake_db):
    resp = handle_request(_rpc("tools/call", {"name": "arl_task_submit",
                                              "args": {"target": "a.com"}}))
    assert resp["result"].get("isError") is True


# ------------------------------------------------------ stdio 端到端 ----

def test_serve_stdio_round_trip():
    stdin_lines = "\n".join([
        json.dumps(_rpc("initialize")),
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json.dumps(_rpc("tools/list", msg_id=2)),
        "not-json",
        "",
    ]) + "\n"
    out = io.StringIO()
    serve(stdin=io.StringIO(stdin_lines), stdout=out)
    lines = [json.loads(x) for x in out.getvalue().strip().splitlines()]
    # initialize 响应 + tools/list 响应 + parse error；notification 无响应
    assert len(lines) == 3
    assert lines[0]["result"]["serverInfo"]["name"] == "arl-platform"
    assert lines[1]["id"] == 2 and "tools" in lines[1]["result"]
    assert lines[2]["error"]["code"] == -32700


def test_module_importable_without_app_side_effects():
    """scripts 目录以子进程方式导入不触发 app 导入链（延迟导入生效）。"""
    code = (
        "import importlib.util, json;"
        "spec = importlib.util.spec_from_file_location("
        "'m', 'scripts/mcp_server.py');"
        "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m);"
        "print(json.dumps(len(m.TOOLS)))"
    )
    result = subprocess.run([sys.executable, "-c", code],
                            capture_output=True, text=True, timeout=60,
                            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    assert result.returncode == 0
    assert json.loads(result.stdout.strip()) == 5
