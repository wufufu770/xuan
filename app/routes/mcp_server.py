"""玄览平台 MCP Server（Streamable HTTP，JSON-RPC 2.0）。

外部 AI Agent（Claude / Cursor / DeepSeek 等）以本端点为 MCP 服务器，
tools/list 获取平台工具，tools/call 直接驱动玄览。
- 鉴权：Token 头（与 REST API 同一 API Key）
- danger 工具（下发任务/创建计划）默认对 MCP 关闭—— blast radius 控制
- 每次调用记 audit
"""

import json

from flask_restx import Namespace, Resource

from app import utils
from app.utils import get_logger, auth
from app.utils.audit import audit
from app.services.agent_tools import TOOLS, call_tool, MCP_BLOCKED

ns = Namespace('mcp', description="玄览 MCP Server（供外部 AI Agent 接入）")

logger = get_logger()

PROTOCOL_VERSION = "2025-03-26"
SERVER_INFO = {"name": "xuanlan-mcp", "version": "1.0.0"}

JSONRPC_OK = {"jsonrpc": "2.0", "id": None}


def _result(req_id, result):
    return dict(JSONRPC_OK, id=req_id, result=result)


def _error(req_id, code, message):
    return dict(JSONRPC_OK, id=req_id,
                error={"code": code, "message": message})


def _mcp_tools():
    return [{"name": t["name"], "description": t["description"],
             "inputSchema": t["parameters"]}
            for t in TOOLS if not t["danger"]]


def _handle(req):
    method = str(req.get("method") or "")
    req_id = req.get("id")
    params = req.get("params") or {}

    if method == "initialize":
        return _result(req_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": SERVER_INFO,
        })
    if method == "notifications/initialized":
        return _result(req_id, {})
    if method == "ping":
        return _result(req_id, {})
    if method == "tools/list":
        return _result(req_id, {"tools": _mcp_tools()})
    if method == "tools/call":
        name = str(params.get("name") or "").strip()
        arguments = params.get("arguments") or {}
        if name in MCP_BLOCKED:
            return _result(req_id, {
                "content": [{"type": "text",
                             "text": "工具 {} 属破坏性操作，MCP 侧禁用（如需请联系管理员）".format(name)}],
                "isError": True})
        result = call_tool(name, arguments, allow_danger=False)
        audit("mcp_tool_call", detail={"tool": name, "ok": result.get("ok")})
        text = json.dumps(result.get("result") if result.get("ok")
                          else {"error": result.get("error")},
                          ensure_ascii=False)
        return _result(req_id, {"content": [{"type": "text", "text": text}],
                                "isError": not bool(result.get("ok"))})
    return _error(req_id, -32601, "Method not found: {}".format(method or "(empty)"))


@ns.route('')
class McpEndpoint(Resource):

    @auth
    def post(self):
        """MCP JSON-RPC 2.0 入口（initialize / tools/list / tools/call / ping）"""
        try:
            req = request_json()
        except Exception:
            return _error(None, -32700, "Parse error")
        method = str(req.get("method") or "")
        if method.startswith("notifications/"):
            # 通知类消息无响应体（JSON-RPC 规范），MCP 客户端不等待
            return _result(req.get("id"), {})

        resp = _handle(req)
        logger.info("mcp call method={} ok".format(method or "?"))
        return resp


def request_json():
    from flask import request
    return json.loads(request.get_data(as_text=True) or "{}")
