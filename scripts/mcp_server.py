#!/usr/bin/env python3
"""ARL 平台 MCP Server（stdio，零第三方依赖）。

实现 MCP 协议子集：initialize / tools/list / tools/call（newline-delimited
JSON-RPC 2.0）。直接复用平台代码（同机部署，共享 Mongo/Celery），把资产
查询、任务下发、报告生成暴露给 AI 客户端（Claude/Cursor 等）。

接入（部署机）：
    /opt/ARL/venv/bin/python /opt/ARL/scripts/mcp_server.py

工具清单：
    arl_stats          平台健康与统计
    arl_task_submit    下发域名/IP 任务（target/name/policy_id 可选）
    arl_task_status    查询任务状态（task_id 或 recent）
    arl_asset_query    资产查询（site/domain/ip + keyword/scope_id）
    arl_report_generate 生成资产组报告并返回 job_id

安全说明：与平台同等鉴权边界——本进程可直接读库，仅应在可信主机上运行，
不要暴露到网络。
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PROTOCOL_VERSION = "2024-11-05"

TOOLS = [
    {
        "name": "arl_stats",
        "description": "平台统计与健康：任务成功率、资产总量、凤鸟 token 剩余时长",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "arl_task_submit",
        "description": "下发资产侦察任务（域名或 IP 目标）",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标域名或 IP"},
                "name": {"type": "string", "description": "任务名"},
                "policy_id": {"type": "string", "description": "可选策略 ID"},
            },
            "required": ["target", "name"],
        },
    },
    {
        "name": "arl_task_status",
        "description": "查询任务状态；给 task_id 查单个，不给则返回最近 10 条",
        "inputSchema": {
            "type": "object",
            "properties": {"task_id": {"type": "string"}},
        },
    },
    {
        "name": "arl_asset_query",
        "description": "资产查询：collection=site/domain/ip，支持 keyword 正则与 scope_id 过滤",
        "inputSchema": {
            "type": "object",
            "properties": {
                "collection": {"type": "string",
                               "enum": ["site", "domain", "ip"]},
                "keyword": {"type": "string", "description": "正则关键词"},
                "scope_id": {"type": "string"},
                "limit": {"type": "integer", "description": "默认 20，上限 100"},
            },
            "required": ["collection"],
        },
    },
    {
        "name": "arl_report_generate",
        "description": "为资产组生成 xlsx 报告（异步），返回 job_id",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scope_id": {"type": "string"},
                "scope_name": {"type": "string"},
                "use_llm": {"type": "boolean"},
            },
            "required": ["scope_id"],
        },
    },
]

_TASK_ID_RE = re.compile(r"^[0-9a-fA-F]{24}$")


def tool_arl_stats(_args):
    from app.utils import conn_db
    from app.services.system_health import collect_health
    data = {"health": collect_health()}
    for name in ("domain", "site", "ip", "vulnerability"):
        try:
            data[name] = conn_db(name).count_documents({})
        except Exception:
            data[name] = None
    return json.dumps(data, ensure_ascii=False, default=str)


def tool_arl_task_submit(args):
    from app.helpers.task import submit_task_task
    target = str(args.get("target") or "").strip()
    name = str(args.get("name") or "").strip()
    if not target or not name:
        raise ValueError("target/name 必填")
    task_list = submit_task_task(target, name, {})
    return json.dumps({"submitted": len(task_list),
                       "task_ids": [t.get("task_id") for t in task_list]},
                      ensure_ascii=False)


def tool_arl_task_status(args):
    from bson import ObjectId
    from app.utils import conn_db
    task_id = str(args.get("task_id") or "").strip()
    fields = {"name": 1, "target": 1, "status": 1, "task_tag": 1,
              "start_time": 1, "end_time": 1}
    if task_id:
        if not _TASK_ID_RE.match(task_id):
            raise ValueError("task_id 格式非法")
        doc = conn_db("task").find_one({"_id": ObjectId(task_id)}, fields)
        return json.dumps(doc or {}, ensure_ascii=False, default=str)
    rows = list(conn_db("task").find({}, fields).sort("_id", -1).limit(10))
    return json.dumps(rows, ensure_ascii=False, default=str)


def tool_arl_asset_query(args):
    from app.utils import conn_db
    collection = str(args.get("collection") or "").strip()
    if collection not in ("site", "domain", "ip"):
        raise ValueError("collection 仅支持 site/domain/ip")
    query = {}
    keyword = str(args.get("keyword") or "").strip()
    if keyword:
        pattern = re.compile(keyword)
        query["$or"] = [{"site": pattern}, {"hostname": pattern},
                        {"domain": pattern}, {"ip": pattern}, {"title": pattern}]
    scope_id = str(args.get("scope_id") or "").strip()
    if scope_id:
        query["scope_id"] = scope_id
    limit = min(max(int(args.get("limit") or 20), 1), 100)
    rows = list(conn_db(collection).find(query).limit(limit))
    return json.dumps(rows, ensure_ascii=False, default=str)


def tool_arl_report_generate(args):
    from app.services import report_center
    scope_id = str(args.get("scope_id") or "").strip()
    if not scope_id:
        raise ValueError("scope_id 必填")
    job_id = report_center.submit_report_job(
        scope_id,
        scope_name=str(args.get("scope_name") or "").strip(),
        use_llm=bool(args.get("use_llm")))
    return json.dumps({"job_id": job_id,
                       "hint": "轮询 GET /api/report/job/?job_id= 或再次用 arl_task_status 语义查询"},
                      ensure_ascii=False)


TOOL_HANDLERS = {
    "arl_stats": tool_arl_stats,
    "arl_task_submit": tool_arl_task_submit,
    "arl_task_status": tool_arl_task_status,
    "arl_asset_query": tool_arl_asset_query,
    "arl_report_generate": tool_arl_report_generate,
}


def handle_request(message):
    """处理一条 JSON-RPC 消息，返回响应 dict 或 None（notification）。"""
    if not isinstance(message, dict):
        return _error(None, -32600, "Invalid Request")
    method = message.get("method")
    msg_id = message.get("id")

    if method == "initialize":
        return _result(msg_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "arl-platform", "version": "1.0.0"},
        })
    if method is None or method.startswith("notifications/"):
        return None
    if method == "tools/list":
        return _result(msg_id, {"tools": TOOLS})
    if method == "tools/call":
        params = message.get("params") or {}
        tool_name = str(params.get("name") or "")
        handler = TOOL_HANDLERS.get(tool_name)
        if not handler:
            return _error(msg_id, -32602,
                          "Unknown tool: {}".format(tool_name))
        try:
            output = handler(params.get("args") or {})
            return _result(msg_id, {"content": [{"type": "text", "text": output}]})
        except Exception as exc:
            return _result(msg_id, {
                "content": [{"type": "text", "text": "error: {}".format(exc)}],
                "isError": True})
    return _error(msg_id, -32601, "Method not found: {}".format(method))


def _result(msg_id, result):
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _error(msg_id, code, message):
    return {"jsonrpc": "2.0", "id": msg_id,
            "error": {"code": code, "message": message}}


def serve(stdin=None, stdout=None):
    """主循环：逐行读 JSON，写响应。stdin/stdout 可注入供测试。"""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except ValueError:
            response = _error(None, -32700, "Parse error")
        else:
            response = handle_request(message)
        if response is not None:
            stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
            stdout.flush()


if __name__ == "__main__":
    serve()
