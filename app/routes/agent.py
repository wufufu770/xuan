"""玄览智能助手：会话管理 + SSE 流式聊天（平台工具循环）。

- 会话库：agent_conversation / agent_message（DeepSeek 式管理：新建/重命名/删除/续聊）
- 聊天：/agent/chat SSE——delta 文本、tool 步骤、tool_result、done/error 事件
- 工具：app/services/agent_tools.TOOLS（与 MCP Server 共用）；内部 Agent 允许
  danger 工具但逐次审计（前端步骤可见）
"""

import json

from bson import ObjectId
from flask import Response, stream_with_context
from flask_restx import fields, Namespace

from app import utils
from app.utils import get_logger, auth
from app.utils.audit import audit
from . import ARLResource
from app.services.agent_tools import TOOLS, call_tool, tool_call_events
from app.services.agent_llm import chat_messages

ns = Namespace('agent', description="玄览智能助手（平台 Agent）")

logger = get_logger()

CONV_COLLECTION = "agent_conversation"
MSG_COLLECTION = "agent_message"
MAX_ROUNDS = 8
TITLE_MAX = 40

SYSTEM_PROMPT = """你是玄览（XuanLan）资产侦察与风险管理平台的内置智能助手。

平台能力地图（你可通过工具直接操作）：
- 资产检索：search_assets（站点/域名/IP）、asset_ext_query（企业情报：APP/小程序/ICP 备案）
- 任务：submit_task（quick/standard/deep 模板下发）、task_status、list_tasks
- 风险：list_risks（漏洞 + Nuclei，可按 severity 过滤）
- 资产组：create_scope、scope_assets
- 自动化：schedule_scan（周期扫描计划）
- 报告：generate_report（Word 报告，可带 LLM 摘要）
- 总览：platform_overview

行为准则：
1. 先理解用户意图，需要数据时优先调用工具获取事实，不要编造资产或风险数据；
2. 回答用简体中文，简洁、结构化（列表/表格），关键数据给出来源工具名；
3. submit_task / schedule_scan 属于会产生实际扫描的动作——确认目标与参数合理后再调用，
   并在回答中明确说明已下发了什么；
4. 单轮最多连续调用 8 次工具；工具失败时如实说明原因并给出建议。
"""


def _now():
    return utils.curr_date()


def _ensure_conversation(conv_id, first_message=""):
    if conv_id:
        try:
            doc = utils.conn_db(CONV_COLLECTION).find_one({"_id": ObjectId(conv_id)})
        except Exception:
            doc = None
        if doc:
            return conv_id, doc.get("title") or "新会话"
    title = first_message.strip()[:TITLE_MAX] or "新会话"
    doc = {"title": title, "create_time": _now(), "update_time": _now()}
    inserted = utils.conn_db(CONV_COLLECTION).insert_one(doc)
    return str(inserted.inserted_id), title


def _save_message(conversation_id, **fields):
    doc = {"conversation_id": conversation_id, "create_time": _now()}
    doc.update(fields)
    utils.conn_db(MSG_COLLECTION).insert_one(doc)


def _load_history(conversation_id):
    msgs = []
    for doc in utils.conn_db(MSG_COLLECTION).find(
            {"conversation_id": conversation_id}).sort("_id", 1).limit(200):
        role = doc.get("role")
        entry = {"role": role, "content": doc.get("content") or ""}
        if doc.get("tool_calls"):
            entry["tool_calls"] = doc["tool_calls"]
        if role == "tool":
            entry["tool_call_id"] = doc.get("tool_call_id") or ""
        msgs.append(entry)
    return msgs


def _sse(payload):
    return "data: {}\n\n".format(json.dumps(payload, ensure_ascii=False))


def _stream(conversation_id, user_message):
    """SSE 生成器：工具循环，逐步产出事件。"""
    try:
        yield _sse({"type": "start", "conversation_id": conversation_id})
        _save_message(conversation_id, role="user", content=user_message)

        messages = ([{"role": "system", "content": SYSTEM_PROMPT}] +
                    _load_history(conversation_id))
        for _round in range(MAX_ROUNDS):
            ok, assistant, error = chat_messages(messages, tools=TOOLS)
            if not ok:
                yield _sse({"type": "error", "message": error})
                _save_message(conversation_id, role="assistant",
                              content="（调用失败）{}".format(error))
                return

            calls = assistant.get("tool_calls") or []
            if not calls:
                content = assistant.get("content") or ""
                _save_message(conversation_id, role="assistant", content=content)
                yield _sse({"type": "delta", "text": content})
                break

            internal = {"role": "assistant", "content": assistant.get("content") or "",
                        "tool_calls": calls}
            _save_message(conversation_id, **internal)
            messages.append(internal)
            for call in calls:
                ev = tool_call_events(call["name"], call.get("arguments"))
                yield _sse({"type": "tool", "name": call["name"],
                            "description": ev["description"],
                            "arguments": ev["arguments"]})
                result = call_tool(call["name"], call.get("arguments"),
                                   allow_danger=True)
                audit("agent_tool_call", detail={
                    "tool": call["name"], "ok": result.get("ok"),
                    "conversation_id": conversation_id})
                summary = json.dumps(result.get("result") if result.get("ok")
                                     else {"error": result.get("error")},
                                     ensure_ascii=False)[:1500]
                yield _sse({"type": "tool_result", "name": call["name"],
                            "ok": bool(result.get("ok")), "summary": summary})
                tool_msg = {"role": "tool", "tool_call_id": call["id"],
                            "name": call["name"], "content": summary}
                _save_message(conversation_id, **tool_msg)
                messages.append(tool_msg)
        else:
            yield _sse({"type": "error", "message": "已达单轮工具调用上限（{}）".format(MAX_ROUNDS)})

        utils.conn_db(CONV_COLLECTION).update_one(
            {"_id": ObjectId(conversation_id)},
            {"$set": {"update_time": _now()}})
        yield _sse({"type": "done", "conversation_id": conversation_id})
    except Exception as exc:  # 生成器任何异常都不能断流无告
        logger.exception("agent stream failed")
        yield _sse({"type": "error", "message": "内部错误: {}".format(exc)})


@ns.route('/chat')
class AgentChat(ARLResource):

    chat_model = ns.model('AgentChat', {
        'message': fields.String(required=True, description="用户消息"),
        'conversation_id': fields.String(required=False, description="会话 ID，留空新建"),
    })

    @auth
    @ns.expect(chat_model)
    def post(self):
        """智能助手对话（SSE 流式：delta/tool/tool_result/done/error）"""
        args = self.parse_args(self.chat_model)
        message = str(args.get("message") or "").strip()
        if not message:
            return {"code": 400, "message": "消息不能为空", "data": {}}
        conv_id, _title = _ensure_conversation(
            str(args.get("conversation_id") or "").strip(), message)
        audit("agent_chat", detail={"conversation_id": conv_id})

        gen = _stream(conv_id, message)
        return Response(stream_with_context(gen),
                        mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache",
                                 "X-Accel-Buffering": "no"})


@ns.route('/conversations/')
class AgentConversations(ARLResource):

    create_model = ns.model('AgentConvCreate', {
        'title': fields.String(required=False, description="会话标题，缺省为新会话"),
    })

    @auth
    def get(self):
        """会话列表（按更新时间倒序）"""
        docs = list(utils.conn_db(CONV_COLLECTION).find(
            {}, {"title": 1, "create_time": 1, "update_time": 1}
        ).sort("update_time", -1).limit(100))
        for d in docs:
            d["_id"] = str(d["_id"])
        return {"code": 200, "message": "success", "data": {"items": docs}}

    @auth
    @ns.expect(create_model)
    def post(self):
        """新建会话"""
        args = self.parse_args(self.create_model)
        title = str(args.get("title") or "").strip()[:TITLE_MAX] or "新会话"
        doc = {"title": title, "create_time": _now(), "update_time": _now()}
        inserted = utils.conn_db(CONV_COLLECTION).insert_one(doc)
        return {"code": 200, "message": "success",
                "data": {"conversation_id": str(inserted.inserted_id)}}


delete_conv_model = ns.model('AgentConvDelete', {
    'conversation_id': fields.String(required=True, description="会话 ID"),
})
rename_conv_model = ns.model('AgentConvRename', {
    'conversation_id': fields.String(required=True, description="会话 ID"),
    'title': fields.String(required=True, description="新标题"),
})


@ns.route('/conversations/delete/')
class AgentConvDelete(ARLResource):

    @auth
    @ns.expect(delete_conv_model)
    def post(self):
        """删除会话及其全部消息"""
        args = self.parse_args(delete_conv_model)
        conv_id = str(args.get("conversation_id") or "").strip()
        try:
            oid = ObjectId(conv_id)
        except Exception:
            return {"code": 400, "message": "conversation_id 非法", "data": {}}
        utils.conn_db(CONV_COLLECTION).delete_one({"_id": oid})
        utils.conn_db(MSG_COLLECTION).delete_many({"conversation_id": conv_id})
        return {"code": 200, "message": "已删除", "data": {"conversation_id": conv_id}}


@ns.route('/conversations/rename/')
class AgentConvRename(ARLResource):

    @auth
    @ns.expect(rename_conv_model)
    def post(self):
        """重命名会话"""
        args = self.parse_args(rename_conv_model)
        conv_id = str(args.get("conversation_id") or "").strip()
        title = str(args.get("title") or "").strip()[:TITLE_MAX] or "新会话"
        utils.conn_db(CONV_COLLECTION).update_one(
            {"_id": ObjectId(conv_id)} if conv_id else {"_none": 1},
            {"$set": {"title": title, "update_time": _now()}})
        return {"code": 200, "message": "已重命名", "data": {"conversation_id": conv_id}}


@ns.route('/conversations/messages/')
class AgentConvMessages(ARLResource):

    @auth
    def get(self):
        """会话消息历史（内部表示，前端渲染用）"""
        from flask import request
        conv_id = str(request.args.get("conversation_id") or "").strip()
        msgs = []
        for doc in utils.conn_db(MSG_COLLECTION).find(
                {"conversation_id": conv_id}).sort("_id", 1).limit(500):
            msgs.append({
                "role": doc.get("role"), "content": doc.get("content") or "",
                "tool_calls": doc.get("tool_calls") or [],
                "name": doc.get("name") or "",
                "create_time": doc.get("create_time") or "",
            })
        return {"code": 200, "message": "success", "data": {"items": msgs}}
