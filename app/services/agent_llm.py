"""Agent LLM 客户端：带工具调用（function calling）的对话，双格式适配。

内部统一消息表示（agent 会话库存的即该形状）：
  {"role": "system"|"user", "content": str}
  {"role": "assistant", "content": str, "tool_calls": [{"id","name","arguments":dict}]}
  {"role": "tool", "tool_call_id": str, "name": str, "content": str}

对外返回 (ok, assistant_msg, error)，assistant_msg 为内部表示。
openai（兼容）与 anthropic 两种格式由 _to_provider/_from_provider 适配。
"""

import json

import requests

from app.config import Config
from app.utils import get_logger
from app.services.ai_judge import (
    get_active_provider, _chat_endpoint, _request_headers, _redact)

logger = get_logger()

DEFAULT_TIMEOUT = 120


def chat_messages(messages, tools=None, temperature=0.2, max_tokens=4096,
                  timeout=None, provider=None):
    """带工具的多轮对话。tools 为 agent_tools.TOOLS（None=纯聊天）。

    返回 (ok, assistant_msg, error)；assistant_msg = {"role":"assistant",
    "content": str, "tool_calls": [...]（可能为空列表）}。
    """
    provider = provider or get_active_provider()
    if not provider:
        return False, None, "AI 未启用或凭证未配置（AI 配置页）"
    if not bool(getattr(Config, "AI_ENABLE", False)):
        return False, None, "AI 未启用（AI 配置页可开启）"
    fmt = str(provider.get("format") or "openai").lower()
    base = str(provider.get("base_url") or "").strip().rstrip("/")
    if not (base and provider.get("api_key") and provider.get("model")):
        return False, None, "供应商配置不完整（base_url / api_key / model）"

    timeout = timeout or int(getattr(Config, "AI_TIMEOUT", DEFAULT_TIMEOUT) or
                             DEFAULT_TIMEOUT)
    try:
        if fmt == "anthropic":
            payload, headers = _to_anthropic(messages, tools, provider,
                                             temperature, max_tokens)
            response = requests.post(_chat_endpoint(base), json=payload,
                                     headers=headers, timeout=timeout)
        else:
            payload, headers = _to_openai(messages, tools, provider,
                                          temperature, max_tokens)
            response = requests.post(base + "/chat/completions", json=payload,
                                     headers=headers, timeout=timeout)
    except Exception as e:
        return False, None, "请求失败: {}".format(_redact(e))

    if response.status_code != 200:
        return False, None, "HTTP {}: {}".format(
            response.status_code, _redact(response.text[:400]))

    try:
        body = response.json()
        if fmt == "anthropic":
            return True, _from_anthropic(body), ""
        return True, _from_openai(body), ""
    except Exception as e:
        return False, None, "AI 响应解析失败: {}".format(_redact(e))


# ---------------------------------------------------------- openai 适配 ----

def _to_openai(messages, tools, provider, temperature, max_tokens):
    out = []
    for m in messages:
        role = m.get("role")
        if role in ("system", "user"):
            out.append({"role": role, "content": m.get("content") or ""})
        elif role == "assistant":
            entry = {"role": "assistant",
                     "content": m.get("content") or ""}
            calls = m.get("tool_calls") or []
            if calls:
                entry["tool_calls"] = [{
                    "id": c["id"], "type": "function",
                    "function": {"name": c["name"],
                                 "arguments": json.dumps(c.get("arguments") or {},
                                                         ensure_ascii=False)},
                } for c in calls]
                if not entry["content"]:
                    entry["content"] = None
            out.append(entry)
        elif role == "tool":
            out.append({"role": "tool", "tool_call_id": m.get("tool_call_id"),
                        "content": m.get("content") or ""})
    payload = {"model": provider.get("model"), "messages": out,
               "temperature": temperature, "max_tokens": max_tokens,
               "stream": False}
    if tools:
        payload["tools"] = [{
            "type": "function",
            "function": {"name": t["name"], "description": t["description"],
                         "parameters": t["parameters"]},
        } for t in tools]
    return payload, _request_headers(provider)


def _from_openai(body):
    message = (body.get("choices") or [{}])[0].get("message") or {}
    calls = []
    for c in (message.get("tool_calls") or []):
        fn = c.get("function") or {}
        try:
            arguments = json.loads(fn.get("arguments") or "{}")
        except Exception:
            arguments = {}
        calls.append({"id": c.get("id") or "call_{}".format(len(calls)),
                      "name": fn.get("name") or "", "arguments": arguments})
    return {"role": "assistant", "content": message.get("content") or "",
            "tool_calls": calls}


# -------------------------------------------------------- anthropic 适配 ----

def _to_anthropic(messages, tools, provider, temperature, max_tokens):
    out = []
    for m in messages:
        role = m.get("role")
        if role == "system":
            continue
        if role == "user":
            out.append({"role": "user", "content": m.get("content") or ""})
        elif role == "assistant":
            blocks = []
            if m.get("content"):
                blocks.append({"type": "text", "text": m["content"]})
            for c in (m.get("tool_calls") or []):
                blocks.append({"type": "tool_use", "id": c["id"],
                               "name": c["name"],
                               "input": c.get("arguments") or {}})
            out.append({"role": "assistant", "content": blocks or [{"type": "text", "text": ""}]})
        elif role == "tool":
            out.append({"role": "user", "content": [{
                "type": "tool_result", "tool_use_id": m.get("tool_call_id"),
                "content": m.get("content") or ""}]})
    payload = {"model": provider.get("model"), "max_tokens": max_tokens,
               "temperature": temperature, "messages": out}
    if tools:
        payload["tools"] = [{"name": t["name"], "description": t["description"],
                             "input_schema": t["parameters"]} for t in tools]
    headers = _request_headers(provider)
    headers["anthropic-version"] = headers.get("anthropic-version", "2023-06-01")
    return payload, headers


def _from_anthropic(body):
    text_parts, calls = [], []
    for block in (body.get("content") or []):
        btype = block.get("type")
        if btype == "text":
            text_parts.append(block.get("text") or "")
        elif btype == "tool_use":
            calls.append({"id": block.get("id") or "call_{}".format(len(calls)),
                          "name": block.get("name") or "",
                          "arguments": block.get("input") or {}})
    return {"role": "assistant", "content": "\n".join(text_parts),
            "tool_calls": calls}
