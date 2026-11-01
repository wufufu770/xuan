import json
import os
import re
import time

import requests
import yaml

from app import utils
from app.config import Config, basedir

logger = utils.get_logger()

MAX_BATCH_SITES = 50
AI_JUDGED_STATE = "judged"
AI_PENDING_STATE = "pending"

SUPPORTED_COLLECTIONS = ("site", "asset_site")

DEFAULT_TIMEOUT = 60

CONFIG_PATH = os.path.join(basedir, 'config.yaml')


def _load_yaml_ai():
    """每次请求直接读 config.yaml 的 AI 区段——gunicorn 多 worker 各有内存副本，
    写 yaml 后只有落盘数据对所有 worker 立即可见。"""
    try:
        with open(CONFIG_PATH) as f:
            data = yaml.load(f, Loader=yaml.SafeLoader) or {}
        return data.get("AI") or {}
    except Exception:
        return {}


def _provider_keys():
    keys = [str(p.get("api_key") or "").strip() for p in get_providers()]
    legacy = str(getattr(Config, "AI_API_KEY", "") or "").strip()
    if legacy:
        keys.append(legacy)
    return [k for k in keys if k]


def _redact(value):
    text = str(value or "")
    for key in _provider_keys():
        if key and key in text:
            text = text.replace(key, "******")
    return text


def get_providers():
    """供应商列表（实时读 config.yaml）；旧单配置自动兼容为一个供应商。"""
    ai = _load_yaml_ai()
    providers = [p for p in (ai.get("PROVIDERS") or []) if isinstance(p, dict)]
    if providers:
        return providers
    base = str(ai.get("BASE_URL") or getattr(Config, "AI_BASE_URL", "") or "").strip()
    key = str(ai.get("API_KEY") or getattr(Config, "AI_API_KEY", "") or "").strip()
    model = str(ai.get("MODEL") or getattr(Config, "AI_MODEL", "") or "").strip()
    if base and key:
        return [{
            "id": "legacy",
            "name": "默认供应商",
            "format": "openai",
            "base_url": base,
            "api_key": key,
            "model": model,
        }]
    return []


def get_active_provider_id():
    active_id = str(getattr(Config, "AI_ACTIVE_ID", "") or "").strip()
    providers = get_providers()
    for p in providers:
        if str(p.get("id") or "") == active_id:
            return active_id
    return providers[0].get("id") if providers else ""


def get_active_provider():
    active_id = get_active_provider_id()
    for p in get_providers():
        if str(p.get("id") or "") == active_id:
            return p
    return None


def ai_enabled():
    provider = get_active_provider()
    if not provider:
        return False
    return (
        bool(getattr(Config, "AI_ENABLE", False)) and
        bool(str(provider.get("api_key") or "").strip()) and
        bool(str(provider.get("base_url") or "").strip()) and
        bool(str(provider.get("model") or "").strip())
    )


def _chat_endpoint(base):
    base = base.rstrip("/")
    # Anthropic 地址以 /v1 结尾时不再追加
    return base + "/messages" if base.endswith("/v1") else base + "/v1/messages"


def _models_endpoint(base):
    base = base.rstrip("/")
    return base + "/models" if base.endswith("/v1") else base + "/v1/models"


def _request_headers(provider):
    headers = {"Content-Type": "application/json"}
    api_key = str(provider.get("api_key") or "").strip()
    fmt = str(provider.get("format") or "openai").lower()
    if fmt == "anthropic":
        headers["x-api-key"] = api_key
        headers["anthropic-version"] = "2023-06-01"
    elif api_key:
        headers["Authorization"] = "Bearer {}".format(api_key)
    return headers


def ai_chat(prompt, system_prompt="", temperature=0.2, max_tokens=2048,
            timeout=None, provider=None):
    """AI chat 调用，支持 openai（兼容）与 anthropic 两种格式，返回 (ok, content, error)。"""
    provider = provider or get_active_provider()
    if not provider:
        return False, "", "AI 未启用或凭证未配置"
    if not bool(getattr(Config, "AI_ENABLE", False)):
        return False, "", "AI 研判未启用（AI 与集成页可开启）"

    fmt = str(provider.get("format") or "openai").lower()
    base = str(provider.get("base_url") or "").strip().rstrip("/")
    api_key = str(provider.get("api_key") or "").strip()
    model = str(provider.get("model") or "").strip()
    if not (base and api_key and model):
        return False, "", "供应商配置不完整（base_url / api_key / model）"

    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    timeout = timeout or int(getattr(Config, "AI_TIMEOUT", DEFAULT_TIMEOUT) or
                             DEFAULT_TIMEOUT)

    try:
        if fmt == "anthropic":
            payload = {
                "model": model,
                "max_tokens": max_tokens,
                "temperature": temperature,
                "messages": messages,
            }
            if system_prompt:
                payload["system"] = system_prompt
            response = requests.post(
                _chat_endpoint(base),
                json=payload,
                headers=_request_headers(provider),
                timeout=timeout,
            )
        else:
            response = requests.post(
                base + "/chat/completions",
                json={
                    "model": model,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                    "stream": False,
                },
                headers=_request_headers(provider),
                timeout=timeout,
            )
    except Exception as e:
        error = _redact(e)
        logger.warning("AI chat request failed: {}".format(error))
        return False, "", str(error)

    if response.status_code != 200:
        error = _redact(response.text[:500])
        logger.warning("AI chat http {}: {}".format(response.status_code, error))
        return False, "", "HTTP {}: {}".format(response.status_code, error)

    try:
        body = response.json()
        if fmt == "anthropic":
            content = body["content"][0]["text"] or ""
        else:
            content = body["choices"][0]["message"]["content"] or ""
        return True, content, ""
    except Exception as e:
        error = "invalid AI response: {}".format(_redact(e))
        logger.warning(error)
        return False, "", error


def fetch_models(provider):
    """拉取供应商可用模型列表，返回 (ok, models, error)。"""
    fmt = str(provider.get("format") or "openai").lower()
    base = str(provider.get("base_url") or "").strip().rstrip("/")
    api_key = str(provider.get("api_key") or "").strip()
    if not (base and api_key):
        return False, [], "base_url 与 api_key 必填"

    try:
        if fmt == "anthropic":
            r = requests.get(_models_endpoint(base),
                             headers={"x-api-key": api_key,
                                      "anthropic-version": "2023-06-01"},
                             timeout=15)
        else:
            r = requests.get(base + "/models",
                             headers={"Authorization": "Bearer {}".format(api_key)},
                             timeout=15)
    except Exception as e:
        return False, [], str(e)

    if r.status_code != 200:
        return False, [], "HTTP {}: {}".format(r.status_code, _redact(r.text[:300]))

    try:
        body = r.json()
    except Exception as e:
        return False, [], "invalid response: {}".format(e)

    data = body.get("data") or body.get("models") or []
    models = []
    for item in data:
        mid = (item.get("id") or item.get("name") or "").strip() \
            if isinstance(item, dict) else str(item).strip()
        if mid and mid not in models:
            models.append(mid)
    return True, sorted(models), ""


def test_connection(provider_id=""):
    provider = None
    if provider_id:
        provider = next(
            (p for p in get_providers() if str(p.get("id") or "") == provider_id), None)
        if provider is None:
            return {"ok": False, "message": "供应商不存在", "elapsed": 0}

    started = time.time()
    ok, content, error = ai_chat(
        "请回复：ok", system_prompt="你是连通性测试助手。",
        max_tokens=16, timeout=15, provider=provider)
    name = (provider or {}).get("name") or (provider or {}).get("model") or "AI"
    return {
        "ok": ok,
        "message": "连接正常：{}".format(str(content or "").strip()[:50]) if ok
        else error,
        "elapsed": round(time.time() - started, 2),
    }


def extract_json(text):
    """从模型回复中提取 JSON（容忍 markdown 代码块包裹）。"""
    text = str(text or "").strip()
    if not text:
        return None

    fence_match = re.search(r"```(?:json)?\s*(.+?)\s*```", text, re.S)
    if fence_match:
        text = fence_match.group(1).strip()

    for start_char, end_char in (("[", "]"), ("{", "}")):
        start = text.find(start_char)
        end = text.rfind(end_char)
        if start != -1 and end > start:
            candidate = text[start:end + 1]
            try:
                return json.loads(candidate)
            except ValueError:
                continue
    return None


SITE_BRIEF_FIELDS = (
    "site", "hostname", "title", "ip", "port", "status", "http_server",
    "cdn_name", "waf_name",
)


def build_site_brief(site_doc, index, max_paths=10, max_vulns=5):
    """把 site 文档压缩成给模型的研判素材。"""
    doc = site_doc or {}
    fingers = []
    for finger in doc.get("finger") or []:
        if isinstance(finger, dict) and finger.get("name"):
            fingers.append(str(finger["name"]))
        elif isinstance(finger, str):
            fingers.append(finger)

    brief = {
        "id": index,
        "site": str(doc.get("site") or ""),
        "title": str(doc.get("title") or "")[:100],
        "fingerprints": fingers[:10],
        "ip": str(doc.get("ip") or ""),
        "port": doc.get("port"),
        "status": doc.get("status"),
        "server": str(doc.get("http_server") or "")[:60],
    }
    for key in ("cdn_name", "waf_name"):
        if doc.get(key):
            brief[key] = str(doc[key])[:40]

    task_id = str(doc.get("task_id") or "")
    site_url = str(doc.get("site") or "")
    if task_id and site_url:
        paths = utils.conn_db("fileleak").find(
            {"task_id": task_id, "site": {"$in": [site_url, doc.get("hostname") or ""]}},
            {"_id": 0, "url": 1},
        ).limit(max_paths)
        path_list = [str(item.get("url") or "") for item in paths if item.get("url")]
        if path_list:
            brief["known_paths"] = path_list

        vulns = utils.conn_db("vuln").find(
            {"task_id": task_id, "site": site_url},
            {"_id": 0, "vul_name": 1, "level": 1},
        ).limit(max_vulns)
        vuln_list = [
            "{}({})".format(item.get("vul_name"), item.get("level"))
            for item in vulns if item.get("vul_name")
        ]
        if vuln_list:
            brief["known_vulns"] = vuln_list

    return brief


JUDGE_SYSTEM_PROMPT = (
    "你是 SRC 漏洞挖掘领域的资产研判专家。根据给定的 Web 资产信息，"
    "评估每个资产对漏洞挖掘的价值并给出结论。"
    "你必须只输出一个 JSON 数组，不要输出任何其他文字。"
    "数组每个元素形如："
    '{"id": <输入中的id>, "ai_priority": "P0|P1|P2|P3", "ai_summary": "<不超过80字的中文结论>"}。'
    "ai_priority 含义：P0=高价值目标(登录口/管理后台/上传/API网关/已知组件可打)，"
    "P1=有价值(业务系统/多接口/疑似未授权面)，P2=一般(静态页/官网)，P3=低价值(默认页/无效/纯跳转)。"
    "ai_summary 需指出研判依据（指纹/路径/标题特征）和下一步测试建议。"
)


def judge_site_batch(site_docs, scope="批量研判", max_paths=10):
    """批量研判：一次调用最多 MAX_BATCH_SITES 个站点，返回 per-doc 更新。"""
    if not site_docs:
        return {"input_count": 0, "judged_count": 0, "failed_count": 0}

    briefs = []
    id_map = {}
    for index, doc in enumerate(site_docs):
        briefs.append(build_site_brief(doc, index, max_paths=max_paths))
        id_map[index] = doc

    prompt = "研判范围：{}\n资产列表(JSON)：\n{}".format(
        scope, json.dumps(briefs, ensure_ascii=False))

    ok, content, error = ai_chat(
        prompt, system_prompt=JUDGE_SYSTEM_PROMPT, temperature=0.1,
        max_tokens=max(1024, len(briefs) * 180))

    updates = {}
    judged_count = 0
    now = utils.curr_date()
    if ok:
        parsed = extract_json(content)
        results = parsed if isinstance(parsed, list) else []
        valid_results = {}
        for item in results:
            if not isinstance(item, dict):
                continue
            try:
                item_id = int(item.get("id"))
            except (TypeError, ValueError):
                continue
            if item_id in id_map and item_id not in valid_results:
                valid_results[item_id] = item

        for index, doc in id_map.items():
            item = valid_results.get(index)
            summary = str((item or {}).get("ai_summary") or "").strip()
            priority = str((item or {}).get("ai_priority") or "").strip().upper()
            if item and summary:
                if priority not in ("P0", "P1", "P2", "P3"):
                    priority = "P2"
                updates[str(doc["_id"])] = {
                    "ai_state": AI_JUDGED_STATE,
                    "ai_summary": summary[:300],
                    "ai_priority": priority,
                    "ai_judged_date": now,
                }
                judged_count += 1
            else:
                updates[str(doc["_id"])] = {
                    "ai_state": AI_PENDING_STATE,
                    "ai_error": "模型未返回该资产的研判结果",
                    "ai_judged_date": now,
                }
    else:
        for doc in id_map.values():
            updates[str(doc["_id"])] = {
                "ai_state": AI_PENDING_STATE,
                "ai_error": error[:300],
                "ai_judged_date": now,
            }

    return {
        "input_count": len(site_docs),
        "judged_count": judged_count,
        "failed_count": len(site_docs) - judged_count,
        "error": "" if ok else error,
        "updates": updates,
    }


def _apply_updates(collection, updates):
    from bson import ObjectId

    conn = utils.conn_db(collection)
    applied = 0
    for site_id, fields in (updates or {}).items():
        try:
            query = {"_id": ObjectId(site_id)}
        except Exception:
            continue
        result = conn.update_one(query, {"$set": fields})
        applied += result.modified_count
    return applied


def load_site_docs(site_ids, collection="site"):
    from bson import ObjectId

    if collection not in SUPPORTED_COLLECTIONS:
        raise ValueError("unsupported collection: {}".format(collection))

    object_ids = []
    for site_id in site_ids or []:
        try:
            object_ids.append(ObjectId(str(site_id)))
        except Exception:
            continue
    if not object_ids:
        return []

    docs = list(utils.conn_db(collection).find({"_id": {"$in": object_ids}}))
    docs.sort(key=lambda item: str(item["_id"]))
    return docs


def judge_sites_by_ids(site_ids, collection="site", scope="批量研判"):
    site_ids = [str(item) for item in (site_ids or [])][:MAX_BATCH_SITES]
    if not site_ids:
        return {"input_count": 0, "judged_count": 0, "failed_count": 0,
                "error": "site_ids 为空"}

    docs = load_site_docs(site_ids, collection=collection)
    if not docs:
        return {"input_count": len(site_ids), "judged_count": 0,
                "failed_count": len(site_ids), "error": "没有找到对应站点"}

    result = judge_site_batch(docs, scope=scope)
    updates = result.pop("updates", {})
    result["applied_count"] = _apply_updates(collection, updates)
    result["collection"] = collection
    return result


def judge_task_sites(task_id, collection="site", max_sites=100):
    """任务后处理：对本任务所有未研判站点自动打分。"""
    query = {"task_id": str(task_id), "ai_state": {"$exists": False}}
    docs = list(utils.conn_db(collection).find(query, {"_id": 1}).limit(max_sites))
    site_ids = [str(item["_id"]) for item in docs]
    if not site_ids:
        return {"input_count": 0, "judged_count": 0, "failed_count": 0}

    total = {"input_count": 0, "judged_count": 0, "failed_count": 0,
             "applied_count": 0}
    for start in range(0, len(site_ids), MAX_BATCH_SITES):
        batch = site_ids[start:start + MAX_BATCH_SITES]
        result = judge_sites_by_ids(batch, collection=collection,
                                    scope="任务自动研判")
        for key in ("input_count", "judged_count", "failed_count",
                    "applied_count"):
            total[key] += int(result.get(key) or 0)
    return total


JS_SENSITIVE_SYSTEM_PROMPT = (
    "你是安全研究员，从给定的 JavaScript 代码片段中提取敏感信息。"
    "只输出 JSON 数组，元素形如 "
    '{"record_type": "<类型>", "content": "<发现内容，<=200字>"}。'
    "record_type 可选：api_key, access_key, secret, jwt, password, "
    "internal_url, internal_ip, config, other。没有发现则输出 []。"
)


def ai_extract_sensitive(js_text, source=""):
    """AI 兜底提取 JS 敏感信息，返回 record 列表。"""
    if not ai_enabled():
        return []

    snippet = str(js_text or "")[:12000]
    if len(snippet) < 200:
        return []

    ok, content, error = ai_chat(
        "来源:{}\n```javascript\n{}\n```".format(source, snippet),
        system_prompt=JS_SENSITIVE_SYSTEM_PROMPT, temperature=0.0,
        max_tokens=1500)
    if not ok:
        logger.debug("AI js extract failed: {}".format(_redact(error)))
        return []

    parsed = extract_json(content)
    if not isinstance(parsed, list):
        return []

    records = []
    for item in parsed[:30]:
        if not isinstance(item, dict):
            continue
        record_type = str(item.get("record_type") or "other")[:30]
        record_content = str(item.get("content") or "").strip()
        if not record_content:
            continue
        records.append({
            "record_type": record_type,
            "content": record_content[:500],
            "source": "ai",
            "site": str(source or ""),
        })
    return records
