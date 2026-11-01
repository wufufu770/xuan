"""玄览平台 Agent 工具注册表（内部 Agent 与 MCP Server 共用）。

每个工具 = {name, description, parameters(JSON Schema), handler, danger}。
handler 面向服务层/集合直连（无 Flask request 依赖），返回可 JSON 序列化的
dict；danger 工具在 MCP 侧默认禁用，内部 Agent 调用时由前端确认卡把关。
"""

import re
import time

from bson import ObjectId

from app import utils
from app.config import Config

logger = utils.get_logger()

MAX_ROWS = 20


def _conn(name):
    return utils.conn_db(name)


def _clean(doc, drop_fields=()):
    out = {}
    for k, v in (doc or {}).items():
        if k in drop_fields:
            continue
        if k == "_id":
            v = str(v)
        out[k] = v
    return out


def _rx(keyword):
    return {"$regex": re.escape(str(keyword or "").strip()), "$options": "i"}


# ------------------------------------------------------------ 工具实现 ----

def tool_platform_overview():
    body = _conn("task").estimated_document_count()
    data = {
        "tasks": body,
        "sites": _conn("site").estimated_document_count(),
        "domains": _conn("domain").estimated_document_count(),
        "ips": _conn("ip").estimated_document_count(),
        "vulns": _conn("vuln").estimated_document_count(),
        "nuclei_results": _conn("nuclei_result").estimated_document_count(),
        "scopes": _conn("asset_scope").estimated_document_count(),
        "policies": _conn("policy").estimated_document_count(),
        "scheduled_monitors": _conn("scheduler").estimated_document_count(),
        "github_monitors": _conn("github_scheduler").estimated_document_count(),
        "fingerprint_total": _conn("fingerprint").estimated_document_count(),
        "poc_total": _conn("poc").estimated_document_count(),
    }
    return data


def tool_search_assets(kind="site", keyword="", size=MAX_ROWS):
    kind = str(kind or "site").strip().lower()
    conf = {"site": ("site", "site"), "domain": ("domain", "domain"),
            "ip": ("ip", "ip")}.get(kind)
    if not conf:
        return {"error": "kind 须为 site|domain|ip"}
    coll, field = conf
    size = min(max(int(size or MAX_ROWS), 1), 50)
    query = {field: _rx(keyword)} if keyword else {}
    rows = list(_conn(coll).find(query, {"_id": 0}).limit(size))
    return {"kind": kind, "count": len(rows), "items": rows}


def tool_asset_ext_query(kind="app", keyword="", size=MAX_ROWS):
    from app.routes.asset_ext import KIND_CONF
    kind = str(kind or "app").strip().lower()
    if kind not in KIND_CONF:
        return {"error": "kind 须为 app|miniprogram|icp"}
    size = min(max(int(size or MAX_ROWS), 1), 50)
    name_field = KIND_CONF[kind][0]
    query = {}
    if keyword:
        rx = _rx(keyword)
        query = {"$or": [{"ent_name": rx}, {"{}.{}".format(kind, name_field): rx}]}
    items = []
    for doc in _conn("fengniao_intel").find(query).limit(200):
        for row in (doc.get(kind) or []):
            if isinstance(row, dict):
                item = dict(row)
                item["ent_name"] = doc.get("ent_name")
                items.append(item)
    return {"kind": kind, "count": len(items), "items": items[:size]}


def tool_submit_task(target, name="", template="standard"):
    """按模板下发扫描任务（quick|standard|deep）。"""
    from app.helpers import submit_task_task

    templates = {
        "quick": {"port_scan_type": "test", "domain_brute": True, "arl_search": True,
                  "site_identify": True, "port_scan": True},
        "standard": {"port_scan_type": "top1000", "domain_brute": True, "arl_search": True,
                     "dns_query_plugin": True, "alt_dns": True, "site_identify": True,
                     "ssl_cert": True, "port_scan": True},
        "deep": {"port_scan_type": "all", "domain_brute": True, "arl_search": True,
                 "dns_query_plugin": True, "alt_dns": True, "search_engines": True,
                 "site_identify": True, "ssl_cert": True, "file_leak": True,
                 "nuclei_scan": True, "nuclei_scan_confirm": True, "site_spider": True,
                 "port_scan": True},
    }
    options = templates.get(str(template or "standard").strip().lower())
    if not options:
        return {"error": "template 须为 quick|standard|deep"}
    if not str(target or "").strip() or not str(name or "").strip():
        return {"error": "target 与 name 必填"}
    name = str(name).strip() or "Agent-任务-{}".format(utils.curr_date())
    task_list = submit_task_task(target=str(target).strip(), name=name, options=options)
    return {"submitted": len(task_list or []),
            "task_ids": [str(t.get("task_id")) for t in (task_list or [])],
            "name": name, "template": template}


def tool_task_status(task_id):
    try:
        oid = ObjectId(str(task_id))
    except Exception:
        return {"error": "task_id 非法: {}".format(task_id)}
    doc = _conn("task").find_one({"_id": oid})
    if not doc:
        return {"error": "任务不存在: {}".format(task_id)}
    stages = list(_conn("task_stage").find({"task_id": str(task_id)}, {"_id": 0}))
    return {"task": _clean(doc, ("options",)), "stages": stages[:20]}


def tool_list_tasks(status="", size=MAX_ROWS):
    size = min(max(int(size or MAX_ROWS), 1), 50)
    query = {"status": status} if status else {}
    rows = list(_conn("task").find(
        query, {"_id": 1, "name": 1, "target": 1, "status": 1,
                "start_time": 1, "end_time": 1}).sort("_id", -1).limit(size))
    for r in rows:
        r["_id"] = str(r["_id"])
    return {"count": len(rows), "items": rows}


def tool_list_risks(severity="", size=MAX_ROWS):
    size = min(max(int(size or MAX_ROWS), 1), 50)
    query = {"severity": str(severity).strip().lower()} if severity else {}
    rows = list(_conn("vuln").find(
        query, {"_id": 0, "vul_name": 1, "severity": 1, "plg_name": 1,
                "target": 1, "url": 1}).sort("_id", -1).limit(size))
    nuclei = list(_conn("nuclei_result").find(
        {"vuln_severity": _rx(severity)} if severity else {},
        {"_id": 0, "template_id": 1, "vuln_name": 1, "vuln_severity": 1,
         "vuln_url": 1}).sort("_id", -1).limit(size))
    return {"vuln_count": len(rows), "vulns": rows,
            "nuclei_count": len(nuclei), "nuclei": nuclei}


def tool_create_scope(name, scope, scope_type="domain"):
    if not str(name or "").strip() or not str(scope or "").strip():
        return {"error": "name 与 scope 必填"}
    result = _conn("asset_scope").insert_one({
        "name": str(name).strip(), "scope_type": str(scope_type or "domain"),
        "scope": str(scope).strip(), "scope_array": [x.strip() for x in
                                                     re.split(r",|\s", str(scope)) if x.strip()],
        "black_scope": "", "black_scope_array": [],
    })
    return {"scope_id": str(result.inserted_id)}


def tool_schedule_scan(target, cron="0 */6 * * *", policy_name="", task_tag="task"):
    """创建周期扫描计划（策略按名称取第一个匹配，缺省用第一个可用策略）。"""
    from bson import ObjectId

    policy = None
    if policy_name:
        policy = _conn("policy").find_one({"name": str(policy_name).strip()})
    if not policy:
        policy = _conn("policy").find_one()
    if not policy:
        return {"error": "暂无可用策略——请先在任务策略页创建"}
    ok_flag, msg = utils.check_cron_interval(cron)
    if not ok_flag:
        return {"error": "cron 非法: {}".format(msg if isinstance(msg, str) else "间隔过短（最小 6 小时）")}
    _, next_sec, _ = utils.check_cron(cron)
    data = {
        "name": "Agent-计划-{}".format(str(target).strip()[:40]),
        "target": str(target).strip(), "task_tag": str(task_tag or "task"),
        "schedule_type": "recurrent_scan", "policy_id": str(policy["_id"]),
        "policy_name": policy.get("name", ""), "cron": cron,
        "start_date": "", "start_time": 0,
        "status": "scheduled", "run_number": 0,
        "last_run_time": 0, "last_run_date": "-",
        "next_run_date": utils.time2date(time.time() + next_sec),
    }
    inserted = _conn("task_schedule").insert_one(data)
    return {"schedule_id": str(inserted.inserted_id), "policy_name": policy.get("name", ""),
            "cron": cron, "next_run_date": data["next_run_date"]}


def tool_generate_report(scope_id, scope_name="", use_llm=False):
    from app.services import report_center
    job_id = report_center.submit_report_job(
        str(scope_id).strip(), scope_name=str(scope_name or "").strip(),
        use_llm=bool(use_llm))
    return {"job_id": str(job_id), "hint": "报告中心页可查进度与下载"}


def tool_scope_assets(scope_id):
    """资产组边界与关联资产统计。"""
    from bson import ObjectId
    try:
        doc = _conn("asset_scope").find_one({"_id": ObjectId(str(scope_id))})
    except Exception:
        doc = None
    if not doc:
        return {"error": "资产组不存在: {}".format(scope_id)}
    sid = str(doc["_id"])
    counts = {name: _conn(name).count_documents({"scope_id": sid})
              for name in ("asset_domain", "asset_site", "asset_ip")}
    return {"name": doc.get("name"), "scope_type": doc.get("scope_type"),
            "scope_array": doc.get("scope_array") or [],
            "black_scope_array": doc.get("black_scope_array") or [],
            "assets": counts}


# ------------------------------------------------------------ 注册表 ----

TOOLS = [
    {"name": "platform_overview",
     "description": "获取玄览平台总览：任务/站点/域名/IP/漏洞/资产组/策略/计划任务等数量统计",
     "parameters": {"type": "object", "properties": {}, "required": []},
     "handler": tool_platform_overview, "danger": False},

    {"name": "search_assets",
     "description": "检索资产库（site 站点 / domain 域名 / ip），按关键字模糊匹配",
     "parameters": {"type": "object", "properties": {
         "kind": {"type": "string", "enum": ["site", "domain", "ip"]},
         "keyword": {"type": "string", "description": "关键字，留空返回最新"},
         "size": {"type": "integer", "description": "返回条数，默认 20，上限 50"}},
         "required": []},
     "handler": tool_search_assets, "danger": False},

    {"name": "asset_ext_query",
     "description": "检索企业情报资产：APP / 小程序 / ICP 备案（来自凤鸟企业采集）",
     "parameters": {"type": "object", "properties": {
         "kind": {"type": "string", "enum": ["app", "miniprogram", "icp"]},
         "keyword": {"type": "string", "description": "企业名或条目名关键字"},
         "size": {"type": "integer"}}, "required": []},
     "handler": tool_asset_ext_query, "danger": False},

    {"name": "submit_task",
     "description": "下发扫描任务（模板 quick 快速 / standard 标准 / deep 深度）",
     "parameters": {"type": "object", "properties": {
         "target": {"type": "string", "description": "目标：域名/IP/网段"},
         "name": {"type": "string", "description": "任务名"},
         "template": {"type": "string", "enum": ["quick", "standard", "deep"]}},
         "required": ["target", "name"]},
     "handler": tool_submit_task, "danger": True},

    {"name": "task_status",
     "description": "查询任务状态与阶段明细",
     "parameters": {"type": "object", "properties": {
         "task_id": {"type": "string"}}, "required": ["task_id"]},
     "handler": tool_task_status, "danger": False},

    {"name": "list_tasks",
     "description": "列出最近任务（可按 status 过滤：waiting/doing/done/error/stop）",
     "parameters": {"type": "object", "properties": {
         "status": {"type": "string"}, "size": {"type": "integer"}}, "required": []},
     "handler": tool_list_tasks, "danger": False},

    {"name": "list_risks",
     "description": "检索风险中心：漏洞（vuln）与 Nuclei 结果，可按严重等级过滤",
     "parameters": {"type": "object", "properties": {
         "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", ""]},
         "size": {"type": "integer"}}, "required": []},
     "handler": tool_list_risks, "danger": False},

    {"name": "create_scope",
     "description": "创建资产组（域名或 IP 段集合）",
     "parameters": {"type": "object", "properties": {
         "name": {"type": "string"}, "scope": {"type": "string"},
         "scope_type": {"type": "string", "enum": ["domain", "ip"]}},
         "required": ["name", "scope"]},
     "handler": tool_create_scope, "danger": False},

    {"name": "schedule_scan",
     "description": "创建周期扫描计划任务（cron 周期，策略按名称匹配，缺省用第一个策略）",
     "parameters": {"type": "object", "properties": {
         "target": {"type": "string"}, "cron": {"type": "string"},
         "policy_name": {"type": "string"},
         "task_tag": {"type": "string", "enum": ["task", "risk_cruising"]}},
         "required": ["target"]},
     "handler": tool_schedule_scan, "danger": True},

    {"name": "generate_report",
     "description": "为资产组生成 Word 报告（可选 LLM 执行摘要），异步任务",
     "parameters": {"type": "object", "properties": {
         "scope_id": {"type": "string"}, "scope_name": {"type": "string"},
         "use_llm": {"type": "boolean"}}, "required": ["scope_id"]},
     "handler": tool_generate_report, "danger": False},

    {"name": "scope_assets",
     "description": "查看资产组边界（范围/黑名单）与关联资产统计",
     "parameters": {"type": "object", "properties": {
         "scope_id": {"type": "string"}}, "required": ["scope_id"]},
     "handler": tool_scope_assets, "danger": False},
]

TOOLS_BY_NAME = {t["name"]: t for t in TOOLS}
MCP_BLOCKED = [t["name"] for t in TOOLS if t["danger"]]


def call_tool(name, arguments=None, allow_danger=False):
    """统一执行入口：返回 {ok, result|error}；异常收口为 error。"""
    tool = TOOLS_BY_NAME.get(str(name or "").strip())
    if not tool:
        return {"ok": False, "error": "未知工具: {}".format(name)}
    if tool["danger"] and not allow_danger:
        return {"ok": False, "error": "工具 {} 为破坏性操作，MCP 侧默认禁用".format(name)}
    arguments = arguments or {}
    try:
        result = tool["handler"](**arguments)
    except TypeError as exc:
        return {"ok": False, "error": "参数错误: {}".format(exc)}
    except Exception as exc:
        logger.warning("agent tool {} failed: {}".format(name, exc))
        return {"ok": False, "error": "执行失败: {}".format(exc)}
    return {"ok": True, "result": result}


def tool_call_events(name, arguments):
    """工具调用的中文事件描述（前端步骤条/会话渲染用）。"""
    tool = TOOLS_BY_NAME.get(name) or {}
    return {"name": name, "description": tool.get("description", ""),
            "arguments": arguments or {}, "danger": tool.get("danger", False)}
