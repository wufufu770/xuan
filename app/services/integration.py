"""数据源接入统一管理：空间测绘 / 被动收集 / 情报平台的凭证注册表。

仓库惯例：config.yaml 是跨进程凭证载体（routes/engines.py 说明——
gunicorn 多 worker 各有内存副本，保存加锁落盘后只有 yaml 对所有进程立即可见）。
本模块在其上提供：

  - VENDORS      厂商注册表（yaml 读写位置、字段 schema、探活函数）
  - view()       掩码视图（API/前端渲染用）
  - save_vendor() 字段级保存（locked_update 加锁落盘）+ 本进程 Config 同步
  - reload_runtime() mtime 缓存热更新——worker 进程在任务执行点调用，
    把 yaml 里的 FOFA/GITHUB/QUERY_PLUGIN 同步进内存 Config
  - test_vendor() 每厂商最小鉴权探活

FOFA/Hunter/Quake 三家与 routes/engines.py 的引擎凭证同段读写；
engines 保留旧 REST 契约，本模块是全量注册表的唯一实现。
"""

import os

import yaml

from app import utils
from app.config import Config, basedir
from app.utils.yamlconf import locked_update, load_config

CONFIG_PATH = os.path.join(basedir, 'config.yaml')

logger = utils.get_logger()


def _mask(value):
    value = str(value or "").strip()
    if not value:
        return ""
    if len(value) <= 8:
        return "****"
    return value[:4] + "****" + value[-4:]


def _redact(value, *secrets):
    text = str(value or "")
    for secret in secrets:
        secret = str(secret or "").strip()
        if secret:
            text = text.replace(secret, "***")
    return text


# ----------------------------------------------------------- 厂商注册表 ----
# yaml 写法两种：
#   ("FOFA", "KEY")                      顶层段内键（fofa/github）
#   ("QUERY_PLUGIN", "hunter_qax", "api_key")  被动收集插件段内子配置
# fields: (字段键, 展示名, 敏感)；enable=True 的厂商有被动收集开关。
VENDORS = {
    "fofa": {
        "name": "FOFA", "group": "mapping",
        "yaml": ("FOFA", None, "KEY"),
        "fields": [("key", "API Key", True)],
        "enable": True, "enable_hint": "启用 FOFA 被动子域收集（fofa/fofa_cert 插件）",
        "test": "fofa",
        "hint": "同时供 FOFA 采集任务使用；hunter_cert/quake_cert 等插件继承各自厂商配置",
    },
    "hunter_qax": {
        "name": "鹰图 Hunter", "group": "mapping",
        "yaml": ("QUERY_PLUGIN", "hunter_qax", None),
        "fields": [("api_key", "API Key", True)],
        "enable": True, "enable_hint": "启用鹰图被动收集（hunter_cert 继承本配置）",
        "test": "hunter_qax",
        "hint": "奇安信鹰图开放平台；hunter_cert 插件继承本 Key",
    },
    "quake_360": {
        "name": "360 Quake", "group": "mapping",
        "yaml": ("QUERY_PLUGIN", "quake_360", None),
        "fields": [("quake_token", "Token", True)],
        "enable": True, "enable_hint": "启用 Quake 被动收集（quake_cert 继承本配置）",
        "test": "quake_360",
        "hint": "360 空间测绘；quake_cert 插件继承本 Token",
    },
    "zoomeye": {
        "name": "ZoomEye", "group": "mapping",
        "yaml": ("QUERY_PLUGIN", "zoomeye", None),
        "fields": [("api_key", "API Key", True)],
        "enable": True, "enable_hint": "启用 ZoomEye 被动收集",
        "test": "zoomeye",
        "hint": "知道创宇钟馗之眼",
    },
    "shodan": {
        "name": "Shodan", "group": "mapping",
        "yaml": ("QUERY_PLUGIN", "shodan", None),
        "fields": [("api_key", "API Key", True)],
        "enable": True, "enable_hint": "启用 Shodan 被动收集",
        "test": "shodan",
        "hint": "DNS 域名库被动子域；免费档可用",
    },
    "censys": {
        "name": "Censys", "group": "mapping",
        "yaml": ("QUERY_PLUGIN", "censys", None),
        "fields": [("auth_email", "API ID（邮箱）", False),
                   ("auth_key", "API Secret", True)],
        "enable": True, "enable_hint": "启用 Censys 被动收集",
        "test": "censys",
        "hint": "主机/证书 DNS 名称检索；API ID + Secret 双要素",
    },
    "virustotal": {
        "name": "VirusTotal", "group": "plugin",
        "yaml": ("QUERY_PLUGIN", "virustotal", None),
        "fields": [("api_key", "API Key", True)],
        "enable": True, "enable_hint": "启用 VirusTotal 被动收集",
        "test": "virustotal",
        "hint": "被动子域 + 证书透明度",
    },
    "securitytrails": {
        "name": "SecurityTrails", "group": "plugin",
        "yaml": ("QUERY_PLUGIN", "securitytrails", None),
        "fields": [("api_key", "API Key", True)],
        "enable": True, "enable_hint": "启用 SecurityTrails 被动收集",
        "test": "securitytrails",
        "hint": "历史 DNS 与子域",
    },
    "chaos": {
        "name": "Chaos (ProjectDiscovery)", "group": "plugin",
        "yaml": ("QUERY_PLUGIN", "chaos", None),
        "fields": [("api_key", "API Key", True)],
        "enable": True, "enable_hint": "启用 Chaos 被动收集",
        "test": None,
        "hint": "公开子域数据集；未内置探活，保存后由任务实际调用验证",
    },
    "passivetotal": {
        "name": "RiskIQ PassiveTotal", "group": "plugin",
        "yaml": ("QUERY_PLUGIN", "passivetotal", None),
        "fields": [("auth_email", "账号邮箱", False), ("auth_key", "API Key", True)],
        "enable": True, "enable_hint": "启用 PassiveTotal 被动收集",
        "test": "passivetotal",
        "hint": "邮箱 + API Key 双要素",
    },
    "github": {
        "name": "GitHub Token", "group": "intel",
        "yaml": ("GITHUB", None, "TOKEN"),
        "fields": [("token", "Personal Access Token", True)],
        "enable": False, "enable_hint": "",
        "test": "github",
        "hint": "GitHub 泄露监控（计划任务 → GitHub 泄露监控）与代码搜索用",
    },
}

# 免密被动来源（无需凭证，配置 QUERY_PLUGIN.<name>.enable 即可开关）
KEYLESS_SOURCES = [
    ["crtsh", "crt.sh 证书透明"],
    ["rapiddns", "RapidDNS"],
    ["wayback", "Wayback 历史"],
    ["alienvault", "AlienVault OTX"],
    ["certspotter", "Certspotter"],
    ["subfinder", "subfinder 聚合"],
]

GROUP_NAMES = {"mapping": "空间测绘", "plugin": "被动收集", "intel": "情报平台"}


# --------------------------------------------------------------- 读写 ----
def _vendor_section(data, vendor):
    """按注册表取厂商配置 dict（可能为空）。"""
    section, subkey, _ = VENDORS[vendor]["yaml"]
    conf = data.get(section) or {}
    if subkey:
        return conf.get(subkey) or {}
    return conf


def _vendor_get(data, vendor, field_key):
    """取厂商单字段原始值：字段键 → yaml 实际键。"""
    section, subkey, direct = VENDORS[vendor]["yaml"]
    conf = _vendor_section(data, vendor)
    if direct:            # ("FOFA", None, "KEY")：字段 key → 段内键 KEY
        return conf.get(direct)
    return conf.get(field_key)


def view():
    """全量掩码视图，按 group 分组返回。"""
    data = load_config(CONFIG_PATH)
    groups = {}
    for vendor, spec in VENDORS.items():
        conf = _vendor_section(data, vendor)
        values = {}
        configured = False
        for field_key, label, sensitive in spec["fields"]:
            raw = str(_vendor_get(data, vendor, field_key) or "").strip()
            if raw:
                configured = True
            values[field_key] = _mask(raw) if (sensitive and raw) else raw
        item = {
            "vendor": vendor,
            "name": spec["name"],
            "configured": configured,
            "values": values,
            "field_defs": [{"key": k, "label": label}
                           for k, label, _s in spec["fields"]],
            "testable": bool(spec.get("test")),
            "hint": spec.get("hint", ""),
        }
        if spec.get("enable"):
            item["enabled"] = bool(conf.get("enable"))
            item["enable_hint"] = spec["enable_hint"]
        groups.setdefault(spec["group"], []).append(item)
    return {
        "groups": [{"group": g, "name": GROUP_NAMES[g], "items": items}
                   for g, items in groups.items()],
        "keyless_sources": [{"vendor": v, "name": n} for v, n in KEYLESS_SOURCES],
    }


def _set_plugin_enable(data, spec, vendor, value):
    """写被动收集开关。

    插件型厂商（hunter_qax 等）的 enable 在 QUERY_PLUGIN.<vendor> 子配置内；
    fofa 凭证在顶层 FOFA 段，其插件开关单独放 QUERY_PLUGIN.fofa.enable。
    """
    section, subkey, _direct = spec["yaml"]
    if section == "QUERY_PLUGIN" and subkey:
        conf = data.setdefault(section, {}).setdefault(subkey, {})
        if isinstance(conf, dict):
            conf["enable"] = bool(value)
        return
    query_plugin = data.setdefault("QUERY_PLUGIN", {})
    sub = query_plugin.setdefault(vendor, {})
    if not isinstance(sub, dict):
        sub = {}
        query_plugin[vendor] = sub
    sub["enable"] = bool(value)


def save_vendor(vendor, fields, enable=None, clear=False):
    """保存/清除一个厂商的凭证。

    fields 键为注册表 fields 的字段键；留空/缺省字段不改动（掩码回显场景），
    clear=True 清空全部字段并停用。返回 (updated_keys, cleared_keys)。
    """
    spec = VENDORS.get(vendor)
    if not spec:
        raise ValueError("未知数据源: {}".format(vendor))

    section, subkey, direct = spec["yaml"]
    updated, cleared = [], []

    with locked_update(CONFIG_PATH) as data:
        if subkey:
            conf = data.setdefault(section, {})
            if not isinstance(conf, dict):
                conf = {}
                data[section] = conf
            section_conf = conf.setdefault(subkey, {})
            if not isinstance(section_conf, dict):
                section_conf = {}
                conf[subkey] = section_conf
        else:
            section_conf = data.setdefault(section, {})
            if not isinstance(section_conf, dict):
                section_conf = {}
                data[section] = section_conf

        if clear:
            for field_key, label, _s in spec["fields"]:
                yaml_key = direct or field_key
                if str(section_conf.get(yaml_key) or "").strip():
                    section_conf[yaml_key] = ""
                    cleared.append(field_key)
            if spec.get("enable"):
                _set_plugin_enable(data, spec, vendor, False)
        else:
            for field_key, label, _s in spec["fields"]:
                value = str(fields.get(field_key) or "").strip()
                if not value:
                    continue
                yaml_key = direct or field_key
                section_conf[yaml_key] = value
                updated.append(field_key)
            if updated and spec.get("enable"):
                # 插件型厂商随新 Key 自动启用；fofa/github 型仅显式传参时变更
                eff_enable = enable if enable is not None \
                    else (section == "QUERY_PLUGIN")
                if eff_enable is not None:
                    _set_plugin_enable(data, spec, vendor, eff_enable)
            elif spec.get("enable") and enable is not None:
                _set_plugin_enable(data, spec, vendor, enable)

    _sync_process_config()
    return updated, cleared


def _sync_process_config():
    """把 yaml 当前内容同步进本进程 Config（与 reload_runtime 共用实现）。"""
    data = load_config(CONFIG_PATH)
    Config.FOFA_KEY = str((data.get("FOFA") or {}).get("KEY") or "").strip()
    Config.GITHUB_TOKEN = str((data.get("GITHUB") or {}).get("TOKEN") or "").strip()
    query_plugin = data.get("QUERY_PLUGIN")
    if isinstance(query_plugin, dict):
        Config.QUERY_PLUGIN_CONFIG = query_plugin


_mtime_cache = {"ts": None}


def reload_runtime(force=False):
    """worker 热更新入口：config.yaml 有变化时同步内存 Config。

    在任务执行点调用（被动收集插件分发、github 监控任务启动、FOFA 任务提交）。
    mtime 未变化时零开销（一次 stat）。
    """
    try:
        mtime = os.path.getmtime(CONFIG_PATH)
    except OSError:
        return False
    if not force and _mtime_cache["ts"] == mtime:
        return False
    _mtime_cache["ts"] = mtime
    _sync_process_config()
    return True


# --------------------------------------------------------------- 探活 ----
def _test_fofa(key):
    from app.services.fofaClient import FofaClient
    client = FofaClient(key, page_size=1, max_page=1)
    data = client.fofa_search_all('is_domain=true')
    return {"ok": True, "message": "连接正常，命中 {} 条".format(data.get("size", "?"))}


def _test_github(token):
    resp = utils.http_req("https://api.github.com/user", "get",
                          headers={"Authorization": "Bearer {}".format(token),
                                   "Accept": "application/vnd.github+json"},
                          timeout=(5.1, 15.1))
    if resp.status_code == 200:
        login = (resp.json() or {}).get("login") or "?"
        return {"ok": True, "message": "鉴权成功：{}".format(login)}
    return {"ok": False, "message": "HTTP {}".format(resp.status_code)}


def _test_virustotal(key):
    resp = utils.http_req(
        "https://www.virustotal.com/api/v3/domains/example.com/subdomains?limit=1",
        "get", headers={"x-apikey": key}, timeout=(5.1, 15.1))
    if resp.status_code == 200:
        return {"ok": True, "message": "连接正常"}
    return {"ok": False, "message": "HTTP {}".format(resp.status_code)}


def _test_hunter_qax(key):
    from urllib.parse import quote
    query = quote('ip="8.8.8.8"')
    resp = utils.http_req(
        "https://hunter.qianxin.com/openApi/search?api-key={}&search={}&page=1&page_size=1".format(
            key, query),
        "get", timeout=(5.1, 15.1))
    body = resp.json() if resp.status_code == 200 else {}
    code = body.get("code")
    if code == 200:
        return {"ok": True, "message": "连接正常，剩余配额 {}".format(
            (body.get("data") or {}).get("rest_quota", "?"))}
    return {"ok": False,
            "message": _redact("code {} {}".format(code, body.get("message") or ""), key)}


def _test_quake_360(token):
    resp = utils.http_req("https://quake.360.net/api/v3/user/info", "get",
                          headers={"X-QuakeToken": token},
                          timeout=(5.1, 15.1))
    body = resp.json() if resp.status_code == 200 else {}
    if body.get("code") == 0:
        return {"ok": True, "message": "连接正常"}
    return {"ok": False,
            "message": _redact("code {} {}".format(body.get("code"), body.get("message") or ""), token)}


def _test_zoomeye(key):
    resp = utils.http_req("https://api.zoomeye.org/resources-info", "get",
                          headers={"API-KEY": key}, timeout=(5.1, 15.1))
    if resp.status_code == 200:
        return {"ok": True, "message": "连接正常"}
    return {"ok": False, "message": "HTTP {}".format(resp.status_code)}


def _test_securitytrails(key):
    resp = utils.http_req("https://api.securitytrails.com/v1/domain/example.com",
                          "get", headers={"APIKEY": key, "Accept": "application/json"},
                          timeout=(5.1, 15.1))
    if resp.status_code == 200:
        return {"ok": True, "message": "连接正常"}
    return {"ok": False, "message": "HTTP {}".format(resp.status_code)}


def _test_passivetotal(fields):
    email = str(fields.get("auth_email") or "").strip()
    key = str(fields.get("auth_key") or "").strip()
    if not email or not key:
        return {"ok": False, "message": "需要账号邮箱与 API Key"}
    resp = utils.http_req("https://api.passivetotal.org/v2/account/quota", "get",
                          auth=(email, key), timeout=(5.1, 15.1))
    if resp.status_code == 200:
        return {"ok": True, "message": "连接正常"}
    return {"ok": False, "message": "HTTP {}".format(resp.status_code)}


def _test_shodan(key):
    resp = utils.http_req("https://api.shodan.io/api-info", "get",
                          params={"key": key}, timeout=(5.1, 15.1))
    if resp.status_code == 200:
        plan = (resp.json() or {}).get("plan") or "?"
        return {"ok": True, "message": "连接正常（{} 档）".format(plan)}
    return {"ok": False, "message": "HTTP {}".format(resp.status_code)}


def _test_censys(fields):
    email = str(fields.get("auth_email") or "").strip()
    key = str(fields.get("auth_key") or "").strip()
    if not email or not key:
        return {"ok": False, "message": "需要 API ID 与 API Secret"}
    resp = utils.http_req("https://search.censys.io/api/v2/account", "get",
                          auth=(email, key), timeout=(5.1, 15.1))
    if resp.status_code == 200:
        login_email = ((resp.json() or {}).get("result") or {}).get("email") or "?"
        return {"ok": True, "message": "连接正常：{}".format(login_email)}
    return {"ok": False, "message": "HTTP {}".format(resp.status_code)}


TESTERS = {
    "fofa": lambda fields: _test_fofa(str(fields.get("key") or "").strip()),
    "github": lambda fields: _test_github(str(fields.get("token") or "").strip()),
    "virustotal": lambda fields: _test_virustotal(str(fields.get("api_key") or "").strip()),
    "hunter_qax": lambda fields: _test_hunter_qax(str(fields.get("api_key") or "").strip()),
    "quake_360": lambda fields: _test_quake_360(str(fields.get("quake_token") or "").strip()),
    "zoomeye": lambda fields: _test_zoomeye(str(fields.get("api_key") or "").strip()),
    "shodan": lambda fields: _test_shodan(str(fields.get("api_key") or "").strip()),
    "censys": lambda fields: _test_censys(fields),
    "securitytrails": lambda fields: _test_securitytrails(str(fields.get("api_key") or "").strip()),
    "passivetotal": lambda fields: _test_passivetotal(fields),
}


def test_vendor(vendor):
    """对已保存（或传入）凭证做最小鉴权探活。"""
    spec = VENDORS.get(vendor)
    if not spec:
        return {"ok": False, "message": "未知数据源: {}".format(vendor)}

    data = load_config(CONFIG_PATH)
    fields = {field_key: str(_vendor_get(data, vendor, field_key) or "").strip()
              for field_key, _label, _s in spec["fields"]}

    tester = spec.get("test")
    if not tester:
        if any(fields.values()):
            return {"ok": True, "tested": False,
                    "message": "已配置（该厂商未内置探活，任务实际调用时验证）"}
        return {"ok": False, "message": "尚未配置"}

    fn = TESTERS.get(vendor)
    if fn is None:
        return {"ok": False, "message": "未知数据源: {}".format(vendor)}

    if not any(fields.values()):
        return {"ok": False, "message": "尚未配置，无法探活"}

    try:
        result = fn(fields)
    except Exception as e:
        secrets = [v for v in fields.values() if v]
        return {"ok": False, "message": _redact("连接失败：{}".format(e), *secrets)}
    if isinstance(result.get("message"), str):
        result["message"] = _redact(result["message"],
                                    *[v for v in fields.values() if v])
    return result
