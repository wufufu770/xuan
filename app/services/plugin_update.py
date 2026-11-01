"""插件化在线更新（方案书 P3：指纹/POC 插件化在线更新）。

注册表 = 管理员配置的可信 JSON 索引（PLUGIN_REGISTRY_URL），描述可用插件：
    {"plugins": [{"plugin": 名, "version": 版本, "kind": "fingerprint|poc",
                  "sha256": 载荷哈希, "payload_url": 载荷地址}]}

安装防护（沿用 mcode-theme 整改的成熟手法）：
  - 载荷 URL 仅 http/https，DNS 解析后拒绝环回/私网/链路本地/保留地址（SSRF）
  - 载荷 5MB 上限 + sha256 校验（防篡改）
  - fingerprint 载荷 = [{"name", "rule"}]：规则过表达式校验后按 name
    upsert 指纹库（纯数据，不执行任何代码）
  - poc 载荷 = {"file": 插件文件名, "code": xing 插件源码}：文件名白名单
    + compile() 语法检查后落盘 xing plugins 目录（管理员信任注册表）
安装记录入 plugin_install 集合（name 唯一），version 比对支撑 check_update。
"""

import hashlib
import ipaddress
import os
import re
import socket
import time
import urllib.request

from app import utils
from app.config import Config

PLUGIN_INSTALL_COLLECTION = "plugin_install"

MAX_INDEX_BYTES = 512 * 1024
MAX_PAYLOAD_BYTES = 5 * 1024 * 1024
POC_FILE_RE = re.compile(r"^[A-Za-z0-9_\-]+\.py$")
KINDS = ("fingerprint", "poc")

logger = utils.get_logger()


def validate_fetch_url(url):
    """SSRF 防护：仅 http/https；DNS 解析后拒绝环回/私网/链路本地/保留地址。"""
    from urllib.parse import urlparse
    p = urlparse(str(url or ""))
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("插件来源仅支持 http/https: {}".format(url))
    try:
        infos = socket.getaddrinfo(p.hostname, None)
    except OSError as exc:
        raise ValueError("无法解析主机 {}: {}".format(p.hostname, exc))
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            raise ValueError("拒绝访问内网/保留地址（SSRF 防护）: {} → {}".format(
                p.hostname, ip))
    return str(url)


def _fetch(url, fetcher=None, limit=MAX_PAYLOAD_BYTES):
    """下载载荷（大小上限内）。fetcher 为测试注入点：fetcher(url) -> bytes。"""
    if fetcher is not None:
        data = fetcher(url)
    else:
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = resp.read(limit + 1)
    data = bytes(data or b"")
    if len(data) > limit:
        raise ValueError("载荷超过 {}MB 上限".format(limit // (1024 * 1024)))
    return data


def parse_index(raw):
    """注册表索引校验与归一化，返回插件条目列表。"""
    import json
    data = json.loads(raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else str(raw))
    plugins = (data or {}).get("plugins")
    if not isinstance(plugins, list):
        raise ValueError("注册表索引缺少 plugins 列表")
    entries = []
    for item in plugins:
        name = str((item or {}).get("plugin") or "").strip()
        version = str((item or {}).get("version") or "").strip()
        kind = str((item or {}).get("kind") or "").strip()
        sha256 = str((item or {}).get("sha256") or "").strip().lower()
        payload_url = str((item or {}).get("payload_url") or "").strip()
        if not name or not version or kind not in KINDS:
            raise ValueError("插件条目缺少 plugin/version/kind 或 kind 非法: {}".format(item))
        if not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise ValueError("插件 {} 的 sha256 非法".format(name))
        entries.append({"plugin": name, "version": version, "kind": kind,
                        "sha256": sha256, "payload_url": payload_url})
    return entries


def installed_map():
    """已安装插件名 -> 版本。"""
    return {str(doc.get("plugin")): str(doc.get("version") or "")
            for doc in utils.conn_db(PLUGIN_INSTALL_COLLECTION).find({})}


def check_update(fetcher=None, registry_url=None):
    """拉取注册表并与已安装版本比对，返回逐条状态。

    status: new（未安装）/ update（版本不同）/ current（一致）。
    """
    url = str(registry_url or getattr(Config, "PLUGIN_REGISTRY_URL", "") or "").strip()
    if not url:
        raise ValueError("未配置 PLUGIN_REGISTRY_URL")
    raw = _fetch(validate_fetch_url(url), fetcher,
                 limit=MAX_INDEX_BYTES)
    entries = parse_index(raw)
    installed = installed_map()
    result = []
    for entry in entries:
        cur = installed.get(entry["plugin"])
        status = "current" if cur == entry["version"] else ("update" if cur else "new")
        result.append(dict(entry, installed_version=cur or "", status=status))
    return result


def _install_fingerprint(payload, update_existing=True):
    """fingerprint 载荷安装：[{name, rule}] 校验后按 name upsert。"""
    import json
    from app.services import check_expression_with_error

    rules = json.loads(payload.decode("utf-8") if isinstance(payload, (bytes, bytearray))
                      else str(payload))
    if not isinstance(rules, list):
        raise ValueError("fingerprint 载荷应为规则列表")
    inserted = updated = invalid = 0
    for row in rules:
        name = str((row or {}).get("name") or "").strip()
        rule = str((row or {}).get("rule") or "").strip()
        if not name or not rule:
            invalid += 1
            continue
        flag, err = check_expression_with_error(rule)
        if not flag:
            logger.warning("plugin_update 规则无效跳过 {}: {}".format(name, err))
            invalid += 1
            continue
        conn = utils.conn_db("fingerprint")
        old = conn.find_one({"name": name})
        if old and not update_existing:
            continue
        conn.update_one(
            {"name": name},
            {"$set": {"name": name, "human_rule": rule,
                      "update_date": utils.curr_date_obj()}},
            upsert=True)
        if old:
            updated += 1
        else:
            inserted += 1
    return {"inserted": inserted, "updated": updated, "invalid": invalid}


def _poc_plugins_dir():
    """xing 插件目录（可测试替换）。"""
    from xing.conf import Conf as npoc_conf
    return os.path.join(npoc_conf.PROJECT_DIRECTORY, "plugins")


def _install_poc(payload, plugins_dir=None):
    """poc 载荷安装：{file, code} 白名单文件名 + 语法检查后落盘。"""
    import json
    data = json.loads(payload.decode("utf-8") if isinstance(payload, (bytes, bytearray))
                      else str(payload))
    filename = str((data or {}).get("file") or "").strip()
    code = str((data or {}).get("code") or "")
    if not POC_FILE_RE.fullmatch(filename):
        raise ValueError("poc 文件名非法（仅允许字母数字下划线连字符 .py）: {}".format(filename))
    if not code.strip():
        raise ValueError("poc 载荷缺少 code")
    try:
        compile(code, filename, "exec")     # 语法检查，不执行
    except SyntaxError as exc:
        raise ValueError("poc 源码语法错误: {}".format(exc))
    root = plugins_dir or _poc_plugins_dir()
    os.makedirs(root, exist_ok=True)
    dest = os.path.realpath(os.path.join(root, filename))
    if not dest.startswith(os.path.realpath(root) + os.sep):
        raise ValueError("poc 目标路径逃逸: {}".format(filename))
    with open(dest, "w", encoding="utf-8") as f:
        f.write(code)
    return {"file": filename, "bytes": len(code.encode("utf-8"))}


def install_plugin(entry, fetcher=None, plugins_dir=None):
    """安装单个插件：SSRF 校验 -> 下载 -> sha256 校验 -> 按 kind 落地 -> 记录。

    返回 {plugin, version, kind, result}；任何校验失败抛 ValueError。
    """
    name = str(entry.get("plugin") or "").strip()
    version = str(entry.get("version") or "").strip()
    kind = str(entry.get("kind") or "").strip()
    if not name or not version or kind not in KINDS:
        raise ValueError("插件条目非法: {}".format(entry))
    url = validate_fetch_url(entry.get("payload_url"))
    payload = _fetch(url, fetcher)

    digest = hashlib.sha256(payload).hexdigest()
    if digest != str(entry.get("sha256") or "").lower():
        raise ValueError("插件 {} 载荷 sha256 不匹配（拒绝安装）".format(name))

    if kind == "fingerprint":
        detail = _install_fingerprint(payload)
    else:
        detail = _install_poc(payload, plugins_dir=plugins_dir)

    utils.conn_db(PLUGIN_INSTALL_COLLECTION).update_one(
        {"plugin": name},
        {"$set": {"plugin": name, "version": version, "kind": kind,
                  "sha256": digest, "install_ts": time.time(),
                  "install_date": utils.curr_date()}},
        upsert=True)
    logger.info("plugin_update 安装 {} v{} ({}) {}".format(name, version, kind, detail))
    return {"plugin": name, "version": version, "kind": kind, "result": detail}
