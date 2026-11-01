# -*- coding:UTF-8 -*-
import os

import yaml
import requests
from flask_restx import fields, Namespace

from app.config import Config, basedir
from app.utils import get_logger, auth
from app.utils.audit import audit
from app.utils.yamlconf import load_config as _load_config_atomic
from app.utils.yamlconf import locked_update as _locked_update
from . import ARLResource

ns = Namespace('engines', description="测绘引擎凭证配置")

logger = get_logger()

CONFIG_PATH = os.path.join(basedir, 'config.yaml')

HUNTER_USER_INFO_URL = "https://hunter.qianxin.com/openApi/user/info"
QUAKE_USER_INFO_URL = "https://quake.360.net/api/v3/user/info"


def _mask(value):
    value = str(value or "").strip()
    if not value:
        return ""
    if len(value) <= 8:
        return "****"
    return value[:4] + "****" + value[-4:]


def _load_config():
    with open(CONFIG_PATH) as f:
        return yaml.load(f, Loader=yaml.SafeLoader) or {}


def _yaml_engine_conf():
    """每次请求直接读 config.yaml——gunicorn 多 worker 各有内存副本，
    保存落盘后只有 yaml 对所有 worker 立即可见。"""
    data = _load_config()
    query_plugin = data.get("QUERY_PLUGIN") or {}
    return (
        data.get("FOFA") or {},
        query_plugin.get("hunter_qax") or {},
        query_plugin.get("quake_360") or {},
    )


def _load_config():
    # 原子读：写入侧走 tmp + os.replace，读到的一定是完整文件
    return _load_config_atomic(CONFIG_PATH)


def _save_config(data):
    """加锁落盘（fengniao 等路由复用本函数）。

    锁内重读磁盘最新内容，仅覆盖本次涉及的顶层键（FOFA/QUERY_PLUGIN/...），
    避免与并发保存的其他凭证（如 FENGNIAR_TOKEN）互相覆盖；
    tmp 文件保持 0600 再原子替换，避免 config.yaml 在保存后掉权限。
    """
    with _locked_update(CONFIG_PATH) as fresh:
        for key, value in data.items():
            fresh[key] = value


def build_data(data, message="success"):
    ret = {
        "message": message,
        "code": 200,
        "data": {}
    }
    if data:
        ret["data"] = data
    return ret


@ns.route('/')
class EnginesConfig(ARLResource):

    @auth
    def get(self):
        """
        查询测绘引擎凭证（Key 掩码显示，实时读 config.yaml）
        """
        fofa_conf, hunter_conf, quake_conf = _yaml_engine_conf()
        hunter_key = str(hunter_conf.get("api_key") or "").strip()
        quake_token = str(quake_conf.get("quake_token") or "").strip()
        fofa_key = str(fofa_conf.get("KEY") or getattr(Config, "FOFA_KEY", "") or "").strip()

        return build_data({
            "fofa": {
                "key_masked": _mask(fofa_key),
                "configured": bool(fofa_key),
                "email": str(fofa_conf.get("EMAIL") or ""),
                "url": str(fofa_conf.get("URL") or Config.FOFA_URL),
            },
            "hunter_qax": {
                "key_masked": _mask(hunter_key),
                "configured": bool(hunter_key),
                "enabled": bool(hunter_conf.get("enable")),
                "key_masked_display": _mask(hunter_key) or "未配置",
            },
            "quake_360": {
                "token_masked": _mask(quake_token),
                "configured": bool(quake_token),
                "enabled": bool(quake_conf.get("enable")),
                "token_masked_display": _mask(quake_token) or "未配置",
            },
        })

    save_model = ns.model('EnginesSave', {
        'fofa_key': fields.String(description="FOFA Key"),
        'fofa_email': fields.String(description="FOFA 邮箱（旧版 API 预留字段）"),
        'hunter_api_key': fields.String(description="Hunter（奇安信鹰图）API Key"),
        'quake_token': fields.String(description="Quake（360）Token"),
        'delete': fields.List(
            fields.String(enum=["fofa", "hunter_qax", "quake_360"]),
            description="要清除凭证的引擎列表"),
    })

    @auth
    @ns.expect(save_model)
    def post(self):
        """
        保存/清除测绘引擎凭证（写入 config.yaml，Web 进程即时生效）
        """
        args = self.parse_args(self.save_model)
        data = _load_config()
        updated = []
        cleared = []

        # 先处理删除：清空凭证并停用对应被动源
        for engine in (args.get("delete") or []):
            if engine == "fofa":
                fofa_conf = data.setdefault("FOFA", {})
                fofa_conf["KEY"] = ""
                fofa_conf["EMAIL"] = ""
                Config.FOFA_KEY = ""
                cleared.append("fofa")
            elif engine == "hunter_qax":
                query_plugin = data.setdefault("QUERY_PLUGIN", {})
                hunter_conf = query_plugin.setdefault("hunter_qax", {})
                hunter_conf["api_key"] = ""
                hunter_conf["enable"] = False
                Config.QUERY_PLUGIN_CONFIG = query_plugin
                cleared.append("hunter_qax")
            elif engine == "quake_360":
                query_plugin = data.setdefault("QUERY_PLUGIN", {})
                quake_conf = query_plugin.setdefault("quake_360", {})
                quake_conf["quake_token"] = ""
                quake_conf["enable"] = False
                Config.QUERY_PLUGIN_CONFIG = query_plugin
                cleared.append("quake_360")

        fofa_key = str(args.get("fofa_key") or "").strip()
        fofa_email = str(args.get("fofa_email") or "").strip()
        if fofa_key or fofa_email:
            fofa_conf = data.setdefault("FOFA", {})
            if fofa_key:
                fofa_conf["KEY"] = fofa_key
                Config.FOFA_KEY = fofa_key
                updated.append("fofa_key")
            if fofa_email:
                fofa_conf["EMAIL"] = fofa_email
                updated.append("fofa_email")

        hunter_key = str(args.get("hunter_api_key") or "").strip()
        if hunter_key:
            query_plugin = data.setdefault("QUERY_PLUGIN", {})
            hunter_conf = query_plugin.setdefault("hunter_qax", {})
            hunter_conf["api_key"] = hunter_key
            hunter_conf["enable"] = True
            Config.QUERY_PLUGIN_CONFIG = query_plugin
            updated.append("hunter_api_key")

        quake_token = str(args.get("quake_token") or "").strip()
        if quake_token:
            query_plugin = data.setdefault("QUERY_PLUGIN", {})
            quake_conf = query_plugin.setdefault("quake_360", {})
            quake_conf["quake_token"] = quake_token
            quake_conf["enable"] = True
            Config.QUERY_PLUGIN_CONFIG = query_plugin
            updated.append("quake_token")

        if updated or cleared:
            _save_config(data)

        if updated:
            logger.info("engine credentials updated: {}".format(",".join(updated)))
        if cleared:
            logger.info("engine credentials cleared: {}".format(",".join(cleared)))
        if updated or cleared:
            audit("engine_credentials_change",
                  detail={"updated": updated, "cleared": cleared})

        message = "保存成功" if updated else ("凭证已清除" if cleared else "未提供需要更新的凭证")
        return build_data({
            "updated": updated,
            "cleared": cleared,
            "hint": "Web 端已即时生效；扫描 Worker 为独立进程，需重启后读取新配置",
        }, message)


@ns.route('/test')
class EnginesTest(ARLResource):

    test_model = ns.model('EnginesTest', {
        'engine': fields.String(required=True, enum=["fofa", "hunter_qax", "quake_360"],
                                description="要测试的引擎"),
    })

    @auth
    @ns.expect(test_model)
    def post(self):
        """
        测试引擎连接（使用已保存的凭证，实时读 config.yaml）
        """
        args = self.parse_args(self.test_model)
        engine = str(args.get("engine") or "").strip()
        fofa_conf, hunter_conf, quake_conf = _yaml_engine_conf()
        try:
            if engine == "fofa":
                key = str(fofa_conf.get("KEY") or getattr(Config, "FOFA_KEY", "") or "").strip()
                base_url = str(fofa_conf.get("URL") or Config.FOFA_URL).rstrip("/")
                if not key:
                    return build_data({"ok": False, "message": "FOFA Key 未配置"})
                r = requests.get(base_url + "/api/v1/info/my",
                                 params={"key": key}, timeout=10)
                body = r.json()
                if body.get("error"):
                    return build_data({"ok": False,
                                       "message": str(body.get("errmsg") or "认证失败")})
                return build_data({"ok": True, "message": "连接正常：{}".format(
                    body.get("email") or "账号有效")})

            if engine == "hunter_qax":
                api_key = str(hunter_conf.get("api_key") or "").strip()
                if not api_key:
                    return build_data({"ok": False, "message": "Hunter API Key 未配置"})
                # Hunter 开放 API 没有账号信息端点，用 page_size=1 的最小搜索验证凭证
                # （按 Hunter 计费规则，本次测试消耗 1 个查询积分）
                r = requests.get("https://hunter.qianxin.com/openApi/search",
                                 params={"api-key": api_key,
                                         "search": 'domain="example.com"',
                                         "page": 1, "page_size": 1, "is_web": 3,
                                         "start_time": "2020-01-01",
                                         "end_time": "2030-01-01"},
                                 timeout=15)
                try:
                    body = r.json()
                except Exception:
                    return build_data({"ok": False,
                                       "message": "响应异常：{}".format(r.text[:150])})
                if body.get("code") == 200:
                    return build_data({"ok": True,
                                       "message": "连接正常（本次测试消耗 1 个查询积分）"})
                return build_data({"ok": False,
                                   "message": "{}（code {}）".format(
                                       body.get("message") or "认证失败",
                                       body.get("code"))})

            if engine == "quake_360":
                token = str(quake_conf.get("quake_token") or "").strip()
                if not token:
                    return build_data({"ok": False, "message": "Quake Token 未配置"})
                r = requests.get(QUAKE_USER_INFO_URL,
                                 headers={"X-QuakeToken": token}, timeout=10)
                body = r.json()
                if body.get("code") == 0:
                    user_info = body.get("data") or {}
                    return build_data({"ok": True, "message": "连接正常：{}".format(
                        user_info.get("email") or user_info.get("username") or "账号有效")})
                return build_data({"ok": False,
                                   "message": str(body.get("message") or "认证失败")})

            return build_data({"ok": False, "message": "不支持的引擎：{}".format(engine)})
        except Exception as e:
            logger.exception("engine test failed: {}".format(engine))
            return build_data({"ok": False, "message": "网络请求失败：{}".format(e)})
