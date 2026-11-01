# -*- coding:UTF-8 -*-
import os
import time

import yaml
from flask_restx import fields, Namespace

from app.config import Config, basedir
from app.utils import get_logger, auth
from . import ARLResource

ns = Namespace('ai', description="AI 资产研判")

logger = get_logger()

CONFIG_PATH = os.path.join(basedir, 'config.yaml')

SUPPORTED_FORMATS = ("openai", "anthropic")


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


def _save_config(data):
    tmp_path = CONFIG_PATH + ".tmp"
    with open(tmp_path, "w") as f:
        yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False,
                       default_flow_style=False)
    os.replace(tmp_path, CONFIG_PATH)


def build_data(data, message="success"):
    ret = {
        "message": message,
        "code": 200,
        "data": {}
    }
    if data:
        ret["data"] = data
    return ret


def _new_provider_id():
    return "p-{}".format(int(time.time() * 1000))


def _provider_view(p):
    api_key = str(p.get("api_key") or "").strip()
    return {
        "id": str(p.get("id") or ""),
        "name": str(p.get("name") or ""),
        "format": str(p.get("format") or "openai"),
        "base_url": str(p.get("base_url") or ""),
        "model": str(p.get("model") or ""),
        "api_key_masked": _mask(api_key),
        "configured": bool(api_key),
    }


def _ai_config_view():
    from app.services.ai_judge import get_providers, get_active_provider_id

    providers = [_provider_view(p) for p in get_providers()]
    active_id = str(get_active_provider_id() or "")
    ready = any(p["id"] == active_id and p["configured"] and p["base_url"] and p["model"]
                for p in providers)
    return {
        "enable": bool(Config.AI_ENABLE),
        "active_id": active_id,
        "providers": providers,
        "ready": ready and bool(Config.AI_ENABLE),
    }


def _sync_provider_config(data):
    """把 yaml 里的 AI.PROVIDERS / ACTIVE_ID 同步进内存 Config。"""
    ai_conf = data.get("AI") or {}
    providers = ai_conf.get("PROVIDERS")
    Config.AI_PROVIDERS = [p for p in (providers or []) if isinstance(p, dict)]
    Config.AI_ACTIVE_ID = str(ai_conf.get("ACTIVE_ID") or "")

    # 兼容旧字段：把启用中供应商的连接信息镜像到 AI_BASE_URL/API_KEY/MODEL
    active_id = Config.AI_ACTIVE_ID
    active = next((p for p in Config.AI_PROVIDERS if str(p.get("id") or "") == active_id), None)
    if active is None and Config.AI_PROVIDERS:
        active = Config.AI_PROVIDERS[0]
    if active:
        Config.AI_BASE_URL = str(active.get("base_url") or Config.AI_BASE_URL or "")
        Config.AI_API_KEY = str(active.get("api_key") or Config.AI_API_KEY or "")
        Config.AI_MODEL = str(active.get("model") or Config.AI_MODEL or "")


@ns.route('/config')
class AIConfig(ARLResource):

    @auth
    def get(self):
        """
        查询 AI 供应商列表（Key 掩码显示）
        """
        return build_data(_ai_config_view())

    save_model = ns.model('AIProviderSave', {
        'id': fields.String(description="供应商 ID（更新时传入，新增留空）"),
        'name': fields.String(description="供应商名称"),
        'format': fields.String(required=True, enum=list(SUPPORTED_FORMATS),
                                description="接口格式：openai（OpenAI 兼容）或 anthropic"),
        'base_url': fields.String(required=True, description="接口地址"),
        'api_key': fields.String(description="API Key（更新时留空保持原值）"),
        'model': fields.String(required=True, description="模型名称"),
    })

    @auth
    @ns.expect(save_model)
    def post(self):
        """
        保存供应商（新增或更新，并设为启用中）
        """
        args = self.parse_args(self.save_model)
        data = _load_config()
        ai_conf = data.setdefault("AI", {})

        providers = [p for p in (ai_conf.get("PROVIDERS") or []) if isinstance(p, dict)]
        pid = str(args.get("id") or "").strip()
        fmt = str(args.get("format") or "openai").strip().lower()
        base_url = str(args.get("base_url") or "").strip().rstrip("/")
        model = str(args.get("model") or "").strip()
        api_key = str(args.get("api_key") or "").strip()
        name = str(args.get("name") or "").strip()

        if fmt not in SUPPORTED_FORMATS:
            return build_data({"ok": False, "message": "不支持的接口格式"}, "参数错误")
        if not base_url or not model:
            return build_data({"ok": False, "message": "base_url 与 model 必填"}, "参数错误")

        target = next((p for p in providers if str(p.get("id") or "") == pid), None) if pid else None
        if target is None:
            pid = _new_provider_id()
            target = {"id": pid}
            providers.append(target)

        target.update({
            "id": pid,
            "name": name or ("Anthropic" if fmt == "anthropic" else "OpenAI 兼容"),
            "format": fmt,
            "base_url": base_url,
            "model": model,
        })
        if api_key:
            target["api_key"] = api_key
        elif "api_key" not in target:
            # 新建供应商未填 Key 时继承旧单配置的 Key（迁移场景）
            legacy_key = str(ai_conf.get("API_KEY") or "").strip()
            if legacy_key:
                target["api_key"] = legacy_key

        ai_conf["PROVIDERS"] = providers
        ai_conf["ACTIVE_ID"] = pid
        ai_conf["ENABLE"] = True
        Config.AI_ENABLE = True
        _sync_provider_config(data)

        _save_config(data)
        logger.info("AI provider saved: {} ({})".format(pid, fmt))
        return build_data(_ai_config_view(), "保存成功，已启用该供应商")


@ns.route('/delete')
class AIProviderDelete(ARLResource):

    delete_model = ns.model('AIProviderDelete', {
        'id': fields.String(required=True, description="供应商 ID"),
    })

    @auth
    @ns.expect(delete_model)
    def post(self):
        """
        删除供应商（若为启用中则自动切换到列表第一个）
        """
        args = self.parse_args(self.delete_model)
        pid = str(args.get("id") or "").strip()
        data = _load_config()
        ai_conf = data.setdefault("AI", {})
        providers = [p for p in (ai_conf.get("PROVIDERS") or []) if isinstance(p, dict)]
        remain = [p for p in providers if str(p.get("id") or "") != pid]

        if len(remain) == len(providers):
            return build_data({"ok": False, "message": "供应商不存在"}, "删除失败")

        ai_conf["PROVIDERS"] = remain
        if str(ai_conf.get("ACTIVE_ID") or "") == pid:
            ai_conf["ACTIVE_ID"] = str(remain[0]["id"]) if remain else ""
        Config.AI_PROVIDERS = remain
        Config.AI_ACTIVE_ID = str(ai_conf.get("ACTIVE_ID") or "")
        _sync_provider_config(data)

        _save_config(data)
        logger.info("AI provider deleted: {}".format(pid))
        return build_data(_ai_config_view(), "删除成功")


@ns.route('/activate')
class AIProviderActivate(ARLResource):

    activate_model = ns.model('AIProviderActivate', {
        'id': fields.String(required=True, description="供应商 ID"),
    })

    @auth
    @ns.expect(activate_model)
    def post(self):
        """
        切换启用中的供应商
        """
        args = self.parse_args(self.activate_model)
        pid = str(args.get("id") or "").strip()
        data = _load_config()
        ai_conf = data.setdefault("AI", {})
        providers = [p for p in (ai_conf.get("PROVIDERS") or []) if isinstance(p, dict)]
        if not any(str(p.get("id") or "") == pid for p in providers):
            return build_data({"ok": False, "message": "供应商不存在"}, "切换失败")

        ai_conf["ACTIVE_ID"] = pid
        Config.AI_ACTIVE_ID = pid
        _sync_provider_config(data)
        _save_config(data)
        return build_data(_ai_config_view(), "已切换启用供应商")


@ns.route('/models')
class AIModels(ARLResource):

    models_model = ns.model('AIModels', {
        'id': fields.String(description="已保存供应商 ID（与下面三项二选一）"),
        'format': fields.String(enum=list(SUPPORTED_FORMATS), description="接口格式"),
        'base_url': fields.String(description="接口地址"),
        'api_key': fields.String(description="API Key（未保存时直接填写）"),
    })

    @auth
    @ns.expect(models_model)
    def post(self):
        """
        获取供应商可用模型列表
        """
        import requests

        from app.services.ai_judge import get_providers, get_active_provider_id

        args = self.parse_args(self.models_model)
        pid = str(args.get("id") or "").strip()
        if pid:
            provider = next(
                (p for p in get_providers() if str(p.get("id") or "") == pid), None)
            if provider is None:
                return build_data({"ok": False, "message": "供应商不存在"})
        else:
            fmt = str(args.get("format") or "openai").strip().lower()
            provider = {
                "format": fmt,
                "base_url": str(args.get("base_url") or "").strip().rstrip("/"),
                "api_key": str(args.get("api_key") or "").strip(),
            }
            if not provider["base_url"] or not provider["api_key"]:
                return build_data({"ok": False, "message": "base_url 与 api_key 必填"})

        fmt = str(provider.get("format") or "openai").lower()
        base = str(provider.get("base_url") or "").strip().rstrip("/")
        api_key = str(provider.get("api_key") or "").strip()

        try:
            if fmt == "anthropic":
                models_base = base if base.endswith("/v1") else base + "/v1"
                r = requests.get(models_base + "/models",
                                 headers={"x-api-key": api_key,
                                          "anthropic-version": "2023-06-01"},
                                 timeout=15)
            else:
                r = requests.get(base + "/models",
                                 headers={"Authorization": "Bearer {}".format(api_key)},
                                 timeout=15)

            if r.status_code != 200:
                return build_data({"ok": False,
                                   "message": "HTTP {}: {}".format(r.status_code, r.text[:200])})

            body = r.json()
            data = body.get("data") or body.get("models") or []
            models = []
            for item in data:
                mid = item.get("id") or item.get("name") if isinstance(item, dict) else str(item)
                if mid and mid not in models:
                    models.append(mid)
            return build_data({"ok": True, "models": sorted(models)})
        except Exception as e:
            logger.warning("fetch AI models failed: {}".format(e))
            return build_data({"ok": False, "message": "请求失败：{}".format(e)})


@ns.route('/test')
class AITest(ARLResource):

    test_model = ns.model('AITest', {
        'id': fields.String(description="已保存供应商 ID（不传则测试启用中的供应商）"),
    })

    @auth
    @ns.expect(test_model)
    def post(self):
        """
        测试 AI 连接（最小 chat 调用）
        """
        from app.services.ai_judge import test_connection

        args = self.parse_args(self.test_model)
        result = test_connection(provider_id=str(args.get("id") or "").strip())
        logger.info("AI connection test ok:{}".format(result.get("ok")))
        return build_data(result)


@ns.route('/judge')
class AIJudge(ARLResource):

    judge_model = ns.model('AIJudge', {
        'site_ids': fields.List(
            fields.String(required=True, description="站点 _id"),
            required=True, description="站点 ID 列表（单次最多 50）"),
        'scope': fields.String(description="研判范围说明", default="批量研判"),
        'collection': fields.String(
            description="集合 site|asset_site", enum=["site", "asset_site"],
            default="site"),
    })

    @auth
    @ns.expect(judge_model)
    def post(self):
        """
        提交 AI 研判任务（异步，arlpost 队列；单次批量上限 50）
        """
        from app import celerytask
        from app.modules import CeleryAction, CeleryRoutingKey

        args = self.parse_args(self.judge_model)
        site_ids = [str(item) for item in (args.get("site_ids") or []) if item]
        if not site_ids:
            return build_data({"ok": False, "message": "site_ids 为空"})

        collection = str(args.get("collection") or "site")
        if collection not in ("site", "asset_site"):
            return build_data({"ok": False, "message": "不支持的集合：{}".format(collection)})

        if len(site_ids) > 50:
            return build_data({
                "ok": False,
                "message": "单次批量上限 50，当前 {} 个".format(len(site_ids))})

        judge_data = {
            "site_ids": site_ids,
            "collection": collection,
            "scope": str(args.get("scope") or "批量研判")[:100],
        }
        try:
            async_result = celerytask.arl_post.apply_async(
                kwargs={"options": {
                    "celery_action": CeleryAction.AI_JUDGE_TASK,
                    "data": judge_data,
                }})
        except Exception as e:
            logger.exception("submit AI judge task failed")
            return build_data({"ok": False, "message": "任务下发失败：{}".format(e)})

        return build_data({
            "ok": True,
            "celery_id": str(async_result),
            "site_count": len(site_ids),
            "collection": collection,
            "hint": "研判结果写回站点 ai_state/ai_summary/ai_priority 字段",
        })


@ns.route('/judge_result')
class AIJudgeResult(ARLResource):

    result_model = ns.model('AIJudgeResult', {
        'site_ids': fields.List(
            fields.String(required=True, description="站点 _id"), required=True),
        'collection': fields.String(
            description="集合 site|asset_site", enum=["site", "asset_site"],
            default="site"),
    })

    @auth
    @ns.expect(result_model)
    def post(self):
        """
        查询站点的 AI 研判结果
        """
        from bson import ObjectId

        args = self.parse_args(self.result_model)
        collection = str(args.get("collection") or "site")
        if collection not in ("site", "asset_site"):
            return build_data({"ok": False, "message": "不支持的集合"})

        object_ids = []
        for site_id in (args.get("site_ids") or []):
            try:
                object_ids.append(ObjectId(str(site_id)))
            except Exception:
                continue

        from app import utils as arl_utils

        fields = {
            "_id": 1, "site": 1, "title": 1,
            "ai_state": 1, "ai_summary": 1, "ai_priority": 1,
            "ai_error": 1, "ai_judged_date": 1,
        }
        items = []
        if object_ids:
            items = list(arl_utils.conn_db(collection).find(
                {"_id": {"$in": object_ids}}, fields))
        for item in items:
            item["_id"] = str(item["_id"])
        return build_data({"items": items})
