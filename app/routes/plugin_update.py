# -*- coding:UTF-8 -*-
"""插件在线更新 API（方案书 P3：指纹/POC 插件化在线更新）。"""
from flask_restx import fields, Namespace

from app import utils
from app.config import Config
from app.modules import ErrorMsg
from app.services import plugin_update
from app.utils import auth
from app.utils.audit import audit
from . import ARLResource

ns = Namespace('plugin_update', description="插件在线更新")

install_fields = ns.model('pluginInstall', {
    'plugin': fields.String(required=True, description="插件名（注册表 plugin 字段）"),
})


@ns.route('/status/')
class PluginUpdateStatus(ARLResource):
    @auth
    def get(self):
        """已安装插件清单 + 注册表配置状态。"""
        installed = [
            {"plugin": doc.get("plugin"), "version": doc.get("version"),
             "kind": doc.get("kind"), "install_date": doc.get("install_date")}
            for doc in utils.conn_db(plugin_update.PLUGIN_INSTALL_COLLECTION)
                .find({}, {"_id": 0}).sort("plugin", 1)]
        return utils.build_ret(ErrorMsg.Success, {
            "registry_configured": bool(str(getattr(Config, "PLUGIN_REGISTRY_URL", "") or "").strip()),
            "installed": installed,
        })


@ns.route('/check/')
class PluginUpdateCheck(ARLResource):
    @auth
    def post(self):
        """拉取注册表并与已安装版本比对（SSRF 防护 + 索引校验）。"""
        try:
            items = plugin_update.check_update()
        except Exception as exc:
            return utils.build_ret(ErrorMsg.Error, {'msg': str(exc)})
        audit("plugin_update_check")
        return utils.build_ret(ErrorMsg.Success, {"items": items})


@ns.route('/install/')
class PluginUpdateInstall(ARLResource):
    @auth
    @ns.expect(install_fields)
    def post(self):
        """安装/更新指定插件（sha256 校验 + 语义校验后落地）。"""
        args = self.parse_args(install_fields)
        name = (args.get('plugin') or '').strip()
        try:
            items = plugin_update.check_update()
        except Exception as exc:
            return utils.build_ret(ErrorMsg.Error, {'msg': str(exc)})
        entry = next((i for i in items if i["plugin"] == name), None)
        if not entry:
            return utils.build_ret(ErrorMsg.Error, {'msg': "注册表中没有插件 {}".format(name)})
        try:
            result = plugin_update.install_plugin(entry)
        except Exception as exc:
            return utils.build_ret(ErrorMsg.Error, {'msg': str(exc)})
        audit("plugin_update_install", detail={"plugin": name, "version": result.get("version")})
        return utils.build_ret(ErrorMsg.Success, result)
