"""数据源接入 API（读掩码视图 / 字段级保存 / 逐厂商探活）。

凭证写入走 integration 服务（yamlconf 加锁落盘），敏感值掩码回显；
保存与探活均记 audit。
"""

from flask_restx import fields, Namespace

from app import utils
from app.utils import get_logger, auth
from app.utils.audit import audit
from . import ARLResource
from app.services import integration

ns = Namespace('integration', description="数据源接入（空间测绘/被动收集/情报平台）")

logger = get_logger()


@ns.route('/')
class IntegrationConfig(ARLResource):

    @auth
    def get(self):
        """全部数据源接入状态（敏感值掩码）"""
        return {"code": 200, "message": "success", "data": integration.view()}

    save_model = ns.model('IntegrationSave', {
        'vendor': fields.String(required=True, enum=list(integration.VENDORS.keys()),
                                description="数据源标识"),
        'fields': fields.Raw(required=False, description="字段键值（字段键为键，留空不改）"),
        'enable': fields.Boolean(required=False, description="被动收集开关（插件型厂商）"),
        'clear': fields.Boolean(default=False, description="清空该厂商凭证并停用"),
    })

    @auth
    @ns.expect(save_model)
    def post(self):
        """保存/清除一个数据源的凭证（写入 config.yaml，全进程经热更新生效）"""
        args = self.parse_args(self.save_model)
        vendor = str(args.get("vendor") or "").strip()
        fields = args.get("fields") or {}
        enable = args.get("enable")
        clear = bool(args.get("clear"))

        if vendor not in integration.VENDORS:
            return {"code": 400, "message": "未知数据源: {}".format(vendor), "data": {}}

        updated, cleared = integration.save_vendor(vendor, fields, enable=enable,
                                                   clear=clear)
        if updated or cleared:
            audit("integration_credentials_change",
                  detail={"vendor": vendor,
                          "updated": updated, "cleared": cleared,
                          "enable": enable, "clear": clear})
            logger.info("integration credentials updated: {} {}".format(
                vendor, ",".join(updated or cleared)))

        message = "保存成功" if updated else ("凭证已清除" if cleared else "未提供需要更新的字段")
        return {"code": 200, "message": message,
                "data": {"vendor": vendor, "updated": updated, "cleared": cleared}}


@ns.route('/test/')
class IntegrationTest(ARLResource):

    test_model = ns.model('IntegrationTest', {
        'vendor': fields.String(required=True, enum=list(integration.VENDORS.keys()),
                                description="数据源标识"),
    })

    @auth
    @ns.expect(test_model)
    def post(self):
        """对已保存凭证做最小鉴权探活"""
        args = self.parse_args(self.test_model)
        vendor = str(args.get("vendor") or "").strip()
        result = integration.test_vendor(vendor)
        audit("integration_credentials_test",
              detail={"vendor": vendor, "ok": result.get("ok")})
        return {"code": 200, "message": "success", "data": result}
