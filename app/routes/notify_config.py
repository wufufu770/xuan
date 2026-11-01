"""通知渠道配置 API（读掩码/写配置，yamlconf 加锁落盘）。

覆盖 config.yaml 中 DINGDING / FEISHU / WXWORK / EMAIL / WEBHOOK 五个渠道段。
敏感值返回掩码；写入走 audit。

键名说明：CHANNEL_FIELDS 里每个条目是 (yaml 段内键, 展示名, 敏感)；
WXWORK 在 config.yaml 是顶层键 WX_WORK_WEBHOOK，单独处理。
"""

from flask_restx import fields, Namespace

from app import utils
from app.utils import get_logger, auth
from app.utils.audit import audit
from . import ARLResource
from .engines import CONFIG_PATH, _load_config, _mask
from app.utils.yamlconf import locked_update

ns = Namespace('notify_config', description="通知渠道配置")

logger = get_logger()

# channel -> {"section": yaml 顶层段名 或 None(顶层), "fields": [(段内键, 展示名, 敏感)]}
CHANNELS = {
    "dingding": {"section": "DINGDING",
                 "fields": [("ACCESS_TOKEN", "AccessToken", True),
                            ("SECRET", "加签 Secret", True)]},
    "feishu": {"section": "FEISHU",
               "fields": [("WEBHOOK_URL", "Webhook 地址", True),
                          ("SECRET", "加签 Secret", True)]},
    "wxwork": {"section": None,
               "fields": [("WX_WORK_WEBHOOK", "Webhook 地址", True)]},
    "webhook": {"section": "WEBHOOK",
                "fields": [("URL", "URL", True), ("TOKEN", "Token", True)]},
    "email": {"section": "EMAIL",
              "fields": [("HOST", "SMTP 服务器", False), ("PORT", "端口", False),
                         ("USERNAME", "账号", False), ("PASSWORD", "密码", True),
                         ("TO", "收件人", False)]},
}


def _section(data, channel):
    """取渠道当前配置 dict（顶层键渠道包装成单键 dict）。"""
    spec = CHANNELS[channel]
    if spec["section"] is None:
        key = spec["fields"][0][0]
        return {key: data.get(key, "")}
    return data.get(spec["section"], {}) or {}


def _channel_configured(data, channel):
    section = _section(data, channel)
    return any(str(v or "").strip() for v in section.values())


@ns.route('/')
class NotifyConfig(ARLResource):

    @auth
    def get(self):
        """通知渠道配置（敏感值掩码）"""
        data = _load_config()
        out = {}
        for channel, spec in CHANNELS.items():
            section = _section(data, channel)
            values = {}
            for key, label, sensitive in spec["fields"]:
                raw = str(section.get(key) or "").strip()
                if raw:
                    values[label] = _mask(raw) if sensitive else raw
            out[channel] = {"configured": _channel_configured(data, channel),
                            "values": values}
        return {"code": 200, "message": "success", "data": out}

    save_model = ns.model('NotifyConfigSave', {
        'channel': fields.String(required=True, enum=list(CHANNELS.keys()),
                                 description="渠道"),
        'fields': fields.Raw(required=True, description="字段键值（展示名为键）"),
        'clear': fields.Boolean(default=False, description="清空该渠道"),
    })

    @auth
    @ns.expect(save_model)
    def post(self):
        """保存/清空渠道配置（加锁写 config.yaml，全 worker 即时可见）"""
        args = self.parse_args(self.save_model)
        channel = str(args.get("channel") or "").strip().lower()
        if channel not in CHANNELS:
            return {"code": 400, "message": "未知渠道", "data": {}}
        clearing = bool(args.get("clear"))
        incoming = args.get("fields") or {}
        spec = CHANNELS[channel]

        with locked_update(CONFIG_PATH) as data:
            if clearing:
                empty = {key: "" for key, _label, _s in spec["fields"]}
                if spec["section"] is None:
                    data.update(empty)
                else:
                    data.setdefault(spec["section"], {}).update(empty)
            else:
                label_to_key = {label: key for key, label, _s in spec["fields"]}
                updates = {}
                for label, value in incoming.items():
                    key = label_to_key.get(label)
                    if key:
                        updates[key] = str(value or "").strip()
                if spec["section"] is None:
                    data.update(updates)
                else:
                    data.setdefault(spec["section"], {}).update(updates)

        audit("notify_config_change",
              detail={"channel": channel, "clear": clearing})
        return {"code": 200, "message": "已保存" if not clearing else "已清除",
                "data": {"channel": channel}}
