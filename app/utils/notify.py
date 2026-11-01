"""统一告警分发入口。

遍历所有已配置渠道（钉钉/飞书/企业微信/邮件/通用 Webhook）发送同一条告警，
复用 utils.push 现有发送函数；渠道间互不影响，整体永不抛异常——
告警是旁路能力，绝不能反过来打断扫描/调度主流程。
"""

import requests

from app.config import Config
from app.utils import get_logger
from . import push

logger = get_logger()

WEBHOOK_TIMEOUT = 10


def _is_set(value):
    return bool(str(value or "").strip())


def _send_webhook(title, markdown):
    """通用 Webhook：POST JSON {title, content, token}，适配自建接收端。"""
    if not _is_set(Config.WEB_HOOK_URL):
        return False
    headers = {}
    if _is_set(Config.WEB_HOOK_TOKEN):
        headers["Token"] = Config.WEB_HOOK_TOKEN
    resp = requests.post(Config.WEB_HOOK_URL, timeout=WEBHOOK_TIMEOUT,
                         json={"title": title, "content": markdown},
                         headers=headers)
    return resp.status_code == 200


def send_alert(title, markdown=""):
    """向全部已配置渠道发送告警。返回 {渠道: 是否成功/已跳过}。"""
    body = markdown or title
    results = {}

    try:
        if _is_set(Config.DINGDING_ACCESS_TOKEN) and _is_set(Config.DINGDING_SECRET):
            data = push.dingding_send(
                msg=body, access_token=Config.DINGDING_ACCESS_TOKEN,
                secret=Config.DINGDING_SECRET, msgtype="markdown", title=title)
            results["dingding"] = bool(data and data.get("errcode", -1) == 0)
        else:
            results["dingding"] = "skipped"
    except Exception as exc:
        logger.warning("notify dingding failed: %s", exc)
        results["dingding"] = False

    try:
        if _is_set(Config.FEISHU_WEBHOOK):
            data = push.feishu_send(msg=body, webhook_url=Config.FEISHU_WEBHOOK,
                                    secret=Config.FEISHU_SECRET, title=title)
            results["feishu"] = bool(data and data.get("code", -1) == 0)
        else:
            results["feishu"] = "skipped"
    except Exception as exc:
        logger.warning("notify feishu failed: %s", exc)
        results["feishu"] = False

    try:
        if _is_set(Config.WX_WORK_WEBHOOK):
            data = push.wx_work_send(msg=body, webhook_url=Config.WX_WORK_WEBHOOK)
            results["wxwork"] = bool(data)
        else:
            results["wxwork"] = "skipped"
    except Exception as exc:
        logger.warning("notify wxwork failed: %s", exc)
        results["wxwork"] = False

    try:
        if _is_set(Config.WEB_HOOK_URL):
            results["webhook"] = _send_webhook(title, body)
        else:
            results["webhook"] = "skipped"
    except Exception as exc:
        logger.warning("notify webhook failed: %s", exc)
        results["webhook"] = False

    try:
        if _is_set(Config.EMAIL_HOST) and _is_set(Config.EMAIL_USERNAME) \
                and _is_set(Config.EMAIL_PASSWORD):
            push.send_email(host=Config.EMAIL_HOST, port=Config.EMAIL_PORT,
                            mail=Config.EMAIL_USERNAME,
                            password=Config.EMAIL_PASSWORD, to=Config.EMAIL_TO,
                            title=title, html="<pre>{}</pre>".format(body))
            results["email"] = True
        else:
            results["email"] = "skipped"
    except Exception as exc:
        logger.warning("notify email failed: %s", exc)
        results["email"] = False

    logger.info("alert sent: %s %s", title, results)
    return results
