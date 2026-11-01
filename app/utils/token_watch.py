"""凤鸟 token 到期看门。

到期前 24 小时（以及已过期）时经统一告警分发提醒重新登录；
alert_state 集合做 12 小时冷却，避免每个调度周期（58 秒）重复轰炸。
供 scheduler 主循环调用，任何异常由调用方吞掉，不得影响调度。
"""

import time

from .conn import conn_db

STATE_KEY = "fengniao_token_exp"
ALERT_BEFORE_HOURS = 24
COOLDOWN_SECONDS = 12 * 3600


def check_fengniao_token(now=None, notify=None):
    """返回告警文本（已发送）或 None（无需告警）。notify 供测试注入。
    任何内部异常吞掉返回 None：看门是旁路能力，自身不得引爆调度循环。"""
    try:
        return _check_fengniao_token(now=now, notify=notify)
    except Exception:
        return None


def _check_fengniao_token(now=None, notify=None):
    from app.routes.fengniao import _token_from_yaml
    from app.services.fengniao import token_expire_time
    from .notify import send_alert

    token = _token_from_yaml()
    if not token:
        return None
    expires = token_expire_time(token)
    if not expires:
        return None

    now = time.time() if now is None else now
    hours_left = (expires - now) / 3600.0
    if hours_left > ALERT_BEFORE_HOURS:
        return None

    state = conn_db("alert_state").find_one({"key": STATE_KEY})
    if state and now - float(state.get("last_sent_ts") or 0) < COOLDOWN_SECONDS:
        return None

    exp_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(expires))
    text = ("凤鸟 token 预计 {} 过期（剩余 {:.1f} 小时）。\n"
            "请在 数据源管理 页重新登录刷新，过期后企业情报采集将失败。".format(
                exp_text, hours_left))
    (notify or send_alert)("凤鸟 token 即将过期", text)
    conn_db("alert_state").update_one(
        {"key": STATE_KEY},
        {"$set": {"last_sent_ts": now, "last_alert": text,
                  "expires_ts": expires}},
        upsert=True)
    return text
