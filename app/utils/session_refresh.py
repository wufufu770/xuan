"""会话池静默续期看门：调度循环周期调用，过期/失败推送通知。

对齐 token_watch 模式（旁路能力，异常吞掉不引爆调度循环）。
"""

import time

from app import utils
from app.utils.notify import send_alert

logger = utils.get_logger()

_last_run = {"ts": 0}
INTERVAL = 6 * 3600   # 6 小时一轮


def check_sessions(now=None, refresh_all=None, notify=None):
    """到点对会话池做静默续期；返回汇总文本（已推送）或 None（未到点/无需）。

    notify 供测试注入；refresh_all 供测试注入（session_window.refresh_all）。
    """
    now = now or time.time()
    if now - _last_run["ts"] < INTERVAL:
        return None
    _last_run["ts"] = now

    try:
        from app.services.session_window import refresh_all as _refresh_all
        refresh_all = refresh_all or _refresh_all
        results = refresh_all() or []
    except Exception as exc:
        logger.warning("session refresh failed: %s", exc)
        return None

    if not results:
        return None
    failed = [r for r in results if r.get("ok") is False]
    ok = [r for r in results if r.get("ok") is True]
    summary = "会话池静默续期完成：成功 {}，失败 {}{}".format(
        len(ok), len(failed),
        ("；失败账号：" + "、".join("{}:{}".format(r["source"], r["account"])
                          for r in failed[:5])) if failed else "")
    if failed:
        title = "玄览会话池：{} 个数据源会话续期/探活失败".format(len(failed))
        try:
            (notify or send_alert)(title, summary + "\n\n请在会话池页对失败账号做窗口重登。")
        except Exception as exc:
            logger.warning("session refresh notify failed: %s", exc)
    logger.info(summary)
    return summary
