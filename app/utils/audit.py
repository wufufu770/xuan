"""安全审计日志。

记录认证与凭据变更事件到 audit_log 集合；任何失败都不得影响业务请求，
因此整体吞异常。身份识别延迟导入 user_login_header，避免循环依赖。
"""

import time

from flask import request

from .conn import conn_db


def _client_ip():
    try:
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.remote_addr or ""
    except RuntimeError:  # 无请求上下文（如 Celery 任务内调用）
        return ""


def _current_username():
    try:
        from .user import user_login_header
        info = user_login_header()
        if isinstance(info, dict):
            return info.get("username", "")
    except Exception:
        pass
    return ""


def audit(action, username=None, detail=None):
    """记录一条审计事件；username 缺省时从请求 Token 反查。永不抛异常。"""
    try:
        conn_db("audit_log").insert_one({
            "time": time.time(),
            "save_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "action": action,
            "username": username if username is not None else _current_username(),
            "ip": _client_ip(),
            "detail": detail or {},
        })
    except Exception:
        pass
