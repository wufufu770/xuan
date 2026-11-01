"""会话池登录 CLI：有头浏览器人工登录 -> storage_state 加密入池。

登录判定：该 source 的必需 cookie 齐全（fengniao 要求 token cookie）。
完成后自动：入池 -> 探活 -> 同步 config.yaml（凤鸟过渡双写）。

用法（在有桌面环境的部署机上）：
    cd /opt/ARL && venv/bin/python scripts/session_login.py \
        --source fengniao --account default \
        --login-url https://www.riskbird.com/ [--timeout 300] [--headless]
"""

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import Config                      # noqa: E402
from app.services import session_pool              # noqa: E402
from app.utils import get_logger                   # noqa: E402

logger = get_logger()


def required_cookies(source):
    return session_pool.REQUIRED_COOKIES.get(source, [])


def has_required_cookies(context, source):
    required = set(required_cookies(source))
    if not required:
        return True
    names = {c.get("name") for c in context.cookies()}
    return required.issubset(names)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, help="数据源（fengniao 等）")
    parser.add_argument("--account", default="default", help="账号标识")
    parser.add_argument("--login-url", required=True, help="登录页地址")
    parser.add_argument("--timeout", type=int, default=300, help="等待登录秒数")
    parser.add_argument("--headless", action="store_true", help="无头模式（默认有头人工登录）")
    args = parser.parse_args()

    required = required_cookies(args.source)
    print("必需 cookie: {}".format(",".join(required) or "(无要求)"))

    context, handle = session_pool.launch_context(
        args.source, args.account, headless=args.headless, owner="cli")
    try:
        page = context.pages[0] if context.pages else context.new_page()
        page.goto(args.login_url, wait_until="domcontentloaded", timeout=60000)
        print("请在打开的浏览器窗口中完成登录（含滑块/验证码），等待最多 {} 秒...".format(args.timeout))

        deadline = time.time() + args.timeout
        while time.time() < deadline:
            if has_required_cookies(context, args.source):
                break
            time.sleep(3)
        else:
            print("登录超时：未在 {} 秒内检测到所需 cookie，未入池".format(args.timeout))
            return 1

        state = context.storage_state()
        expires_hint = 0
        if args.source == "fengniao":
            from app.services.fengniao import token_expire_time
            for cookie in state.get("cookies") or []:
                if cookie.get("name") == "token":
                    expires_hint = token_expire_time(cookie.get("value"))

        session_pool.save_state(args.source, args.account, state,
                                expires_hint=expires_hint)
        ok, detail = session_pool.run_health_check(args.source, args.account)

        synced = False
        if args.source == "fengniao":
            synced = session_pool.sync_fengniao_to_config(
                os.path.join(os.path.dirname(os.path.dirname(
                    os.path.abspath(__file__))), "app", "config.yaml"),
                account=args.account)

        print("登录态已入池：{}:{} 探活={}（{}）".format(
            args.source, args.account, "通过" if ok else "未通过", detail))
        if args.source == "fengniao":
            if expires_hint:
                print("token 过期时间：{}".format(time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime(expires_hint))))
            print("config.yaml 同步：{}".format("已写入" if synced else "未写入"))
        return 0 if ok else 2
    finally:
        session_pool.close_context(context, handle)


if __name__ == "__main__":
    sys.exit(main())
