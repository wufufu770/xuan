"""路由鉴权覆盖静态断言（无第三方依赖，可直接 python3 -m pytest 运行）。

规则：app/routes 下所有 Resource 类的 get/post/put/delete 方法必须挂 @auth，
白名单须写明替代控制手段。防止再次出现 stats/image 式的鉴权缺口回归。

运行：python3 -m pytest tests/test_auth_coverage.py -q
"""

import ast
import os

import pytest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROUTES_DIR = os.path.join(BASE_DIR, "app", "routes")

HTTP_METHODS = {"get", "post", "put", "delete"}

# (文件名, 类名) -> 理由（必须说明替代控制手段）
WHITELIST = {
    ("user.py", "LoginARL"): "登录接口本身无需鉴权",
    ("user.py", "LogoutARL"): "函数内校验 token，登出失败无副作用",
    ("user.py", "ChangePassARL"): "函数内校验 token + 旧密码",
    ("image.py", "ARLImage"): "HMAC 签名保护（utils/signing.py），<img> 无法携带 Token 头",
}

# 白名单必须兑现的替代控制检查：(文件名, 类名, 源码中必须出现的调用)
WHITELIST_EVIDENCE = {
    ("image.py", "ARLImage"): "verify_image",
}


def _iter_resource_methods(source, filename):
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        base_names = {
            getattr(base, "id", getattr(base, "attr", ""))
            for base in node.bases
        }
        if not base_names & {"Resource", "ARLResource"}:
            continue
        for child in node.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                    and child.name in HTTP_METHODS:
                yield filename, node.name, child


def _has_auth_decorator(func_node):
    for dec in func_node.decorator_list:
        if isinstance(dec, ast.Name) and dec.id == "auth":
            return True
        if isinstance(dec, ast.Attribute) and dec.attr == "auth":
            return True
    return False


def test_no_unauthenticated_route_methods():
    offenders = []
    for filename in sorted(os.listdir(ROUTES_DIR)):
        if not filename.endswith(".py") or filename.startswith("__"):
            continue
        path = os.path.join(ROUTES_DIR, filename)
        with open(path, encoding="utf-8") as f:
            source = f.read()
        for file_name, class_name, func_node in _iter_resource_methods(source, filename):
            if _has_auth_decorator(func_node):
                continue
            key = (file_name, class_name)
            if key in WHITELIST:
                evidence = WHITELIST_EVIDENCE.get(key)
                if evidence and evidence not in source:
                    offenders.append(
                        "{}:{} -> 白名单声称用 {} 保护，但源码中未见调用".format(
                            file_name, class_name, evidence))
                continue
            offenders.append("{}:{}#{} 缺少 @auth（如属豁免请加入白名单并说明理由）".format(
                file_name, class_name, func_node.name))
    assert not offenders, "存在未鉴权路由方法：\n" + "\n".join(offenders)


def test_whitelist_entries_still_exist():
    """白名单条目指向的类被删除/改名时提醒清理，避免白名单腐化。"""
    existing = set()
    for filename in sorted(os.listdir(ROUTES_DIR)):
        if not filename.endswith(".py") or filename.startswith("__"):
            continue
        with open(os.path.join(ROUTES_DIR, filename), encoding="utf-8") as f:
            source = f.read()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.ClassDef):
                existing.add((filename, node.name))
    stale = [key for key in WHITELIST if key not in existing]
    assert not stale, "白名单条目已失效（类不存在），请清理：{}".format(stale)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
