"""探针：登录后探测统一控制台 API 面的每个端点，输出状态矩阵找缺失服务。

前端融合重构后，console.html 原生实现全部页面（无 bundle iframe），
本脚本固定一份端点契约清单做全量可达性回归。
"""
import json
import os
import urllib.error
import urllib.request

BASE = os.environ.get("ARL_BASE", "http://127.0.0.1:5003")
CREDS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "deploy", "dev-credentials.env")

# 统一控制台 17 页对应的调用面
PATHS = [
    "/ai/activate", "/ai/config", "/ai/delete", "/ai/models", "/ai/judge", "/ai/test",
    "/agent/chat", "/agent/conversations/",
    "/asset_domain/", "/asset_ext/", "/asset_ip/", "/asset_scope/", "/asset_scope/add/",
    "/asset_scope/delete/", "/asset_site/",
    "/cert/", "/console/info",
    "/engines/", "/engines/test",
    "/fengniao/attach_scope/", "/fengniao/collect/", "/fengniao/config/",
    "/fengniao/group/", "/fengniao/groups/", "/fengniao/job/", "/fengniao/test/",
    "/fingerprint/", "/fingerprint/delete/", "/fingerprint/export/",
    "/fingerprint/upload/", "/stat_finger/",
    "/github_scheduler/", "/github_scheduler/delete/",
    "/github_scheduler/recover/", "/github_scheduler/stop/",
    "/github_monitor_result/",
    "/github_task/",
    "/host_collision/", "/integration/", "/integration/test/", "/nuclei_result/",
    "/poc/", "/poc/delete/", "/poc/sync/",
    "/policy/", "/policy/add/", "/policy/delete/", "/policy/edit/",
    "/policy_yaml/clone/", "/policy_yaml/graph/", "/policy_yaml/yaml_export/",
    "/policy_yaml/yaml_import/",
    "/scheduler/", "/scheduler/add/", "/scheduler/delete/", "/scheduler/recover/",
    "/scheduler/stop/",
    "/sensitive_interface/", "/session_pool/window/status/", "/stats/summary/", "/supply_chain/reverse",
    "/task/", "/task/delete/",
    "/task_schedule/", "/task_schedule/delete/",
    "/task_schedule/recover/", "/task_schedule/stop/",
    "/user/login", "/user/list/",
]


def login():
    vals = {}
    for line in open(CREDS):
        if "=" in line and not line.startswith("#"):
            k, v = line.strip().split("=", 1)
            vals[k] = v
    body = json.dumps({"username": vals.get("ARL_ADMIN_USER", "admin"),
                       "password": vals.get("ARL_ADMIN_PASSWORD", "")}).encode()
    req = urllib.request.Request(BASE + "/api/user/login", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.load(resp)["data"]["token"]


def probe(token, path, method):
    req = urllib.request.Request(BASE + "/api" + path, method=method,
                                 headers={"Token": token,
                                          "Content-Type": "application/json"},
                                 data=b"{}" if method == "POST" else None)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        return "ERR:{}".format(type(e).__name__)


def main():
    token = login()
    missing, ok_rows, method_only = [], [], []
    for path in PATHS:
        g = probe(token, path, "GET")
        if g == 404:
            p = probe(token, path, "POST")
            if p == 404:
                missing.append((path, g, p))
            else:
                method_only.append((path, g, p))
        elif g in (401, 403, 405):
            p = probe(token, path, "POST")
            method_only.append((path, g, p))
        else:
            ok_rows.append((path, g))

    print("== 完全缺失（GET/POST 均 404） ==")
    for row in missing:
        print("  MISSING", row[0])
    print("\n== 方法受限/需 POST（预期，删除/停止类端点） ==")
    for row in method_only:
        print("  ", row)
    print("\n== 正常可达 ({}) ==".format(len(ok_rows)))
    for row in ok_rows:
        print("  ", row)
    print("\nSUMMARY missing={} method_only={} ok={}".format(
        len(missing), len(method_only), len(ok_rows)))


if __name__ == "__main__":
    main()
