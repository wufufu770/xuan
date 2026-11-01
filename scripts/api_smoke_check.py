"""API 实拼冒烟：对真实栈做建→查→改→停→删全链路验证（带唯一前缀与 finally 清理）。

覆盖：任务策略 CRUD+编辑、资产组增删范围、监控任务启停、定时扫描计划、
GitHub 监控计划、指纹增删+YAML 上传、POC 检索筛选、风险筛选、集成凭证往返、
FOFA 无 Key 优雅报错。
用法：.venv/bin/python scripts/api_smoke_check.py
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ.get("ARL_BASE", "http://127.0.0.1:5003")
CREDS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "deploy", "dev-credentials.env")
TAG = "walk-api-{}".format(int(time.time()))

CHECKS = []


def check(name, ok, detail=""):
    CHECKS.append((name, ok, detail))
    print("  {} {}{}".format("✓" if ok else "✗ FAIL", name,
                             (" | " + str(detail)[:160]) if detail and not ok else ""))
    return ok


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


TOKEN = None


def call(path, payload=None, method=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(BASE + "/api" + path, data=data,
                                 headers={"Token": TOKEN,
                                          "Content-Type": "application/json"},
                                 method=method or ("POST" if data else "GET"))
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        try:
            return json.load(e)
        except Exception:
            return {"code": e.code}


def pick_items(body):
    """兼容两种响应形状：ARL 列表为顶层 {items,total}，自建路由为 {code,data:{items}}。"""
    d = body.get("data")
    if isinstance(d, dict):
        return d.get("items") or []
    if isinstance(d, list):
        return d
    return body.get("items") or []


def main():
    global TOKEN
    TOKEN = login()
    scope_id = policy_id = sched_id = ts_id = gh_id = None

    try:
        # ---------------- 任务策略 ----------------
        r = call("/policy/add/", {"name": TAG + "-pol", "desc": "smoke",
                                  "policy": {"domain_config": {"domain_brute": True},
                                             "ip_config": {"port_scan": True, "port_scan_type": "test"},
                                             "site_config": {"site_identify": True},
                                             "file_leak": False}})
        policy_id = (r.get("data") or {}).get("policy_id")
        check("策略新增", bool(policy_id), r)
        r = call("/policy/edit/", {"policy_id": policy_id,
                                   "policy_data": {"desc": "smoke-edited"}})
        check("策略编辑", r.get("code") == 200, r)
        items = [i for i in pick_items(call("/policy/?size=100")) if i.get("name") == TAG + "-pol"]
        check("策略列表可检索且描述已更新",
              len(items) == 1 and items[0].get("desc") == "smoke-edited", items)

        # ---------------- 资产组 ----------------
        r = call("/asset_scope/", {"name": TAG + "-scope", "scope": "example.com",
                                   "black_scope": "", "scope_type": "domain"})
        scope_id = (r.get("data") or {}).get("scope_id")
        check("资产组新增", bool(scope_id), r)
        r = call("/asset_scope/add/", {"scope": "sub.example.com", "scope_id": scope_id})
        check("资产组追加范围", r.get("code") == 200, r)
        r = call("/asset_scope/delete/?scope=sub.example.com&scope_id=" + scope_id)
        check("资产组移除单条范围", r.get("code") == 200, r)

        # ---------------- 资产组监控 ----------------
        r = call("/scheduler/add/", {"scope_id": scope_id, "domain": "example.com",
                                     "interval": 21600, "name": ""})
        ret = r.get("data") or []
        sched_id = (ret[0] or {}).get("job_id") if isinstance(ret, list) and ret else None
        check("监控任务创建(6h)", bool(sched_id), r)
        r = call("/scheduler/stop/", {"job_id": sched_id})
        check("监控任务停止", r.get("code") == 200, r)
        r = call("/scheduler/recover/", {"job_id": sched_id})
        check("监控任务恢复", r.get("code") == 200, r)
        rows = [i for i in pick_items(call("/scheduler/?size=100")) if i.get("_id") == sched_id]
        check("监控任务列表含新任务且字段齐备",
              len(rows) == 1 and "interval" in rows[0] and "status" in rows[0], rows)

        # ---------------- 定时扫描计划 ----------------
        r = call("/task_schedule/", {"name": TAG + "-ts", "target": "example.com",
                                     "schedule_type": "recurrent_scan", "cron": "0 */6 * * *",
                                     "start_date": "", "policy_id": policy_id,
                                     "task_tag": "task"})
        ts_id = (r.get("data") or {}).get("_id")
        check("定时扫描计划创建(周期)", bool(ts_id), r)
        r = call("/task_schedule/stop/", {"_id": [ts_id]})
        check("定时扫描停止", r.get("code") == 200, r)
        r = call("/task_schedule/recover/", {"_id": [ts_id]})
        check("定时扫描恢复", r.get("code") == 200, r)
        rows = [i for i in pick_items(call("/task_schedule/?size=100")) if i.get("_id") == ts_id]
        check("定时扫描列表含策略名/下次运行",
              len(rows) == 1 and rows[0].get("policy_name") and rows[0].get("next_run_date"), rows)

        # ---------------- GitHub 泄露监控 ----------------
        r = call("/github_scheduler/", {"name": TAG + "-gh", "keyword": "walk-smoke-kw",
                                        "cron": "0 */6 * * *"})
        gh_id = None
        rows = [i for i in pick_items(call("/github_scheduler/?size=100"))
                if i.get("keyword") == "walk-smoke-kw"]
        if rows:
            gh_id = rows[0]["_id"]
        check("GitHub 监控创建", r.get("code") == 200 and bool(gh_id), r)
        r = call("/github_scheduler/stop/", {"_id": [gh_id]})
        check("GitHub 监控停止", r.get("code") == 200, r)
        r = call("/github_scheduler/recover/", {"_id": [gh_id]})
        check("GitHub 监控恢复", r.get("code") == 200, r)

        # ---------------- 指纹 ----------------
        rule = 'body="{}"'.format(TAG)
        r = call("/fingerprint/", {"name": TAG + "-fp", "human_rule": rule})
        check("指纹新增", r.get("code") == 200, r)
        r = call("/fingerprint/", {"name": TAG + "-fp-dup", "human_rule": rule})
        check("重复规则被拒", r.get("code") != 200, r)
        rows = [i for i in pick_items(call("/fingerprint/?name=" + TAG)) if i.get("name") == TAG + "-fp"]
        check("指纹检索", len(rows) == 1, rows)

        # 指纹 YAML 上传 + 清理
        boundary = "----walk{} ".format(int(time.time() * 1000)).replace(" ", "")
        yaml_body = '- name: {}-up\n  rule: body="{}-up"\n'.format(TAG, TAG)
        payload = ("--{b}\r\nContent-Disposition: form-data; name=\"update\"\r\n\r\n"
                   "false\r\n--{b}\r\nContent-Disposition: form-data; name=\"file\"; "
                   "filename=\"fp.yml\"\r\nContent-Type: application/octet-stream\r\n\r\n"
                   "{y}\r\n--{b}--\r\n").format(b=boundary, y=yaml_body).encode()
        req = urllib.request.Request(
            BASE + "/api/fingerprint/upload/", data=payload, method="POST",
            headers={"Token": TOKEN, "Content-Type": "multipart/form-data; boundary=" + boundary})
        with urllib.request.urlopen(req, timeout=30) as resp:
            up = json.load(resp)
        check("指纹 YAML 上传成功1条", (up.get("data") or {}).get("success_cnt") == 1, up)
        rows = [i for i in pick_items(call("/fingerprint/?name=" + TAG + "-up"))
                if i.get("name") == TAG + "-up"]
        check("上传后指纹可检索", len(rows) == 1, rows)
        if rows:
            call("/fingerprint/delete/", {"_id": [rows[0]["_id"]]})

        # ---------------- POC / 风险筛选 ----------------
        r = call("/poc/?size=5&plugin_type=brute")
        check("POC 类型筛选", r.get("code") == 200 and
              all((i.get("plugin_type") == "brute") for i in pick_items(r)), r)
        r = call("/vuln/?size=5&severity=high")
        check("漏洞等级筛选(空结果也须 200)", r.get("code") == 200, r)
        r = call("/nuclei_result/?size=5")
        check("Nuclei 结果列表", r.get("code") == 200, r)

        # ---------------- 集成凭证往返 ----------------
        r = call("/integration/", {"vendor": "chaos", "fields": {"api_key": TAG + "-k"}})
        check("集成凭证保存", r.get("code") == 200 and r["data"]["updated"] == ["api_key"], r)
        v = call("/integration/")["data"]
        chaos = next(i for g in v["groups"] for i in g["items"] if i["vendor"] == "chaos")
        check("集成掩码视图", chaos["configured"] and "****" in chaos["values"]["api_key"], chaos)
        r = call("/integration/test/", {"vendor": "chaos"})
        check("无探活厂商标注 untested", r["data"].get("ok") is True and r["data"].get("tested") is False, r)
        r = call("/integration/", {"vendor": "chaos", "clear": True, "fields": {}})
        check("集成凭证清除", r.get("code") == 200, r)

        # ---------------- FOFA 无 Key 优雅报错 ----------------
        r = call("/task_fofa/test", {"query": 'is_domain=true'})
        err = str((r.get("data") or {}).get("error") or r.get("message") or "")
        check("FOFA 未配置时优雅报错(业务码非 5xx, 明确提示)", "Fofa key" in err, r)

        # ---------------- 健康接口 ----------------
        r = call("/stats/summary/")
        check("统计摘要", r.get("code") == 200 and "domains" in (r.get("data") or {}), r)

    finally:
        print("\n== 清理 ==")
        if gh_id:
            check("清理 GitHub 监控", call("/github_scheduler/delete/", {"_id": [gh_id]}).get("code") == 200)
        if ts_id:
            check("清理定时扫描", call("/task_schedule/delete/", {"_id": [ts_id]}).get("code") == 200)
        if sched_id:
            check("清理监控任务", call("/scheduler/delete/", {"job_id": [sched_id]}).get("code") == 200)
        if policy_id:
            check("清理策略", call("/policy/delete/", {"policy_id": [policy_id]}).get("code") == 200)
        if scope_id:
            check("清理资产组", call("/asset_scope/delete/", {"scope_id": [scope_id]}).get("code") == 200)
        rows = [i for i in pick_items(call("/fingerprint/?name=" + TAG))]
        if rows:
            call("/fingerprint/delete/", {"_id": [i["_id"] for i in rows]})
            print("  ✓ 清理指纹 x{}".format(len(rows)))

    failed = [(n, d) for n, ok, d in CHECKS if not ok]
    print("\nSUMMARY: {} checks, {} failed".format(len(CHECKS), len(failed)))
    if failed:
        for n, d in failed:
            print("  FAIL:", n, str(d)[:200])
        sys.exit(1)
    print("API_SMOKE_OK")


if __name__ == "__main__":
    main()
