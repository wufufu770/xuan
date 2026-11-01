"""控制台全页遍历 bug 猎捕：逐页导航 + 开抽屉 + 切 tab + 翻页 + 非法输入，
收集未捕获 JS 异常、console.error 与 4xx/5xx 响应，输出缺陷清单。

用法：.venv/bin/python scripts/console_walk_check.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from console_e2e_check import admin_creds, _find_chrome, BASE, nav  # noqa: E402


def main():
    user, password = admin_creds()
    chrome = _find_chrome()

    from playwright.sync_api import sync_playwright

    issues = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, executable_path=chrome,
                                    args=["--no-sandbox"])
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.set_default_timeout(15000)

        def on_pageerror(exc):
            issues.append(f"JS未捕获异常: {str(exc)[:200]}")
        def on_console(msg):
            if msg.type == "error":
                text = msg.text
                loc = (msg.location or {}).get("url", "") if isinstance(msg.location, dict) else ""
                if "favicon" in text or "favicon" in loc or "net::ERR" in text:
                    return
                issues.append(f"console.error: {text[:160]} @ {loc[-80:]}")
        def on_response(resp):
            if resp.status >= 400:
                issues.append(f"HTTP {resp.status}: {resp.url.split('5003')[-1][:120]}")
        page.on("pageerror", on_pageerror)
        page.on("console", on_console)
        page.on("response", on_response)

        page.goto(BASE + "/console.html")
        page.fill("#li-user", user)
        page.fill("#li-pass", password)
        page.click("#login .btn.primary")
        page.wait_for_selector("#app", state="visible")
        page.wait_for_timeout(1500)

        def drawer_round(drawer_btn, probe_sel, page_title):
            """开抽屉→断关键控件→关闭，收集期间异常。"""
            page.click(drawer_btn)
            try:
                page.wait_for_selector(probe_sel, state="visible", timeout=6000)
            except Exception as exc:
                issues.append(f"[{page_title}] 抽屉 {drawer_btn} 打开失败: {str(exc)[:80]}")
                page.evaluate("closeDrawer && closeDrawer()")
                return
            page.wait_for_timeout(300)
            page.evaluate("closeDrawer && closeDrawer()")
            page.wait_for_timeout(400)
            # 关闭后抽屉应不可见（transform 出屏）
            visible = page.evaluate(
                "(()=>{const d=document.querySelector('#drawer');"
                "const r=d.getBoundingClientRect();return r.x < window.innerWidth-40;})()")
            if visible:
                issues.append(f"[{page_title}] 抽屉关闭后仍在可视区")

        def pager_round(prev_sel, next_sel, label):
            for sel, name in [(next_sel, "下一页"), (prev_sel, "上一页")]:
                btn = page.locator(sel).first
                if not btn.count():
                    continue
                if btn.is_disabled():
                    continue
                btn.click()
                page.wait_for_timeout(700)
            if not page.locator(".pager").count():
                issues.append(f"[{label}] 分页控件缺失")

        # ---------- 逐页 ----------
        nav(page, "#/overview", "看板"); page.wait_for_timeout(1500)

        nav(page, "#/assets", "资产检索")
        page.fill("#as-q", "demo"); page.click("text=查询"); page.wait_for_timeout(1200)
        pager_round("#as-pager .btn.sm >> nth=0", "#as-pager .btn.sm >> nth=1", "资产检索")
        # 非法输入：空查询
        page.fill("#as-q", ""); page.click("text=查询"); page.wait_for_timeout(700)

        nav(page, "#/scopes", "资产组"); page.wait_for_timeout(900)
        drawer_round("text=新建资产组", "#scf-name", "资产组")
        # 非法：空表单提交
        page.click("text=新建资产组")
        page.wait_for_selector("#scf-name", state="visible")
        page.click("#drawer button.primary"); page.wait_for_timeout(500)
        page.evaluate("closeDrawer && closeDrawer()")

        nav(page, "#/tasks", "任务管理"); page.wait_for_timeout(900)
        drawer_round("text=新建任务", "#tf-target", "任务管理")
        pager_round("#tk-pager .btn.sm >> nth=0", "#tk-pager .btn.sm >> nth=1", "任务管理")

        nav(page, "#/policy", "任务策略"); page.wait_for_timeout(900)
        drawer_round("text=新建策略", "#pf-name", "任务策略")

        nav(page, "#/schedules", "计划任务"); page.wait_for_timeout(900)
        drawer_round("text=新建监控任务", "#mf-domain", "计划任务-监控")
        page.click("button:has-text('定时扫描')"); page.wait_for_timeout(700)
        drawer_round("text=新建计划任务", "#tsf-name", "计划任务-扫描")
        page.click("button:has-text('GitHub 泄露监控')"); page.wait_for_timeout(700)
        drawer_round("text=新建 GitHub 监控", "#ghf-keyword", "计划任务-GitHub")

        nav(page, "#/risks", "风险中心"); page.wait_for_timeout(900)
        page.click("button:has-text('Nuclei')"); page.wait_for_timeout(700)
        pager_round("#risk-pager .btn.sm >> nth=0", "#risk-pager .btn.sm >> nth=1", "风险中心")

        nav(page, "#/engines", "扫描引擎"); page.wait_for_timeout(900)
        page.click("text=生成执行图"); page.wait_for_timeout(800)

        nav(page, "#/fingerprints", "指纹库"); page.wait_for_timeout(900)
        drawer_round("text=新建指纹", "#fpf-name", "指纹库")
        # 非法规则提交（应 toast 而非异常）
        page.click("text=新建指纹"); page.wait_for_selector("#fpf-name", state="visible")
        page.fill("#fpf-name", "walk-smoke"); page.fill("#fpf-rule", "not_a_valid_rule((")
        page.click("#drawer button.primary"); page.wait_for_timeout(800)
        page.evaluate("closeDrawer && closeDrawer()")

        nav(page, "#/poc", "POC 库"); page.wait_for_timeout(900)
        pager_round("#poc-pager .btn.sm >> nth=0", "#poc-pager .btn.sm >> nth=1", "POC 库")
        # 筛选组合
        page.fill("#poc-vul", "不存在的漏洞"); page.click("text=查询"); page.wait_for_timeout(700)
        if "暂无" not in page.locator("#poc-table").inner_text():
            issues.append("[POC 库] 无命中筛选未显示空态")

        nav(page, "#/sources", "数据源接入"); page.wait_for_timeout(900)
        # 空保存（无字段）应返回未提供更新字段
        page.locator("button.btn.sm.primary", has_text="保存").first.click()
        page.wait_for_timeout(700)
        # 探活未配置厂商 → toast 失败文案
        page.locator("button.btn.sm", has_text="测试连接").first.click()
        page.wait_for_timeout(900)
        # FOFA 空查询
        page.click("text=测试查询"); page.wait_for_timeout(500)
        # FOFA 非法查询
        page.fill("#ft-query", "'\"invalid"); page.click("text=测试查询")
        page.wait_for_timeout(1200)

        nav(page, "#/ai", "AI 配置"); page.wait_for_timeout(900)
        drawer_round("text=新增供应商", "#aif-url", "AI 配置")
        # 空保存
        page.click("text=新增供应商"); page.wait_for_selector("#aif-url", state="visible")
        page.click("#drawer button.primary"); page.wait_for_timeout(500)
        page.evaluate("closeDrawer && closeDrawer()")
        # 空研判提交
        page.click("text=提交研判"); page.wait_for_timeout(600)

        nav(page, "#/sessions", "会话池"); page.wait_for_timeout(900)
        page.click("text=接入并探活"); page.wait_for_timeout(600)  # 空 token → toast
        # storage_state JSON 非法（先展开 details）
        page.locator("details summary", has_text="storage_state").click()
        page.wait_for_timeout(300)
        page.fill("#sp-json", "not-json")
        page.click("text=导入并探活"); page.wait_for_timeout(600)

        nav(page, "#/diff", "监控变化"); page.wait_for_timeout(900)
        nav(page, "#/reports", "报告中心"); page.wait_for_timeout(900)
        # 空 scope 生成报告 → toast
        page.click("text=生成报告"); page.wait_for_timeout(600)
        nav(page, "#/settings", "通知渠道"); page.wait_for_timeout(900)
        nav(page, "#/users", "用户管理"); page.wait_for_timeout(900)

        # 刷新路由直达（深链）
        for route, title in [("#/scopes", "资产组"), ("#/sources", "数据源接入"),
                             ("#/risks", "风险中心")]:
            page.goto(BASE + "/console.html" + route)
            try:
                page.wait_for_function(
                    "t => { const h = document.querySelector('#view h2.page');"
                    " return !!h && h.textContent.includes(t); }",
                    arg=title, timeout=8000)
            except Exception:
                issues.append(f"[深链] {route} 直开未渲染")
            page.wait_for_timeout(500)

        browser.close()

    seen = set()
    uniq = []
    for i in issues:
        if i not in seen:
            seen.add(i)
            uniq.append(i)
    if uniq:
        print("ISSUES ({}) :".format(len(uniq)))
        for i in uniq:
            print("  -", i)
        sys.exit(1)
    print("WALK_OK: 全页遍历无未捕获异常/无意外 4xx5xx/console.error")


if __name__ == "__main__":
    main()
