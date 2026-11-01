"""控制台 UI 端到端验证：真实浏览器登录 + 各页渲染 + 截图目检。

融合重构后 console.html 原生实现全部 17 页（无 bundle iframe）。
全程 127.0.0.1（访问本机 Docker 栈 5003）。截图存 /tmp/console-shots/。
用法：.venv/bin/python scripts/console_e2e_check.py
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BASE = os.environ.get("ARL_BASE", "http://127.0.0.1:5003")
SHOTS = "/tmp/console-shots"
CREDS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "deploy", "dev-credentials.env")


def admin_creds():
    vals = {}
    for line in open(CRED_FILE := CREDS):
        if "=" in line and not line.startswith("#"):
            k, v = line.strip().split("=", 1)
            vals[k] = v
    return vals.get("ARL_ADMIN_USER", "admin"), vals.get("ARL_ADMIN_PASSWORD", "")


def _find_chrome():
    base = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(base)
    for entry in sorted(os.listdir(os.path.join(root, "tools", "chrome-for-testing"))):
        candidate = os.path.join(root, "tools", "chrome-for-testing", entry,
                                 "chrome-linux64", "chrome")
        if os.path.exists(candidate):
            return candidate
    raise SystemExit("未找到包内 Chrome")


def nav(page, route, expect_title):
    """hash 路由跳转并等待该页渲染完成（首段标题匹配）。

    同文档 fragment 跳转偶发不触发 hashchange，重试并以 reload 兜底，
    消除 E2E 偶发超时。
    """
    last = ""
    for _ in range(3):
        page.goto(BASE + "/console.html" + route)
        try:
            page.wait_for_function(
                "t => { const h = document.querySelector('#view h2.page');"
                " return !!h && h.textContent.includes(t); }",
                arg=expect_title, timeout=8000)
            return
        except Exception as exc:
            last = str(exc)
            page.reload()
            page.wait_for_timeout(500)
    raise RuntimeError("路由未渲染: {} ({})".format(route, last))


def main():
    os.makedirs(SHOTS, exist_ok=True)
    user, password = admin_creds()
    chrome = _find_chrome()

    from playwright.sync_api import sync_playwright

    failures = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, executable_path=chrome,
                                    args=["--no-sandbox"])
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.set_default_timeout(20000)

        # 1 登录页渲染
        page.goto(BASE + "/console.html")
        page.wait_for_selector("#login", state="visible")
        page.screenshot(path=f"{SHOTS}/01-login.png")

        # 2 登录
        page.fill("#li-user", user)
        page.fill("#li-pass", password)
        page.click("#login .btn.primary")
        page.wait_for_selector("#app", state="visible")
        page.wait_for_timeout(1200)

        # 3 总览：统计卡片 + 趋势图 + 漏洞分布 donut（数据无关断言）
        if not page.locator(".stat").count():
            failures.append("总览统计卡片未渲染")
        page.wait_for_timeout(1500)
        if not page.locator("#trend-svg polyline").count():
            failures.append("任务趋势折线未渲染")
        if not page.locator("#sev-donut svg").count():
            failures.append("漏洞分布 donut 未渲染")
        page.screenshot(path=f"{SHOTS}/02-overview.png")

        # 4 资产页：单搜索栏智能路由 + 详情抽屉
        nav(page, "#/assets", "资产检索")
        for tab in ["APP", "小程序", "ICP 备案"]:
            if not page.locator("button.btn", has_text=tab).count():
                failures.append(f"资产检索缺维度 tab: {tab}")
        page.fill("#as-q", "demo")
        page.click("text=查询")
        page.wait_for_timeout(1500)
        site_rows = page.locator("#as-table tbody tr").count()
        if site_rows < 5:
            failures.append(f"资产单搜索结果异常（{site_rows} 行）")
        if not page.locator("#as-pager").inner_text().strip():
            failures.append("资产分页控件缺失")
        # 点行开详情抽屉
        page.locator("#as-table tbody tr").first.click()
        page.wait_for_timeout(600)
        if "资产详情" not in page.locator("#drawer").inner_text():
            failures.append("资产详情抽屉未打开")
        page.evaluate("closeDrawer && closeDrawer()")
        page.screenshot(path=f"{SHOTS}/03-assets.png")

        # 5 任务页 + 新建抽屉（扫描模板制）
        nav(page, "#/tasks", "任务管理")
        page.click("text=新建任务")
        page.wait_for_selector("#tf-target", state="visible")
        if not page.locator("#tf-checks input[type=checkbox]").count():
            failures.append("任务开关未渲染")
        for tpl in ["快速", "标准", "深度"]:
            if not page.locator("button[data-tpl]", has_text=tpl).count():
                failures.append(f"任务模板按钮缺失: {tpl}")
        if not page.locator("#tf-tpl-desc").count():
            failures.append("模板说明缺失")
        page.screenshot(path=f"{SHOTS}/04-task-form.png")
        page.fill("#tf-target", "example.com")
        page.fill("#tf-name", "冒烟测试任务")
        page.click("text=下发任务")
        page.wait_for_timeout(2500)   # 真实下发（example.com 冒烟）
        body = page.locator("#tk-table").inner_text()
        if "冒烟测试任务" not in body:
            failures.append("任务未出现在列表")

        # 6 会话池交互流程（接入→探活→重新录入→删除）
        nav(page, "#/sessions", "会话池")
        page.evaluate("closeDrawer && closeDrawer()")   # 防御：hash 路由不重载，残留抽屉拦截点击
        page.fill("#sp-token", "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3OTYwMDAwMDB9.sig")
        page.click("#sp-onboard-btn")
        page.wait_for_timeout(2000)
        sp_text = page.locator("#sp-list").inner_text()
        if "fengniao / default" not in sp_text:
            failures.append("会话池接入后账号卡片未出现")
        # 探活
        sp_probe = page.locator("#sp-list button", has_text="探活").first
        sp_probe.click()
        page.wait_for_timeout(1500)
        # 重新录入展开
        sp_re = page.locator("#sp-list button", has_text="重新录入").first
        sp_re.click()
        page.wait_for_timeout(400)
        if not page.locator("#sp-list .sp-reboard input").count():
            failures.append("重新录入输入区未展开")
        # 重新录入提交（覆盖 token）
        page.fill("#sp-list .sp-reboard input", "token=abc123; app-uuid=WEB-Z")
        page.locator("#sp-list .sp-reboard button").first.click()
        page.wait_for_timeout(1500)
        sp_text2 = page.locator("#sp-list").inner_text()
        if "fengniao / default" not in sp_text2:
            failures.append("重新录入后账号消失")
        page.screenshot(path=f"{SHOTS}/06-sessions.png")
        # 删除（confirm 对话框 → 接受）——精确定位 fengniao 卡，防止多卡时误删
        page.on("dialog", lambda d: d.accept())
        sp_del = page.locator(".card", has_text="fengniao / default") \
            .locator("button", has_text="删除").first
        sp_del.click()
        page.wait_for_timeout(1500)
        sp_text3 = page.locator("#sp-list").inner_text()
        if "fengniao / default" in sp_text3:
            failures.append("删除后账号仍在列表")
        if "暂无数据源" not in sp_text3:
            failures.append("删除后空状态未出现")

        # 7 融合重构后的原生页面逐一渲染断言（无 iframe，页面级控件必须在）
        for view, shot, expect, probe_selector, probe_name in [
            ("#/scopes",       "12-scopes",       "资产组",   "text=新建资产组",  "新建资产组"),
            ("#/policy",       "13-policy",       "任务策略", "text=新建策略",    "新建策略"),
            ("#/schedules",    "14-schedules",    "计划任务", "text=资产组监控",  "资产组监控tab"),
            ("#/fingerprints", "15-fingerprints", "指纹库",   "text=新建指纹",    "新建指纹"),
            ("#/poc",          "16-poc",          "POC 库",   "text=同步 NPoC",   "同步NPoC"),
            ("#/risks",        "17-risks",        "风险中心", "text=批量删除",    "风险批量删除"),
            ("#/ai",           "18-ai",           "AI 配置",  "text=新增供应商",  "新增供应商"),
            ("#/sources",      "21-sources",      "数据源接入", "text=FOFA 采集任务", "FOFA采集任务卡"),
            ("#/assistant",    "22-assistant",    "智能助手", "text=新建会话",    "助手新建会话"),
            ("#/diff",         "05-diff",         "监控变化", "#df-scope",        "scope过滤输入"),
            ("#/reports",      "07-reports",      "报告中心", "text=生成报告",    "生成报告"),
            ("#/engines",      "08-engines",      "扫描引擎", "#eg-policy",       "执行图策略选择"),
            ("#/settings",     "11-settings",     "通知渠道", "text=钉钉",        "钉钉渠道卡"),
            ("#/users",        "09-users",        "用户管理", "text=创建",        "用户创建"),
        ]:
            nav(page, view, expect)
            page.wait_for_timeout(600)
            if not page.locator(probe_selector).count():
                failures.append(f"{expect} 页缺关键控件: {probe_name}")
            page.screenshot(path=f"{SHOTS}/{shot}.png")

        # 8 企业情报（吸收 appdl）
        nav(page, "#/enterprise", "企业情报")
        page.evaluate("closeDrawer && closeDrawer()")
        page.wait_for_timeout(800)
        ent_text = page.locator("#view").inner_text()
        for kw in ["企业情报", "集团概览", "解析全部链接"]:
            if kw not in ent_text:
                failures.append(f"企业情报页缺失: {kw}")
        page.screenshot(path=f"{SHOTS}/10-enterprise.png")

        # 9 交互抽查：策略新建抽屉结构化表单 + 计划任务 tab 切换
        nav(page, "#/policy", "任务策略")
        page.click("text=新建策略")
        page.wait_for_selector("#pf-name", state="visible")
        for group, label in [("#pf-dc", "域名配置"), ("#pf-sc", "站点配置")]:
            if not page.locator(f"{group} input[data-k]").count():
                failures.append(f"策略表单 {label} 开关缺失")
        page.screenshot(path=f"{SHOTS}/19-policy-form.png")
        page.evaluate("closeDrawer && closeDrawer()")

        nav(page, "#/schedules", "计划任务")
        page.click("button:has-text('定时扫描')")
        page.wait_for_timeout(700)
        if not page.locator("text=新建计划任务").count():
            failures.append("计划任务定时扫描 tab 未切换")
        page.click("button:has-text('GitHub 泄露监控')")
        page.wait_for_timeout(700)
        if not page.locator("text=新建 GitHub 监控").count():
            failures.append("GitHub 监控 tab 未切换")
        page.screenshot(path=f"{SHOTS}/20-schedules-tabs.png")

        # 10 悬浮窗与窗口登录入口
        if not page.locator("#ai-fab").count():
            failures.append("AI 助手悬浮球缺失")
        nav(page, "#/sessions", "会话池")
        page.wait_for_timeout(500)
        if not page.locator("text=窗口登录").count():
            failures.append("会话池缺窗口登录入口")

        # 11 冗余清理断言：页面上不应再有 iframe / bundle 引用
        if page.locator("#view iframe").count():
            failures.append("页面仍存在 iframe（融合未完成）")
        html = page.content()
        if "/bundle" in html:
            failures.append("页面仍引用 /bundle")

        browser.close()

    if failures:
        print("FAIL:")
        for f in failures:
            print("  -", f)
        sys.exit(1)
    print("CONSOLE_E2E_OK: 登录/总览/资产/任务下发/17 原生页/交互抽查 全部通过")
    print("截图目录:", SHOTS)


if __name__ == "__main__":
    main()
