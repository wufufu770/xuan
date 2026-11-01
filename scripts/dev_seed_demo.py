#!/usr/bin/env python3
"""向本地 Docker 开发栈注入演示数据（用于 UI 验证与截图演示）。

仅在 arl_dev_mongodb 容器存在时可用；数据为虚构样例。
用法：.venv/bin/python scripts/dev_seed_demo.py [--wipe]
"""

import subprocess
import sys
import os

CREDS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "deploy", "dev-credentials.env")

JS = """
const now = Date.now();
function oid(daysAgo){
  const sec = Math.floor((now - daysAgo*86400000)/1000);
  return ObjectId(sec.toString(16).padStart(12, "0") + "0".repeat(12));
}
function dt(daysAgo, h){
  const d = new Date(now - daysAgo*86400000); d.setHours(h||10, 0, 0, 0);
  return d.toISOString().replace('T',' ').slice(0,19);
}
db.task.deleteMany({task_tag: "demo"});
db.site.deleteMany({source: "demo"});
db.domain.deleteMany({source: "demo"});
db.ip.deleteMany({source: "demo"});
db.vulnerability.deleteMany({source: "demo"});
db.monitor_diff.deleteMany({source: "demo"});

const tasks = [
  ["demo-电商主站", "shop-demo.cn", "done", 13, 13],
  ["demo-集团全量", "group-demo.cn", "done", 9, 8],
  ["demo-边缘资产", "edge-demo.cn", "error", 6, 6],
  ["demo-供应链", "supply-demo.cn", "done", 4, 3],
  ["demo-双周巡检", "biweekly-demo.cn", "done", 1, 1],
  ["demo-临时排查", "incident-demo.cn", "stop", 0, 0],
];
tasks.forEach(([name, target, status, startDays, endDays]) => {
  db.task.insertOne({
    _id: oid(startDays),
    name, target, status, task_tag: "demo",
    start_time: dt(startDays, 9), end_time: dt(endDays, 18),
    create_time: dt(startDays, 9),
  });
});

const sites = [
  ["http://shop-demo.cn", "演示商城 - 首页", 200, ["Nginx", "Vue"], 12],
  ["https://api.shop-demo.cn", "API Gateway", 200, ["Kong"], 12],
  ["http://admin.shop-demo.cn", "后台管理登录", 401, ["Tomcat"], 12],
  ["http://group-demo.cn", "集团官网", 200, ["Apache", "jQuery"], 8],
  ["https://oa.group-demo.cn", "OA 系统", 200, ["Vue", "Element"], 8],
  ["http://mail.group-demo.cn", "WebMail", 302, ["Exchange"], 8],
  ["http://edge-demo.cn", "边缘节点", 200, ["Caddy"], 5],
  ["http://grafana.edge-demo.cn", "Grafana", 200, ["Grafana"], 5],
  ["http://supply-demo.cn", "供应商门户", 200, ["PHP"], 3],
  ["https://sso.supply-demo.cn", "统一认证", 200, ["Keycloak"], 3],
  ["http://biweekly-demo.cn", "巡检首页", 200, ["Nginx"], 1],
  ["http://old.biweekly-demo.cn", "旧站（下线中）", 503, ["Apache"], 1],
];
sites.forEach(([site, title, status, fingers, daysAgo], idx) => {
  const sec = Math.floor((now - daysAgo*86400000)/1000) + idx;
  db.site.insertOne({
    _id: ObjectId(sec.toString(16).padStart(12, "0") + idx.toString(16).padStart(12, "0")),
    task_id: ObjectId(sec.toString(16).padStart(12, "0") + "0".repeat(12)).toString(),
    task_tag: "demo", source: "demo",
    site, title, status, canonical_site: site, pipeline_eligible: true,
    finger: fingers.map(n => ({name: n})),
    save_date: dt(daysAgo, 12),
  });
});

const domains = ["shop-demo.cn", "api.shop-demo.cn", "admin.shop-demo.cn",
  "group-demo.cn", "oa.group-demo.cn", "mail.group-demo.cn",
  "edge-demo.cn", "grafana.edge-demo.cn", "supply-demo.cn", "sso.supply-demo.cn"];
domains.forEach((d, i) => {
  db.domain.insertOne({
    task_id: oid(13 - (i % 6)).toString(), task_tag: "demo", source: "demo",
    domain: d, resolve_status: "resolved",
    save_date: dt(13 - (i % 6), 11),
  });
});

const ips = [
  ["47.100.1.1", [80, 443]], ["47.100.1.2", [80, 8080, 9200]],
  ["47.100.2.1", [22, 80, 3389]], ["47.100.2.2", [443]],
  ["39.10.3.1", [80, 8080, 8443]], ["39.10.3.2", [6379]],
];
ips.forEach(([ip, ports], i) => {
  db.ip.insertOne({
    task_id: oid(12 - (i % 5)).toString(), task_tag: "demo", source: "demo",
    ip, port_info: ports.map(p => ({port_id: p})),
    save_date: dt(12 - (i % 5), 13),
  });
});

const vulns = [
  ["SQL 注入（演示）", "high", "http://shop-demo.cn/item?id=1", 5],
  ["弱口令 admin/admin（演示）", "critical", "http://admin.shop-demo.cn", 5],
  ["未授权 Elasticsearch（演示）", "critical", "47.100.1.2:9200", 4],
  ["Struts2-045（演示）", "critical", "http://supply-demo.cn", 3],
  ["XSS 反射型（演示）", "medium", "http://biweekly-demo.cn/q=", 1],
  ["目录列表启用（演示）", "low", "http://old.biweekly-demo.cn/backup/", 1],
  ["Redis 未授权（演示）", "critical", "39.10.3.2:6379", 4],
  ["敏感信息泄露 .git（演示）", "medium", "http://edge-demo.cn/.git/", 2],
];
vulns.forEach(([name, severity, url, daysAgo]) => {
  db.vulnerability.insertOne({
    task_id: oid(daysAgo).toString(), task_tag: "demo", source: "demo",
    vul_name: name, severity, url,
    plg_name: "demo-scanner",
    save_date: dt(daysAgo, 14),
  });
});

db.monitor_diff.insertMany([
  {job_id: "demo-job-1", scope_id: "demo-scope", source: "domain",
   target: "shop-demo.cn", run_date: dt(2, 9), run_ts: now - 2*86400000, run_number: 3,
   diff: {domains: {added: ["promo.shop-demo.cn", "act.shop-demo.cn"], removed: [],
                     added_total: 2, removed_total: 0},
          ports: {added: ["47.100.1.2:9200"], removed: [],
                  added_total: 1, removed_total: 0},
          sites: {added: ["https://api.shop-demo.cn"], removed: [], changed: [],
                  added_total: 1, removed_total: 0, changed_total: 0}}},
  {job_id: "demo-job-1", scope_id: "demo-scope", source: "domain",
   target: "shop-demo.cn", run_date: dt(5, 9), run_ts: now - 5*86400000, run_number: 2,
   diff: {domains: {added: [], removed: ["old.shop-demo.cn"],
                    added_total: 0, removed_total: 1},
          ports: {added: [], removed: ["47.100.1.1:8080"],
                  added_total: 0, removed_total: 1},
          sites: {added: [], removed: [], changed: [],
                  added_total: 0, removed_total: 0, changed_total: 0}}},
]);
print("SEED_OK");
"""


def main():
    wipe = "--wipe" in sys.argv
    creds = {}
    for line in open(CREDS):
        if "=" in line:
            k, v = line.strip().split("=", 1)
            creds[k] = v

    js = "db.getSiblingDB('arl');\n" + JS
    js = js.replace("db.task", "db.task").replace("db.site", "db.site")
    cmd_js = "const __db = db.getSiblingDB('arl');\n" + JS.split("\n", 1)[1]
    cmd_js = cmd_js.replace("db.task", "__db.task").replace(
        "db.site", "__db.site").replace("db.domain", "__db.domain").replace(
        "db.ip", "__db.ip").replace("db.vulnerability", "__db.vulnerability").replace(
        "db.monitor_diff", "__db.monitor_diff")
    if wipe:
        cmd_js = ("__db.task.deleteMany({task_tag:'demo'});"
                  "__db.site.deleteMany({source:'demo'});"
                  "__db.domain.deleteMany({source:'demo'});"
                  "__db.ip.deleteMany({source:'demo'});"
                  "__db.vulnerability.deleteMany({source:'demo'});"
                  "__db.monitor_diff.deleteMany({source:'demo'});"
                  "print('WIPED');")
    result = subprocess.run(
        ["docker", "exec", "arl_dev_mongodb", "mongosh", "--quiet",
         "--username", creds.get("MONGO_APP_USER", ""),
         "--password", creds.get("MONGO_APP_PASSWORD", ""),
         "--authenticationDatabase", "arl", "arl", "--eval", cmd_js],
        capture_output=True, text=True, timeout=120)
    out = (result.stdout + result.stderr).strip().splitlines()
    for line in out[-4:]:
        print(line)
    if "SEED_OK" not in (result.stdout + result.stderr) and not wipe:
        sys.exit(1)


if __name__ == "__main__":
    main()
