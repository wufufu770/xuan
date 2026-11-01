"""扫描引擎执行图：把策略 options 编译为分阶段节点图（供前端可视化）。

- 节点：taskStage 注册表的 55 个阶段，按五阶段工作流分组
  （light / heavy_top / heavy_full / post / post_finalize）
- 节点状态：enabled（选项显式开启）/ disabled（显式关闭）/ auto（无对应
  选项键，运行时按条件触发，如增量闭环、B 面发现）
- 边：阶段内顺序连边 + 阶段间末尾→开头连接
"""

from app.services.taskStage import (
    TASK_STAGE_DISPLAY_NAMES,
    TASK_STAGE_ORDER,
)

PHASE_ORDER = ["light", "heavy_top", "heavy_full", "post", "post_finalize"]

PHASE_STAGES = {
    "light": [
        "domain_brute", "dns_query_plugin", "arl_search", "search_engines",
        "dns_auxiliary", "alt_dns", "cert_candidate_verify",
        "asset_seed_probe", "known_service_seed", "asset_seed_prefill",
    ],
    "heavy_top": ["port_scan_top1000", "ssl_cert_top1000"],
    "heavy_full": [
        "port_scan", "port_scan_full", "ssl_cert", "ssl_cert_full",
        "save_ip_info", "find_site", "fetch_site", "site_capture",
        "site_spider", "runtime_artifact", "web_info_hunter",
        "site_spider_domain_update", "wih_domain_update",
        "entry_feedback_spider", "entry_feedback_runtime_artifact",
        "entry_feedback_wih", "entry_feedback_domain_update",
        "post_dns_feedback", "post_dns_feedback_domain_update",
        "discovery_delta", "discovery_delta_port_scan",
        "discovery_delta_port_scan_top1000", "discovery_delta_port_scan_full",
        "discovery_delta_ssl", "discovery_delta_fetch_site",
        "discovery_delta_spider", "discovery_delta_runtime_artifact",
        "discovery_delta_wih", "discovery_delta_domain_update",
        "bface_discover",
    ],
    "post": [
        "file_leak", "nuclei_scan", "wayback_backtrack", "bing_deep",
        "js_deep", "framework_probe", "shadow_tag", "ai_judge",
    ],
    "post_finalize": ["npoc_service_detection", "poc_run", "weak_brute",
                      "findvhost", "common_run"],
}

# 选项键 -> 控制的阶段列表
OPTION_STAGE_MAP = {
    "domain_brute": ["domain_brute"],
    "dns_query_plugin": ["dns_query_plugin"],
    "arl_search": ["arl_search"],
    "alt_dns": ["alt_dns"],
    "search_engines": ["search_engines"],
    "dns_auxiliary": ["dns_auxiliary"],
    "cert_candidate_verify": ["cert_candidate_verify"],
    "port_scan": ["port_scan", "port_scan_top1000", "port_scan_full"],
    "ssl_cert": ["ssl_cert", "ssl_cert_top1000", "ssl_cert_full"],
    "site_identify": ["find_site", "fetch_site"],
    "site_capture": ["site_capture"],
    "site_spider": ["site_spider", "site_spider_domain_update"],
    "web_info_hunter": ["web_info_hunter", "wih_domain_update"],
    "file_leak": ["file_leak"],
    "npoc_service_detection": ["npoc_service_detection"],
}


def _stage_state(stage, options):
    """返回 enabled / disabled / auto。"""
    for option_key, stages in OPTION_STAGE_MAP.items():
        if stage in stages and option_key in options:
            enabled = bool(options.get(option_key))
            if enabled and option_key == "port_scan":
                scan_type = str(options.get("port_scan_type") or "test")
                if stage == "port_scan_full" and scan_type != "custom" and \
                        scan_type != "full":
                    return "disabled"
            return "enabled" if enabled else "disabled"
    # 特殊条件阶段
    if stage == "poc_run":
        return "enabled" if options.get("poc_config") else "disabled"
    if stage == "weak_brute":
        return "enabled" if options.get("brute_config") else "disabled"
    return "auto"


def build_engine_graph(policy):
    """policy dict -> 图结构（nodes 分阶段 + edges）。"""
    options = policy.get("domain_config") or {}
    # domain_config/ip_config/site_config 都可能带开关；合并视图（site/ip 键同名）
    for section in ("ip_config", "site_config"):
        for key, value in (policy.get(section) or {}).items():
            options.setdefault(key, value)

    phases = []
    all_nodes = []
    for phase in PHASE_ORDER:
        nodes = []
        for stage in PHASE_STAGES[phase]:
            node = {
                "stage": stage,
                "name": TASK_STAGE_DISPLAY_NAMES.get(stage, stage),
                "state": _stage_state(stage, options),
            }
            nodes.append(node)
            all_nodes.append(node)
        phases.append({"phase": phase, "nodes": nodes})

    edges = []
    for i, phase in enumerate(phases):
        nodes = phase["nodes"]
        for j in range(len(nodes) - 1):
            edges.append({"from": nodes[j]["stage"], "to": nodes[j + 1]["stage"]})
        if i + 1 < len(phases) and nodes and phases[i + 1]["nodes"]:
            edges.append({"from": nodes[-1]["stage"],
                          "to": phases[i + 1]["nodes"][0]["stage"]})

    enabled_count = sum(1 for n in all_nodes if n["state"] == "enabled")
    return {
        "phases": phases,
        "edges": edges,
        "summary": {
            "total_stages": len(all_nodes),
            "enabled": enabled_count,
            "disabled": sum(1 for n in all_nodes if n["state"] == "disabled"),
            "auto": sum(1 for n in all_nodes if n["state"] == "auto"),
            "registered": len(TASK_STAGE_ORDER),
        },
    }
