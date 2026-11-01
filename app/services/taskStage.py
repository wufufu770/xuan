TASK_STAGE_DISPLAY_NAMES = {
    "domain_brute": "域名爆破",
    "dns_query_plugin": "被动收集",
    "arl_search": "ARL 历史查询",
    "alt_dns": "DNS 智能生成",
    "search_engines": "搜索引擎调用",
    "dns_auxiliary": "DNS 补充发现",
    "asset_seed_probe": "资产种子探活",
    "cert_candidate_verify": "证书候选验证",
    "known_service_seed": "测绘端口探活",
    "asset_seed_prefill": "种子结果预入库",
    "port_scan": "端口扫描",
    "port_scan_top1000": "Top1000 端口扫描",
    "port_scan_full": "全端口扫描",
    "ssl_cert_top1000": "Top1000 证书获取",
    "ssl_cert_full": "全端口证书补充",
    "ssl_cert": "SSL 证书获取",
    "save_ip_info": "IP 信息保存",
    "find_site": "站点发现",
    "fetch_site": "站点详情采集",
    "site_capture": "站点截图",
    "site_spider": "站点爬虫",
    "runtime_artifact": "运行时资源归档",
    "web_info_hunter": "WIH 调用",
    "site_spider_domain_update": "爬虫域名回流",
    "wih_domain_update": "WIH 域名回流",
    "entry_feedback_spider": "入口反馈爬虫",
    "entry_feedback_runtime_artifact": "入口反馈运行时归档",
    "entry_feedback_wih": "入口反馈 WIH",
    "entry_feedback_domain_update": "入口反馈域名回流",
    "post_dns_feedback": "后置 DNS 智能反馈",
    "post_dns_feedback_domain_update": "后置 DNS 域名回流",
    "discovery_delta": "后置资产增量闭环",
    "discovery_delta_port_scan": "增量端口扫描",
    "discovery_delta_port_scan_top1000": "增量 Top1000 端口扫描",
    "discovery_delta_port_scan_full": "增量全端口扫描",
    "discovery_delta_ssl": "增量 SSL 证书获取",
    "discovery_delta_fetch_site": "增量站点详情采集",
    "discovery_delta_spider": "增量站点爬虫",
    "discovery_delta_runtime_artifact": "增量运行时归档",
    "discovery_delta_wih": "增量 WIH 调用",
    "discovery_delta_domain_update": "增量域名回流",
    "bface_discover": "B 面发现",
    "file_leak": "目录扫描",
    "nuclei_scan": "Nuclei 扫描",
    "wayback_backtrack": "Wayback 历史回溯",
    "bing_deep": "Bing 深度搜索",
    "js_deep": "JS 深度分析",
    "framework_probe": "框架驱动探测",
    "shadow_tag": "影子资产识别",
    "ai_judge": "AI 资产研判",
    "findvhost": "Host 碰撞",
    "npoc_service_detection": "服务协议识别",
    "poc_run": "PoC 扫描",
    "weak_brute": "弱口令爆破",
    "common_run": "统计同步",
}


TASK_STAGE_ORDER = [
    "domain_brute",
    "dns_query_plugin",
    "arl_search",
    "search_engines",
    "dns_auxiliary",
    "alt_dns",
    "cert_candidate_verify",
    "asset_seed_probe",
    "known_service_seed",
    "asset_seed_prefill",
    "port_scan",
    "port_scan_top1000",
    "ssl_cert_top1000",
    "port_scan_full",
    "ssl_cert_full",
    "ssl_cert",
    "save_ip_info",
    "find_site",
    "fetch_site",
    "site_capture",
    "site_spider",
    "runtime_artifact",
    "web_info_hunter",
    "site_spider_domain_update",
    "wih_domain_update",
    "entry_feedback_spider",
    "entry_feedback_runtime_artifact",
    "entry_feedback_wih",
    "entry_feedback_domain_update",
    "post_dns_feedback",
    "post_dns_feedback_domain_update",
    "discovery_delta",
    "discovery_delta_port_scan",
    "discovery_delta_port_scan_top1000",
    "discovery_delta_port_scan_full",
    "discovery_delta_ssl",
    "discovery_delta_fetch_site",
    "discovery_delta_spider",
    "discovery_delta_runtime_artifact",
    "discovery_delta_wih",
    "discovery_delta_domain_update",
    "bface_discover",
    "npoc_service_detection",
    "poc_run",
    "weak_brute",
    "file_leak",
    "nuclei_scan",
    "wayback_backtrack",
    "bing_deep",
    "js_deep",
    "framework_probe",
    "shadow_tag",
    "ai_judge",
    "findvhost",
    "common_run",
]


TASK_STAGE_ORDER_MAP = {stage: index for index, stage in enumerate(TASK_STAGE_ORDER)}


def stage_order(stage_name):
    return TASK_STAGE_ORDER_MAP.get(stage_name, len(TASK_STAGE_ORDER) + 1)


def split_stage_summary(summary):
    payload = dict(summary or {})
    status = payload.pop("_stage_status", "done")
    if status == "partial":
        completed = 0
        for key in (
                "completed_targets", "completed_batches", "completed_site_count",
                "output_count", "processed_site_count"):
            try:
                completed = max(completed, int(payload.get(key, 0) or 0))
            except (TypeError, ValueError):
                continue
        # A stage that produced usable output is complete from the workflow's
        # perspective; retain the reason as a warning so the UI does not make
        # the whole task look stuck or failed.
        if completed > 0:
            reason = str(
                payload.get("warning") or
                payload.get("partial_reason") or
                "stage completed with partial results"
            )
            payload["warning"] = reason
            payload["completion_state"] = "done_with_warnings"
            status = "done_with_warnings"
    return payload, status
