import time
import random
import copy
import re
import json
import hashlib
import ipaddress
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from collections import Counter
import dns.exception
import dns.resolver
from bson import ObjectId
from pymongo import UpdateOne
from app import utils
from app.config import Config
from app import services
from app import modules
from app.modules import ScanPortType, DomainDictType, CollectSource, TaskStatus
from app.services import fetchCert, run_risk_cruising, run_sniffer, BaseUpdateTask
from app.services.commonTask import CommonTask, WebSiteFetch
from app.helpers.domain import find_private_domain_by_task_id, find_public_ip_by_task_id, find_vhost_candidate_ip_by_task_id
from app.services.findVhost import find_vhost
from app.services.dns_query import run_query_plugin
from app.services.searchEngines import search_engines
from app.services import domain_site_update
from app.services.storage import (
    cert_matches_domain,
    extract_cert_domains,
    save_domain_documents,
    save_site_documents,
    save_url_page_map,
    upsert_with_sources,
)
from app.services.edgeAsset import (
    classify_edge_host,
    classify_edge_infrastructure,
    is_ztna_host,
)
from app.services.assetPolicy import has_strong_edge_marker
from app.utils.site_scope import (
    formal_domain_query,
    formal_pipeline_query,
    formal_site_query,
)
from app.services.taskStage import split_stage_summary
from app.services.resourceBudget import acquire as acquire_resource_budget
from app.helpers.task import is_nuclei_scan_enabled
from app.utils.host_collision import (
    HOST_COLLISION_ALLOWED_DNS_STATUSES,
    HOST_COLLISION_BLOCKED_CANDIDATE_REASONS,
    HOST_COLLISION_BLOCKED_REASON_FRAGMENTS,
    HOST_COLLISION_CANDIDATE_COLLECTIONS,
    HOST_COLLISION_POLICY_VERSION,
    HOST_COLLISION_WEAK_ENDPOINT_SOURCES,
)

logger = utils.get_logger()

POST_DNS_FEEDBACK_SOURCE = "post_dns_feedback"
DISCOVERY_DELTA_COLLECTION = "discovery_delta_state"
POST_DNS_FEEDBACK_SOURCE_SCORES = {
    "active_ssl_san": 100,
    "cert_query_verified": 95,
    CollectSource.SITESPIDER: 90,
    "wih": 85,
    "entry_feedback": 80,
}

'''
域名爆破
'''


class DomainBruteResult(list):
    def __init__(self, values=None, meta=None):
        super().__init__(values or [])
        self.meta = dict(meta or {})


class DomainBrute(object):
    def __init__(
            self, base_domain, word_file=Config.DOMAIN_DICT_2W,
            wildcard_domain_ip=None, task_id="", progress_callback=None):
        if wildcard_domain_ip is None:
            wildcard_domain_ip = []
        self.base_domain = base_domain
        self.base_domain_scope = "." + base_domain.strip(".")
        self._word_file = word_file
        self.dicts = utils.load_file(word_file)

        self.brute_out = []
        self.domain_info_list = []
        self.meta = {}
        self.wildcard_domain_ip = wildcard_domain_ip  # 保存获取的泛解析IP
        self.task_id = str(task_id or "")
        self.progress_callback = progress_callback

    def _brute_domain(self):
        if not Config.DOMAIN_BRUTE_PLUS:
            logger.warning("DOMAIN_BRUTE_PLUS=false ignored; legacy massdns brute is disabled")
        try:
            self.brute_out = services.domain_brute_plus(
                self.base_domain,
                self._word_file,
                meta=self.meta,
                task_id=self.task_id,
                progress_callback=self.progress_callback,
            )
            logger.info("domain_brute_plus success {}, result {}".format(
                self.base_domain, len(self.brute_out)))
            return
        except services.DomainBrutePlusError as e:
            self.meta.update({
                "resolver_status": "failed",
                "resolver_error": str(e),
            })
            logger.warning("domain_brute_plus failed on {}, skip massdns fallback: {}".format(
                self.base_domain, e))
        except Exception as e:
            self.meta.update({
                "resolver_status": "failed",
                "resolver_error": str(e),
            })
            logger.exception("domain_brute_plus unexpected error on {}, skip massdns fallback".format(
                self.base_domain))
        self.brute_out = []
        return

    def _build_domain_info(self):
        resolved = {}
        for item in self.brute_out:
            domain = str(item.get("domain") or "").strip(".").lower()
            if not domain or not utils.domain_parsed(domain) or utils.check_domain_black(domain):
                continue
            record = str(item.get("record") or "").strip().strip(".")
            if not record:
                continue
            current = resolved.setdefault(domain, {"ips": set(), "cnames": set()})
            if item.get("type") == "CNAME":
                if utils.domain_parsed(record) and not utils.check_domain_black(record):
                    current["cnames"].add(record.lower())
            elif utils.is_vaild_ip_target(record):
                current["ips"].add(record)

        cname_only = [
            domain for domain, values in resolved.items()
            if values["cnames"] and not values["ips"]
        ]
        if cname_only:
            fallback_map = services.resolver_domain(cname_only)
            for domain, ips in fallback_map.items():
                if domain in resolved:
                    resolved[domain]["ips"].update(ips or [])

        output = []
        for domain in sorted(resolved):
            values = resolved[domain]
            ips = sorted(values["ips"])
            if not ips:
                continue
            cnames = sorted(values["cnames"])
            output.append(modules.DomainInfo(**{
                "domain": domain,
                "type": "CNAME" if cnames else "A",
                "record": cnames or ips,
                "ips": ips,
            }))
        self.domain_info_list = output

    '''
    DomainInfo
    '''

    def run(self):
        start_time = time.time()
        logger.info("start brute {} with dict {}".format(self.base_domain, len(self.dicts)))
        self._brute_domain()
        elapse = time.time() - start_time
        logger.info("end brute {}, result {}, elapse {}".format(self.base_domain,
                                                                len(self.brute_out), elapse))

        self._build_domain_info()
        return DomainBruteResult(self.domain_info_list, meta=self.meta)


# 端口扫描
class ScanPortResult(list):
    def __init__(self, values=None, meta=None):
        super().__init__(values or [])
        self.meta = dict(meta or {})


class ScanPort(object):
    def __init__(self, domain_info_list, option):
        self.domain_info_list = domain_info_list
        self.ipv4_map = {}
        self.ip_cdn_map = {}
        self.have_cdn_ip_list = []
        self.skip_scan_cdn_ip = False

        if option is None:
            option = {
                "ports": ScanPortType.TEST,
                "service_detect": False,
                "os_detect": False,
                "port_parallelism": 32,
                "port_min_rate": 64,
                "custom_host_timeout": None,
                "exclude_ports": None
            }

        if 'skip_scan_cdn_ip' in option:
            self.skip_scan_cdn_ip = option["skip_scan_cdn_ip"]
            del option["skip_scan_cdn_ip"]

        self.batch_callback = option.pop("batch_callback", None)
        self.option = option

    def get_cdn_name(self, ip, domain_info):
        cdn_name = utils.get_cdn_name_by_ip(ip)
        if cdn_name:
            return cdn_name

        if domain_info.type != "CNAME":
            return ""

        if not domain_info.record_list:
            return ""

        for cname in domain_info.record_list:
            cdn_match = utils.get_cdn_match_by_cname_strict(cname)
            if cdn_match:
                return cdn_match.get("name", "")

            infrastructure = classify_edge_infrastructure(cname)
            if infrastructure:
                return infrastructure

        if len(domain_info.ip_list) >= 4:
            return "CDN"

        return ""

    def run(self):
        for info in self.domain_info_list:
            for ip in info.ip_list:
                old_domain = self.ipv4_map.get(ip, set())
                old_domain.add(info.domain)
                self.ipv4_map[ip] = old_domain

                if ip not in self.ip_cdn_map:
                    cdn_name = self.get_cdn_name(ip, info)
                    self.ip_cdn_map[ip] = cdn_name
                    if cdn_name:
                        self.have_cdn_ip_list.append(ip)

        all_ipv4_list = self.ipv4_map.keys()
        if self.skip_scan_cdn_ip:
            all_ipv4_list = list(set(all_ipv4_list) - set(self.have_cdn_ip_list))

        start_time = time.time()
        logger.info("start port_scan {}".format(len(all_ipv4_list)))
        ip_port_result = []
        scan_meta = {}
        if all_ipv4_list:
            option = copy.deepcopy(self.option)
            if self.batch_callback is not None:
                option["batch_callback"] = self._handle_batch_result
            ip_port_result = services.port_scan(all_ipv4_list, **option)
            scan_meta = dict(getattr(ip_port_result, "meta", {}) or {})
            elapse = time.time() - start_time
            logger.info("end port_scan result {}, elapse {}".format(len(ip_port_result), elapse))

        ip_info_obj = self.build_ip_info_objects(ip_port_result)

        if self.skip_scan_cdn_ip:
            fake_cdn_ip_info = self.build_fake_cdn_ip_info()
            ip_info_obj.extend(fake_cdn_ip_info)

        return ScanPortResult(ip_info_obj, meta=scan_meta)

    def _handle_batch_result(self, ip_port_result, batch_index, total_batches, profile):
        ip_info_obj = self.build_ip_info_objects(ip_port_result)
        if self.batch_callback is not None:
            self.batch_callback(ip_info_obj, batch_index, total_batches, profile)

    def _build_port_info_obj(self, port_info):
        if isinstance(port_info, modules.PortInfo):
            return port_info

        if hasattr(port_info, "dump_json"):
            port_info = port_info.dump_json(flag=False)

        if not isinstance(port_info, dict):
            logger.warning("skip invalid port_info type:{} value:{}".format(type(port_info), port_info))
            return None

        return modules.PortInfo(**port_info)

    def build_ip_info_objects(self, ip_port_result):
        ip_info_obj = []
        for result in ip_port_result:
            curr_ip = result["ip"]
            item = dict(result)
            item["domain"] = list(self.ipv4_map.get(curr_ip, []))
            item["cdn_name"] = self.ip_cdn_map.get(curr_ip, "")

            port_info_obj_list = []
            for port_info in item.get("port_info") or []:
                port_info_obj = self._build_port_info_obj(port_info)
                if port_info_obj:
                    port_info_obj_list.append(port_info_obj)

            item["port_info"] = port_info_obj_list
            ip_info_obj.append(modules.IPInfo(**item))

        return ip_info_obj

    def build_fake_cdn_ip_info(self):
        ret = []
        map_80_port = {
            "port_id": 80,
            "service_name": "http",
            "version": "",
            "protocol": "tcp",
            "product": ""
        }
        fake_80_port = modules.PortInfo(**map_80_port)

        map_443_port = {
            "port_id": 443,
            "service_name": "https",
            "version": "",
            "protocol": "tcp",
            "product": ""
        }
        fake_443_port = modules.PortInfo(**map_443_port)
        fake_port_info = [fake_80_port, fake_443_port]

        for ip in self.ip_cdn_map:
            cdn_name = self.ip_cdn_map[ip]
            if not cdn_name:
                continue

            item = {
                "ip": ip,
                "domain": list(self.ipv4_map[ip]),
                "port_info": copy.deepcopy(fake_port_info),
                "cdn_name": cdn_name,
                "os_info": {}

            }
            ret.append(modules.IPInfo(**item))

        return ret


'''
站点发现
'''


class FindSite(object):
    def __init__(self, ip_info_list, task_id=None, base_domain=""):
        self.ip_info_list = ip_info_list
        self.task_id = task_id
        self.base_domain = base_domain

    def _blocked_ip_reasons(self):
        reasons = {}
        ips = set()
        for info in self.ip_info_list:
            ip = str(getattr(info, "ip", "") or "").strip()
            if not ip:
                continue
            ips.add(ip)
            if getattr(info, "cdn_name", ""):
                reasons[ip] = "cdn"

        if not self.task_id or not ips:
            return reasons

        for item in utils.conn_db("ip").find(
            {"task_id": self.task_id, "ip": {"$in": sorted(ips)}},
            {"_id": 0, "ip": 1, "cdn_name": 1, "port_scan_overopen": 1},
        ):
            ip = item.get("ip")
            if item.get("cdn_name"):
                reasons[ip] = "cdn"

        current_dns_ips = set()
        for item in utils.conn_db("domain").find(
            formal_domain_query({
                "task_id": self.task_id,
                "ips": {"$in": sorted(ips)},
            }),
            {"_id": 0, "ips": 1},
        ):
            current_dns_ips.update(
                str(ip or "").strip() for ip in (item.get("ips") or []) if str(ip or "").strip())

        for item in utils.conn_db("asset_seed_candidate").find(
            {
                "task_id": self.task_id,
                "candidate_type": "cert_ip",
                "ip": {"$in": sorted(ips)},
            },
            {
                "_id": 0,
                "ip": 1,
                "status": 1,
                "pipeline_eligible": 1,
                "cert_verify_status": 1,
            },
        ):
            ip = str(item.get("ip") or "").strip()
            if ip and ip not in current_dns_ips:
                reasons[ip] = "cert_candidate_without_current_dns"

        edge_query = {
            "task_id": self.task_id,
            "ip": {"$in": sorted(ips)},
            "$or": [
                {"cdn": True}, {"cdn_name": {"$exists": True, "$nin": [None, ""]}},
                {"waf": True}, {"waf_name": {"$exists": True, "$nin": [None, ""]}},
                {"edge": True}, {"edge_name": {"$exists": True, "$nin": [None, ""]}},
                {"tag": "边缘入口"},
                {"webserver": {"$regex": r"volc[-_. ]?dcdn|bytecdn|\bstgw\b", "$options": "i"}},
            ],
        }
        for item in utils.conn_db("asset_seed_alive").find(
                formal_pipeline_query(edge_query),
                {"_id": 0, "ip": 1, "cdn": 1, "cdn_name": 1, "waf": 1,
                 "waf_name": 1, "waf_strength": 1, "edge": 1, "edge_name": 1,
                 "tag": 1, "webserver": 1, "cname": 1}):
            ip = item.get("ip")
            if ip and ip not in reasons and has_strong_edge_marker(item):
                reasons[ip] = "edge_probe"
        return reasons

    def _overopen_ips(self):
        if not self.task_id:
            return set()
        ips = [str(getattr(info, "ip", "") or "").strip() for info in self.ip_info_list]
        ips = sorted(set(ip for ip in ips if ip))
        if not ips:
            return set()
        return set(
            item.get("ip")
            for item in utils.conn_db("ip").find(
                {
                    "task_id": self.task_id,
                    "ip": {"$in": ips},
                    "port_scan_overopen": True,
                },
                {"_id": 0, "ip": 1},
            )
            if item.get("ip")
        )

    def _exact_port_map(self, ip, domains):
        if not self.task_id or not ip or not domains:
            return {}

        result = {}
        query = {
            "task_id": self.task_id,
            "ip": ip,
            "domain": {"$in": sorted(set(domains))},
        }
        fields = {
            "_id": 0,
            "domain": 1,
            "port": 1,
            "ports": 1,
            "candidate_type": 1,
            "pipeline_eligible": 1,
            "status": 1,
            "verified_ports": 1,
        }
        for item in utils.conn_db("asset_seed_candidate").find(query, fields):
            domain = item.get("domain")
            if not domain:
                continue
            if item.get("candidate_type") == "cert_ip":
                if item.get("pipeline_eligible") is not True or item.get("status") == "quarantined":
                    continue
                values = list(item.get("verified_ports") or [])
            else:
                values = list(item.get("ports") or [])
                if item.get("port") not in (None, ""):
                    values.append(item.get("port"))
            for value in values:
                try:
                    port = int(value)
                except (TypeError, ValueError):
                    continue
                if 0 < port <= 65535:
                    result.setdefault(domain, set()).add(port)
        return result

    @staticmethod
    def _fallback_ports():
        values = set()
        for value in str(getattr(Config, "FIND_SITE_FALLBACK_PORTS", "80,443")).split(","):
            try:
                port = int(value.strip())
            except (TypeError, ValueError):
                continue
            if 0 < port <= 65535:
                values.add(port)
        return values

    @staticmethod
    def _build_urls(host, port_info):
        port_id = int(port_info.port_id)
        service_name = str(getattr(port_info, "service_name", "") or "").lower()
        product = str(getattr(port_info, "product", "") or "").lower()
        text = "{} {}".format(service_name, product)

        https_ports = {443, 8443, 9443, 10443, 12443, 18443}
        http_ports = {80, 81, 88, 800, 8000, 8001, 8008, 8080, 8081, 8088, 8089, 8090, 9000}

        if port_id == 80:
            return ["http://{}".format(host)]
        if port_id == 443:
            return ["https://{}".format(host)]

        if "https" in text or "ssl" in text or "tls" in text or port_id in https_ports:
            return ["https://{}:{}".format(host, port_id), "http://{}:{}".format(host, port_id)]

        if "http" in text or "web" in text or port_id in http_ports:
            return ["http://{}:{}".format(host, port_id), "https://{}:{}".format(host, port_id)]

        return ["http://{}:{}".format(host, port_id), "https://{}:{}".format(host, port_id)]

    def _build(self):
        url_temp_list = []
        blocked_reasons = self._blocked_ip_reasons()
        overopen_ips = self._overopen_ips()
        skipped = Counter()
        for info in self.ip_info_list:
            blocked_reason = blocked_reasons.get(str(getattr(info, "ip", "") or "").strip(), "")
            if blocked_reason:
                skipped[blocked_reason] += 1
                continue

            domain_hosts = []
            for host in info.domain or []:
                host = str(host or "").strip()
                if not host:
                    continue
                parts = host.split(".")
                if len(parts) == 4 and all(x.isdigit() for x in parts):
                    continue
                domain_hosts.append(host)

            port_info_list = list(info.port_info_list or [])
            combination_count = len(domain_hosts) * len(port_info_list) * 2
            combination_limit = max(int(getattr(Config, "FIND_SITE_MAX_COMBINATIONS_PER_IP", 2000)), 1)
            restrict_domain_ports = info.ip in overopen_ips or combination_count > combination_limit
            exact_port_map = {}
            fallback_ports = set()
            if restrict_domain_ports:
                exact_port_map = self._exact_port_map(info.ip, domain_hosts)
                fallback_ports = self._fallback_ports()
                restrict_reason = "overopen" if info.ip in overopen_ips else "combination_limit"
                logger.warning(
                    "find_site restrict shared ip:{} reason:{} domains:{} ports:{} combinations:{} limit:{} task:{}".format(
                        info.ip, restrict_reason, len(domain_hosts), len(port_info_list), combination_count,
                        combination_limit, self.task_id,
                    )
                )

            for host in domain_hosts:
                selected = port_info_list
                if restrict_domain_ports:
                    allowed = set(exact_port_map.get(host, set())) | fallback_ports
                    selected = []
                    for item in port_info_list:
                        try:
                            port_id = int(item.port_id)
                        except (TypeError, ValueError):
                            continue
                        if port_id in allowed:
                            selected.append(item)
                for port_info in selected:
                    url_temp_list.extend(self._build_urls(host, port_info))

            if Config.FIND_SITE_PROBE_IP_HOSTS and info.ip:
                for port_info in port_info_list:
                    url_temp_list.extend(self._build_urls(info.ip, port_info))

        if skipped:
            logger.info("find_site skipped blocked ips:{} reasons:{} task:{}".format(
                sum(skipped.values()), dict(skipped), self.task_id))
        return url_temp_list

    def run(self):
        url_temp_list = set(self._build())
        start_time = time.time()
        alive_urls = services.httpx_probe_urls(
            list(url_temp_list), task_id=self.task_id,
            base_domain=self.base_domain, source="find_site")

        # 去除https和http相同的
        alive_site = []
        for x in alive_urls:
            if x.startswith("https://"):
                alive_site.append(x)

            elif x.startswith("http://"):
                x_temp = "https://" + x[7:]
                if x_temp not in alive_urls:
                    alive_site.append(x)

        elapse = time.time() - start_time
        logger.info("end httpx_probe_urls result {}, elapse {}".format(len(alive_site), elapse))

        return alive_site


'''
域名智能组合
'''


class AltDNS(object):
    def __init__(self, domain_info_list, base_domain, wildcard_domain_ip=None):
        self.domain_info_list = domain_info_list
        self.base_domain = base_domain
        self.domains = []
        self.subdomains = []
        inner_dicts = "test adm admin api app beta demo dev front int internal intra ops pre pro prod qa sit staff stage test uat"
        self.dicts = inner_dicts.split()
        self.wildcard_domain_ip = wildcard_domain_ip

    def _fetch_domains(self):
        base_len = len(self.base_domain)
        for item in self.domain_info_list:
            if not item.domain.endswith("." + self.base_domain):
                continue

            if utils.check_domain_black("a." + item.domain):
                continue

            self.domains.append(item.domain)
            subdomain = item.domain[:- (base_len + 1)]
            if "." in subdomain:
                self.subdomains.append(subdomain.split(".")[-1])

        random.shuffle(self.subdomains)

        most_cnt = 50
        if len(self.domains) < 1000:
            most_cnt = 30
            self.dicts.extend(self._load_dict())

        sub_dicts = list(dict(Counter(self.subdomains).most_common(most_cnt)).keys())
        self.dicts.extend(sub_dicts)

        self.dicts = list(set(self.dicts))

    def _load_dict(self):
        """加载内部字典"""
        d = set()
        for x in utils.load_file(Config.altdns_dict_path):
            x = x.strip()
            if x:
                d.add(x)

        return list(d)

    def run(self):
        t1 = time.time()
        self._fetch_domains()

        logger.info("start {} AltDNS {}  dict {}".format(self.base_domain,
                                                         len(self.domains), len(self.dicts)))

        out = services.alt_dns(self.domains, self.base_domain,
                               self.dicts, wildcard_domain_ip=self.wildcard_domain_ip)

        elapse = time.time() - t1
        logger.info("end AltDNS result {}, elapse {}".format(len(out), elapse))

        return out


def domain_brute(
        base_domain, word_file=Config.DOMAIN_DICT_2W, wildcard_domain_ip=None,
        task_id="", progress_callback=None):
    if wildcard_domain_ip is None:
        wildcard_domain_ip = []

    b = DomainBrute(
        base_domain,
        word_file,
        wildcard_domain_ip,
        task_id=task_id,
        progress_callback=progress_callback,
    )
    return b.run()


def scan_port(domain_info_list, option=None):
    s = ScanPort(domain_info_list, option)
    return s.run()


def find_site(ip_info_list, task_id=None, base_domain=""):
    f = FindSite(ip_info_list, task_id=task_id, base_domain=base_domain)
    return f.run()


def probe_domain_sites(
    domain_info_list,
    task_id=None,
    base_domain="",
    source="domain_probe",
    ports=None,
):
    targets = []
    for item in domain_info_list:
        domain = getattr(item, "domain", item)
        domain = str(domain or "").strip()
        if not domain:
            continue

        if domain.startswith("http://") or domain.startswith("https://"):
            targets.append(domain)
        elif ports:
            targets.append(domain)
        else:
            targets.append("https://{}".format(domain))
            targets.append("http://{}".format(domain))

    alive_urls = services.httpx_probe_urls(
        list(set(targets)), task_id=task_id,
        base_domain=base_domain, source=source, ports=ports)

    alive_sites = []
    alive_set = set(alive_urls)
    for url in alive_urls:
        if url.startswith("https://"):
            alive_sites.append(url)
        elif url.startswith("http://"):
            https_url = "https://" + url[7:]
            if https_url not in alive_set:
                alive_sites.append(url)

    return list(set(alive_sites))


def alt_dns(domain_info_list, base_domain, wildcard_domain_ip=None):
    a = AltDNS(domain_info_list, base_domain, wildcard_domain_ip=wildcard_domain_ip)
    return a.run()


def ssl_cert(ip_info_list, base_domain):
    try:
        f = fetchCert.SSLCert(ip_info_list, base_domain)
        return f.run()
    except Exception as e:
        logger.exception(e)

    return {}


'''
domain_brute
domain_brute_type  test big bigbig
port_scan_type
port_scan
service_detection
service_brute
os_detection
link_fetch
site_identify
site_capture
file_leak
alt_dns
ssl_cert
skip_scan_cdn_ip
dns_query_plugin
'''

SHARED_RECORD_MARK_COUNT = 35


class DomainTask(CommonTask):
    def __init__(self, base_domain=None, task_id=None, options=None):
        super().__init__(task_id=task_id)

        self.base_domain = base_domain
        self.task_id = task_id
        self.options = options

        self.domain_info_list = []  # 在 start_site_fetch 运行后会清空，用来释放内存
        self.ip_info_list = []
        self.ip_set = set()
        self.site_list = []
        self.record_map = {}
        self.ipv4_map = {}
        self.cert_map = {}
        self.service_info_list = []
        # 用来区分是正常任务还是监控任务
        self.task_tag = "task"

        # 用来存放泛解析域名映射的IP
        self._not_found_domain_ips = None
        self._wildcard_probe_samples = []
        self.wildcard_candidate_domains = set()
        self.wildcard_quarantined_count = 0
        self._parent_wildcard_records = {}
        self._parent_wildcard_samples = {}
        self.parent_wildcard_probe_count = 0
        self.parent_wildcard_detected_parents = set()
        self.parent_wildcard_quarantined_count = 0
        self.shared_record_domains = set()
        self._domain_dict_size = None
        self._domain_word_file = None

        self.npoc_service_target_set = set()

        self.web_site_fetch = None

        self.wih_domain_set = set()  # 通过调用 WebInfoHunter 获取的域名集合

        scan_port_map = {
            "test": ScanPortType.TEST,
            "top100": ScanPortType.TOP100,
            "top1000": ScanPortType.TOP1000,
            "all": ScanPortType.ALL,
            "custom": self.options.get("port_custom", "80,443")
        }
        option_scan_port_type = self.options.get("port_scan_type", "test")
        scan_port_option = {
            "ports": scan_port_map.get(option_scan_port_type, ScanPortType.TEST),
            "service_detect": bool(self.options.get("service_detection", False)) and Config.ENABLE_NMAP_SERVICE_DETECTION,
            "os_detect": bool(self.options.get("os_detection", False)) and Config.ENABLE_NMAP_OS_DETECTION,
            "skip_scan_cdn_ip": self.options.get("skip_scan_cdn_ip", False),  # 跳过扫描CDN IP
            "port_parallelism": self.options.get("port_parallelism", 32),  # 探测报文并行度
            "port_min_rate": self.options.get("port_min_rate", 64),  # 最少发包速率
            "custom_host_timeout": None,  # 主机超时时间(s)
            "exclude_ports": self.options.get("exclude_ports", None),  # 排除的端口
            "task_id": self.task_id,
            "skip_host_discovery": bool(Config.ASSET_SEED_PROBE),
        }

        # 只有当设置为自定义时才会去设置超时时间
        if self.options.get("host_timeout_type") == "custom":
            scan_port_option["custom_host_timeout"] = self.options.get("host_timeout", 60 * 15)

        if Config.ASSET_SEED_PROBE and Config.ASSET_SEED_FORCE_FULL_PORT and self.options.get("port_scan"):
            logger.warning("ASSET_SEED_FORCE_FULL_PORT ignored; use task port_scan_type:{} as requested".format(
                option_scan_port_type))

        self.scan_port_option = scan_port_option

        self.base_update_task = BaseUpdateTask(self.task_id)
        self.asset_seed_alive_sites = []
        self.asset_seed_alive_ips = []
        self.edge_asset_ips = set()
        self._last_task_stat_refresh = 0.0
        self._incremental_enriched_site_keys = None
        self.pending_incremental_sites = {}
        self._incremental_enrich_lock = threading.Lock()
        self._incremental_enrich_executor = None
        self._incremental_enrich_futures = []
        self.incremental_site_probe_failed = False
        self.post_seed_domains = set()
        self.mutation_seed_domains = set()
        self.delegated_subdomains = set()
        self.verified_cert_ip_domains = {}
        self.quarantined_candidate_ips = set()
        self.preprobe_domain_state = {}

    @staticmethod
    def _list_value(value):
        if value in (None, ""):
            return []
        if isinstance(value, (list, tuple, set)):
            return list(value)
        return [value]

    def hydrate_from_storage(self):
        self.domain_info_list = []
        self.ip_info_list = []
        self.ip_set = set()
        self.ipv4_map = {}
        self.record_map = {}
        self._wildcard_probe_samples = []
        self.wildcard_candidate_domains = set()
        self.wildcard_quarantined_count = 0
        self._parent_wildcard_records = {}
        self._parent_wildcard_samples = {}
        self.parent_wildcard_probe_count = 0
        self.parent_wildcard_detected_parents = set()
        self.parent_wildcard_quarantined_count = 0
        self.shared_record_domains = set()
        self.site_list = []
        self.asset_seed_alive_sites = []
        self.asset_seed_alive_ips = []
        self.edge_asset_ips = set()
        self.post_seed_domains = set()
        self.delegated_subdomains = set()
        self.verified_cert_ip_domains = {}
        self.quarantined_candidate_ips = set()
        self.preprobe_domain_state = {}

        domain_seen = set()
        for item in utils.conn_db("domain").find(
                formal_domain_query({"task_id": self.task_id}),
                {"_id": 0, "domain": 1, "record": 1, "type": 1, "ips": 1,
                 "source": 1, "sources": 1, "edge_preclassified": 1,
                 "edge_kind": 1, "edge_provider": 1,
                 "edge_pipeline_eligible": 1,
                 "asset_seed_probe_eligible": 1,
                 "asset_seed_probe_skip_reason": 1}):
            domain = str(item.get("domain") or "").strip(".").lower()
            if not domain or domain in domain_seen:
                continue
            domain_seen.add(domain)
            if item.get("edge_preclassified"):
                self.preprobe_domain_state[domain] = {
                    "edge_kind": item.get("edge_kind", ""),
                    "edge_provider": item.get("edge_provider", ""),
                    "edge_pipeline_eligible": item.get(
                        "edge_pipeline_eligible", True),
                    "asset_seed_probe_eligible": item.get(
                        "asset_seed_probe_eligible", True),
                    "asset_seed_probe_skip_reason": item.get(
                        "asset_seed_probe_skip_reason", ""),
                }
            records = self._list_value(item.get("record"))
            ips = self._list_value(item.get("ips"))
            self.domain_info_list.append(modules.DomainInfo(**{
                "domain": domain,
                "record": records,
                "type": item.get("type") or ("A" if ips else "CNAME"),
                "ips": ips,
            }))
            if records:
                self.record_map[records[0]] = self.record_map.get(records[0], 0) + 1
            sources = set(self._list_value(item.get("sources")))
            if item.get("source"):
                sources.add(item.get("source"))
            if "active_ssl_san" in sources:
                self.post_seed_domains.add(domain)

        self.gen_ipv4_map()
        self.quarantined_candidate_ips = self._load_quarantined_candidate_ips()

        for item in utils.conn_db("asset_seed_candidate").find(
            {
                "task_id": self.task_id,
                "candidate_type": "cert_ip",
                "cert_verified": True,
            },
            {
                "_id": 0,
                "ip": 1,
                "domain": 1,
                "candidate_type": 1,
                "cert_verified": 1,
                "cert_verify_status": 1,
                "pipeline_eligible": 1,
                "status": 1,
                "verified_domains": 1,
                "verified_ports": 1,
            },
        ):
            if not self._candidate_is_pipeline_eligible(item):
                continue
            ip = str(item.get("ip") or "").strip()
            domains = {
                str(value or "").strip(".").lower()
                for value in (item.get("verified_domains") or [])
                if str(value or "").strip()
            }
            if ip and domains:
                self.verified_cert_ip_domains.setdefault(ip, set()).update(domains)

        for item in utils.conn_db("ip").find(
                {"task_id": self.task_id},
                {"_id": 0, "ip": 1, "domain": 1, "port_info": 1,
                 "os_info": 1, "cdn_name": 1}):
            ip = str(item.get("ip") or "").strip()
            if not ip:
                continue
            if ip in self.quarantined_candidate_ips:
                logger.info("hydrate skip quarantined cert candidate ip:{} task:{}".format(
                    ip, self.task_id))
                continue
            stored_domains = {
                str(value or "").strip(".").lower()
                for value in self._list_value(item.get("domain"))
                if str(value or "").strip()
            }
            if (
                stored_domains and
                not (stored_domains & domain_seen) and
                ip not in self.verified_cert_ip_domains
            ):
                logger.info(
                    "hydrate skip ip without formal domain relation ip:{} task:{}".format(
                        ip, self.task_id))
                continue
            port_info_list = []
            for port_info in item.get("port_info") or []:
                if not isinstance(port_info, dict):
                    continue
                try:
                    port_info_list.append(modules.PortInfo(**port_info))
                except (TypeError, ValueError):
                    logger.warning("skip invalid stored port_info task:{} ip:{} value:{}".format(
                        self.task_id, ip, port_info))
            self.ip_info_list.append(modules.IPInfo(**{
                "ip": ip,
                "domain": sorted(stored_domains),
                "port_info": port_info_list,
                "os_info": item.get("os_info") or {},
                "cdn_name": item.get("cdn_name") or "",
            }))

        alive_sites = set()
        alive_ips = set()
        for item in utils.conn_db("asset_seed_alive").find(
                formal_pipeline_query({"task_id": self.task_id}),
                {"_id": 0, "url": 1, "ip": 1, "cdn": 1, "cdn_name": 1,
                 "waf": 1, "waf_name": 1, "waf_strength": 1, "edge": 1,
                 "edge_name": 1, "tag": 1, "webserver": 1, "cname": 1}):
            url = str(item.get("url") or "").strip()
            if url:
                alive_sites.add(url)
            if has_strong_edge_marker(item):
                continue
            ip = str(item.get("ip") or "").strip()
            if ip:
                alive_ips.add(ip)
        self.asset_seed_alive_sites = sorted(alive_sites)
        self.asset_seed_alive_ips = sorted(alive_ips)

        self.site_list = sorted({
            str(item.get("site") or "").strip()
            for item in utils.conn_db("site").find(
                formal_site_query({"task_id": self.task_id}),
                {"_id": 0, "site": 1})
            if str(item.get("site") or "").strip()
        })
        logger.info(
            "hydrate task:{} domains:{} ips:{} sites:{} alive_ips:{}".format(
                self.task_id, len(self.domain_info_list), len(self.ip_info_list),
                len(self.site_list), len(self.asset_seed_alive_ips)))
        return {
            "domain_count": len(self.domain_info_list),
            "ip_count": len(self.ip_info_list),
            "site_count": len(self.site_list),
            "alive_ip_count": len(self.asset_seed_alive_ips),
        }

    def refresh_task_statistic(self, force=False):
        now = time.time()
        interval = max(float(getattr(Config, "TASK_STAT_REFRESH_INTERVAL", 5) or 5), 0.0)
        if not force and interval and now - self._last_task_stat_refresh < interval:
            return False
        self.insert_task_stat()
        self._last_task_stat_refresh = now
        return True

    @property
    def domain_word_file(self) -> str:
        if self._domain_word_file is None:
            brute_dict_map = {
                "test": DomainDictType.TEST,
                "big": DomainDictType.BIG
            }
            domain_brute_type = self.options.get("domain_brute_type", "test")
            domain_word_file = brute_dict_map.get(domain_brute_type, DomainDictType.TEST)
            self._domain_word_file = domain_word_file

        return self._domain_word_file

    @property
    def domain_dict_size(self):
        if self._domain_dict_size is None:
            self._domain_dict_size = len(utils.load_file(self.domain_word_file))

        return self._domain_dict_size

    @property
    def not_found_domain_ips(self):
        # Multiple positive random labels are required before treating a DNS
        # signature as wildcard evidence. One flaky resolver answer must not
        # suppress real domains.
        if self._not_found_domain_ips is None:
            probe_count = max(int(getattr(
                Config, "DNS_WILDCARD_PROBE_COUNT", 3) or 3), 2)
            samples = []
            for _ in range(probe_count):
                fake_domain = "at" + utils.random_choices(10) + "." + self.base_domain
                records = set(utils.get_ip(fake_domain, log_flag=False) or [])
                records.update(utils.get_cname(fake_domain, log_flag=False) or [])
                if records:
                    samples.append({
                        "domain": fake_domain,
                        "records": sorted(records),
                    })

            wildcard_records = set()
            if len(samples) >= 2:
                record_counts = Counter(
                    record
                    for sample in samples
                    for record in sample["records"]
                )
                wildcard_records = {
                    record for record, count in record_counts.items()
                    if count >= 2
                }
                # Round-robin wildcard pools may return a different address
                # for every query. Multiple positive random labels still prove
                # wildcard behavior, so retain the whole observed pool.
                if not wildcard_records:
                    wildcard_records = set(record_counts)

            self._wildcard_probe_samples = samples
            self._not_found_domain_ips = sorted(wildcard_records)
            if self._not_found_domain_ips:
                logger.info(
                    "wildcard dns detected domain:{} probes:{} records:{}".format(
                        self.base_domain,
                        len(samples),
                        self._not_found_domain_ips,
                    ))

        return self._not_found_domain_ips

    def _ensure_parent_wildcard_state(self):
        if not hasattr(self, "_parent_wildcard_records"):
            self._parent_wildcard_records = {}
        if not hasattr(self, "_parent_wildcard_samples"):
            self._parent_wildcard_samples = {}
        if not hasattr(self, "parent_wildcard_probe_count"):
            self.parent_wildcard_probe_count = 0
        if not hasattr(self, "parent_wildcard_detected_parents"):
            self.parent_wildcard_detected_parents = set()
        if not hasattr(self, "parent_wildcard_quarantined_count"):
            self.parent_wildcard_quarantined_count = 0

    @staticmethod
    def _normalize_dns_record(value):
        return str(value or "").strip().lower().strip(".")

    @classmethod
    def _dns_signature(cls, records):
        return {
            cls._normalize_dns_record(value)
            for value in (records or [])
            if cls._normalize_dns_record(value)
        }

    @classmethod
    def _wildcard_sample_signatures(cls, samples):
        signatures = set()
        for sample in samples or []:
            signature = tuple(sorted(cls._dns_signature(
                (sample or {}).get("records") or [])))
            if signature:
                signatures.add(signature)
        return signatures

    @classmethod
    def _wildcard_pool_is_rotating(cls, samples):
        """Return true when positive random labels resolve to different pools."""
        positive_samples = [
            sample for sample in (samples or [])
            if cls._dns_signature((sample or {}).get("records") or [])
        ]
        return (
            len(positive_samples) >= 2 and
            len(cls._wildcard_sample_signatures(positive_samples)) >= 2
        )

    def _direct_parent_domain(self, domain):
        domain = self._normalize_dns_record(domain)
        base_domain = self._normalize_dns_record(self.base_domain)
        if not domain or domain == base_domain:
            return ""
        if not domain.endswith("." + base_domain):
            return ""
        parent = domain.split(".", 1)[1]
        if parent == base_domain or parent.endswith("." + base_domain):
            return parent
        return ""

    def _probe_parent_wildcard(self, parent):
        self._ensure_parent_wildcard_state()
        parent = self._normalize_dns_record(parent)
        if not parent:
            return set()
        if parent in self._parent_wildcard_records:
            return set(self._parent_wildcard_records[parent])

        probe_count = max(int(getattr(
            Config, "DNS_WILDCARD_PROBE_COUNT", 3) or 3), 2)
        samples = []
        for _ in range(probe_count):
            fake_domain = "at" + utils.random_choices(10) + "." + parent
            records = set(utils.get_ip(fake_domain, log_flag=False) or [])
            records.update(utils.get_cname(fake_domain, log_flag=False) or [])
            signature = self._dns_signature(records)
            if signature:
                samples.append({
                    "domain": fake_domain,
                    "records": sorted(signature),
                })

        wildcard_records = set()
        if len(samples) >= 2:
            record_counts = Counter(
                record
                for sample in samples
                for record in sample["records"]
            )
            wildcard_records = {
                record for record, count in record_counts.items()
                if count >= 2
            }
            if not wildcard_records:
                wildcard_records = set(record_counts)

        self.parent_wildcard_probe_count += probe_count
        self._parent_wildcard_samples[parent] = samples
        self._parent_wildcard_records[parent] = sorted(wildcard_records)
        if wildcard_records:
            self.parent_wildcard_detected_parents.add(parent)
            logger.info(
                "parent wildcard dns detected parent:{} probes:{} records:{}".format(
                    parent, len(samples), sorted(wildcard_records)))
        return wildcard_records

    def _generated_wildcard_details(
        self, domain, candidate_records, check_parent=True
    ):
        candidate_signature = self._dns_signature(candidate_records)
        if not candidate_signature:
            return None

        root_records = self._dns_signature(self.not_found_domain_ips)
        root_match = candidate_signature & root_records
        if root_match:
            return {
                "reason": "wildcard_dns",
                "parent": self._normalize_dns_record(self.base_domain),
                "wildcard_records": sorted(root_records),
                "candidate_records": sorted(candidate_signature),
                "matched_records": sorted(root_match),
                "match_strategy": "record_overlap",
            }

        root_samples = list(getattr(self, "_wildcard_probe_samples", []) or [])
        if root_records and self._wildcard_pool_is_rotating(root_samples):
            return {
                "reason": "wildcard_dns_rotating_pool",
                "parent": self._normalize_dns_record(self.base_domain),
                "wildcard_records": sorted(root_records),
                "candidate_records": sorted(candidate_signature),
                "matched_records": [],
                "match_strategy": "rotating_random_labels",
                "wildcard_sample_signature_count": len(
                    self._wildcard_sample_signatures(root_samples)),
            }

        if not check_parent:
            return None

        parent = self._direct_parent_domain(domain)
        base_domain = self._normalize_dns_record(self.base_domain)
        if not parent or parent == base_domain:
            return None
        parent_records = self._probe_parent_wildcard(parent)
        parent_match = candidate_signature & parent_records
        parent_samples = list(
            getattr(self, "_parent_wildcard_samples", {}).get(parent) or [])
        rotating_pool = self._wildcard_pool_is_rotating(parent_samples)
        if not parent_match and not rotating_pool:
            return None
        return {
            "reason": (
                "parent_wildcard_dns"
                if parent_match else "parent_wildcard_rotating_pool"
            ),
            "parent": parent,
            "wildcard_records": sorted(parent_records),
            "candidate_records": sorted(candidate_signature),
            "matched_records": sorted(parent_match),
            "match_strategy": (
                "record_overlap" if parent_match else "rotating_random_labels"
            ),
            "wildcard_sample_signature_count": len(
                self._wildcard_sample_signatures(parent_samples)),
        }

    def _wildcard_metric_snapshot(self):
        self._ensure_parent_wildcard_state()
        return {
            "probe_count": self.parent_wildcard_probe_count,
            "quarantined_count": self.parent_wildcard_quarantined_count,
            "detected_parents": set(self.parent_wildcard_detected_parents),
        }

    def _wildcard_metric_delta(self, before):
        before = before or {}
        detected_before = set(before.get("detected_parents") or [])
        detected_now = set(getattr(
            self, "parent_wildcard_detected_parents", set()) or set())
        new_parents = sorted(detected_now - detected_before)
        return {
            "parent_wildcard_probe_count": max(
                self.parent_wildcard_probe_count -
                int(before.get("probe_count", 0) or 0), 0),
            "parent_wildcard_detected_count": len(new_parents),
            "parent_wildcard_detected_parents": new_parents,
            "parent_wildcard_quarantined_count": max(
                self.parent_wildcard_quarantined_count -
                int(before.get("quarantined_count", 0) or 0), 0),
        }

    def save_domain_info_list(self, domain_info_list, source=CollectSource.DOMAIN_BRUTE):
        save_domain_documents(self.task_id, domain_info_list, source)
        domains = {
            str(getattr(info, "domain", "") or "").strip().lower().strip(".")
            for info in domain_info_list or []
        }
        wildcard_domains = sorted(
            domains & getattr(self, "wildcard_candidate_domains", set()))
        if wildcard_domains:
            utils.conn_db("domain").update_many(
                {"task_id": self.task_id, "domain": {"$in": wildcard_domains}},
                {"$set": {
                    "wildcard_suspect": True,
                    "wildcard_action": "preserved",
                }},
            )
        shared_domains = sorted(
            domains & getattr(self, "shared_record_domains", set()))
        if shared_domains:
            utils.conn_db("domain").update_many(
                {"task_id": self.task_id, "domain": {"$in": shared_domains}},
                {"$set": {
                    "shared_record": True,
                    "shared_record_action": "preserved",
                }},
            )

    def save_vhost_ip_candidates(self, results):
        bulk_cnt = 0
        seed_cnt = 0
        black_domain_skip_cnt = 0
        for result in results:
            domain = str(result.get("domain") or "").strip(".").lower()
            if domain and utils.check_domain_black(domain):
                black_domain_skip_cnt += 1
                continue
            intels = list(result.get("intels") or [])
            if result.get("intel"):
                intels.append(result.get("intel"))
            if not intels:
                continue
            seen_intel = set()
            for intel in intels:
                if not isinstance(intel, dict):
                    continue
                ip = str(intel.get("ip") or "").strip()
                if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                    continue
                if not utils.not_in_black_ips(ip) or utils.get_ip_type(ip) != "PUBLIC":
                    continue
                source = str(intel.get("source") or result.get("source") or "").strip()
                port = intel.get("port")
                try:
                    port = int(port) if port not in (None, "") else None
                except (TypeError, ValueError):
                    port = None
                marker = (ip, port, source)
                if marker in seen_intel:
                    continue
                seen_intel.add(marker)
                web_title = str(intel.get("web_title") or intel.get("title") or "")
                query_type = str(intel.get("query_type") or "domain").strip().lower()
                result_candidate_type = str(result.get("candidate_type") or "").strip()
                if result_candidate_type == "cert_ip" or query_type == "cert":
                    candidate_type = "cert_ip"
                elif result_candidate_type == "mapping_ip":
                    candidate_type = "mapping_ip"
                else:
                    candidate_type = "mapping"
                source_family = str(intel.get("source_family") or "").strip()
                evidence = {
                    "source": source,
                    "source_family": source_family,
                    "query_type": query_type,
                    "domain": domain,
                    "ip": ip,
                    "port": port,
                    "protocol": str(intel.get("protocol") or ""),
                    "url": str(intel.get("url") or ""),
                    "web_title": web_title,
                    "status_code": intel.get("status_code"),
                    "updated_at": str(intel.get("updated_at") or ""),
                }
                add_to_set = {"evidence": evidence}
                if source:
                    add_to_set["sources"] = source
                if domain:
                    add_to_set["domains"] = domain
                if port is not None:
                    add_to_set["ports"] = port
                if web_title:
                    add_to_set["web_titles"] = web_title
                common_set = {
                    "task_id": self.task_id,
                    "target": self.base_domain,
                    "domain": domain,
                    "ip": ip,
                    "ip_type": "PUBLIC",
                    "last_seen_at": utils.curr_date(),
                }
                if source:
                    common_set["last_source"] = source
                if source_family:
                    common_set["last_source_family"] = source_family
                set_on_insert = {
                    "status": "pending",
                    "save_date": utils.curr_date(),
                }
                if candidate_type == "cert_ip":
                    # Certificate evidence is stronger than an ordinary
                    # historical mapping and must not be downgraded later.
                    common_set["candidate_type"] = "cert_ip"
                else:
                    set_on_insert["candidate_type"] = candidate_type
                if port is not None:
                    common_set["port"] = port
                if web_title:
                    common_set["web_title"] = web_title
                common_update = {
                    "$set": common_set,
                    "$setOnInsert": set_on_insert,
                    "$addToSet": add_to_set,
                }
                if source:
                    common_update["$setOnInsert"]["source"] = source

                if domain:
                    query = {"task_id": self.task_id, "domain": domain, "ip": ip}
                    utils.conn_db('vhost_ip_candidate').update_one(
                        query, common_update, upsert=True)
                    bulk_cnt += 1

                seed_query = {"task_id": self.task_id, "ip": ip, "domain": domain}
                utils.conn_db('asset_seed_candidate').update_one(
                    seed_query, common_update, upsert=True)
                seed_cnt += 1

        if bulk_cnt:
            logger.info("save vhost ip candidates {}, task:{}".format(bulk_cnt, self.task_id))
        if seed_cnt:
            logger.info("save asset seed candidates {}, task:{}".format(seed_cnt, self.task_id))
        if black_domain_skip_cnt:
            logger.info("skip black domain candidates {}, task:{}".format(
                black_domain_skip_cnt, self.task_id))

    def domain_brute(self):
        # 调用工具去进行域名爆破，如果存在泛解析，会把包含泛解析的IP的域名给删除
        domain_info_list = domain_brute(
            self.base_domain,
            word_file=self.domain_word_file,
            wildcard_domain_ip=self.not_found_domain_ips,
            task_id=self.task_id,
            progress_callback=lambda summary: self.base_update_task.update_stage_progress(
                "domain_brute", summary),
        )
        brute_meta = dict(getattr(domain_info_list, "meta", {}) or {})

        domain_info_list = self.clear_domain_info_by_record(domain_info_list)
        if self.task_tag == "task":
            self.save_domain_info_list(domain_info_list, source=CollectSource.DOMAIN_BRUTE)
            try:
                priority_words = {
                    str(value or "").strip().lower()
                    for value in utils.load_file(getattr(
                        Config, "DOMAIN_DICT_PRIORITY", ""))
                    if str(value or "").strip()
                }
            except Exception as e:
                logger.warning("load domain priority dictionary failed: {}".format(e))
                priority_words = set()
            family_counts = Counter()
            operations = []
            for info in domain_info_list:
                domain = str(info.domain or "").strip().lower().strip(".")
                prefix = ""
                if domain.endswith("." + self.base_domain):
                    prefix = domain[:-(len(self.base_domain) + 1)]
                family = (
                    "priority" if prefix and "." not in prefix
                    and prefix in priority_words else "base")
                if domain == self.base_domain:
                    family = "root"
                family_counts[family] += 1
                operations.append(UpdateOne(
                    {"task_id": self.task_id, "domain": domain},
                    {
                        "$set": {
                            "dns_candidate_family": family,
                            "dns_dictionary_version": brute_meta.get(
                                "dictionary_version", ""),
                        },
                        "$addToSet": {
                            "dns_candidate_families": family,
                        },
                    },
                ))
            if operations:
                utils.conn_db("domain").bulk_write(operations, ordered=False)
            brute_meta["dictionary_net_new_counts"] = dict(family_counts)
        self.domain_info_list.extend(domain_info_list)
        summary = brute_meta
        summary.update({
            "output_count": len(domain_info_list),
            "wildcard_quarantined_count": self.wildcard_quarantined_count,
            "filtered_count": max(
                int(brute_meta.get("resolved_candidate_count", 0) or 0) -
                len(domain_info_list),
                0,
            ),
            "net_new_output_count": len(domain_info_list),
        })
        if brute_meta.get("resolver_status") == "failed":
            summary.update({
                "partial_reason": "domain_brute_resolver_failed",
                "_stage_status": "partial",
            })
        return summary

    def _quarantine_wildcard_domain(
        self,
        info,
        source="wildcard_dns",
        wildcard_details=None,
    ):
        domain = str(getattr(info, "domain", "") or "").strip().lower().strip(".")
        if not domain:
            return False
        if domain == str(getattr(self, "base_domain", "") or "").strip().lower().strip("."):
            return False
        self.wildcard_candidate_domains.add(domain)

        task_id = str(getattr(self, "task_id", "") or "")
        if not task_id:
            return True

        existing = utils.conn_db("domain").find_one(
            {"task_id": task_id, "domain": domain},
            {"_id": 0, "source": 1, "sources": 1},
        ) or {}
        strong_sources = {"active_ssl_san", "cert_query_verified", "task_target"}
        observed_sources = set(self._list_value(existing.get("sources")))
        if existing.get("source"):
            observed_sources.add(existing.get("source"))
        if observed_sources & strong_sources:
            self.wildcard_candidate_domains.discard(domain)
            return False

        ips = sorted({
            str(value or "").strip()
            for value in (getattr(info, "ip_list", None) or [])
            if str(value or "").strip()
        }) or [""]
        candidate_records = sorted({
            str(value or "").strip().strip(".")
            for value in (
                list(getattr(info, "record_list", None) or []) +
                list(getattr(info, "ip_list", None) or [])
            )
            if str(value or "").strip()
        })
        wildcard_details = dict(wildcard_details or {})
        wildcard_records = list(
            wildcard_details.get("wildcard_records") or candidate_records)
        quarantine_reason = str(
            wildcard_details.get("reason") or "wildcard_dns")
        wildcard_parent = str(
            wildcard_details.get("parent") or self.base_domain or "")
        matched_records = list(
            wildcard_details.get("matched_records") or [])
        match_strategy = str(
            wildcard_details.get("match_strategy") or "record_overlap")
        wildcard_sample_signature_count = int(
            wildcard_details.get("wildcard_sample_signature_count", 0) or 0)
        now = utils.curr_date()
        source_value = str(source or "wildcard_dns")
        for ip in ips:
            update = {
                "$set": {
                    "task_id": task_id,
                    "target": self.base_domain,
                    "domain": domain,
                    "ip": ip,
                    "candidate_type": "wildcard_dns",
                    "candidate_disposition": "host_only",
                    "status": "quarantined",
                    "pipeline_eligible": False,
                    "wildcard_suspect": True,
                    "wildcard_parent": wildcard_parent,
                    "wildcard_records": wildcard_records,
                    "candidate_dns_records": candidate_records,
                    "wildcard_matched_records": matched_records,
                    "wildcard_match_strategy": match_strategy,
                    "wildcard_sample_signature_count": (
                        wildcard_sample_signature_count),
                    "quarantine_reason": quarantine_reason,
                    "last_seen_at": now,
                },
                "$setOnInsert": {
                    "source": source_value,
                    "save_date": now,
                },
                "$addToSet": {
                    "sources": source_value,
                },
            }
            utils.conn_db("asset_seed_candidate").update_one(
                {"task_id": task_id, "ip": ip, "domain": domain},
                update,
                upsert=True,
            )
        utils.conn_db("domain").update_one(
            {"task_id": task_id, "domain": domain},
            {"$set": {
                "wildcard_suspect": True,
                "wildcard_action": "quarantined",
                "candidate_disposition": "wildcard_dns",
                "pipeline_eligible": False,
                "wildcard_parent": wildcard_parent,
                "wildcard_records": wildcard_records,
                "candidate_dns_records": candidate_records,
                "wildcard_matched_records": matched_records,
                "wildcard_match_strategy": match_strategy,
                "wildcard_sample_signature_count": (
                    wildcard_sample_signature_count),
                "quarantine_reason": quarantine_reason,
                "quarantined_at": now,
            }},
        )
        self.wildcard_quarantined_count += 1
        if quarantine_reason.startswith("parent_wildcard"):
            self._ensure_parent_wildcard_state()
            self.parent_wildcard_quarantined_count += 1
        return True

    def clear_domain_info_by_record(
        self,
        domain_info_list,
        source="wildcard_dns",
        check_parent_wildcard=False,
    ):
        """Drop malformed and wildcard DNS rows from the formal asset path."""
        new_list = []
        for info in domain_info_list:
            if not info.record_list or not info.ip_list:
                continue

            domain = str(getattr(info, "domain", "") or "").strip().lower().strip(".")
            candidate_records = self._dns_signature(
                list(info.record_list or []) + list(info.ip_list or []))
            root_records = self._dns_signature(self.not_found_domain_ips)
            matched_root = candidate_records & root_records
            wildcard_details = None
            if domain and matched_root:
                wildcard_details = {
                    "reason": "wildcard_dns",
                    "parent": self._normalize_dns_record(self.base_domain),
                    "wildcard_records": sorted(root_records),
                    "candidate_records": sorted(candidate_records),
                    "matched_records": sorted(matched_root),
                }
            elif domain:
                wildcard_details = self._generated_wildcard_details(
                    domain,
                    candidate_records,
                    check_parent=check_parent_wildcard,
                )
            if wildcard_details:
                if self._quarantine_wildcard_domain(
                    info, source=source, wildcard_details=wildcard_details
                ):
                    continue

            record = info.record_list[0]
            cnt = self.record_map.get(record, 0)
            cnt += 1
            self.record_map[record] = cnt
            if domain and cnt > SHARED_RECORD_MARK_COUNT:
                self.shared_record_domains.add(domain)

            new_list.append(info)

        return new_list

    def _filter_generated_cname_documents(
        self,
        documents,
        source="wildcard_dns",
    ):
        filtered = []
        for item in documents or []:
            domain = str(item.get("domain") or "").strip().lower().strip(".")
            records = self._list_value(item.get("record"))
            wildcard_details = self._generated_wildcard_details(domain, records)
            if wildcard_details:
                info = modules.DomainInfo(**{
                    "domain": domain,
                    "type": "CNAME",
                    "record": records,
                    "ips": [],
                })
                if self._quarantine_wildcard_domain(
                    info, source=source, wildcard_details=wildcard_details
                ):
                    continue
            filtered.append(item)
        return filtered

    def arl_search(self):
        arl_t1 = time.time()
        logger.info("start arl fetch {}".format(self.base_domain))
        arl_all_domains = utils.arl_domain(self.base_domain)
        domain_info_list = self.build_domain_info(arl_all_domains)
        resolved_domains = {
            str(info.domain or "").strip(".").lower()
            for info in domain_info_list
            if getattr(info, "domain", "")
        }
        candidate_domains = set()
        for item in arl_all_domains:
            domain = item.get("domain") if isinstance(item, dict) else item
            domain = str(domain or "").strip().strip("*.").lower()
            if (
                domain
                and (domain == self.base_domain or domain.endswith("." + self.base_domain))
                and utils.is_valid_domain(domain)
                and not utils.check_domain_black(domain)
            ):
                candidate_domains.add(domain)
        unresolved_domains = sorted(candidate_domains - resolved_domains)
        if self.task_tag == "task":
            domain_info_list = self.clear_domain_info_by_record(domain_info_list)
            self.save_domain_info_list(domain_info_list, source=CollectSource.ARL)
            if unresolved_domains:
                save_domain_documents(self.task_id, [
                    {
                        "domain": domain,
                        "type": "UNKNOWN",
                        "record": [],
                        "ips": [],
                        "resolve_status": "unresolved",
                    }
                    for domain in unresolved_domains
                ], CollectSource.ARL)

        self.domain_info_list.extend(domain_info_list)
        elapse = time.time() - arl_t1
        logger.info("end arl fetch {} resolved:{} unresolved:{} elapse {}".format(
            self.base_domain, len(domain_info_list), len(unresolved_domains), elapse))
        return {
            "output_count": len(candidate_domains),
            "resolved_count": len(domain_info_list),
            "unresolved_count": len(unresolved_domains),
        }

    def build_domain_info(self, domains):
        """
        构建domain_info_list 带去重功能
        """
        fake_list = []
        domains_set = set()
        for item in domains:
            domain = item
            if isinstance(item, dict):
                domain = item["domain"]

            domain = domain.lower().strip()
            if domain in domains_set:
                continue
            domains_set.add(domain)

            if utils.check_domain_black(domain):
                continue

            fake = {
                "domain": domain,
                "type": "CNAME",
                "record": [],
                "ips": []
            }
            fake_info = modules.DomainInfo(**fake)
            if fake_info not in self.domain_info_list:
                fake_list.append(fake_info)

        if self.task_tag == "monitor":
            return fake_list
        domain_info_list = services.build_domain_info(fake_list)

        return domain_info_list

    def _recover_alt_dns_records(self, dns_records, resolved_info_list):
        """Preserve trusted DNSX evidence when a second lookup is transiently empty."""
        resolved_domains = {
            str(getattr(info, "domain", "") or "").strip().lower().strip(".")
            for info in resolved_info_list or []
        }
        grouped = {}
        for item in dns_records or []:
            if not isinstance(item, dict):
                continue
            domain = str(item.get("domain") or "").strip().lower().strip(".")
            if (
                not domain
                or not domain.endswith("." + self.base_domain)
                or not utils.domain_parsed(domain)
                or utils.check_domain_black(domain)
            ):
                continue
            values = grouped.setdefault(domain, {"ips": set(), "cnames": set()})
            record_values = item.get("record") or []
            if not isinstance(record_values, (list, tuple, set)):
                record_values = [record_values]
            record_type = str(item.get("type") or "").upper()
            for record in record_values:
                record = str(record or "").strip().lower().strip(".")
                if not record:
                    continue
                if record_type == "CNAME" and utils.domain_parsed(record):
                    values["cnames"].add(record)
                elif record_type == "A" and utils.is_vaild_ip_target(record):
                    values["ips"].add(record)

        recovered_info = []
        cname_only_documents = []
        for domain in sorted(grouped):
            if domain in resolved_domains:
                continue
            values = grouped[domain]
            ips = sorted(values["ips"])
            cnames = sorted(values["cnames"])
            if ips:
                recovered_info.append(modules.DomainInfo(**{
                    "domain": domain,
                    "type": "CNAME" if cnames else "A",
                    "record": cnames or ips,
                    "ips": ips,
                }))
            elif cnames:
                cname_only_documents.append({
                    "domain": domain,
                    "type": "CNAME",
                    "record": cnames,
                    "ips": [],
                    "cname_only": True,
                    "dns_evidence_status": "cname_only",
                })
        return recovered_info, cname_only_documents

    def alt_dns_current(self):
        primary_domain = utils.get_fld(self.base_domain)
        # 当前下发的是主域名，就跳过
        if primary_domain == self.base_domain or primary_domain == "":
            return []
        fake = {
            "domain": self.base_domain,
            "type": "CNAME",
            "record": [],
            "ips": []
        }
        fake_info = modules.DomainInfo(**fake)

        logger.info("alt_dns_current {}, primary_domain:{}".format(self.base_domain, primary_domain))
        data = alt_dns([fake_info], primary_domain, wildcard_domain_ip=self.not_found_domain_ips)

        return data

    def alt_dns(self):
        if self.task_tag == "monitor" and len(self.domain_info_list) >= 800:
            logger.info("skip alt_dns on monitor {}".format(self.base_domain))
            return

        if len(self.domain_info_list) > 300 and self.not_found_domain_ips:
            logger.warning(
                "{} wildcard DNS with {} known domains; continue bounded alt_dns via puredns".format(
                    self.base_domain, len(self.domain_info_list)))

        alive_sites = probe_domain_sites(
            self.domain_info_list,
            task_id=self.task_id,
            base_domain=self.base_domain,
            source="alt_dns_seed",
        )
        alive_domains = set()
        for site in alive_sites:
            domain = urlparse(site).hostname
            if domain:
                alive_domains.add(domain.lower().strip("."))

        resolved_domains = {
            str(info.domain or "").strip().lower().strip(".")
            for info in self.domain_info_list
            if getattr(info, "domain", "")
        }
        profile_domains = []
        seen_profile_domains = set()
        for group in (
                sorted(alive_domains),
                sorted(resolved_domains - alive_domains),
                sorted(self.mutation_seed_domains - resolved_domains - alive_domains)):
            for domain in group:
                if not domain or domain in seen_profile_domains:
                    continue
                seen_profile_domains.add(domain)
                profile_domains.append(domain)

        if not profile_domains:
            logger.info("alt_dns no usable profile domains {}".format(self.base_domain))
            return {"output_count": 0, "profile_seed_count": 0}

        logger.info(
            "alt_dns profile domains {} alive:{} resolved:{} passive:{} total:{}".format(
                self.base_domain,
                len(alive_domains),
                len(resolved_domains),
                len(self.mutation_seed_domains),
                len(profile_domains),
            ))

        seed_scores = {}
        for domain in self.mutation_seed_domains:
            seed_scores[domain] = max(seed_scores.get(domain, 0), 30)
        for domain in resolved_domains:
            seed_scores[domain] = max(seed_scores.get(domain, 0), 60)
        for domain in alive_domains:
            seed_scores[domain] = max(seed_scores.get(domain, 0), 100)
        try:
            source_documents = utils.conn_db("domain").find(
                formal_domain_query({"task_id": self.task_id}),
                {"_id": 0, "domain": 1, "source": 1, "sources": 1})
            for item in source_documents:
                domain = str(item.get("domain") or "").strip().lower().strip(".")
                if not domain:
                    continue
                sources = set(self._list_value(item.get("sources")))
                if item.get("source"):
                    sources.add(item.get("source"))
                seed_scores[domain] = (
                    seed_scores.get(domain, 0) + min(len(sources), 4) * 10)
        except Exception as e:
            logger.warning("load mutation source scores failed task:{} error:{}".format(
                self.task_id, e))

        mutation_generation_meta = {}
        mutation_family_map = {}
        try:
            mutation_candidates = services.light_mutation_candidates(
                self.base_domain,
                profile_domains,
                seed_scores=seed_scores,
                meta=mutation_generation_meta,
                family_map=mutation_family_map,
            )
            recursive_candidates = services.recursive_brute_candidates(
                self.base_domain,
                profile_domains,
                delegated_parents=getattr(self, "delegated_subdomains", set()),
            )
        except Exception as e:
            logger.exception("alt_dns candidate generation failed on {}".format(self.base_domain))
            return {
                "output_count": 0,
                "error_count": 1,
                "error": str(e),
                "partial_reason": "alt_dns_candidate_generation_failed",
                "_stage_status": "partial",
            }

        known_domains = resolved_domains | set(self.mutation_seed_domains)
        total_limit = max(int(getattr(
            Config,
            "ALT_DNS_TOTAL_RESOLVE_LIMIT",
            Config.ALTERX_RESOLVE_LIMIT + getattr(Config, "RECURSIVE_BRUTE_LIMIT", 1200),
        ) or 0), 0)
        candidate_sources = {}
        ordered_candidates = []

        def add_candidates(values, source, source_limit):
            selected_count = 0
            for candidate in values:
                candidate = str(candidate or "").strip().lower().strip(".")
                if not candidate or not candidate.endswith("." + self.base_domain):
                    continue
                if candidate in known_domains:
                    continue
                if candidate not in candidate_sources:
                    if total_limit and len(ordered_candidates) >= total_limit:
                        break
                    candidate_sources[candidate] = set()
                    ordered_candidates.append(candidate)
                    selected_count += 1
                candidate_sources[candidate].add(source)
                if source_limit and selected_count >= source_limit:
                    break

        add_candidates(
            mutation_candidates,
            CollectSource.ALTDNS,
            max(int(getattr(Config, "ALTERX_RESOLVE_LIMIT", 1200) or 0), 0),
        )
        add_candidates(
            recursive_candidates,
            CollectSource.RECURSIVE_BRUTE,
            max(int(getattr(Config, "RECURSIVE_BRUTE_LIMIT", 1200) or 0), 0),
        )
        logger.info(
            "alt_dns candidates mutation_raw:{} recursive_raw:{} selected:{} known:{} limit:{}".format(
                len(mutation_candidates),
                len(recursive_candidates),
                len(ordered_candidates),
                len(known_domains),
                total_limit,
            ))
        if not ordered_candidates:
            return {
                "output_count": 0,
                "profile_seed_count": len(profile_domains),
                "mutation_candidate_count": 0,
                "recursive_candidate_count": 0,
            }

        resolve_meta = {
            "profile_seed_count": len(profile_domains),
            "alive_seed_count": len(alive_domains),
            "resolved_seed_count": len(resolved_domains),
            "passive_seed_count": len(self.mutation_seed_domains),
            "mutation_candidate_count": sum(
                1 for sources in candidate_sources.values()
                if CollectSource.ALTDNS in sources),
            "recursive_candidate_count": sum(
                1 for sources in candidate_sources.values()
                if CollectSource.RECURSIVE_BRUTE in sources),
            "mutation_family_candidate_counts": dict(
                mutation_generation_meta.get("family_candidate_counts", {})),
            "mutation_selected_seed_count": int(
                mutation_generation_meta.get("selected_seed_count", 0) or 0),
            "mutation_learned_label_count": int(
                mutation_generation_meta.get("learned_label_count", 0) or 0),
            "mutation_learned_token_count": int(
                mutation_generation_meta.get("learned_token_count", 0) or 0),
            "mutation_top_tokens": list(
                mutation_generation_meta.get("top_tokens", []) or []),
        }
        candidate_family_map = {
            candidate: (
                mutation_family_map.get(candidate, "unknown")
                if CollectSource.ALTDNS in candidate_sources.get(candidate, set())
                else "recursive"
            )
            for candidate in ordered_candidates
        }
        try:
            alt_dns_out = services.resolve_candidates_plus(
                self.base_domain,
                ordered_candidates,
                puredns_timeout=int(getattr(
                    Config, "ALT_DNS_PUREDNS_TIMEOUT", 300) or 300),
                dnsx_timeout=int(getattr(Config, "ALT_DNS_DNSX_TIMEOUT", 180) or 180),
                meta=resolve_meta,
                candidate_families=candidate_family_map,
            )
        except services.DomainBrutePlusError as e:
            logger.warning("alt_dns puredns/dnsx resolver failed on {}: {}".format(
                self.base_domain, e))
            resolve_meta.update({
                "output_count": 0,
                "error_count": 1,
                "error": str(e),
                "resolver_status": "failed",
                "partial_reason": "alt_dns_resolver_failed",
                "_stage_status": "partial",
            })
            return resolve_meta
        except Exception as e:
            logger.exception("alt_dns unexpected resolver failure on {}".format(self.base_domain))
            return {
                "output_count": 0,
                "error_count": 1,
                "error": str(e),
                "partial_reason": "alt_dns_resolver_failed",
                "_stage_status": "partial",
            }

        if len(alt_dns_out) <= 0:
            summary = {"output_count": 0}
            summary.update(resolve_meta)
            return summary

        wildcard_before = self._wildcard_metric_snapshot()
        alt_domain_info_list = self.build_domain_info(alt_dns_out)
        recovered_info, cname_only_documents = self._recover_alt_dns_records(
            alt_dns_out, alt_domain_info_list)
        alt_domain_info_list.extend(recovered_info)
        if self.task_tag == "task":
            alt_domain_info_list = self.clear_domain_info_by_record(
                alt_domain_info_list,
                source="alt_dns_generated",
                check_parent_wildcard=True,
            )
            cname_only_documents = self._filter_generated_cname_documents(
                cname_only_documents,
                source="alt_dns_generated",
            )

            logger.info(
                "alt_dns real result:{} dnsx_recovered:{} cname_only_preserved:{}".format(
                    len(alt_domain_info_list),
                    len(recovered_info),
                    len(cname_only_documents),
                ))

            if len(alt_domain_info_list) > 0:
                for source in (CollectSource.ALTDNS, CollectSource.RECURSIVE_BRUTE):
                    source_items = [
                        info for info in alt_domain_info_list
                        if source in candidate_sources.get(
                            str(info.domain or "").strip().lower().strip("."), set())
                    ]
                    if source_items:
                        self.save_domain_info_list(source_items, source=source)

            if cname_only_documents:
                for source in (CollectSource.ALTDNS, CollectSource.RECURSIVE_BRUTE):
                    source_items = [
                        item for item in cname_only_documents
                        if source in candidate_sources.get(item["domain"], set())
                    ]
                    if source_items:
                        save_domain_documents(self.task_id, source_items, source)

        self.domain_info_list.extend(alt_domain_info_list)
        output_domains = {
            str(info.domain or "").strip().lower().strip(".")
            for info in alt_domain_info_list
            if getattr(info, "domain", "")
        }
        output_domains.update(item["domain"] for item in cname_only_documents)
        if self.task_tag == "task" and len(str(self.task_id)) == 24:
            for domain in sorted(output_domains):
                if CollectSource.ALTDNS in candidate_sources.get(domain, set()):
                    family = mutation_family_map.get(domain, "unknown")
                else:
                    family = "recursive"
                utils.conn_db("domain").update_one(
                    {"task_id": self.task_id, "domain": domain},
                    {
                        "$set": {
                            "dns_candidate_family": family,
                            "dns_candidate_stage": "alt_dns",
                        },
                        "$addToSet": {
                            "dns_candidate_families": family,
                        },
                    },
                )
        summary = {"output_count": len(output_domains)}
        summary.update(resolve_meta)
        summary["output_count"] = len(output_domains)
        summary["resolved_output_count"] = len(alt_domain_info_list)
        summary["dnsx_recovered_output_count"] = len(recovered_info)
        summary["cname_only_preserved_count"] = len(cname_only_documents)
        summary["mutation_output_count"] = sum(
            1 for domain in output_domains
            if CollectSource.ALTDNS in candidate_sources.get(domain, set()))
        summary["recursive_output_count"] = sum(
            1 for domain in output_domains
            if CollectSource.RECURSIVE_BRUTE in candidate_sources.get(domain, set()))
        summary["mutation_family_output_counts"] = dict(Counter(
            mutation_family_map.get(domain, "unknown")
            for domain in output_domains
            if CollectSource.ALTDNS in candidate_sources.get(domain, set())
        ))
        summary.update(self._wildcard_metric_delta(wildcard_before))
        return summary

    def _post_dns_feedback_seeds(self):
        known_domains = set()
        seed_sources = {}
        seed_scores = {}

        def add_seed(domain, sources):
            domain = str(domain or "").strip().lower().strip("*.")
            if (
                not domain or
                (domain != self.base_domain and
                 not domain.endswith("." + self.base_domain)) or
                not utils.is_valid_domain(domain) or
                utils.check_domain_black(domain)
            ):
                return
            matched_sources = {
                str(source or "").strip()
                for source in sources or []
                if str(source or "").strip() in POST_DNS_FEEDBACK_SOURCE_SCORES
            }
            if not matched_sources:
                return
            seed_sources.setdefault(domain, set()).update(matched_sources)
            seed_scores[domain] = max(
                seed_scores.get(domain, 0),
                max(POST_DNS_FEEDBACK_SOURCE_SCORES[source]
                    for source in matched_sources),
            )

        for item in utils.conn_db("domain").find(
                formal_domain_query({"task_id": self.task_id}),
                {"_id": 0, "domain": 1, "source": 1, "sources": 1}):
            domain = str(item.get("domain") or "").strip().lower().strip(".")
            if domain:
                known_domains.add(domain)
            sources = set(self._list_value(item.get("sources")))
            if item.get("source"):
                sources.add(item.get("source"))
            add_seed(domain, sources)

        for domain in self.post_seed_domains:
            add_seed(domain, ["active_ssl_san"])

        web_fetch = getattr(self, "web_site_fetch", None)
        if web_fetch is not None:
            for domain in getattr(web_fetch, "site_spider_domain_set", set()):
                add_seed(domain, [CollectSource.SITESPIDER])
            for domain in getattr(web_fetch, "wih_domain_set", set()):
                add_seed(domain, ["wih"])

        ordered = sorted(
            seed_sources,
            key=lambda domain: (
                -seed_scores.get(domain, 0),
                domain.count("."),
                len(domain),
                domain,
            ),
        )
        source_counts = Counter()
        for sources in seed_sources.values():
            source_counts.update(sources)
        return ordered, seed_scores, known_domains, dict(source_counts)

    def post_dns_feedback(self):
        if self.task_tag != "task":
            return {
                "input_count": 0,
                "output_count": 0,
                "skip_reason": "non_task_profile",
            }

        seeds, seed_scores, known_domains, seed_source_counts = (
            self._post_dns_feedback_seeds())
        if not seeds:
            return {
                "input_count": 0,
                "output_count": 0,
                "known_domain_count": len(known_domains),
                "seed_source_counts": {},
                "skip_reason": "no_post_discovery_seeds",
            }

        total_limit = max(int(getattr(
            Config, "POST_DNS_FEEDBACK_LIMIT", 800) or 0), 0)
        mutation_limit = min(max(int(getattr(
            Config, "POST_DNS_FEEDBACK_MUTATION_LIMIT", 600) or 0), 0), total_limit)
        recursive_limit = min(max(int(getattr(
            Config, "POST_DNS_FEEDBACK_RECURSIVE_LIMIT", 200) or 0), 0),
            max(total_limit - mutation_limit, 0))
        seed_limit = max(int(getattr(
            Config, "POST_DNS_FEEDBACK_SEED_LIMIT", 80) or 0), 0)
        per_seed_limit = max(int(getattr(
            Config, "POST_DNS_FEEDBACK_PER_SEED_LIMIT", 20) or 0), 0)
        if not total_limit or not mutation_limit or not seed_limit:
            return {
                "input_count": len(seeds),
                "output_count": 0,
                "known_domain_count": len(known_domains),
                "seed_source_counts": seed_source_counts,
                "skip_reason": "post_dns_feedback_disabled_by_limit",
            }

        generation_meta = {}
        candidate_family_map = {}
        mutation_candidates = services.light_mutation_candidates(
            self.base_domain,
            seeds,
            seed_scores=seed_scores,
            candidate_limit=mutation_limit,
            seed_limit=seed_limit,
            per_seed_limit=per_seed_limit,
            meta=generation_meta,
            family_map=candidate_family_map,
            known_domains=known_domains,
        )
        recursive_candidates = []
        if recursive_limit:
            recursive_candidates = services.recursive_brute_candidates(
                self.base_domain,
                seeds,
                delegated_parents=self.delegated_subdomains,
            )[:recursive_limit]

        ordered_candidates = []
        seen_candidates = set()
        for candidate in list(mutation_candidates) + list(recursive_candidates):
            candidate = str(candidate or "").strip().lower().strip(".")
            if (
                not candidate or candidate in known_domains or
                candidate in seen_candidates or
                not candidate.endswith("." + self.base_domain)
            ):
                continue
            seen_candidates.add(candidate)
            ordered_candidates.append(candidate)
            if candidate not in candidate_family_map:
                candidate_family_map[candidate] = "recursive"
            if len(ordered_candidates) >= total_limit:
                break

        resolve_meta = {
            "input_count": len(seeds),
            "profile_seed_count": len(seeds),
            "known_domain_count": len(known_domains),
            "seed_source_counts": seed_source_counts,
            "mutation_candidate_count": sum(
                1 for candidate in ordered_candidates
                if candidate_family_map.get(candidate) != "recursive"),
            "recursive_candidate_count": sum(
                1 for candidate in ordered_candidates
                if candidate_family_map.get(candidate) == "recursive"),
            "mutation_family_candidate_counts": dict(Counter(
                candidate_family_map.get(candidate, "unknown")
                for candidate in ordered_candidates
            )),
            "mutation_selected_seed_count": int(
                generation_meta.get("selected_seed_count", 0) or 0),
            "mutation_learned_label_count": int(
                generation_meta.get("learned_label_count", 0) or 0),
            "mutation_learned_token_count": int(
                generation_meta.get("learned_token_count", 0) or 0),
            "mutation_top_tokens": list(
                generation_meta.get("top_tokens", []) or []),
        }
        if not ordered_candidates:
            resolve_meta["output_count"] = 0
            resolve_meta["skip_reason"] = "no_new_feedback_candidates"
            return resolve_meta

        try:
            dns_records = services.resolve_candidates_plus(
                self.base_domain,
                ordered_candidates,
                puredns_timeout=int(getattr(
                    Config, "POST_DNS_FEEDBACK_PUREDNS_TIMEOUT", 180) or 180),
                dnsx_timeout=int(getattr(
                    Config, "POST_DNS_FEEDBACK_DNSX_TIMEOUT", 120) or 120),
                meta=resolve_meta,
                candidate_families=candidate_family_map,
            )
        except services.DomainBrutePlusError as e:
            resolve_meta.update({
                "output_count": 0,
                "error_count": 1,
                "error": str(e),
                "resolver_status": "failed",
                "partial_reason": "post_dns_feedback_resolver_failed",
                "_stage_status": "partial",
            })
            return resolve_meta

        wildcard_before = self._wildcard_metric_snapshot()
        resolved_info = self.build_domain_info(dns_records)
        recovered_info, cname_only_documents = self._recover_alt_dns_records(
            dns_records, resolved_info)
        resolved_info.extend(recovered_info)
        resolved_info = self.clear_domain_info_by_record(
            resolved_info,
            source=POST_DNS_FEEDBACK_SOURCE,
            check_parent_wildcard=True,
        )
        cname_only_documents = self._filter_generated_cname_documents(
            cname_only_documents,
            source=POST_DNS_FEEDBACK_SOURCE,
        )

        if resolved_info:
            self.save_domain_info_list(
                resolved_info, source=POST_DNS_FEEDBACK_SOURCE)
        if cname_only_documents:
            save_domain_documents(
                self.task_id,
                cname_only_documents,
                POST_DNS_FEEDBACK_SOURCE,
            )

        output_domains = {
            str(info.domain or "").strip().lower().strip(".")
            for info in resolved_info if getattr(info, "domain", "")
        }
        output_domains.update(
            item["domain"] for item in cname_only_documents if item.get("domain"))
        for domain in sorted(output_domains):
            family = candidate_family_map.get(domain, "unknown")
            utils.conn_db("domain").update_one(
                {"task_id": self.task_id, "domain": domain},
                {
                    "$set": {
                        "dns_candidate_family": family,
                        "dns_feedback_observed_at": utils.curr_date(),
                    },
                    "$addToSet": {
                        "dns_candidate_families": family,
                        "sources": POST_DNS_FEEDBACK_SOURCE,
                    },
                },
            )

        self.domain_info_list.extend(resolved_info)
        self.post_seed_domains.update(output_domains)
        self.mutation_seed_domains.update(output_domains)
        site_summary = {}
        if output_domains:
            site_summary = domain_site_update(
                self.task_id,
                sorted(output_domains),
                POST_DNS_FEEDBACK_SOURCE,
                reprobe_existing_without_site=True,
                run_file_leak=False,
            ) or {}
            self.insert_task_stat()

        resolve_meta.update({
            "output_count": len(output_domains),
            "net_new_domain_count": len(output_domains),
            "resolved_output_count": len(resolved_info),
            "cname_only_preserved_count": len(cname_only_documents),
            "site_output_count": int(site_summary.get("output_count", 0) or 0),
            "mutation_family_output_counts": dict(Counter(
                candidate_family_map.get(domain, "unknown")
                for domain in output_domains
            )),
        })
        resolve_meta.update(self._wildcard_metric_delta(wildcard_before))
        return resolve_meta

    def _discovery_asset_snapshot(self):
        domains = set()
        ips = set()
        for item in utils.conn_db("domain").find(
                formal_domain_query({"task_id": self.task_id}),
                {"_id": 0, "domain": 1, "ips": 1}):
            domain = str(item.get("domain") or "").strip(".").lower()
            if domain:
                domains.add(domain)
            for ip in self._list_value(item.get("ips")):
                ip = str(ip or "").strip()
                if ip and utils.not_in_black_ips(ip) and utils.get_ip_type(ip) == "PUBLIC":
                    ips.add(ip)

        for item in utils.conn_db("ip").find(
                {"task_id": self.task_id}, {"_id": 0, "ip": 1}):
            ip = str(item.get("ip") or "").strip()
            if ip and utils.not_in_black_ips(ip) and utils.get_ip_type(ip) == "PUBLIC":
                ips.add(ip)

        sites = set()
        for item in utils.conn_db("site").find(
                formal_site_query({"task_id": self.task_id}),
                {"_id": 0, "site": 1}):
            site_key = self._site_key(item.get("site"))
            if site_key:
                sites.add(site_key)
        for item in utils.conn_db("asset_seed_alive").find(
                formal_pipeline_query({"task_id": self.task_id}),
                {"_id": 0, "url": 1}):
            site_key = self._site_key(item.get("url"))
            if site_key:
                sites.add(site_key)
        return {"domains": domains, "ips": ips, "sites": sites}

    def prepare_discovery_delta_state(self):
        max_rounds = max(int(getattr(
            Config, "DISCOVERY_DELTA_MAX_ROUNDS", 2) or 0), 0)
        if (
            not max_rounds or
            getattr(self, "task_tag", "task") != "task" or
            not getattr(self, "task_id", "")
        ):
            return {}

        collection = utils.conn_db(DISCOVERY_DELTA_COLLECTION)
        state = collection.find_one({"task_id": self.task_id})
        if state:
            return state

        snapshot = self._discovery_asset_snapshot()
        now = utils.curr_date()
        collection.update_one(
            {"task_id": self.task_id},
            {
                "$setOnInsert": {
                    "task_id": self.task_id,
                    "status": "pending",
                    "round": 0,
                    "max_rounds": max_rounds,
                    "processed_domains": sorted(snapshot["domains"]),
                    "processed_ips": sorted(snapshot["ips"]),
                    "processed_sites": sorted(snapshot["sites"]),
                    "created_at": now,
                },
                "$set": {"updated_at": now},
            },
            upsert=True,
        )
        return collection.find_one({"task_id": self.task_id}) or {
            "task_id": self.task_id,
            "status": "pending",
            "round": 0,
            "max_rounds": max_rounds,
            "processed_domains": sorted(snapshot["domains"]),
            "processed_ips": sorted(snapshot["ips"]),
            "processed_sites": sorted(snapshot["sites"]),
        }

    def _discovery_delta_domain_info(self, target_ips):
        target_ips = set(target_ips or [])
        if not target_ips:
            return []

        domain_info_list = []
        covered_ips = set()
        for item in utils.conn_db("domain").find(
                formal_domain_query({"task_id": self.task_id}),
                {"_id": 0, "domain": 1, "record": 1, "type": 1, "ips": 1}):
            domain = str(item.get("domain") or "").strip(".").lower()
            ips = sorted({
                str(ip or "").strip()
                for ip in self._list_value(item.get("ips"))
                if str(ip or "").strip() in target_ips
            })
            if not domain or not ips:
                continue
            covered_ips.update(ips)
            domain_info_list.append(modules.DomainInfo(**{
                "domain": domain,
                "record": self._list_value(item.get("record")),
                "type": item.get("type") or "A",
                "ips": ips,
            }))

        for ip in sorted(target_ips - covered_ips):
            domains = sorted(self.verified_cert_ip_domains.get(ip, set()))
            domain_info_list.append(modules.DomainInfo(**{
                "domain": domains[0] if domains else self.base_domain,
                "record": [ip],
                "type": "A",
                "ips": [ip],
            }))

        original_domains = self.domain_info_list
        original_verified = self.verified_cert_ip_domains
        try:
            self.domain_info_list = domain_info_list
            self.verified_cert_ip_domains = {
                ip: domains for ip, domains in original_verified.items()
                if ip in target_ips
            }
            eligible = self._port_scan_domain_info()
        finally:
            self.domain_info_list = original_domains
            self.verified_cert_ip_domains = original_verified

        restricted = []
        for info in eligible:
            ips = sorted(set(info.ip_list) & target_ips)
            if not ips:
                continue
            restricted.append(modules.DomainInfo(**{
                "domain": info.domain,
                "record": info.record_list,
                "type": info.type,
                "ips": ips,
            }))
        return restricted

    def _run_discovery_delta_ports(self, target_ips, round_index):
        if not target_ips or not self.options.get("port_scan"):
            return {}

        domain_info_list = self._discovery_delta_domain_info(target_ips)
        if not domain_info_list:
            return {"input_count": len(target_ips), "output_count": 0}

        original_domains = self.domain_info_list
        self.domain_info_list = domain_info_list
        summaries = {}
        try:
            scan_type = self.options.get("port_scan_type", "test")
            if scan_type == "all" and Config.PORT_SCAN_TOP1000_FIRST:
                summaries["top1000"] = self.run_stage(
                    "discovery_delta_port_scan_top1000",
                    lambda: self.port_scan(
                        ports=ScanPortType.TOP1000, max_targets=0),
                    input_count=len(target_ips),
                )
                if self.task_is_terminal():
                    return summaries
                exclude_ports = (
                    Config.TOP_1000 if Config.FULL_PORT_REMAINING_ONLY else None)
                summaries["full"] = self.run_stage(
                    "discovery_delta_port_scan_full",
                    lambda: self.port_scan(
                        ports=ScanPortType.ALL,
                        exclude_extra_ports=exclude_ports,
                        max_targets=0,
                    ),
                    input_count=len(target_ips),
                )
            else:
                summaries["scan"] = self.run_stage(
                    "discovery_delta_port_scan",
                    lambda: self.port_scan(max_targets=0),
                    input_count=len(target_ips),
                )
        finally:
            self.domain_info_list = original_domains

        summaries["round"] = round_index
        return summaries

    def _discovery_delta_site_candidates(self, processed_sites):
        processed_sites = set(processed_sites or [])
        values = {}
        for collection_name, field in (("site", "site"), ("asset_seed_alive", "url")):
            query = {"task_id": self.task_id}
            if collection_name == "site":
                query = formal_site_query(query)
            for item in utils.conn_db(collection_name).find(
                    query, {"_id": 0, field: 1}):
                site = str(item.get(field) or "").strip()
                site_key = self._site_key(site)
                if site_key and site_key not in processed_sites:
                    values.setdefault(site_key, site)
        allowed = self._filter_edge_sites(values.values())
        return {
            self._site_key(site): site for site in allowed if self._site_key(site)
        }

    def _run_discovery_delta_sites(self, sites, round_index):
        sites = sorted(set(sites or []))
        if not sites:
            return {"input_count": 0, "output_count": 0, "new_domains": []}

        web_fetch = WebSiteFetch(
            task_id=self.task_id,
            sites=sites,
            options=self.options,
            scope_domain=[self.base_domain],
        )
        fetch_summary = self.run_stage(
            "discovery_delta_fetch_site",
            web_fetch.fetch_site,
            input_count=len(sites),
        )
        web_fetch.save_site_info()
        if self.task_is_terminal():
            return {"input_count": len(sites), "fetch": fetch_summary}

        spider_summary = {}
        if self.options.get("site_spider"):
            web_fetch.update_page_url_set()
            spider_summary = self.run_stage(
                "discovery_delta_spider",
                lambda: web_fetch.site_spider(
                    stage_name="discovery_delta_spider"),
                input_count=len(web_fetch.available_sites),
            )
        runtime_summary = {}
        if web_fetch.runtime_artifact_ready() and not self.task_is_terminal():
            runtime_summary = self.run_stage(
                "discovery_delta_runtime_artifact",
                lambda: web_fetch.run_runtime_artifact(
                    stage_name="discovery_delta_runtime_artifact"),
                input_count=len(web_fetch.runtime_artifact_targets),
            )
        if self.task_is_terminal():
            return {
                "input_count": len(sites),
                "fetch": fetch_summary,
                "spider": spider_summary,
                "runtime_artifact": runtime_summary,
            }

        wih_summary = {}
        if self.options.get("web_info_hunter"):
            wih_summary = self.run_stage(
                "discovery_delta_wih",
                lambda: web_fetch.run_web_info_hunter(
                    stage_name="discovery_delta_wih"),
                input_count=len(web_fetch.available_sites),
            )

        discovered_domains = set(web_fetch.site_spider_domain_set)
        discovered_domains.update(web_fetch.wih_domain_set)
        pending_domains = web_fetch.entry_tracker.pending_domains(
            discovered_domains)
        domain_summary = {}
        if pending_domains and not self.task_is_terminal():
            domain_summary = domain_site_update(
                self.task_id,
                pending_domains,
                "discovery_delta",
                url_evidence=web_fetch.site_spider_domain_url_map,
                reprobe_existing_without_site=True,
                run_file_leak=False,
            ) or {}
            web_fetch.entry_tracker.finalize_domains(pending_domains)
            self.insert_task_stat()

        return {
            "input_count": len(sites),
            "output_count": len(web_fetch.available_sites),
            "round": round_index,
            "fetch": fetch_summary,
            "spider": spider_summary,
            "runtime_artifact": runtime_summary,
            "wih": wih_summary,
            "domain_update": domain_summary,
            "new_domains": sorted(discovered_domains),
        }

    def run_discovery_delta(self, state=None):
        state = state or self.prepare_discovery_delta_state()
        if not state:
            return {
                "input_count": 0,
                "output_count": 0,
                "skip_reason": "discovery_delta_disabled",
            }

        max_rounds = max(int(state.get("max_rounds") or getattr(
            Config, "DISCOVERY_DELTA_MAX_ROUNDS", 2) or 0), 0)
        processed_domains = set(state.get("processed_domains") or [])
        processed_ips = set(state.get("processed_ips") or [])
        processed_sites = set(state.get("processed_sites") or [])
        start_round = max(int(state.get("round", 0) or 0), 0) + 1
        collection = utils.conn_db(DISCOVERY_DELTA_COLLECTION)
        round_summaries = []
        total_domains = total_ips = total_sites = 0

        for round_index in range(start_round, max_rounds + 1):
            if self.task_is_terminal():
                break
            self.hydrate_from_storage()
            snapshot = self._discovery_asset_snapshot()
            new_domains = sorted(snapshot["domains"] - processed_domains)
            new_ips = sorted(snapshot["ips"] - processed_ips)
            site_map = self._discovery_delta_site_candidates(processed_sites)
            if not new_domains and not new_ips and not site_map:
                break

            now = utils.curr_date()
            collection.update_one(
                {"task_id": self.task_id},
                {"$set": {
                    "status": "running",
                    "round": round_index,
                    "round_input_domains": len(new_domains),
                    "round_input_ips": len(new_ips),
                    "round_input_sites": len(site_map),
                    "updated_at": now,
                }},
            )

            port_summary = self._run_discovery_delta_ports(
                new_ips, round_index)
            if self.task_is_terminal():
                break
            self.save_ip_info()
            port_site_summary = self.reconcile_port_site_probe_delta()

            ssl_summary = {}
            if self.options.get("ssl_cert") and not self.task_is_terminal():
                ssl_summary = self.run_stage(
                    "discovery_delta_ssl",
                    lambda: self.ssl_cert(
                        phase="discovery_delta_{}".format(round_index)),
                    input_count=len(new_ips),
                )

            site_map = self._discovery_delta_site_candidates(processed_sites)
            site_summary = self._run_discovery_delta_sites(
                list(site_map.values()), round_index)

            processed_domains.update(new_domains)
            processed_ips.update(new_ips)
            processed_sites.update(site_map)
            total_domains += len(new_domains)
            total_ips += len(new_ips)
            total_sites += len(site_map)
            round_summary = {
                "round": round_index,
                "domain_count": len(new_domains),
                "ip_count": len(new_ips),
                "site_count": len(site_map),
                "port_scan": port_summary,
                "port_site_probe": port_site_summary,
                "ssl": ssl_summary,
                "site_discovery": site_summary,
            }
            round_summaries.append(round_summary)
            collection.update_one(
                {"task_id": self.task_id},
                {
                    "$set": {
                        "round": round_index,
                        "processed_domains": sorted(processed_domains),
                        "processed_ips": sorted(processed_ips),
                        "processed_sites": sorted(processed_sites),
                        "last_round_summary": round_summary,
                        "updated_at": utils.curr_date(),
                    },
                    "$push": {"rounds": round_summary},
                },
            )

        if self.task_is_terminal():
            collection.update_one(
                {"task_id": self.task_id},
                {"$set": {
                    "status": "interrupted",
                    "updated_at": utils.curr_date(),
                }},
            )
            return {
                "input_count": total_domains + total_ips + total_sites,
                "output_count": total_domains + total_ips + total_sites,
                "round_count": len(round_summaries),
                "max_rounds": max_rounds,
                "new_domain_count": total_domains,
                "new_ip_count": total_ips,
                "new_site_count": total_sites,
                "partial_reason": "task_terminal",
                "_stage_status": "partial",
                "rounds": round_summaries,
            }

        final_snapshot = self._discovery_asset_snapshot()
        deferred_domains = final_snapshot["domains"] - processed_domains
        deferred_ips = final_snapshot["ips"] - processed_ips
        deferred_sites = set(self._discovery_delta_site_candidates(
            processed_sites))
        deferred_count = (
            len(deferred_domains) + len(deferred_ips) + len(deferred_sites))
        status = "complete_with_deferred" if deferred_count else "complete"
        collection.update_one(
            {"task_id": self.task_id},
            {"$set": {
                "status": status,
                "deferred_domain_count": len(deferred_domains),
                "deferred_ip_count": len(deferred_ips),
                "deferred_site_count": len(deferred_sites),
                "completed_at": utils.curr_date(),
                "updated_at": utils.curr_date(),
            }},
        )
        summary = {
            "input_count": total_domains + total_ips + total_sites,
            "output_count": total_domains + total_ips + total_sites,
            "round_count": len(round_summaries),
            "max_rounds": max_rounds,
            "new_domain_count": total_domains,
            "new_ip_count": total_ips,
            "new_site_count": total_sites,
            "deferred_domain_count": len(deferred_domains),
            "deferred_ip_count": len(deferred_ips),
            "deferred_site_count": len(deferred_sites),
            "rounds": round_summaries,
        }
        child_stage_names = {
            "discovery_delta_port_scan",
            "discovery_delta_port_scan_top1000",
            "discovery_delta_port_scan_full",
            "discovery_delta_ssl",
            "discovery_delta_fetch_site",
            "discovery_delta_spider",
            "discovery_delta_runtime_artifact",
            "discovery_delta_wih",
            "discovery_delta_domain_update",
        }
        child_warning_stages = sorted({
            str(item.get("stage") or "")
            for item in utils.conn_db("task_stage").find(
                {
                    "task_id": self.task_id,
                    "stage": {"$in": sorted(child_stage_names)},
                    "status": {"$in": ["partial", "done_with_warnings"]},
                },
                {"_id": 0, "stage": 1, "status": 1},
            )
            if item.get("stage") in child_stage_names
            and item.get("status") in ("partial", "done_with_warnings")
        })
        if child_warning_stages:
            summary["child_warning_count"] = len(child_warning_stages)
            summary["child_warning_stages"] = child_warning_stages
        if deferred_count or child_warning_stages:
            warning_parts = []
            if deferred_count:
                warning_parts.append(
                    "discovery delta reached the configured round limit")
            if child_warning_stages:
                warning_parts.append(
                    "incomplete child stages: {}".format(
                        ", ".join(child_warning_stages)))
            summary.update({
                "_stage_status": "done_with_warnings",
                "completion_state": "done_with_warnings",
                "warning": "; ".join(warning_parts),
            })
        return summary

    def refresh_post_discovery_context(self):
        self.hydrate_from_storage()
        web_site_fetch = WebSiteFetch(
            task_id=self.task_id,
            sites=self.site_list,
            options=self.options,
            scope_domain=[self.base_domain],
        )
        web_site_fetch.available_sites = list(self.site_list)
        self.web_site_fetch = web_site_fetch
        return {
            "domain_count": len(self.domain_info_list),
            "ip_count": len(self.ip_info_list),
            "site_count": len(self.site_list),
        }

    def _port_scan_domain_info(self):
        filtered = []
        included_ips = set()
        skipped = Counter()
        direct_edge_ips = set()
        for item in utils.conn_db("asset_seed_alive").find(
            formal_pipeline_query({
                "task_id": self.task_id,
                "ip": {"$nin": ["", None]},
            }),
            {"_id": 0, "ip": 1, "cdn": 1, "cdn_name": 1, "waf": 1,
             "waf_name": 1, "waf_strength": 1, "edge": 1, "edge_name": 1,
             "tag": 1, "webserver": 1, "cname": 1, "host": 1,
             "url": 1, "target": 1},
        ):
            if not has_strong_edge_marker(item):
                continue
            ip = str(item.get("ip") or "").strip()
            observed_host = str(item.get("host") or "").strip().strip("[]")
            if not observed_host:
                try:
                    observed_host = str(urlparse(
                        item.get("url") or item.get("target") or ""
                    ).hostname or "").strip().strip("[]")
                except (TypeError, ValueError):
                    observed_host = ""
            if ip and observed_host == ip:
                direct_edge_ips.add(ip)

        for info in self.domain_info_list:
            if self._domain_info_is_edge(info):
                skipped["edge_domain"] += 1
                continue
            ips = []
            for ip in info.ip_list:
                ip = str(ip or "").strip()
                if not ip or not utils.not_in_black_ips(ip) or utils.get_ip_type(ip) != "PUBLIC":
                    skipped["non_public"] += 1
                    continue
                if self._ip_is_edge_only(ip) or ip in direct_edge_ips:
                    skipped["strong_edge_ip"] += 1
                    continue
                if self.options.get("skip_scan_cdn_ip") and utils.get_cdn_name_by_ip(ip):
                    skipped["cdn_ip"] += 1
                    continue
                ips.append(ip)
                included_ips.add(ip)
            if ips:
                filtered.append(modules.DomainInfo(**{
                    "domain": info.domain,
                    "type": info.type,
                    "record": info.record_list,
                    "ips": sorted(set(ips)),
                }))

        for ip, domains in sorted(self.verified_cert_ip_domains.items()):
            if ip in included_ips or ip in direct_edge_ips or self._ip_is_edge_only(ip):
                continue
            if not utils.not_in_black_ips(ip) or utils.get_ip_type(ip) != "PUBLIC":
                continue
            for domain in sorted(domains):
                filtered.append(modules.DomainInfo(**{
                    "domain": domain,
                    "type": "CERT",
                    "record": [ip],
                    "ips": [ip],
                }))
            included_ips.add(ip)

        logger.info(
            "port_scan eligibility domains:{} -> {} ips:{} http_alive:{} skipped:{} task:{}".format(
                len(self.domain_info_list), len(filtered), len(included_ips),
                len(set(self.asset_seed_alive_ips)), dict(skipped), self.task_id))
        return filtered

    def _merge_exclude_ports(self, *values):
        parts = []
        seen = set()
        for value in values:
            if not value:
                continue
            for part in str(value).split(','):
                part = part.strip()
                if not part or part in seen:
                    continue
                seen.add(part)
                parts.append(part)
        return ','.join(parts)

    def _add_trusted_scan_port(self, trusted, ip, port):
        ip = str(ip or "").strip()
        if not ip:
            return
        try:
            port_id = int(port)
        except Exception:
            return
        if port_id <= 0 or port_id > 65535:
            return
        trusted.setdefault(ip, set()).add(str(port_id))

    def _trusted_port_map_for_scan(self):
        trusted = {}

        for ip_info in self.ip_info_list:
            for port_info in ip_info.port_info_list:
                self._add_trusted_scan_port(trusted, ip_info.ip, port_info.port_id)

        for item in utils.conn_db("asset_seed_candidate").find(
            {"task_id": self.task_id, "ip_type": "PUBLIC"},
            {"_id": 0, "ip": 1, "domain": 1, "port": 1, "ports": 1,
             "source": 1, "candidate_type": 1, "cert_verified": 1,
             "cert_verify_status": 1, "pipeline_eligible": 1, "status": 1,
             "verified_ports": 1}
        ):
            if not self._candidate_is_pipeline_eligible(item):
                continue
            if self._candidate_is_edge(item):
                continue

            for port in self._candidate_ports_for_pipeline(item):
                self._add_trusted_scan_port(trusted, item.get("ip"), port)

        if trusted:
            logger.info("trusted scan port map ips:{} ports:{} task:{}".format(
                len(trusted), sum(len(x) for x in trusted.values()), self.task_id))
        return {ip: sorted(ports, key=lambda item: int(item)) for ip, ports in trusted.items()}

    def _merge_ip_info_object(self, new_info):
        for old_info in self.ip_info_list:
            if old_info.ip != new_info.ip:
                continue

            old_info.domain = sorted(set(old_info.domain or []) | set(new_info.domain or []))
            port_map = {}
            for port_info in list(old_info.port_info_list) + list(new_info.port_info_list):
                try:
                    port_id = int(port_info.port_id)
                except Exception:
                    port_id = port_info.port_id
                key = (port_id, getattr(port_info, "protocol", "tcp"))
                current = port_map.get(key)
                if current is None:
                    port_map[key] = port_info
                    continue
                if port_info.service_name or port_info.product or port_info.version:
                    port_map[key] = port_info

            old_info.port_info_list = sorted(
                port_map.values(),
                key=lambda item: int(item.port_id) if str(item.port_id).isdigit() else str(item.port_id)
            )
            if new_info.os_info:
                old_info.os_info = new_info.os_info
            if new_info.cdn_name:
                old_info.cdn_name = new_info.cdn_name
            return old_info

        self.ip_info_list.append(new_info)
        return new_info

    def _save_ip_info_objects(self, ip_info_list):
        saved = 0
        for ip_info_obj in ip_info_list:
            merged_info = self._merge_ip_info_object(ip_info_obj)
            ip_info = merged_info.dump_json(flag=False)
            ip_info["task_id"] = self.task_id
            query = {"task_id": self.task_id, "ip": ip_info.get("ip")}
            utils.conn_db('ip').update_one(query, {"$set": ip_info}, upsert=True)
            saved += 1

        if saved and self.options.get("service_detection") and Config.ENABLE_NMAP_SERVICE_DETECTION:
            self.save_service_info()
        return saved

    @staticmethod
    def _site_key(site):
        return utils.canonical_site_url(site)

    @staticmethod
    def _port_probe_pairs(ip_info_list):
        pairs = set()
        for ip_info in ip_info_list or []:
            ip = str(getattr(ip_info, "ip", "") or "").strip()
            if not ip:
                continue
            port_info_list = getattr(ip_info, "port_info_list", []) or []
            try:
                port_info_list = list(port_info_list)
            except TypeError:
                continue
            for port_info in port_info_list:
                try:
                    port = int(getattr(port_info, "port_id", ""))
                except (TypeError, ValueError):
                    continue
                if 0 < port <= 65535:
                    pairs.add((ip, port))
        return pairs

    def _mark_port_site_probe_state(
            self, ip_info_list, profile, status, site_count=0, error=""):
        pairs = self._port_probe_pairs(ip_info_list)
        if not pairs:
            return 0

        operations = []
        now = utils.curr_date()
        for ip, port in sorted(pairs):
            operations.append(UpdateOne(
                {"task_id": self.task_id, "ip": ip, "port": port},
                {
                    "$set": {
                        "task_id": self.task_id,
                        "ip": ip,
                        "port": port,
                        "profile": profile or "incremental",
                        "status": status,
                        "site_count": int(site_count or 0),
                        "error": str(error or "")[:1000],
                        "updated_at": now,
                    },
                    "$setOnInsert": {"created_at": now},
                    "$inc": {"attempt_count": 1},
                },
                upsert=True,
            ))
        try:
            utils.conn_db("port_site_probe_state").bulk_write(
                operations, ordered=False)
        except Exception as exc:
            self.incremental_site_probe_failed = True
            logger.warning(
                "save port site probe state failed task:{} profile:{} pairs:{} error:{}".format(
                    self.task_id, profile, len(pairs), exc))
            return 0
        return len(pairs)

    def _unresolved_port_site_ip_info(self):
        completed = set()
        for item in utils.conn_db("port_site_probe_state").find(
                {"task_id": self.task_id, "status": "complete"},
                {"_id": 0, "ip": 1, "port": 1}):
            ip = str(item.get("ip") or "").strip()
            try:
                port = int(item.get("port"))
            except (TypeError, ValueError):
                continue
            if ip and 0 < port <= 65535:
                completed.add((ip, port))

        unresolved = []
        unresolved_pairs = set()
        for ip_info in self.ip_info_list:
            ip = str(getattr(ip_info, "ip", "") or "").strip()
            selected_ports = []
            for port_info in getattr(ip_info, "port_info_list", []) or []:
                try:
                    port = int(getattr(port_info, "port_id", ""))
                except (TypeError, ValueError):
                    continue
                pair = (ip, port)
                if not ip or pair in completed or pair in unresolved_pairs:
                    continue
                unresolved_pairs.add(pair)
                selected_ports.append(port_info)
            if not selected_ports:
                continue
            unresolved.append(modules.IPInfo(**{
                "ip": ip,
                "domain": list(getattr(ip_info, "domain", []) or []),
                "port_info": selected_ports,
                "os_info": getattr(ip_info, "os_info", {}) or {},
                "cdn_name": getattr(ip_info, "cdn_name", "") or "",
            }))
        return unresolved, unresolved_pairs

    def reconcile_port_site_probe_delta(self):
        delta_info, delta_pairs = self._unresolved_port_site_ip_info()
        if not delta_pairs:
            return {
                "delta_pair_count": 0,
                "delta_site_count": 0,
                "delta_saved_count": 0,
            }

        logger.warning(
            "find_site final delta task:{} ips:{} pairs:{}".format(
                self.task_id, len(delta_info), len(delta_pairs)))
        try:
            sites = find_site(
                delta_info, task_id=self.task_id, base_domain=self.base_domain)
            saved = save_site_documents(self.task_id, [{
                "site": site,
                "source": "port_scan_final_delta",
                "port_scan_profile": "final_delta",
            } for site in sites])
            marked_pairs = self._mark_port_site_probe_state(
                delta_info, "final_delta", "complete", site_count=len(sites))
            self.site_list = sorted(set(self.site_list) | set(sites))
            summary = {
                "delta_pair_count": len(delta_pairs),
                "delta_site_count": len(set(sites)),
                "delta_saved_count": saved,
            }
            if marked_pairs < len(delta_pairs):
                summary.update({
                    "_stage_status": "partial",
                    "partial_reason": "port_site_probe_state_write_failed",
                    "warning": "Web probe results were saved but coverage state was incomplete",
                    "error_count": len(delta_pairs) - marked_pairs,
                })
            return summary
        except Exception as exc:
            self.incremental_site_probe_failed = True
            self._mark_port_site_probe_state(
                delta_info, "final_delta", "failed", error=exc)
            logger.exception(
                "find_site final delta failed task:{} pairs:{}".format(
                    self.task_id, len(delta_pairs)))
            return {
                "delta_pair_count": len(delta_pairs),
                "delta_site_count": 0,
                "delta_saved_count": 0,
                "_stage_status": "partial",
                "partial_reason": "final_port_site_delta_failed",
                "warning": str(exc)[:500],
                "error_count": 1,
            }

    def _ensure_incremental_enrich_runtime(self):
        if not hasattr(self, "_incremental_enrich_lock"):
            self._incremental_enrich_lock = threading.Lock()
        if not hasattr(self, "_incremental_enrich_executor"):
            self._incremental_enrich_executor = None
        if not hasattr(self, "_incremental_enrich_futures"):
            self._incremental_enrich_futures = []

    def _save_incremental_sites_from_ip_info(self, ip_info_list, profile=""):
        self._ensure_incremental_enrich_runtime()
        if not Config.PORT_SCAN_INCREMENTAL_SITE_PROBE or not ip_info_list:
            return 0

        try:
            sites = find_site(ip_info_list, task_id=self.task_id, base_domain=self.base_domain)
        except Exception as e:
            self.incremental_site_probe_failed = True
            self._mark_port_site_probe_state(
                ip_info_list, profile, "failed", error=e)
            logger.warning("incremental find_site failed profile:{} task:{} error:{}".format(
                profile, self.task_id, e))
            return 0

        if not sites:
            self._mark_port_site_probe_state(
                ip_info_list, profile, "complete", site_count=0)
            return 0

        source = "port_scan_{}".format(profile or "incremental")
        saved = save_site_documents(self.task_id, [{
            "site": site,
            "source": source,
            "port_scan_profile": profile,
        } for site in sites])
        self._mark_port_site_probe_state(
            ip_info_list, profile, "complete", site_count=len(sites))
        with self._incremental_enrich_lock:
            self.site_list = list(set(self.site_list + sites))
            for site in sites:
                key = self._site_key(site)
                if key:
                    self.pending_incremental_sites[key] = site

        logger.info("incremental find_site profile:{} sites:{} saved:{} task:{}".format(
            profile, len(sites), saved, self.task_id))
        return saved

    def enrich_pending_incremental_sites(self, profile="", limit=None):
        self._ensure_incremental_enrich_runtime()
        with self._incremental_enrich_lock:
            has_pending = bool(self.pending_incremental_sites)
        if not has_pending or self.task_is_terminal():
            return 0

        if self._incremental_enriched_site_keys is None:
            self._incremental_enriched_site_keys = {
                self._site_key(item.get("site"))
                for item in utils.conn_db("site").find(
                    formal_site_query({
                        "task_id": self.task_id,
                        "fetch_site_complete": True,
                    }),
                    {"_id": 0, "site": 1},
                )
                if self._site_key(item.get("site"))
            }

        with self._incremental_enrich_lock:
            for key in list(self.pending_incremental_sites):
                if key in self._incremental_enriched_site_keys:
                    self.pending_incremental_sites.pop(key, None)

            pending_items = [
                (key, site) for key, site in self.pending_incremental_sites.items()
                if key not in self._incremental_enriched_site_keys
            ]
            if limit is None:
                limit = int(getattr(
                    Config, "PORT_SCAN_INCREMENTAL_ENRICH_BATCH_SIZE", 24) or 24)
            if limit and limit > 0:
                pending_items = pending_items[:limit]

            selected_keys = {key for key, _ in pending_items}
            new_sites = [site for _, site in pending_items]
            for key in selected_keys:
                self.pending_incremental_sites.pop(key, None)
        if not new_sites:
            return 0

        source = "port_scan_{}".format(profile or "incremental")
        saved_keys = set()

        def _save_batch(site_info_list, progress):
            for item in site_info_list:
                item["source"] = source
                item["port_scan_profile"] = profile
            save_site_documents(self.task_id, site_info_list)
            for item in site_info_list:
                key = self._site_key(item.get("site"))
                if key:
                    saved_keys.add(key)
                    self._incremental_enriched_site_keys.add(key)
            if self.options.get("site_identify"):
                self.insert_finger_stat()
            self.refresh_task_statistic()

        try:
            services.fetch_site(
                new_sites,
                observer_ward_enable=bool(self.options.get("site_identify")),
                task_id=self.task_id,
                on_batch=_save_batch,
            )
        except Exception as e:
            self.incremental_site_probe_failed = True
            logger.warning(
                "incremental fetch_site failed profile:{} task:{} error:{}".format(
                    profile, self.task_id, e))
            logger.exception(e)
        finally:
            with self._incremental_enrich_lock:
                for key, site in pending_items:
                    if key not in saved_keys:
                        self.pending_incremental_sites[key] = site

        return len(saved_keys)

    def _process_incremental_ip_batch(self, ip_info_batch, profile=""):
        site_saved = self._save_incremental_sites_from_ip_info(
            ip_info_batch, profile=profile)
        enriched = 0
        if site_saved:
            enriched = self.enrich_pending_incremental_sites(profile=profile)
        return {
            "site_saved": site_saved,
            "site_enriched": enriched,
        }

    def schedule_incremental_ip_batch(self, ip_info_batch, profile=""):
        self._ensure_incremental_enrich_runtime()
        if not Config.PORT_SCAN_INCREMENTAL_SITE_PROBE or not ip_info_batch:
            return False
        if self._incremental_enrich_executor is None:
            self._incremental_enrich_executor = ThreadPoolExecutor(
                max_workers=1, thread_name_prefix="arl-site-enrich")
        future = self._incremental_enrich_executor.submit(
            self._process_incremental_ip_batch, list(ip_info_batch), profile)
        self._incremental_enrich_futures.append(future)
        return True

    def drain_pending_incremental_sites(self, profile=""):
        self._ensure_incremental_enrich_runtime()
        enriched = 0
        for future in self._incremental_enrich_futures:
            try:
                result = future.result() or {}
                enriched += int(result.get("site_enriched", 0) or 0)
            except Exception as e:
                self.incremental_site_probe_failed = True
                logger.warning("wait incremental enrichment failed task:{} error:{}".format(
                    self.task_id, e))
        self._incremental_enrich_futures = []

        while not self.task_is_terminal():
            with self._incremental_enrich_lock:
                before = len(self.pending_incremental_sites)
            if not before:
                break
            current = self.enrich_pending_incremental_sites(profile=profile)
            enriched += current
            with self._incremental_enrich_lock:
                after = len(self.pending_incremental_sites)
            if current <= 0 or after >= before:
                break
        if self._incremental_enrich_executor is not None:
            self._incremental_enrich_executor.shutdown(wait=True)
            self._incremental_enrich_executor = None
        return enriched

    def _scan_port_with_options(self, domain_info_list, scan_option):
        if not domain_info_list:
            logger.warning("port_scan skipped, no alive non-cdn/waf ip from asset_seed_probe")
            return {"output_count": 0}

        def _on_batch(ip_info_batch, batch_index, total_batches, profile):
            saved = self._save_ip_info_objects(ip_info_batch)
            site_scheduled = self.schedule_incremental_ip_batch(
                ip_info_batch, profile=profile)
            try:
                stage_name = {
                    "top1000": "port_scan_top1000",
                    "full": "port_scan_full",
                }.get(profile, "port_scan")
                self.base_update_task.update_stage_progress(stage_name, {
                    "completed_batches": batch_index,
                    "total_batches": total_batches,
                    "last_batch_saved": saved,
                })
                self.refresh_task_statistic()
            except Exception as e:
                logger.warning("refresh task statistic after port batch failed task:{} error:{}".format(
                    self.task_id, e))
            logger.info("port_scan batch saved {}/{} profile:{} result:{} task:{}".format(
                batch_index, total_batches, profile, saved, self.task_id))
            if site_scheduled:
                logger.info(
                    "port_scan batch site pipeline queued {}/{} profile:{} task:{}".format(
                        batch_index, total_batches, profile, self.task_id))

        scan_option = copy.deepcopy(scan_option)
        scan_option["batch_callback"] = _on_batch
        ip_info_list = scan_port(domain_info_list, scan_option)
        self._save_ip_info_objects(ip_info_list)
        scan_meta = dict(getattr(ip_info_list, "meta", {}) or {})
        summary = {"output_count": len(ip_info_list)}
        summary.update(scan_meta)
        summary["output_count"] = len(ip_info_list)
        if scan_meta.get("partial"):
            summary.update({
                "_stage_status": "partial",
                "partial_reason": scan_meta.get("partial_reason") or "port_scan_partial",
                "warning": scan_meta.get("warning") or "port scan had incomplete batches",
                "error_count": int(scan_meta.get("error_count", 0) or 0),
            })
        elif scan_meta.get("continuation_required"):
            summary.update({
                "_stage_status": "deferred",
                "completion_state": "deferred",
            })
        elif scan_meta.get("completion_state") == "done_with_warnings":
            summary.update({
                "_stage_status": "done_with_warnings",
                "completion_state": "done_with_warnings",
                "warning": scan_meta.get("warning") or "port discovery fallback completed",
            })
        return summary

    def port_scan(self, ports=None, exclude_extra_ports=None, max_targets=None):
        domain_info_list = self._port_scan_domain_info()
        scan_option = copy.deepcopy(self.scan_port_option)
        if ports is not None:
            scan_option["ports"] = ports
        if exclude_extra_ports:
            scan_option["exclude_ports"] = self._merge_exclude_ports(
                scan_option.get("exclude_ports"), exclude_extra_ports)
        if scan_option.get("ports") == ScanPortType.ALL:
            if max_targets is None:
                max_targets = (
                    max(int(getattr(
                        Config, "FULL_PORT_TASK_SLICE_MAX_IPS", 18) or 0), 0)
                    if getattr(Config, "DOMAIN_PHASED_WORKFLOW", True)
                    else 0
                )
            scan_option["max_targets"] = max(int(max_targets or 0), 0)
        scan_option["trusted_port_map"] = self._trusted_port_map_for_scan()
        try:
            summary = self._scan_port_with_options(domain_info_list, scan_option)
        except Exception:
            self.drain_pending_incremental_sites(profile="failed")
            raise
        if scan_option.get("ports") == ScanPortType.ALL:
            profile = "full"
        elif scan_option.get("ports") == ScanPortType.TOP1000:
            profile = "top1000"
        else:
            profile = "default"
        summary["enriched_site_count"] = self.drain_pending_incremental_sites(profile=profile)
        return summary

    def port_scan_top1000(self):
        return self.port_scan(ports=ScanPortType.TOP1000)

    def port_scan_full(self):
        exclude_ports = Config.TOP_1000 if Config.FULL_PORT_REMAINING_ONLY else None
        return self.port_scan(ports=ScanPortType.ALL, exclude_extra_ports=exclude_ports)

    def _service_port_exists(self, ip, port):
        try:
            port = int(port)
        except Exception:
            return True

        for ip_info in self.ip_info_list:
            if ip_info.ip != ip:
                continue
            for port_info in ip_info.port_info_list:
                if int(port_info.port_id) == port:
                    return True
        return False

    def _append_known_service_ip_info(self, ip, port, domain="", scheme="http", source="known_service_seed"):
        try:
            port_id = int(port)
        except Exception:
            return False

        if self._service_port_exists(ip, port_id):
            return False

        service_name = "https" if scheme == "https" else "http"
        port_info = modules.PortInfo(**{
            "port_id": port_id,
            "service_name": service_name,
            "version": "",
            "protocol": "tcp",
            "product": source,
        })
        domains = []
        if domain:
            domains.append(domain)
        item = {
            "ip": ip,
            "domain": domains,
            "port_info": [port_info],
            "cdn_name": utils.get_cdn_name_by_ip(ip),
            "os_info": {},
        }
        self.ip_info_list.append(modules.IPInfo(**item))
        return True

    def _ip_has_current_dns_relation(self, ip):
        return bool(ip and ip in self.ipv4_map and self.ipv4_map.get(ip))

    def _candidate_has_current_dns_relation(self, item):
        ip = str(item.get("ip") or "").strip()
        domain = str(item.get("domain") or "").strip(".").lower()
        if not ip or ip not in self.ipv4_map:
            return False
        if not domain:
            return True
        return domain in self.ipv4_map.get(ip, set())

    @staticmethod
    def _candidate_is_quarantined(item):
        status = str(item.get("status") or "").strip().lower()
        verify_status = str(item.get("cert_verify_status") or "").strip().lower()
        return bool(
            item.get("candidate_type") == "cert_ip" and (
                status == "quarantined" or
                item.get("pipeline_eligible") is False or
                verify_status.startswith("quarantined_")
            )
        )

    def _candidate_is_pipeline_eligible(self, item):
        if self._candidate_is_quarantined(item):
            return False
        if item.get("candidate_type") == "cert_ip":
            return bool(
                item.get("pipeline_eligible") is True and
                item.get("cert_verified") is True and
                item.get("verified_ports") and
                self._candidate_has_current_dns_relation(item)
            )
        return self._candidate_has_current_dns_relation(item)

    def _candidate_ports_for_pipeline(self, item):
        if not self._candidate_is_pipeline_eligible(item):
            return []
        if item.get("candidate_type") == "cert_ip":
            values = list(item.get("verified_ports") or [])
        else:
            values = list(item.get("ports") or [])
            if item.get("port") not in (None, ""):
                values.append(item.get("port"))

        ports = set()
        for value in values:
            try:
                port = int(value)
            except (TypeError, ValueError):
                continue
            if 0 < port <= 65535:
                ports.add(port)
        return sorted(ports)

    def _load_quarantined_candidate_ips(self):
        states = {}
        for item in utils.conn_db("asset_seed_candidate").find(
            {"task_id": self.task_id, "candidate_type": "cert_ip"},
            {
                "_id": 0,
                "ip": 1,
                "domain": 1,
                "candidate_type": 1,
                "cert_verify_status": 1,
                "pipeline_eligible": 1,
                "status": 1,
                "cert_verified": 1,
                "verified_ports": 1,
            },
        ):
            ip = str(item.get("ip") or "").strip()
            if not ip:
                continue
            state = states.setdefault(ip, {
                "current_dns": False,
                "eligible": False,
                "quarantined": False,
            })
            state["current_dns"] = (
                state["current_dns"] or self._candidate_has_current_dns_relation(item))
            state["eligible"] = (
                state["eligible"] or self._candidate_is_pipeline_eligible(item))
            state["quarantined"] = (
                state["quarantined"] or self._candidate_is_quarantined(item))
        return {
            ip for ip, state in states.items()
            if not state["eligible"] and not state["current_dns"]
        }

    def _cert_candidate_sni(self, item):
        values = [item.get("domain")]
        values.extend(self._list_value(item.get("domains")))
        for value in values:
            domain = str(value or "").strip(".").lower()
            if domain and utils.check_domain_black(domain):
                continue
            if domain == self.base_domain or domain.endswith("." + self.base_domain):
                return domain
        return self.base_domain

    def _cert_control_sni(self, ip, port):
        task_marker = re.sub(r"[^a-z0-9]", "", str(self.task_id).lower())[-12:]
        ip_marker = str(ip or "").replace(".", "-")
        return "arl-control-{}-{}-{}.invalid".format(
            task_marker or "task", ip_marker, port)

    def _cert_sni_oracle_canaries(self):
        raw = getattr(
            Config,
            "CERT_CANDIDATE_SNI_CANARIES",
            "baidu.com,qq.com,microsoft.com",
        )
        if isinstance(raw, str):
            values = raw.split(",")
        else:
            values = list(raw or [])

        canaries = []
        base_domain = str(self.base_domain or "").strip(".").lower()
        for value in values:
            domain = str(value or "").strip(".").lower()
            if not domain or not utils.is_valid_domain(domain):
                continue
            if (
                domain == base_domain or
                domain.endswith("." + base_domain) or
                base_domain.endswith("." + domain)
            ):
                continue
            if domain not in canaries:
                canaries.append(domain)
        return canaries

    @staticmethod
    def _cert_fingerprint(cert):
        fingerprints = cert.get("fingerprint") or {}
        for name in ("sha256", "sha1", "md5"):
            value = str(fingerprints.get(name) or "").strip().lower()
            if value:
                return "{}:{}".format(name, value)
        return "fallback:{}|{}|{}|{}".format(
            cert.get("serial_number") or "",
            cert.get("subject_dn") or "",
            (cert.get("subject") or {}).get("common_name") or "",
            (cert.get("extensions") or {}).get("subjectAltName") or "",
        )

    def _domain_name_is_edge(self, domain):
        domain = str(domain or "").strip().strip(".").lower()
        base_domain = str(self.base_domain or "").strip().strip(".").lower()
        in_scope = bool(base_domain and (
            domain == base_domain or domain.endswith("." + base_domain)
        ))
        if domain and not in_scope:
            match = utils.get_cdn_match_by_cname_strict(domain)
            if match and match.get("match_scope") != "record_only":
                return True
        edge_info = classify_edge_host(domain, self.base_domain)
        return bool(edge_info.get("is_edge"))

    def _domain_info_is_edge(self, info):
        domain = str(getattr(info, "domain", "") or "").strip().strip(".").lower()
        preprobe_state = getattr(self, "preprobe_domain_state", {}).get(domain) or {}
        if (preprobe_state and
                preprobe_state.get("edge_pipeline_eligible") is False):
            return True
        if self._domain_name_is_edge(getattr(info, "domain", "")):
            return True

        for record in getattr(info, "record_list", []) or []:
            record = str(record or "").strip().strip(".").lower()
            if not record:
                continue
            if (self.options.get("skip_scan_cdn_ip") and
                    utils.get_cdn_match_by_cname_strict(record)):
                return True
            if self.options.get("skip_scan_cdn_ip") and classify_edge_infrastructure(record):
                return True
        return False

    def _domain_name_is_collision_noise(self, domain):
        labels = [x for x in str(domain or "").strip(".").lower().split(".") if x]
        base_labels = [x for x in str(self.base_domain or "").strip(".").lower().split(".") if x]
        if base_labels and labels[-len(base_labels):] == base_labels:
            labels = labels[:-len(base_labels)]
        noisy_labels = {"cdn", "waf", "edge", "proxy", "shield", "firewall", "ztna", "sase"}
        return bool(set(labels) & noisy_labels)

    def _build_edge_asset_ips(self):
        edge_ips = set()
        edge_domains_by_ip = {}
        for info in self.domain_info_list:
            if not self._domain_info_is_edge(info):
                continue
            for ip in info.ip_list:
                edge_domains_by_ip.setdefault(ip, set()).add(info.domain)

        for ip, domains in (self.ipv4_map or {}).items():
            if not domains:
                continue
            edge_domains = edge_domains_by_ip.get(ip, set())
            ztna_domains = [domain for domain in domains if is_ztna_host(domain)]
            if len(domains) >= 3 and len(ztna_domains) == len(domains):
                edge_ips.add(ip)
                continue
            if not edge_domains:
                continue
            edge_ratio = float(len(edge_domains)) / float(len(domains))
            if len(edge_domains) == len(domains) or (len(edge_domains) >= 10 and edge_ratio >= 0.8):
                edge_ips.add(ip)

        self.edge_asset_ips = edge_ips
        if edge_ips:
            logger.info("edge asset ips filtered:{} sample:{}".format(
                len(edge_ips), sorted(edge_ips)[:8]))

    def _ip_is_edge_only(self, ip):
        return bool(ip and ip in getattr(self, "edge_asset_ips", set()))

    def _candidate_is_edge(self, item):
        domain = str(item.get("domain") or "").strip(".").lower()
        ip = str(item.get("ip") or "").strip()
        if domain and self._domain_name_is_edge(domain):
            return True
        return self._ip_is_edge_only(ip)

    def verify_cert_query_candidates(self):
        if not getattr(Config, "CERT_CANDIDATE_VERIFY_ENABLE", True):
            return {"input_count": 0, "output_count": 0, "skipped": True}

        batch_size = max(int(getattr(
            Config, "CERT_CANDIDATE_VERIFY_BATCH_SIZE", 500) or 500), 1)
        concurrency = max(int(getattr(
            Config, "CERT_CANDIDATE_VERIFY_CONCURRENCY", 20) or 20), 1)
        candidates = list(utils.conn_db("asset_seed_candidate").find(
            {
                "task_id": self.task_id,
                "candidate_type": "cert_ip",
                "ip_type": "PUBLIC",
            },
            {
                "_id": 1,
                "ip": 1,
                "domain": 1,
                "domains": 1,
                "port": 1,
                "ports": 1,
                "sources": 1,
                "candidate_type": 1,
            },
        ))
        targets = []
        target_docs = {}
        candidate_results = {}
        for item in candidates:
            ip = str(item.get("ip") or "").strip()
            if not ip or not utils.not_in_black_ips(ip):
                continue
            sni_domain = self._cert_candidate_sni(item)
            candidate_results.setdefault(item["_id"], {
                "item": item,
                "checked_count": 0,
                "no_cert_count": 0,
                "scope_mismatch_count": 0,
                "shared_default_ports": set(),
                "cert_only_ports": set(),
                "sni_oracle_ports": set(),
                "verified_ports": set(),
                "verified_domains": set(),
                "evidence": [],
            })
            ports = list(item.get("ports") or [])
            if item.get("port") not in (None, ""):
                ports.append(item.get("port"))
            normalized_ports = []
            for raw_port in ports:
                try:
                    port = int(raw_port)
                except (TypeError, ValueError):
                    continue
                if port <= 0 or port > 65535 or port == 80:
                    continue
                if port not in normalized_ports:
                    normalized_ports.append(port)
            if not normalized_ports:
                normalized_ports = [443]
            for port in normalized_ports:
                target = (ip, port, sni_domain)
                if target in target_docs:
                    target_docs[target].append(item)
                    continue
                targets.append(target)
                target_docs[target] = [item]

        def fetch_in_batches(batch_targets, stage):
            fetched = {}
            if not batch_targets:
                return fetched
            total_batches = (len(batch_targets) + batch_size - 1) // batch_size
            with acquire_resource_budget(
                    "tool:cert", task_id=self.task_id, stage=stage):
                for offset in range(0, len(batch_targets), batch_size):
                    batch = batch_targets[offset:offset + batch_size]
                    batch_no = offset // batch_size + 1
                    logger.info(
                        "cert candidate batch {}/{} stage:{} targets:{} task:{}".format(
                            batch_no, total_batches, stage, len(batch), self.task_id))
                    fetched.update(services.fetch_cert_sni(
                        batch, concurrency=concurrency) or {})
            return fetched

        cert_map = fetch_in_batches(targets, "cert_candidate_verify")

        control_targets = []
        for target, cert in cert_map.items():
            if not cert or not cert_matches_domain(cert, self.base_domain):
                continue
            ip, port, _ = target
            control_targets.append((ip, port, self._cert_control_sni(ip, port)))
        control_targets = list(dict.fromkeys(control_targets))
        control_cert_map = fetch_in_batches(
            control_targets, "cert_candidate_sni_control")
        missing_control_targets = [
            target for target in control_targets if target not in control_cert_map]
        if missing_control_targets:
            control_cert_map.update(fetch_in_batches(
                missing_control_targets, "cert_candidate_sni_control_retry"))

        canary_domains = self._cert_sni_oracle_canaries()
        oracle_min_matches = max(int(getattr(
            Config, "CERT_CANDIDATE_SNI_ORACLE_MIN_MATCHES", 2) or 2), 2)
        oracle_endpoints = set()
        for target, cert in cert_map.items():
            if not cert or not cert_matches_domain(cert, self.base_domain):
                continue
            if any(
                    self._candidate_has_current_dns_relation(item)
                    for item in target_docs.get(target, [])):
                continue
            ip, port, _ = target
            control_sni = self._cert_control_sni(ip, port)
            control_cert = control_cert_map.get((ip, port, control_sni))
            if (
                not control_cert or
                self._cert_fingerprint(cert) != self._cert_fingerprint(control_cert)
            ):
                oracle_endpoints.add((ip, port))

        canary_targets = [
            (ip, port, canary)
            for ip, port in sorted(oracle_endpoints)
            for canary in canary_domains
        ]
        canary_cert_map = fetch_in_batches(
            canary_targets, "cert_candidate_sni_oracle")
        oracle_evidence = {}
        oracle_endpoint_count = 0
        for ip, port in sorted(oracle_endpoints):
            values = []
            match_count = 0
            for canary in canary_domains:
                canary_cert = canary_cert_map.get((ip, port, canary))
                canary_matched = bool(
                    canary_cert and cert_matches_domain(canary_cert, canary))
                if canary_matched:
                    match_count += 1
                values.append({
                    "sni": canary,
                    "matched": canary_matched,
                    "fingerprint": (
                        self._cert_fingerprint(canary_cert) if canary_cert else ""),
                })
            is_oracle = bool(
                len(canary_domains) >= oracle_min_matches and
                match_count >= oracle_min_matches)
            if is_oracle:
                oracle_endpoint_count += 1
            oracle_evidence[(ip, port)] = {
                "is_oracle": is_oracle,
                "match_count": match_count,
                "checks": values,
            }

        verified = 0
        rejected = 0
        no_cert = 0
        quarantined = 0
        san_domains = set()
        now = utils.curr_date()
        for target in targets:
            ip, port, sni_domain = target
            cert = cert_map.get(target)
            if not cert:
                for item in target_docs.get(target, []):
                    result = candidate_results[item["_id"]]
                    result["checked_count"] += 1
                    result["no_cert_count"] += 1
                continue

            cert_domains = extract_cert_domains(
                cert, self.base_domain, include_wildcard=True)
            domains = sorted({
                domain[2:] if domain.startswith("*.") else domain
                for domain in cert_domains
                if domain
            })
            matched = bool(cert_domains and cert_matches_domain(cert, self.base_domain))
            control_sni = self._cert_control_sni(ip, port)
            control_cert = control_cert_map.get((ip, port, control_sni)) if matched else None
            target_fingerprint = self._cert_fingerprint(cert)
            control_fingerprint = self._cert_fingerprint(control_cert) if control_cert else ""
            sni_distinct = bool(
                matched and (
                    not control_cert or target_fingerprint != control_fingerprint
                )
            )
            endpoint_oracle = oracle_evidence.get((ip, port), {})
            sni_oracle = bool(endpoint_oracle.get("is_oracle"))
            endpoint_eligible = False
            evidence = {
                "ip": ip,
                "port": port,
                "target_sni": sni_domain,
                "control_sni": control_sni if matched else "",
                "target_fingerprint": target_fingerprint,
                "control_fingerprint": control_fingerprint,
                "matched": matched,
                "sni_distinct": sni_distinct,
                "sni_oracle": sni_oracle,
                "sni_canary_match_count": int(
                    endpoint_oracle.get("match_count") or 0),
                "sni_canary_evidence": list(
                    endpoint_oracle.get("checks") or []),
            }
            for item in target_docs.get(target, []):
                result = candidate_results[item["_id"]]
                result["checked_count"] += 1
                current_dns = self._candidate_has_current_dns_relation(item)
                eligible = bool(matched and current_dns)
                endpoint_eligible = endpoint_eligible or eligible
                item_evidence = dict(evidence)
                item_evidence["current_dns"] = current_dns
                item_evidence["pipeline_eligible"] = eligible
                result["evidence"].append(item_evidence)
                if eligible:
                    result["verified_ports"].add(port)
                    result["verified_domains"].update(domains)
                elif matched:
                    if sni_oracle:
                        result["sni_oracle_ports"].add(port)
                    elif sni_distinct:
                        result["cert_only_ports"].add(port)
                    else:
                        result["shared_default_ports"].add(port)
                else:
                    result["scope_mismatch_count"] += 1

            if endpoint_eligible:
                relation_reason = "current_dns_plus_cert"
            elif sni_oracle:
                relation_reason = "multi_sni_cert_oracle"
            elif matched and sni_distinct:
                relation_reason = "no_current_dns_relation"
            elif matched:
                relation_reason = "same_certificate_for_random_sni"
            else:
                relation_reason = "cert_cn_san_mismatch"
            cert_item = {
                "task_id": self.task_id,
                "target": self.base_domain,
                "ip": ip,
                "port": port,
                "cert": cert,
                "matched": matched,
                "relation_level": "strong" if endpoint_eligible else "weak",
                "relation_reason": relation_reason,
                "verified_domains": domains if endpoint_eligible else [],
                "pipeline_eligible": endpoint_eligible,
                "candidate_disposition": (
                    "pipeline" if endpoint_eligible else "host_only"),
                "host_collision_eligible": bool(
                    endpoint_eligible or not sni_oracle),
                "target_sni": sni_domain,
                "control_sni": control_sni if matched else "",
                "target_fingerprint": target_fingerprint,
                "control_fingerprint": control_fingerprint,
                "sni_distinct": sni_distinct,
                "sni_oracle": sni_oracle,
                "sni_canary_match_count": int(
                    endpoint_oracle.get("match_count") or 0),
                "sni_canary_evidence": list(
                    endpoint_oracle.get("checks") or []),
                "source": "cert_query_active_verify",
                "save_date": now,
            }
            if endpoint_eligible:
                utils.conn_db("cert").update_one(
                    {"task_id": self.task_id, "ip": ip, "port": port},
                    {"$set": cert_item}, upsert=True)
            else:
                utils.conn_db("cert_candidate").update_one(
                    {"task_id": self.task_id, "ip": ip, "port": port},
                    {"$set": cert_item}, upsert=True)
                utils.conn_db("cert").delete_many(
                    {
                        "task_id": self.task_id,
                        "ip": ip,
                        "port": port,
                        "source": "cert_query_active_verify",
                    })

        for result in candidate_results.values():
            item = result["item"]
            query = {"_id": item["_id"]}
            verified_ports = sorted(result["verified_ports"])
            verified_domains = sorted(result["verified_domains"])
            shared_ports = sorted(result["shared_default_ports"])
            cert_only_ports = sorted(result["cert_only_ports"])
            sni_oracle_ports = sorted(result["sni_oracle_ports"])
            if verified_ports:
                state_update = {
                    "$set": {
                        "cert_verified": True,
                        "cert_verify_status": "verified_dns",
                        "cert_checked_at": now,
                        "relation_level": "strong",
                        "status": "verified",
                        "pipeline_eligible": True,
                        "verified_domains": verified_domains,
                        "candidate_disposition": "pipeline",
                        "host_collision_eligible": True,
                        "verified_ports": verified_ports,
                        "cert_sni_evidence": result["evidence"],
                    },
                    "$unset": {
                        "quarantine_reason": "",
                        "quarantined_at": "",
                        "rejection_reason": "",
                        "rejected_at": "",
                        "pipeline_exclusion_reason": "",
                        "shared_default_ports": "",
                        "cert_only_ports": "",
                        "sni_oracle_ports": "",
                    },
                    "$addToSet": {
                        "sources": "cert_query_active_verify",
                    },
                }
                self.verified_cert_ip_domains.setdefault(
                    str(item.get("ip") or "").strip(), set()).update(verified_domains)
                san_domains.update(verified_domains)
                verified += 1
            else:
                if sni_oracle_ports:
                    verify_status = "quarantined_sni_oracle"
                    exclusion_reason = "multi_sni_cert_oracle"
                    candidate_status = "quarantined"
                elif cert_only_ports:
                    verify_status = "quarantined_cert_only"
                    exclusion_reason = "no_current_dns_relation"
                    candidate_status = "quarantined"
                elif shared_ports:
                    verify_status = "quarantined_shared_default"
                    exclusion_reason = "same_certificate_for_random_sni"
                    candidate_status = "quarantined"
                elif result["scope_mismatch_count"]:
                    verify_status = "rejected_scope_mismatch"
                    exclusion_reason = "cert_cn_san_mismatch"
                    candidate_status = "rejected"
                else:
                    verify_status = "quarantined_no_cert"
                    exclusion_reason = "no_active_cert"
                    candidate_status = "quarantined"
                    no_cert += 1
                state_update = {
                    "$set": {
                        "cert_verified": False,
                        "cert_verify_status": verify_status,
                        "cert_checked_at": now,
                        "relation_level": "weak",
                        "status": candidate_status,
                        "pipeline_eligible": False,
                        "pipeline_exclusion_reason": exclusion_reason,
                        "candidate_disposition": "host_only",
                        "host_collision_eligible": not bool(sni_oracle_ports),
                        "verified_domains": [],
                        "verified_ports": [],
                        "shared_default_ports": shared_ports,
                        "cert_only_ports": cert_only_ports,
                        "sni_oracle_ports": sni_oracle_ports,
                        "cert_sni_evidence": result["evidence"],
                    },
                    "$addToSet": {
                        "sources": "cert_query_active_verify",
                    },
                }
                if candidate_status == "rejected":
                    state_update["$set"].update({
                        "rejection_reason": exclusion_reason,
                        "rejected_at": now,
                    })
                    state_update["$unset"] = {
                        "quarantine_reason": "",
                        "quarantined_at": "",
                    }
                    rejected += 1
                else:
                    state_update["$set"].update({
                        "quarantine_reason": exclusion_reason,
                        "quarantined_at": now,
                    })
                    state_update["$unset"] = {"rejection_reason": "", "rejected_at": ""}
                    quarantined += 1

            utils.conn_db("asset_seed_candidate").update_many(query, state_update)
            vhost_query = {
                "task_id": self.task_id,
                "ip": item.get("ip"),
                "candidate_type": "cert_ip",
            }
            if item.get("domain"):
                vhost_query["domain"] = item.get("domain")
            utils.conn_db("vhost_ip_candidate").update_many(vhost_query, state_update)

        self.quarantined_candidate_ips = self._load_quarantined_candidate_ips()

        new_domain_info = self.build_domain_info(sorted(san_domains)) if san_domains else []
        if new_domain_info:
            self.save_domain_info_list(new_domain_info, source="cert_query_verified")
            existing = {item.domain for item in self.domain_info_list}
            self.domain_info_list.extend(
                item for item in new_domain_info if item.domain not in existing)
            self.post_seed_domains.update(item.domain for item in new_domain_info)

        resolved = {item.domain for item in new_domain_info}
        unresolved = [domain for domain in sorted(san_domains) if domain not in resolved]
        existing_resolved = set()
        if unresolved:
            for item in utils.conn_db("domain").find(
                    formal_domain_query({
                        "task_id": self.task_id,
                        "domain": {"$in": unresolved},
                    }),
                    {"_id": 0, "domain": 1, "record": 1, "ips": 1}):
                if item.get("record") or item.get("ips"):
                    existing_resolved.add(item.get("domain"))
        unresolved_to_save = [
            domain for domain in unresolved if domain not in existing_resolved]
        if unresolved_to_save:
            save_domain_documents(self.task_id, [
                {
                    "domain": domain,
                    "type": "UNKNOWN",
                    "record": [],
                    "ips": [],
                    "resolve_status": "unresolved",
                }
                for domain in unresolved_to_save
            ], "cert_query_verified")
        if unresolved:
            self.post_seed_domains.update(unresolved)

        return {
            "input_count": len(targets),
            "output_count": verified,
            "rejected_count": rejected,
            "no_cert_count": no_cert,
            "quarantined_count": quarantined,
            "sni_control_count": len(control_targets),
            "sni_control_retry_count": len(missing_control_targets),
            "sni_canary_count": len(canary_targets),
            "sni_oracle_endpoint_count": oracle_endpoint_count,
            "verified_port_count": sum(
                len(result["verified_ports"]) for result in candidate_results.values()),
            "san_domain_count": len(san_domains),
            "san_unresolved_preserved_count": len(existing_resolved),
            "candidate_count": len(candidates),
            "verify_batch_size": batch_size,
            "verify_batch_count": (
                (len(targets) + batch_size - 1) // batch_size if targets else 0),
            "candidate_truncated_count": 0,
        }

    def _ip_has_edge_probe_marker(self, ip):
        ip = str(ip or "").strip()
        if not ip:
            return False

        fields = {
            "_id": 0, "cdn": 1, "cdn_name": 1, "is_cdn": 1,
            "waf": 1, "waf_name": 1, "waf_strength": 1, "is_waf": 1,
            "edge": 1, "edge_name": 1, "tag": 1, "webserver": 1, "cname": 1,
        }
        query = formal_pipeline_query({"task_id": self.task_id, "ip": ip})
        for item in utils.conn_db("asset_seed_alive").find(query, fields).limit(5):
            if has_strong_edge_marker(item):
                return True
        return False

    def _ip_is_port_scan_overopen(self, ip):
        ip = str(ip or "").strip()
        if not ip:
            return False
        item = utils.conn_db("ip").find_one(
            {"task_id": self.task_id, "ip": ip},
            {"_id": 0, "port_scan_overopen": 1}
        )
        return bool(item and item.get("port_scan_overopen"))

    def _collision_target_ip_allowed(self, ip, skipped=None):
        ip = str(ip or "").strip()
        if not ip or not utils.not_in_black_ips(ip):
            if skipped is not None:
                skipped["invalid_ip"] += 1
            return False
        if utils.get_ip_type(ip) != "PUBLIC":
            if skipped is not None:
                skipped["non_public_ip"] += 1
            return False
        if self._ip_is_edge_only(ip):
            if skipped is not None:
                skipped["edge_ip"] += 1
            return False
        if getattr(Config, "HOST_COLLISION_SKIP_CDN_IP", True) and utils.get_cdn_name_by_ip(ip):
            if skipped is not None:
                skipped["cdn_ip"] += 1
            return False
        if getattr(Config, "HOST_COLLISION_SKIP_EDGE_MARKED_IP", True) and self._ip_has_edge_probe_marker(ip):
            if skipped is not None:
                skipped["waf_or_edge_marked_ip"] += 1
            return False
        if getattr(Config, "HOST_COLLISION_SKIP_OVEROPEN_IP", True) and self._ip_is_port_scan_overopen(ip):
            if skipped is not None:
                skipped["overopen_ip"] += 1
            return False
        return True

    def _should_use_candidate_ip(self, item):
        ip = str(item.get("ip") or "").strip()
        if not ip or not utils.not_in_black_ips(ip):
            return False
        if utils.get_ip_type(ip) != "PUBLIC":
            return False
        if not self._candidate_is_pipeline_eligible(item):
            return False
        if self._candidate_is_edge(item):
            return False
        if self.options.get("skip_scan_cdn_ip") and utils.get_cdn_name_by_ip(ip):
            return False
        return True

    def known_service_seed(self):
        query = {
            "task_id": self.task_id,
            "ip_type": "PUBLIC",
            "ports": {"$exists": True, "$ne": []}
        }
        candidates = list(utils.conn_db("asset_seed_candidate").find(
            query,
            {"_id": 0, "ip": 1, "domain": 1, "ports": 1, "source": 1,
             "port": 1, "candidate_type": 1, "cert_verified": 1,
             "cert_verify_status": 1, "pipeline_eligible": 1, "status": 1,
             "verified_ports": 1}
        ))
        if not candidates:
            return {"input_count": 0, "output_count": 0}

        url_meta = {}
        skipped_weak = 0
        skipped_edge = 0
        for item in candidates:
            ip = str(item.get("ip") or "").strip()
            if not ip or not utils.not_in_black_ips(ip):
                continue
            if not self._candidate_is_pipeline_eligible(item):
                skipped_weak += 1
                continue
            if self._candidate_is_edge(item):
                skipped_edge += 1
                continue
            if self.options.get("skip_scan_cdn_ip") and utils.get_cdn_name_by_ip(ip):
                skipped_edge += 1
                continue

            for port in self._candidate_ports_for_pipeline(item):
                try:
                    port_id = int(port)
                except Exception:
                    continue

                schemes = ["https", "http"] if port_id in [443, 8443, 9443, 10443, 12443] else ["http", "https"]
                for scheme in schemes:
                    if (scheme == "http" and port_id == 80) or (scheme == "https" and port_id == 443):
                        url = "{}://{}".format(scheme, ip)
                    else:
                        url = "{}://{}:{}".format(scheme, ip, port_id)
                    url_meta[url] = {
                        "ip": ip,
                        "port": port_id,
                        "domain": item.get("domain", ""),
                        "source": item.get("source", "known_service_seed"),
                    }

        alive_urls = services.httpx_probe_urls(
            list(url_meta.keys()),
            task_id=self.task_id,
            base_domain=self.base_domain,
            source="known_service_seed",
        )

        appended = 0
        for url in alive_urls:
            meta = url_meta.get(url)
            if not meta:
                parsed = urlparse(url)
                host = parsed.hostname or ""
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
                meta = {"ip": host, "port": port, "domain": "", "source": "known_service_seed"}

            parsed = urlparse(url)
            if self._append_known_service_ip_info(
                meta.get("ip", ""),
                meta.get("port", ""),
                domain=meta.get("domain", ""),
                scheme=parsed.scheme or "http",
                source=meta.get("source", "known_service_seed"),
            ):
                appended += 1

        if alive_urls:
            self.asset_seed_alive_sites = list(set(self.asset_seed_alive_sites + alive_urls))

        logger.info("known_service_seed candidates:{} urls:{} alive:{} appended:{} skipped_weak:{} skipped_edge:{}".format(
            len(candidates), len(url_meta), len(alive_urls), appended, skipped_weak, skipped_edge))
        return {
            "input_count": len(url_meta),
            "output_count": len(alive_urls),
            "service_count": appended,
            "skipped_weak": skipped_weak,
            "skipped_edge": skipped_edge,
        }

    def prefill_asset_seed_results(self):
        saved_ip_with_ports = 0
        if self.ip_info_list:
            saved_ip_with_ports = self._save_ip_info_objects(self.ip_info_list)

        self.save_ip_info()

        site_docs = []
        seen_sites = set()
        for item in utils.conn_db("asset_seed_alive").find(
            formal_pipeline_query({"task_id": self.task_id}),
            {"_id": 0, "url": 1, "title": 1, "status_code": 1, "ip": 1,
             "cdn": 1, "cdn_name": 1, "waf": 1, "waf_name": 1,
             "waf_strength": 1, "waf_reason": 1, "webserver": 1,
             "tech": 1, "edge": 1, "edge_name": 1, "edge_reasons": 1, "tag": 1}
        ):
            url = item.get("url")
            if not url or url in seen_sites:
                continue
            seen_sites.add(url)

            finger = []
            for tech in item.get("tech") or []:
                if tech:
                    finger.append({"name": tech})

            site_docs.append({
                "site": url,
                "title": item.get("title", ""),
                "status": item.get("status_code"),
                "finger": finger,
                "ip": item.get("ip", ""),
                "cdn": item.get("cdn", False),
                "cdn_name": item.get("cdn_name", ""),
                "waf": item.get("waf", False),
                "waf_name": item.get("waf_name", ""),
                "waf_strength": item.get("waf_strength", "none"),
                "waf_reason": item.get("waf_reason", ""),
                "edge": item.get("edge", False),
                "edge_name": item.get("edge_name", ""),
                "edge_reasons": item.get("edge_reasons", []),
                "tag": item.get("tag", []),
                "webserver": item.get("webserver", ""),
            })

        saved_site = save_site_documents(self.task_id, site_docs)
        self.insert_finger_stat()
        self.insert_cip_stat()
        self.insert_task_stat()
        ip_count = utils.conn_db("ip").count_documents({"task_id": self.task_id})
        return {
            "input_count": len(self.ip_info_list) + len(seen_sites),
            "output_count": saved_ip_with_ports + saved_site,
            "ip_count": ip_count,
            "site_count": saved_site,
            "seed_site_count": len(seen_sites),
            "saved_ip_with_ports": saved_ip_with_ports,
        }

    def find_site(self):
        if self.options.get("port_scan"):
            if Config.PORT_SCAN_INCREMENTAL_SITE_PROBE:
                delta_summary = self.reconcile_port_site_probe_delta()
                sites = list(set(self.site_list))
                logger.info(
                    "find_site reconcile incremental sites:{} delta_pairs:{} task:{}".format(
                        len(sites), delta_summary.get("delta_pair_count", 0), self.task_id))
            else:
                delta_summary = {}
                sites = find_site(
                    self.ip_info_list,
                    task_id=self.task_id,
                    base_domain=self.base_domain,
                )
        else:
            delta_summary = {}
            sites = []

        if Config.ASSET_SEED_PROBE:
            direct_domain_targets = sorted(self.post_seed_domains)
        else:
            direct_domain_targets = self.domain_info_list

        if direct_domain_targets:
            direct_sites = probe_domain_sites(
                direct_domain_targets,
                task_id=self.task_id,
                base_domain=self.base_domain,
                source="post_seed_site" if Config.ASSET_SEED_PROBE else "direct_site",
                ports=Config.ASSET_SEED_WEB_PORTS if Config.ASSET_SEED_PROBE else None,
            )
            if direct_sites:
                logger.info("find_site direct probe add {}, existing sites {}".format(
                    len(direct_sites), len(sites)))
                sites = list(set(sites + direct_sites))

        if self.asset_seed_alive_sites:
            sites = list(set(sites + self.asset_seed_alive_sites))

        sites = self._filter_edge_sites(sites)

        self.site_list.extend(sites)
        summary = {
            "input_count": len(self.domain_info_list),
            "output_count": len(set(sites)),
        }
        summary.update(delta_summary)
        return summary

    def update_services(self, service_name, elapsed, summary=None):
        self.base_update_task.update_services(service_name=service_name, elapsed=elapsed, summary=summary)

    def update_task_field(self, field=None, value=None):
        self.base_update_task.update_task_field(field=field, value=value)

    def run_stage(self, stage_name, func, input_count=None):
        self.update_task_field("status", stage_name)
        if not self.base_update_task.start_stage(stage_name, input_count=input_count):
            logger.warning("skip stage {} because task is terminal, task_id:{}".format(stage_name, self.task_id))
            return {}

        t1 = time.time()
        summary = None
        try:
            summary = func()
        except Exception as e:
            elapse = time.time() - t1
            self.base_update_task.fail_stage(stage_name, e, elapsed=elapse)
            raise

        elapse = time.time() - t1
        summary, stage_status = split_stage_summary(summary)
        self.base_update_task.update_services(
            stage_name, elapse, summary=summary, status=stage_status)
        try:
            self.refresh_task_statistic(force=True)
        except Exception as e:
            logger.warning("refresh task statistic after stage {} failed: {}".format(stage_name, e))
        return summary or {}

    def task_is_terminal(self):
        try:
            return self.base_update_task.is_terminal()
        except Exception as e:
            logger.warning("check task terminal failed task_id:{} error:{}".format(self.task_id, e))
            return False

    def stop_if_terminal(self, stage):
        if not self.task_is_terminal():
            return False

        logger.warning("task {} stopped before {}".format(self.task_id, stage))
        return True

    def gen_ipv4_map(self):
        ipv4_map = {}
        for domain_info in self.domain_info_list:
            for ip in domain_info.ip_list:
                old_domain = ipv4_map.get(ip, set())
                old_domain.add(domain_info.domain)
                ipv4_map[ip] = old_domain
                self.ip_set.add(ip)

        self.ipv4_map = ipv4_map
        self._build_edge_asset_ips()

    def _is_edge_site_url(self, site):
        parsed = urlparse(str(site or ""))
        host = (parsed.hostname or "").strip(".").lower()
        query = {
            "task_id": self.task_id,
            "$or": [{"url": site}, {"site": site}]
        }
        if host:
            query["$or"].extend([{"host": host}, {"ip": host}])

        fields = {
            "_id": 0, "cdn": 1, "cdn_name": 1, "waf": 1, "waf_name": 1,
            "waf_strength": 1,
            "edge": 1, "edge_name": 1, "tag": 1, "title": 1,
            "status": 1, "status_code": 1, "webserver": 1, "cname": 1,
        }
        docs = []
        docs.extend(list(utils.conn_db("asset_seed_alive").find(
            formal_pipeline_query(query), fields).limit(2)))
        docs.extend(list(utils.conn_db("site").find(
            formal_site_query(query), fields).limit(2)))
        for item in docs:
            cname = item.get("cname") or ""
            if isinstance(cname, list):
                cname = " ".join([str(value) for value in cname])
            infrastructure = classify_edge_infrastructure(" ".join([
                str(item.get("webserver") or ""),
                str(cname),
                str(item.get("cdn_name") or ""),
                str(item.get("waf_name") or ""),
            ]))
            if has_strong_edge_marker(item) or infrastructure:
                return True

        title = docs[0].get("title", "") if docs else ""
        status_code = (docs[0].get("status") or docs[0].get("status_code")) if docs else None
        extra_text = ""
        if docs:
            cname = docs[0].get("cname") or ""
            if isinstance(cname, list):
                cname = " ".join([str(value) for value in cname])
            extra_text = " ".join([
                str(docs[0].get("webserver") or ""),
                str(cname),
            ])
        edge_info = classify_edge_host(
            site,
            self.base_domain,
            title=title,
            status_code=status_code,
            extra_text=extra_text,
        )
        return bool(edge_info.get("is_edge"))

    def _filter_edge_sites(self, sites):
        filtered = []
        skipped = 0
        seen = set()
        for site in sites or []:
            site = str(site or "").strip()
            if not site or site in seen:
                continue
            seen.add(site)
            if self._is_edge_site_url(site):
                skipped += 1
                continue
            filtered.append(site)

        if skipped:
            logger.info("filter edge sites before WebSiteFetch skipped:{} kept:{} task:{}".format(
                skipped, len(filtered), self.task_id))
        return filtered

    # 只是保存没有开放端口的
    def save_ip_info(self):
        fake_ip_info_list = []
        for ip in self.ipv4_map:
            data = {
                "ip": ip,
                "domain": list(self.ipv4_map[ip]),
                "port_info": [],
                "os_info": {},
                "cdn_name": utils.get_cdn_name_by_ip(ip)
            }
            info_obj = modules.IPInfo(**data)
            if info_obj not in self.ip_info_list:
                fake_ip_info_list.append(info_obj)

        for ip_info_obj in fake_ip_info_list:
            ip_info = ip_info_obj.dump_json(flag=False)
            ip_info["task_id"] = self.task_id
            query = {"task_id": self.task_id, "ip": ip_info.get("ip")}
            utils.conn_db('ip').update_one(query, {"$set": ip_info}, upsert=True)

    def save_service_info(self):
        self.service_info_list = []
        services_list = set()
        for _data in self.ip_info_list:
            port_info_list = _data.port_info_list
            for _info in port_info_list:
                if _info.service_name:
                    if _info.service_name not in services_list:
                        _result = {}
                        _result["service_name"] = _info.service_name
                        _result["service_info"] = []
                        _result["service_info"].append({'ip': _data.ip,
                                                        'port_id': _info.port_id,
                                                        'product': _info.product,
                                                        'version': _info.version})
                        _result["task_id"] = self.task_id
                        self.service_info_list.append(_result)
                        services_list.add(_info.service_name)
                    else:
                        for service_info in self.service_info_list:
                            if service_info.get("service_name") == _info.service_name:
                                service_info['service_info'].append({'ip': _data.ip,
                                                                     'port_id': _info.port_id,
                                                                     'product': _info.product,
                                                                     'version': _info.version})
        if self.service_info_list:
            for service_info in self.service_info_list:
                query = {
                    "task_id": self.task_id,
                    "service_name": service_info.get("service_name")
                }
                utils.conn_db('service').update_one(query, {"$set": service_info}, upsert=True)

    @staticmethod
    def _cert_port_set(value):
        ports = set()
        for part in str(value or "").split(","):
            part = part.strip()
            if not part:
                continue
            try:
                if "-" in part:
                    start, end = [int(x) for x in part.split("-", 1)]
                    ports.update(range(max(start, 1), min(end, 65535) + 1))
                else:
                    port = int(part)
                    if 0 < port <= 65535:
                        ports.add(port)
            except (TypeError, ValueError):
                continue
        return ports

    def _cert_targets(self, phase):
        targets = set()
        first_pass_ports = self._cert_port_set(getattr(
            Config, "SSL_CERT_FIRST_PASS_PORTS", "443,8443,9443"))

        if self.options.get("port_scan"):
            for ip_info in self.ip_info_list:
                for port_info in ip_info.port_info_list:
                    try:
                        port = int(port_info.port_id)
                    except (TypeError, ValueError):
                        continue
                    if port == 80:
                        continue
                    service_text = "{} {}".format(
                        getattr(port_info, "service_name", "") or "",
                        getattr(port_info, "product", "") or "",
                    ).lower()
                    if phase == "top1000" and not (
                            port in first_pass_ports or
                            "https" in service_text or "ssl" in service_text or "tls" in service_text):
                        continue
                    targets.add("{}:{}".format(ip_info.ip, port))
        else:
            targets.update("{}:443".format(ip) for ip in self.ip_set if ip)

        attempted = set()
        target_list = sorted(targets)
        for start in range(0, len(target_list), 1000):
            batch = target_list[start:start + 1000]
            attempted.update(
                item.get("target")
                for item in utils.conn_db("cert_probe_state").find(
                    {"task_id": self.task_id, "target": {"$in": batch}},
                    {"_id": 0, "target": 1})
                if item.get("target")
            )
        return sorted(targets - attempted), len(attempted)

    def _save_cert_probe_state(self, targets, cert_map, phase):
        operations = []
        for target in targets:
            query = {"task_id": self.task_id, "target": target}
            operations.append(UpdateOne(query, {
                "$set": {
                    "task_id": self.task_id,
                    "target": target,
                    "phase": phase,
                    "status": "cert" if target in cert_map else "no_cert",
                    "updated_at": utils.curr_date(),
                },
                "$inc": {"attempt_count": 1},
            }, upsert=True))
        if operations:
            utils.conn_db("cert_probe_state").bulk_write(operations, ordered=False)

    def _save_cert_san_feedback(self, san_domains, phase):
        limit = max(int(getattr(Config, "SSL_CERT_SAN_FEEDBACK_LIMIT", 500) or 500), 0)
        ordered_domains = sorted(
            set(san_domains),
            key=lambda domain: (domain.count("."), len(domain), domain),
        )
        limited_domains = ordered_domains[:limit] if limit else []
        dropped_count = max(0, len(ordered_domains) - len(limited_domains))
        if not limited_domains:
            return {
                "san_domain_count": len(ordered_domains),
                "san_saved_count": 0,
                "san_resolved_count": 0,
                "san_alive_site_count": 0,
                "san_dropped_count": dropped_count,
            }

        existing_docs = list(utils.conn_db("domain").find(
            formal_domain_query({
                "task_id": self.task_id,
                "domain": {"$in": limited_domains},
            }),
            {"_id": 0, "domain": 1},
        ))
        existing_domains = {
            str(item.get("domain") or "").strip(".").lower()
            for item in existing_docs if item.get("domain")
        }
        new_domains = [domain for domain in limited_domains if domain not in existing_domains]
        resolved_info = self.build_domain_info(new_domains) if new_domains else []
        resolved_map = {
            str(info.domain or "").strip(".").lower(): info
            for info in resolved_info if getattr(info, "domain", "")
        }
        domain_info_list = []
        for domain in new_domains:
            info = resolved_map.get(domain)
            if info is None:
                info = modules.DomainInfo(**{
                    "domain": domain,
                    "record": [],
                    "type": "CNAME",
                    "ips": [],
                })
            domain_info_list.append(info)

        if domain_info_list:
            self.save_domain_info_list(domain_info_list, source="active_ssl_san")
        for domain in limited_domains:
            utils.conn_db("domain").update_one(
                {"task_id": self.task_id, "domain": domain},
                {"$addToSet": {"sources": "active_ssl_san", "cert_phases": phase}},
            )

        known_domains = {
            str(info.domain or "").strip(".").lower()
            for info in self.domain_info_list if getattr(info, "domain", "")
        }
        for info in domain_info_list:
            domain = str(info.domain or "").strip(".").lower()
            self.post_seed_domains.add(domain)
            if domain not in known_domains:
                self.domain_info_list.append(info)
                known_domains.add(domain)
            for ip in info.ip_list:
                self.ip_set.add(ip)
                self.ipv4_map.setdefault(ip, set()).add(domain)
        self.post_seed_domains.update(limited_domains)

        alive_sites = []
        if domain_info_list and getattr(Config, "SSL_CERT_SAN_PROBE", True):
            probe_result = services.asset_seed_probe(
                self.task_id, self.base_domain, domain_info_list, ips=[])
            alive_sites = probe_result.get("alive_sites", []) or []
            alive_ips = probe_result.get("alive_ips", []) or []
            self.asset_seed_alive_sites = sorted(set(self.asset_seed_alive_sites) | set(alive_sites))
            self.asset_seed_alive_ips = sorted(set(self.asset_seed_alive_ips) | set(alive_ips))

        return {
            "san_domain_count": len(ordered_domains),
            "san_saved_count": len(domain_info_list),
            "san_resolved_count": len(resolved_info),
            "san_alive_site_count": len(set(alive_sites)),
            "san_dropped_count": dropped_count,
        }

    def ssl_cert(self, phase="single"):
        targets, skipped_attempted = self._cert_targets(phase)
        cert_map = ssl_cert(targets, self.base_domain) if targets else {}
        self.cert_map.update(cert_map)
        self._save_cert_probe_state(targets, cert_map, phase)

        strong_count = 0
        weak_count = 0
        san_domains = set()
        for target, cert in cert_map.items():
            try:
                ip, port_text = target.rsplit(":", 1)
                port = int(port_text)
            except (TypeError, ValueError):
                logger.warning("skip invalid ssl cert target task:{} target:{}".format(
                    self.task_id, target))
                continue
            matched = cert_matches_domain(cert, self.base_domain)
            item = {
                "ip": ip,
                "port": port,
                "cert": cert,
                "task_id": self.task_id,
                "source_type": "active_ssl_fetch",
                "cert_phase": phase,
                "relation_level": "strong" if matched else "weak",
                "relation_reason": "cert_cn_san_match" if matched else "cert_cn_san_mismatch",
            }
            query = {"task_id": self.task_id, "ip": ip, "port": port}
            if matched:
                utils.conn_db('cert').update_one(query, {"$set": item}, upsert=True)
                strong_count += 1
                san_domains.update(extract_cert_domains(cert, self.base_domain))
            else:
                utils.conn_db('cert_candidate').update_one(query, {"$set": item}, upsert=True)
                weak_count += 1

        summary = {
            "input_count": len(targets),
            "output_count": strong_count,
            "candidate_count": weak_count,
            "skipped_attempted_count": skipped_attempted,
            "cert_endpoint_count": len(cert_map),
            "cert_phase": phase,
        }
        summary.update(self._save_cert_san_feedback(san_domains, phase))
        return summary

    def build_single_domain_info(self, domain):
        _type = "A"
        cname = utils.get_cname(domain)
        if cname:
            _type = 'CNAME'
        ips = utils.get_ip(domain)
        if _type == "A":
            record = ips
        else:
            record = cname

        if not ips:
            return

        item = {
            "domain": domain,
            "type": _type,
            "record": record,
            "ips": ips
        }

        return modules.DomainInfo(**item)

    # *** 执行域名查询插件
    def dns_query_plugin(self):
        logger.info("start run dns_query_plugin {}".format(self.base_domain))
        results, source_report = run_query_plugin(
            self.base_domain, [], task_id=self.task_id, include_report=True)
        self.save_vhost_ip_candidates(results)
        domain_sources = {}
        candidate_type_counts = {"cert_ip": 0, "mapping_ip": 0}
        evidence_count = 0
        for result in results:
            domain = str(result.get("domain") or "").strip().lower().strip(".")
            if result.get("candidate_only"):
                candidate_type = str(result.get("candidate_type") or "mapping_ip")
                candidate_type_counts[candidate_type] = (
                    candidate_type_counts.get(candidate_type, 0) + 1)

            intels = list(result.get("intels") or [])
            if result.get("intel"):
                intels.append(result.get("intel"))
            evidence_count += len({
                (
                    str(item.get("source") or ""),
                    str(item.get("ip") or ""),
                    str(item.get("port") or ""),
                    str(item.get("query_type") or ""),
                    str(item.get("url") or ""),
                )
                for item in intels if isinstance(item, dict)
            })

            in_scope = domain == self.base_domain or domain.endswith("." + self.base_domain)
            if (in_scope
                    and utils.is_valid_domain(domain)
                    and not utils.check_domain_black(domain)):
                self.mutation_seed_domains.add(domain)

            if result.get("candidate_only"):
                continue
            if not in_scope:
                continue

            sources = result.get("sources") or [result.get("source")]
            for source in sources:
                if source:
                    domain_sources.setdefault(domain, set()).add(source)

        domain_info_list = self.build_domain_info(sorted(domain_sources))
        resolved_domains = {
            str(info.domain or "").strip(".").lower()
            for info in domain_info_list
            if getattr(info, "domain", "")
        }
        unresolved_domains = sorted(set(domain_sources) - resolved_domains)
        if self.task_tag == "task":
            domain_info_list = self.clear_domain_info_by_record(domain_info_list)
            for source in sorted({value for values in domain_sources.values() for value in values}):
                resolved_source_items = [
                    info for info in domain_info_list
                    if source in domain_sources.get(info.domain, set())
                ]
                unresolved_source_items = [
                    {
                        "domain": domain,
                        "type": "UNKNOWN",
                        "record": [],
                        "ips": [],
                        "resolve_status": "unresolved",
                    }
                    for domain in unresolved_domains
                    if source in domain_sources.get(domain, set())
                ]
                if resolved_source_items:
                    self.save_domain_info_list(resolved_source_items, source=source)
                if unresolved_source_items:
                    save_domain_documents(
                        self.task_id, unresolved_source_items, source)

        cnt = len(domain_info_list)
        self.domain_info_list.extend(domain_info_list)

        logger.info(
            "end run dns_query_plugin {}, result {}, resolved:{}, unresolved_preserved:{}".format(
                self.base_domain, len(results), cnt, len(unresolved_domains)))
        summary = {
            "output_count": len(domain_sources),
            "resolved_count": cnt,
            "unresolved_count": len(unresolved_domains),
            "candidate_count": sum(candidate_type_counts.values()),
            "aggregate_result_count": len(results),
            "cert_ip_candidate_count": candidate_type_counts.get("cert_ip", 0),
            "mapping_ip_candidate_count": candidate_type_counts.get("mapping_ip", 0),
            "evidence_count": evidence_count,
        }
        summary.update(source_report)
        if source_report.get("source_partial_count"):
            errors = source_report.get("source_errors") or []
            summary["warning"] = "; ".join(
                "{}: {}".format(item.get("source", "unknown"), item.get("error", ""))
                for item in errors[:5]
            )
            if source_report.get("source_done_count"):
                summary["_stage_status"] = "done_with_warnings"
                summary["completion_state"] = "done_with_warnings"
            else:
                summary["_stage_status"] = "partial"
                summary["partial_reason"] = "all_passive_sources_incomplete"
        return summary

    def domain_fetch(self, include_alt=True):
        '''****域名爆破开始****'''
        if self.options.get("domain_brute"):
            self.run_stage("domain_brute", self.domain_brute, input_count=self.domain_dict_size)
            if self.stop_if_terminal("dns_query_plugin"):
                return
        else:
            domain_info = self.build_single_domain_info(self.base_domain)
            if domain_info:
                self.domain_info_list.append(domain_info)
                self.save_domain_info_list([domain_info])

        if "{fuzz}" in self.base_domain:
            return

        # ***域名插件查询****
        if self.options.get("dns_query_plugin"):
            self.run_stage("dns_query_plugin", self.dns_query_plugin, input_count=len(self.domain_info_list))
            if self.stop_if_terminal("arl_search"):
                return

        if self.options.get("arl_search"):
            self.run_stage("arl_search", self.arl_search, input_count=1)
            if self.stop_if_terminal("alt_dns"):
                return

        if include_alt and self.options.get("alt_dns"):
            self.run_stage("alt_dns", self.alt_dns, input_count=len(self.domain_info_list))

    def run_alt_dns_stage(self):
        if self.options.get("alt_dns"):
            return self.run_stage("alt_dns", self.alt_dns, input_count=len(self.domain_info_list))
        return {}

    def dns_auxiliary(self):
        candidate_domains = {
            str(getattr(info, "domain", "") or "").strip().lower().strip(".")
            for info in self.domain_info_list
            if str(getattr(info, "domain", "") or "").strip()
        }
        candidate_domains.update(self.mutation_seed_domains)
        try:
            result = services.dns_auxiliary(
                self.base_domain,
                candidate_domains=sorted(candidate_domains),
                task_id=self.task_id,
            )
        except Exception as e:
            logger.warning("dns auxiliary failed target:{} error:{}".format(
                self.base_domain, e))
            return {
                "input_count": len(candidate_domains),
                "output_count": 0,
                "error_count": 1,
                "warning": str(e),
                "partial_reason": "dns_auxiliary_failed",
                "_stage_status": "partial",
            }

        domains = set(result.get("domains") or [])
        domain_sources = result.get("domain_sources") or {}
        self.mutation_seed_domains.update(domains)
        self.delegated_subdomains.update(result.get("delegated_domains") or [])
        already_resolved_domains = {
            str(info.domain or "").strip().lower().strip(".")
            for info in self.domain_info_list
            if getattr(info, "domain", "") and getattr(info, "ip_list", [])
        }

        resolved_info = self.build_domain_info(sorted(domains)) if domains else []
        resolved_info = self.clear_domain_info_by_record(resolved_info)

        # Preserve unresolved AXFR/SRV names as evidence, but never create a
        # formal domain row for a name already proven to be wildcard DNS.
        source_operations = []
        formal_discovered_domains = domains - self.wildcard_candidate_domains
        for domain in sorted(formal_discovered_domains):
            sources = sorted(set(domain_sources.get(domain) or []))
            if not sources:
                continue
            parsed = utils.domain_parsed(domain) or {}
            source_operations.append(UpdateOne(
                {"task_id": self.task_id, "domain": domain},
                {
                    "$setOnInsert": {
                        "task_id": self.task_id,
                        "domain": domain,
                        "fld": parsed.get("fld", self.base_domain),
                        "type": "CNAME",
                        "record": [],
                        "ips": [],
                        "source": sources[0],
                    },
                    "$addToSet": {"sources": {"$each": sources}},
                },
                upsert=True,
            ))
        if source_operations:
            utils.conn_db("domain").bulk_write(source_operations, ordered=False)
        for source in (CollectSource.DNS_AXFR, CollectSource.DNS_SRV):
            source_domains = {
                domain for domain, sources in domain_sources.items()
                if source in sources
            }
            source_info = [
                info for info in resolved_info
                if str(info.domain or "").strip().lower().strip(".") in source_domains
            ]
            if source_info:
                self.save_domain_info_list(source_info, source=source)

        known_domains = {
            str(info.domain or "").strip().lower().strip(".")
            for info in self.domain_info_list
        }
        self.domain_info_list.extend([
            info for info in resolved_info
            if str(info.domain or "").strip().lower().strip(".") not in known_domains
        ])
        resolved_domain_names = already_resolved_domains | {
            str(info.domain or "").strip().lower().strip(".")
            for info in resolved_info
            if getattr(info, "domain", "") and getattr(info, "ip_list", [])
        }

        evidence_operations = []
        for domain, evidence in (result.get("srv_evidence") or {}).items():
            if not evidence:
                continue
            evidence_operations.append(UpdateOne(
                {"task_id": self.task_id, "domain": domain},
                {"$addToSet": {"srv_evidence": {"$each": evidence}}},
                upsert=False,
            ))
        if evidence_operations:
            utils.conn_db("domain").bulk_write(evidence_operations, ordered=False)

        summary = {
            "input_count": len(candidate_domains),
            "output_count": len(resolved_info),
            "discovered_domain_count": len(domains),
            "resolved_domain_count": len(domains & resolved_domain_names),
            "unresolved_domain_count": len(domains - resolved_domain_names),
            "delegated_domain_count": len(self.delegated_subdomains),
        }
        summary.update(result.get("meta") or {})
        return summary

    def start_asset_seed_fetch(self):
        self.gen_ipv4_map()

        if Config.ASSET_SEED_PROBE:
            seed_ips = set(self.ipv4_map.keys()) - set(self.edge_asset_ips)
            passive_seed_ips = set()
            if Config.ASSET_SEED_PROBE_PASSIVE_IPS:
                passive_seed_ips = set(find_vhost_candidate_ip_by_task_id(self.task_id))
                seed_ips.update(passive_seed_ips)
            else:
                logger.info("asset_seed_probe passive candidate ips kept for host collision only")

            def _asset_seed_probe():
                probe_result = services.asset_seed_probe(
                    self.task_id,
                    self.base_domain,
                    self.domain_info_list,
                    ips=list(seed_ips)
                )
                self.asset_seed_alive_sites = probe_result.get("alive_sites", [])
                self.asset_seed_alive_ips = probe_result.get("alive_ips", [])
                unknown_ips = probe_result.get("unknown_ips", [])
                blocked_ips = probe_result.get("blocked_ips", [])
                scan_ips = probe_result.get("scan_ips", [])
                partial_errors = probe_result.get("partial_errors", []) or []
                summary = {
                    "input_count": len(self.domain_info_list) + len(seed_ips),
                    "output_count": len(self.asset_seed_alive_sites),
                    "alive_ip_count": len(self.asset_seed_alive_ips),
                    "unknown_ip_count": len(unknown_ips),
                    "blocked_ip_count": len(blocked_ips),
                    "port_scan_eligible_ip_count": len(scan_ips),
                    "passive_ip_count": len(passive_seed_ips),
                    "httpx_retry_count": int(
                        probe_result.get("httpx_retry_count", 0) or 0),
                    "httpx_recovered_batch_count": int(
                        probe_result.get("httpx_recovered_batch_count", 0) or 0),
                    "httpx_failed_target_count": int(
                        probe_result.get("httpx_failed_target_count", 0) or 0),
                    "preprobe_cdn_domain_count": int(
                        probe_result.get("preprobe_cdn_domain_count", 0) or 0),
                    "preprobe_owned_cdn_domain_count": int(
                        probe_result.get("preprobe_owned_cdn_domain_count", 0) or 0),
                    "preprobe_external_domain_count": int(
                        probe_result.get("preprobe_external_domain_count", 0) or 0),
                    "preprobe_skipped_provider_domain_count": int(
                        probe_result.get(
                            "preprobe_skipped_provider_domain_count", 0) or 0),
                }
                if partial_errors:
                    summary.update({
                        "_stage_status": "partial",
                        "error": "; ".join(partial_errors[:5]),
                        "error_count": len(partial_errors),
                        "partial_reason": "httpx_partial_failure",
                    })
                return summary

            self.run_stage("asset_seed_probe", _asset_seed_probe, input_count=len(self.domain_info_list) + len(seed_ips))
            if self.stop_if_terminal("port_scan"):
                return

            self.run_stage("known_service_seed", self.known_service_seed)
            if self.stop_if_terminal("asset_seed_prefill"):
                return

            self.run_stage("asset_seed_prefill", self.prefill_asset_seed_results)
            if self.stop_if_terminal("port_scan"):
                return

    def run_top_port_phase(self):
        if self.options.get("port_scan"):
            if self.options.get("port_scan_type") == "all" and Config.PORT_SCAN_TOP1000_FIRST:
                self.run_stage("port_scan_top1000", self.port_scan_top1000, input_count=len(self.domain_info_list))
                if self.stop_if_terminal("ssl_cert_top1000"):
                    return
            else:
                if self.options.get("port_scan_type") != "all":
                    self.run_stage("port_scan", self.port_scan, input_count=len(self.domain_info_list))
                if self.stop_if_terminal("ssl_cert"):
                    return

        if self.options.get("ssl_cert"):
            if self.options.get("port_scan_type") == "all" and Config.PORT_SCAN_TOP1000_FIRST:
                self.run_stage(
                    "ssl_cert_top1000",
                    lambda: self.ssl_cert(phase="top1000"),
                    input_count=len(self.ip_info_list) or len(self.ip_set),
                )
            else:
                self.run_stage(
                    "ssl_cert",
                    lambda: self.ssl_cert(phase="single"),
                    input_count=len(self.ip_info_list) or len(self.ip_set),
                )
            if self.stop_if_terminal("save_ip_info"):
                return

        if self.options.get("service_detection") and Config.ENABLE_NMAP_SERVICE_DETECTION:
            self.save_service_info()
        self.save_ip_info()

    def run_full_port_phase(self):
        full_port_summary = {}
        if self.options.get("port_scan") and self.options.get("port_scan_type") == "all":
            if Config.PORT_SCAN_TOP1000_FIRST:
                full_port_summary = self.run_stage(
                    "port_scan_full", self.port_scan_full,
                    input_count=len(self.domain_info_list))
            else:
                full_port_summary = self.run_stage(
                    "port_scan", self.port_scan,
                    input_count=len(self.domain_info_list))
            if full_port_summary.get("continuation_required"):
                return full_port_summary
            if self.stop_if_terminal("ssl_cert_full"):
                return full_port_summary

            # Freeze the delta baseline before the full-pass certificate fetch.
            # SAN feedback can introduce domains and IPs after port discovery;
            # those assets must remain eligible for the incremental closure.
            self.prepare_discovery_delta_state()

            if self.options.get("ssl_cert"):
                self.run_stage(
                    "ssl_cert_full",
                    lambda: self.ssl_cert(phase="full"),
                    input_count=len(self.ip_info_list) or len(self.ip_set),
                )
                if self.stop_if_terminal("save_ip_info"):
                    return full_port_summary

        if self.options.get("service_detection") and Config.ENABLE_NMAP_SERVICE_DETECTION:
            self.save_service_info()
        self.save_ip_info()
        return full_port_summary

    def start_ip_fetch(self):
        self.start_asset_seed_fetch()
        if self.task_is_terminal():
            return
        self.run_top_port_phase()
        if self.task_is_terminal():
            return
        self.run_full_port_phase()

    def start_site_fetch(self, include_post_discovery=True):
        self.run_stage("find_site", self.find_site, input_count=len(self.domain_info_list))
        if self.stop_if_terminal("fetch_site"):
            return

        # 对 domain_info_list 进行清空，回收内存
        self.domain_info_list = []

        web_site_fetch = WebSiteFetch(task_id=self.task_id,
                                      sites=self.site_list, options=self.options,
                                      scope_domain=[self.base_domain])
        web_site_fetch.run_discovery()

        feedback_baseline_sites = {
            str(item.get("site") or "").strip()
            for item in utils.conn_db("site").find(
                formal_site_query({"task_id": self.task_id}),
                {"_id": 0, "site": 1})
            if str(item.get("site") or "").strip()
        }

        self.wih_domain_set = web_site_fetch.wih_domain_set

        self.web_site_fetch = web_site_fetch

        if self.stop_if_terminal("site_spider_domain_update"):
            return

        site_spider_domains = web_site_fetch.entry_tracker.pending_domains(
            web_site_fetch.site_spider_domain_set)
        if site_spider_domains:
            logger.info("site_spider discovered domains: {} task_id:{}".format(
                len(site_spider_domains), self.task_id))
            domain_site_update(
                self.task_id,
                site_spider_domains,
                CollectSource.SITESPIDER,
                url_evidence=web_site_fetch.site_spider_domain_url_map,
                reprobe_existing_without_site=True,
                run_file_leak=False,
            )
            web_site_fetch.entry_tracker.finalize_domains(site_spider_domains)
            self.insert_task_stat()

        if self.stop_if_terminal("wih_domain_update"):
            return
        self.start_wih_domain_update()

        if self.stop_if_terminal("entry_feedback_spider"):
            return
        self.run_entry_feedback_round(feedback_baseline_sites)

        if include_post_discovery:
            if self.stop_if_terminal("file_leak"):
                return
            web_site_fetch.run_post_discovery()

    def post_processing_required(self):
        return bool(
            self.options.get("file_leak") or
            is_nuclei_scan_enabled(self.options) or
            self.options.get("wayback_backtrack") or
            self.options.get("bing_deep") or
            self.options.get("js_deep") or
            self.options.get("framework_probe") or
            self.options.get("ai_judge")
        )

    def run_bface_discover_stage(self):
        from app.services.bfaceProbe import run_bface_discover

        return run_bface_discover(
            self.task_id, self.base_domain, domain_task=self)

    def run_bing_deep_stage(self):
        from app.services import bingDeep

        cooldown = bingDeep.check_profile_cooldown(
            self.task_id, self.base_domain)
        if cooldown.get("cooling"):
            return {
                "skipped": True,
                "reason": "Bing profile 冷却中",
                "cooldown_remaining_seconds": cooldown.get("remaining_seconds"),
                "cooldown_reason": cooldown.get("reason"),
            }

        with acquire_resource_budget(
                "api:bing", task_id=self.task_id, stage="bing_deep"):
            searcher = bingDeep.BingDeepSearch(
                self.task_id, self.base_domain)
            summary = searcher.run()

        saved_path_count, domain_summary = bingDeep.save_bing_results(
            self.task_id, self.base_domain,
            sorted(searcher.discovered_domains),
            searcher.path_records)
        summary["saved_path_count"] = saved_path_count
        summary["domain_update_output_count"] = int(
            domain_summary.get("output_count") or 0)
        summary["discovered_domains"] = sorted(
            searcher.discovered_domains)[:50]
        return summary

    def run_post_processing(self):
        self.hydrate_from_storage()
        if self.task_is_terminal():
            return {"post_processing": False}

        web_site_fetch = WebSiteFetch(
            task_id=self.task_id,
            sites=self.site_list,
            options=self.options,
            scope_domain=[self.base_domain],
        )
        web_site_fetch.available_sites = list(self.site_list)
        self.web_site_fetch = web_site_fetch
        summaries = web_site_fetch.run_post_discovery() or {}
        if self.task_is_terminal():
            return {"post_processing": False, "retry_required": False}

        if self.stop_if_terminal("wayback_backtrack"):
            return {"post_processing": False, "retry_required": False}

        if self.options.get("wayback_backtrack"):
            from app.services import waybackPaths

            self.run_stage(
                "wayback_backtrack",
                lambda: waybackPaths.collect_wayback_paths(
                    self.task_id, self.base_domain),
                input_count=1,
            )

        if self.stop_if_terminal("bing_deep"):
            return {"post_processing": False, "retry_required": False}

        if self.options.get("bing_deep"):
            if not getattr(Config, "BING_ENABLE", False):
                summaries["bing_deep"] = {
                    "skipped": True, "reason": "BING.ENABLE 未开启"}
            else:
                summaries["bing_deep"] = self.run_stage(
                    "bing_deep",
                    self.run_bing_deep_stage,
                    input_count=1,
                )

        if self.stop_if_terminal("js_deep"):
            return {"post_processing": False, "retry_required": False}

        if self.options.get("js_deep"):
            from app.services import ai_judge, jsDeep

            summaries["js_deep"] = self.run_stage(
                "js_deep",
                lambda: jsDeep.run_js_deep(
                    self.task_id, self.base_domain,
                    ai_enabled_fn=ai_judge.ai_enabled),
                input_count=1,
            )

        if self.stop_if_terminal("framework_probe"):
            return {"post_processing": False, "retry_required": False}

        if self.options.get("framework_probe"):
            from app.services import frameworkProbe

            summaries["framework_probe"] = self.run_stage(
                "framework_probe",
                lambda: frameworkProbe.run_framework_probe(self.task_id),
                input_count=1,
            )

        if self.stop_if_terminal("shadow_tag"):
            return {"post_processing": False, "retry_required": False}

        from app.services import shadowAsset

        summaries["shadow_tag"] = self.run_stage(
            "shadow_tag",
            lambda: shadowAsset.shadow_tag_task(self.task_id),
            input_count=1,
        )

        if self.stop_if_terminal("ai_judge"):
            return {"post_processing": False, "retry_required": False}

        if self.options.get("ai_judge"):
            from app.services import ai_judge

            if not ai_judge.ai_enabled():
                summaries["ai_judge"] = {
                    "skipped": True, "reason": "AI 未启用或凭证未配置"}
            else:
                summaries["ai_judge"] = self.run_stage(
                    "ai_judge",
                    lambda: ai_judge.judge_task_sites(self.task_id),
                    input_count=1,
                )

        file_leak_summary = summaries.get("file_leak", {}) or {}
        continuation_required = bool(
            file_leak_summary.get("continuation_required"))
        retry_required = bool(
            int(file_leak_summary.get(
                "retryable_failure_site_count", 0) or 0)
        )
        return {
            "post_processing": True,
            "retry_required": retry_required,
            "continuation_required": continuation_required,
            "summaries": summaries,
        }

    def finalize_post_processing(self):
        if self.task_is_terminal():
            return {"finalized": False}

        # Host collision consumes the complete domain/IP evidence set, so it
        # must run after optional directory/nuclei post-processing has ended.
        self.start_find_vhost()
        if self.stop_if_terminal("common_run"):
            return {"finalized": False}

        self.run_stage("common_run", self.common_run, input_count=1)
        self.finish_task()
        return {"finalized": True}

    def npoc_service_detection(self):
        targets = []
        for ip_info in self.ip_info_list:
            for port_info in ip_info.port_info_list:
                skip_port_list = [80, 443, 843]
                if port_info.port_id in skip_port_list:
                    continue

                targets.append("{}:{}".format(ip_info.ip, port_info.port_id))

        result = run_sniffer(targets)
        for item in result:
            self.npoc_service_target_set.add(item["target"])
            item["task_id"] = self.task_id
            item["save_date"] = utils.curr_date()
            utils.conn_db('npoc_service').insert_one(item)
        return {
            "input_count": len(targets),
            "output_count": len(result),
        }

    def start_poc_run(self):
        """poc run"""
        """服务识别（python）实现"""
        if self.options.get("npoc_service_detection"):
            port_target_count = 0
            for ip_info in self.ip_info_list:
                for port_info in ip_info.port_info_list:
                    if port_info.port_id not in [80, 443, 843]:
                        port_target_count += 1
            self.run_stage("npoc_service_detection", self.npoc_service_detection, input_count=port_target_count)
            if self.stop_if_terminal("poc_run"):
                return

        """ *** npoc 调用 """
        if self.options.get("poc_config"):
            self.run_stage(
                "poc_run",
                lambda: self.web_site_fetch.risk_cruising(self.npoc_service_target_set),
                input_count=len(self.web_site_fetch.poc_sites) + len(self.npoc_service_target_set)
            )
            if self.stop_if_terminal("weak_brute"):
                return

        """弱口令爆破服务"""
        if self.options.get("brute_config"):
            self.run_stage("weak_brute", self.brute_config, input_count=len(self.site_list) + len(self.npoc_service_target_set))

    def brute_config(self):
        plugins = []
        brute_config = self.options.get("brute_config")
        for x in brute_config:
            if not x.get("enable"):
                continue
            plugins.append(x["plugin_name"])

        if not plugins:
            return {"output_count": 0}
        targets = self.site_list.copy()
        targets += list(self.npoc_service_target_set)
        result = run_risk_cruising(targets=targets, plugins=plugins)
        for item in result:
            item["task_id"] = self.task_id
            item["save_date"] = utils.curr_date()
            utils.conn_db('vuln').insert_one(item)
        return {
            "input_count": len(targets),
            "output_count": len(result),
        }

    def _alive_site_host_map(self):
        host_map = {}
        for item in utils.conn_db("site").find(
            formal_site_query({"task_id": self.task_id}),
            {"_id": 0, "site": 1, "ip": 1}
        ):
            parsed = urlparse(str(item.get("site") or ""))
            hostname = str(parsed.hostname or "").strip(".").lower()
            if hostname:
                row = host_map.setdefault(hostname, {"ips": set(), "sites": set()})
                row["sites"].add(str(item.get("site") or ""))
                ip = str(item.get("ip") or "").strip()
                if utils.is_vaild_ip_target(ip):
                    row["ips"].add(ip)
        return host_map

    def _alive_site_hostnames(self):
        return set(self._alive_site_host_map())

    def _host_collision_source_rows(self):
        """Merge every persisted active, passive, certificate and JS Host source."""
        rows = {}

        def values(value):
            if value in (None, ""):
                return []
            if isinstance(value, (list, tuple, set)):
                return list(value)
            return [value]

        def add(domain, sources=None, ips=None):
            domain = str(domain or "").strip().strip("*.").lower()
            if not domain:
                return
            if domain != self.base_domain and not domain.endswith("." + self.base_domain):
                return
            if not utils.is_valid_domain(domain) or utils.check_domain_black(domain):
                return

            row = rows.setdefault(domain, {
                "sources": set(),
                "ips": set(),
                "ip_sources": {},
            })
            for source in values(sources):
                source = str(source or "").strip()
                if source:
                    row["sources"].add(source)
            for ip in values(ips):
                ip = str(ip or "").strip()
                if utils.is_vaild_ip_target(ip):
                    row["ips"].add(ip)
                    ip_sources = row["ip_sources"].setdefault(ip, set())
                    ip_sources.update(row["sources"] or {"unknown"})

        add(self.base_domain, ["task_target"])

        for item in utils.conn_db("domain").find(
            formal_domain_query({"task_id": self.task_id}),
            {"_id": 0, "domain": 1, "source": 1, "sources": 1, "ips": 1},
        ):
            sources = values(item.get("sources"))
            if item.get("source"):
                sources.append(item.get("source"))
            add(item.get("domain"), sources, item.get("ips"))

        for collection_name in ("asset_seed_candidate", "vhost_ip_candidate"):
            for item in utils.conn_db(collection_name).find(
                {"task_id": self.task_id},
                {
                    "_id": 0,
                    "domain": 1,
                    "domains": 1,
                    "verified_domains": 1,
                    "source": 1,
                    "sources": 1,
                    "ip": 1,
                    "candidate_type": 1,
                    "cert_verify_status": 1,
                    "pipeline_eligible": 1,
                    "status": 1,
                    "host_collision_eligible": 1,
                    "pipeline_exclusion_reason": 1,
                    "quarantine_reason": 1,
                    "relation_reason": 1,
                },
            ):
                allowed, _ = self._host_collision_candidate_allowed(item)
                if not allowed:
                    continue
                if (
                        str(item.get("candidate_type") or "").lower() == "wildcard_dns" or
                        str(item.get("quarantine_reason") or "").lower() == "wildcard_dns"):
                    continue
                is_quarantined = (
                    item.get("pipeline_eligible") is False or
                    str(item.get("status") or "").lower() == "quarantined"
                )
                if (is_quarantined and
                        item.get("host_collision_eligible") is not True):
                    continue
                sources = values(item.get("sources"))
                if item.get("source"):
                    sources.append(item.get("source"))
                domains = values(item.get("domain"))
                domains.extend(values(item.get("domains")))
                domains.extend(values(item.get("verified_domains")))
                for domain in domains:
                    add(domain, sources or [collection_name], [item.get("ip")])

        for item in utils.conn_db("entry_asset").find(
            formal_pipeline_query({
                "task_id": self.task_id,
                "seed_type": "domain",
            }),
            {
                "_id": 0,
                "domain": 1,
                "seed": 1,
                "source": 1,
                "collectors": 1,
            },
        ):
            sources = values(item.get("collectors"))
            if item.get("source"):
                sources.append(item.get("source"))
            add(item.get("domain") or item.get("seed"), sources or ["entry_asset"])

        return rows

    def _host_collision_dns_resolvers(self):
        raw_resolvers = getattr(
            Config,
            "HOST_COLLISION_DNS_RESOLVERS",
            "223.5.5.5,119.29.29.29,1.1.1.1,8.8.8.8"
        )
        if isinstance(raw_resolvers, str):
            resolvers = [x.strip() for x in raw_resolvers.split(",") if x.strip()]
        elif isinstance(raw_resolvers, (list, tuple, set)):
            resolvers = [str(x).strip() for x in raw_resolvers if str(x).strip()]
        else:
            resolvers = []
        return resolvers or ["223.5.5.5", "119.29.29.29", "1.1.1.1", "8.8.8.8"]

    def _query_host_collision_dns(self, domain, resolver_ip):
        timeout = max(float(getattr(Config, "HOST_COLLISION_DNS_TIMEOUT", 2) or 2), 0.5)
        lifetime = max(float(getattr(Config, "HOST_COLLISION_DNS_LIFETIME", 4) or 4), timeout)
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [resolver_ip]
        resolver.timeout = timeout
        resolver.lifetime = lifetime
        try:
            answers = resolver.resolve(domain, "A", raise_on_no_answer=False)
            if answers.rrset is None:
                return domain, [], "noanswer"
            values = []
            for answer in answers:
                address = str(getattr(answer, "address", answer)).strip()
                if address:
                    values.append(address)
            return domain, values, ""
        except dns.resolver.NXDOMAIN:
            return domain, [], "nxdomain"
        except dns.resolver.NoAnswer:
            return domain, [], "noanswer"
        except dns.resolver.NoNameservers:
            return domain, [], "nonameserver"
        except dns.exception.Timeout:
            return domain, [], "timeout"
        except Exception as e:
            return domain, [], type(e).__name__

    @staticmethod
    def _classify_host_collision_dns(ips, errors):
        ips = set(ips or [])
        errors = Counter(errors or {})
        if ips:
            ip_types = {utils.get_ip_type(ip) for ip in ips if ip}
            if "PRIVATE" in ip_types and "PUBLIC" in ip_types:
                status = "mixed_private_public_resolve"
            elif "PRIVATE" in ip_types:
                status = "private_resolve"
            elif "PUBLIC" in ip_types:
                status = "public_resolve"
            else:
                status = "non_public_resolve"
        elif errors.get("nxdomain") or errors.get("noanswer"):
            status = "public_unresolved"
        else:
            status = "resolve_error"
        return {
            "status": status,
            "ips": sorted(ips),
            "errors": dict(errors),
        }

    def _fresh_dns_classify(self, domain):
        ips = set()
        errors = Counter()
        resolvers = self._host_collision_dns_resolvers()
        with ThreadPoolExecutor(max_workers=min(len(resolvers), 4)) as executor:
            jobs = ((domain, resolver_ip) for resolver_ip in resolvers)
            for _domain, values, error in executor.map(
                    lambda item: self._query_host_collision_dns(*item), jobs):
                ips.update(values)
                if error:
                    errors[error] += 1
        return self._classify_host_collision_dns(ips, errors)

    def _fresh_dns_classify_many(self, domains):
        domains = sorted(set(str(domain or "").strip().lower().strip(".")
                             for domain in domains if str(domain or "").strip()))
        if not domains:
            return {}
        resolvers = self._host_collision_dns_resolvers()
        worker_count = max(int(getattr(
            Config, "HOST_COLLISION_DNS_CONCURRENCY", 32) or 1), 1)
        worker_count = min(worker_count, 128, len(domains) * len(resolvers))
        grouped = {
            domain: {"ips": set(), "errors": Counter()}
            for domain in domains
        }
        jobs = ((domain, resolver_ip)
                for domain in domains for resolver_ip in resolvers)
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            for domain, values, error in executor.map(
                    lambda item: self._query_host_collision_dns(*item), jobs):
                grouped[domain]["ips"].update(values)
                if error:
                    grouped[domain]["errors"][error] += 1
        logger.info(
            "host_collision dns prefilter domains:{} resolvers:{} workers:{}".format(
                len(domains), len(resolvers), worker_count))
        return {
            domain: self._classify_host_collision_dns(
                value["ips"], value["errors"])
            for domain, value in grouped.items()
        }

    def _save_host_collision_dns_status(
            self, domain, classification, candidate, reason, sources=None,
            pending_updates=None):
        update = {
            "$set": {
                "host_collision_candidate": bool(candidate),
                "host_collision_dns_status": classification.get("status", ""),
                "host_collision_fresh_ips": classification.get("ips", []),
                "host_collision_dns_errors": classification.get("errors", {}),
                "host_collision_reason": reason,
                "host_collision_dns_checked_at": utils.curr_date(),
            }
        }
        if sources:
            update["$addToSet"] = {
                "host_collision_sources": {"$each": sorted(set(sources))}
            }
        operation = UpdateOne(
            {"task_id": self.task_id, "domain": domain}, update)
        if pending_updates is not None:
            pending_updates.append(operation)
        else:
            utils.conn_db("domain").bulk_write([operation], ordered=False)

    def host_collision_domains(self):
        hosts = []
        alive_site_map = self._alive_site_host_map()
        reason_count = Counter()
        source_rows = self._host_collision_source_rows()
        self._host_collision_domain_rows = source_rows
        classifications = self._fresh_dns_classify_many(source_rows)
        dns_status_updates = []
        source_count = Counter()
        for domain, item in sorted(source_rows.items()):
            for source in item.get("sources") or ["unknown"]:
                source_count[source] += 1

            ips = item.get("ips") or []
            ip_types = {utils.get_ip_type(ip) for ip in ips if ip}
            classification = classifications.get(domain) or {
                "status": "resolve_error", "ips": [],
                "errors": {"missing_result": 1},
            }
            dns_status = classification.get("status")
            item["fresh_dns_status"] = dns_status
            item["fresh_ips"] = sorted(classification.get("ips") or [])
            include_candidate = False
            reason = dns_status or "unknown"

            if domain in alive_site_map:
                reason = "alive_site_excluded"
                item["collision_reason"] = reason
                reason_count["skip_alive_site"] += 1
                self._save_host_collision_dns_status(
                    domain,
                    classification,
                    False,
                    reason,
                    sources=item.get("sources"),
                    pending_updates=dns_status_updates,
                )
                continue

            if dns_status in ("private_resolve", "mixed_private_public_resolve", "non_public_resolve"):
                include_candidate = True
            elif dns_status == "public_unresolved":
                include_candidate = True
            elif dns_status == "public_resolve":
                if getattr(Config, "HOST_COLLISION_INCLUDE_PUBLIC_DNS_NO_ALIVE", False):
                    include_candidate = True
                    reason = "public_dns_but_no_alive_site"
                else:
                    reason_count["skip_public_dns"] += 1
            elif dns_status == "resolve_error":
                if "PRIVATE" in ip_types:
                    include_candidate = True
                    reason = "history_private_resolve_after_dns_error"
                else:
                    reason_count["skip_resolve_error"] += 1

            self._save_host_collision_dns_status(
                domain,
                classification,
                include_candidate,
                reason,
                sources=item.get("sources"),
                pending_updates=dns_status_updates,
            )
            item["collision_reason"] = reason
            if include_candidate:
                hosts.append(domain)
                reason_count[reason] += 1

        if dns_status_updates:
            utils.conn_db("domain").bulk_write(dns_status_updates, ordered=False)
        self._host_collision_targeted_domains = {}
        ordered = sorted(set(hosts))
        max_hosts = int(getattr(Config, "HOST_COLLISION_MAX_HOSTS", 0) or 0)
        if max_hosts > 0 and len(ordered) > max_hosts:
            reason_count["capped"] = len(ordered) - max_hosts
            ordered = ordered[:max_hosts]
        logger.info(
            "host_collision domain candidates:{} targeted_hosts:{} targeted_ips:{} "
            "sources:{} reasons:{}".format(
                len(ordered),
                0,
                0,
                dict(source_count),
                dict(reason_count)))
        return ordered

    def _add_collision_target(self, targets, ip, port=None, skipped=None):
        ip = str(ip or "").strip()
        if not ip:
            return False
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if address.version != 4:
            return False
        ip = str(address)
        if not self._collision_target_ip_allowed(ip, skipped=skipped):
            return False

        if port in (None, ""):
            targets.add(ip)
            return True

        try:
            port = int(port)
        except Exception:
            return False

        if port <= 0 or port > 65535:
            return False
        targets.add("{}:{}".format(ip, port))
        return True

    @classmethod
    def _host_collision_reason_blocked(cls, reason):
        reason = str(reason or "").strip().lower()
        if not reason:
            return False
        if reason in HOST_COLLISION_BLOCKED_CANDIDATE_REASONS:
            return True
        return any(
            fragment in reason
            for fragment in HOST_COLLISION_BLOCKED_REASON_FRAGMENTS)

    @classmethod
    def _host_collision_candidate_allowed(cls, item, block_explicit=False):
        if item.get("host_collision_eligible") is False:
            if block_explicit:
                return False, "explicitly_ineligible"

        for field in (
                "cert_verify_status", "pipeline_exclusion_reason",
                "quarantine_reason", "relation_reason"):
            reason = str(item.get(field) or "").strip().lower()
            if cls._host_collision_reason_blocked(reason):
                return False, reason
        return True, ""

    def _host_collision_blocked_candidate_ip_reasons(self):
        cached = getattr(self, "_host_collision_blocked_ip_reasons", None)
        if cached is not None:
            return cached

        blocked = {}
        fields = {
            "_id": 0, "ip": 1, "host_collision_eligible": 1,
            "cert_verify_status": 1, "pipeline_exclusion_reason": 1,
            "quarantine_reason": 1, "relation_reason": 1,
        }
        for collection_name in HOST_COLLISION_CANDIDATE_COLLECTIONS:
            for item in utils.conn_db(collection_name).find(
                    {"task_id": self.task_id}, fields):
                ip = str(item.get("ip") or "").strip()
                if not ip:
                    continue
                allowed, reason = self._host_collision_candidate_allowed(
                    item, block_explicit=False)
                if allowed or not reason or reason == "explicitly_ineligible":
                    continue
                blocked.setdefault(ip, set()).add(reason)

        self._host_collision_blocked_ip_reasons = blocked
        return blocked

    def _host_collision_ip_block_reason(self, ip):
        reasons = self._host_collision_blocked_candidate_ip_reasons().get(
            str(ip or "").strip()) or set()
        if not reasons:
            return ""
        return sorted(reasons)[0]

    def _host_collision_result_target_allowed(self, result):
        ip = str(result.get("ip") or "").strip()
        sources = {
            str(value or "").strip()
            for value in (result.get("endpoint_sources") or [])
            if str(value or "").strip()
        }
        if sources and sources.issubset(HOST_COLLISION_WEAK_ENDPOINT_SOURCES):
            reason = self._host_collision_ip_block_reason(ip)
            if reason:
                return False, reason
        return True, ""

    def host_collision_targets(self):
        targets = set()
        skipped = Counter()
        source_ips = {}

        def add(ip, source):
            ip = str(ip or "").strip().strip("[]")
            skipped_before = sum(skipped.values())
            if not self._add_collision_target(targets, ip, skipped=skipped):
                if sum(skipped.values()) == skipped_before:
                    skipped["invalid_or_non_public"] += 1
                return
            source_ips.setdefault(ip, set()).add(source)

        def add_url(value, source):
            try:
                parsed = urlparse(str(value or "").strip())
            except (TypeError, ValueError):
                return
            add(parsed.hostname, source)

        for ip in (self.ipv4_map or {}):
            add(ip, "current_dns")

        for item in utils.conn_db("domain").find(
            {"task_id": self.task_id}, {"_id": 0, "ips": 1}
        ):
            for ip in item.get("ips") or []:
                add(ip, "domain_dns")

        candidate_collections = set(HOST_COLLISION_CANDIDATE_COLLECTIONS)
        for collection_name in (
            "asset_seed_candidate",
            "vhost_ip_candidate",
            "asset_seed_alive",
            "ip",
            "cert",
            "cert_candidate",
        ):
            fields = {
                "_id": 0, "ip": 1, "host_collision_eligible": 1,
                "cert_verify_status": 1, "pipeline_exclusion_reason": 1,
                "quarantine_reason": 1, "relation_reason": 1,
            }
            for item in utils.conn_db(collection_name).find(
                    {"task_id": self.task_id}, fields):
                if collection_name in candidate_collections:
                    allowed, reason = self._host_collision_candidate_allowed(
                        item, block_explicit=True)
                    if not allowed:
                        skipped["candidate_{}".format(reason)] += 1
                        continue
                add(item.get("ip"), collection_name)

        for item in utils.conn_db("site").find(
            {"task_id": self.task_id}, {"_id": 0, "ip": 1, "site": 1}
        ):
            if item.get("ip"):
                add(item.get("ip"), "site")
            else:
                add_url(item.get("site"), "site_url")

        for item in utils.conn_db("url").find(
            {"task_id": self.task_id}, {"_id": 0, "url": 1}
        ):
            add_url(item.get("url"), "url")

        for item in utils.conn_db("entry_asset").find(
            {
                "task_id": self.task_id,
                "seed_type": {"$in": ["public_ip_url", "private_ip_url"]},
            },
            {"_id": 0, "domain": 1, "seed": 1},
        ):
            add(item.get("domain"), "entry_asset")
            add_url(item.get("seed"), "entry_asset_url")

        ordered = sorted(targets)
        max_targets = int(getattr(Config, "HOST_COLLISION_MAX_TARGETS", 0) or 0)
        if max_targets > 0 and len(ordered) > max_targets:
            skipped["capped"] = len(ordered) - max_targets
            ordered = ordered[:max_targets]

        source_count = Counter()
        for sources in source_ips.values():
            for source in sources:
                source_count[source] += 1
        logger.info(
            "host_collision targets:{} sources:{} skipped:{}".format(
                len(ordered), dict(source_count), dict(skipped)))
        return ordered

    @staticmethod
    def _host_collision_schemes(port, service="", protocol=""):
        try:
            port = int(port)
        except (TypeError, ValueError):
            return []
        marker = "{} {}".format(service or "", protocol or "").lower()
        if any(value in marker for value in ("https", "ssl", "tls")):
            return ["https"]
        if "http" in marker:
            return ["http"]
        if port in {443, 4443, 5443, 6443, 7443, 8443, 9443, 10443}:
            return ["https"]
        if port in {
                80, 81, 3000, 5000, 7001, 7002, 8000, 8001, 8080,
                8081, 8088, 8888, 9000, 9080, 10000}:
            return ["http"]
        return []

    def host_collision_endpoints(self):
        targets = self.host_collision_targets()
        allowed_ips = set(targets)
        targeted_domains = getattr(self, "_host_collision_targeted_domains", {})
        endpoint_map = {}

        def add(ip, port, scheme="", source="", domains=None, service="", protocol=""):
            ip = str(ip or "").strip().strip("[]")
            if ip not in allowed_ips:
                return
            try:
                port = int(port)
            except (TypeError, ValueError):
                return
            if port <= 0 or port > 65535:
                return
            schemes = [str(scheme).lower()] if scheme in ("http", "https") else \
                self._host_collision_schemes(port, service=service, protocol=protocol)
            for value in schemes:
                key = (value, ip, port)
                row = endpoint_map.setdefault(key, {
                    "scheme": value,
                    "ip": ip,
                    "port": port,
                    "sources": set(),
                    "domains": set(),
                })
                if source:
                    row["sources"].add(str(source))
                row["domains"].update(domains or [])
                row["domains"].update(targeted_domains.get(ip) or [])

        def add_url(raw_url, ip="", source="", domains=None):
            try:
                parsed = urlparse(str(raw_url or "").strip())
            except (TypeError, ValueError):
                return
            if parsed.scheme not in ("http", "https"):
                return
            target_ip = str(ip or parsed.hostname or "").strip().strip("[]")
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            add(target_ip, port, parsed.scheme, source=source, domains=domains)

        for ip in targets:
            add(ip, 80, "http", source="default_web_port")
            add(ip, 443, "https", source="default_web_port")

        for item in utils.conn_db("ip").find(
                {"task_id": self.task_id}, {"_id": 0, "ip": 1, "port_info": 1}):
            for port_info in item.get("port_info") or []:
                add(
                    item.get("ip"),
                    port_info.get("port_id") or port_info.get("port"),
                    source="ip_port_info",
                    service=port_info.get("service_name") or port_info.get("product"),
                    protocol=port_info.get("protocol"),
                )

        for item in utils.conn_db("site").find(
                {"task_id": self.task_id}, {"_id": 0, "ip": 1, "site": 1}):
            add_url(item.get("site"), ip=item.get("ip"), source="site")

        for collection_name in ("cert", "cert_candidate"):
            for item in utils.conn_db(collection_name).find(
                    {"task_id": self.task_id}, {
                        "_id": 0, "ip": 1, "port": 1,
                        "host_collision_eligible": 1,
                        "cert_verify_status": 1,
                        "pipeline_exclusion_reason": 1,
                        "quarantine_reason": 1,
                        "relation_reason": 1,
                    }):
                if collection_name == "cert_candidate":
                    allowed, _ = self._host_collision_candidate_allowed(
                        item, block_explicit=True)
                    if not allowed:
                        continue
                add(item.get("ip"), item.get("port") or 443, "https", source=collection_name)

        for collection_name in ("asset_seed_candidate", "vhost_ip_candidate"):
            fields = {
                "_id": 0, "ip": 1, "port": 1, "ports": 1,
                "protocol": 1, "evidence": 1,
                "host_collision_eligible": 1,
                "cert_verify_status": 1,
                "pipeline_exclusion_reason": 1,
                "quarantine_reason": 1,
                "relation_reason": 1,
            }
            for item in utils.conn_db(collection_name).find(
                    {"task_id": self.task_id}, fields):
                allowed, _ = self._host_collision_candidate_allowed(
                    item, block_explicit=True)
                if not allowed:
                    continue
                ip = item.get("ip")
                for evidence in item.get("evidence") or []:
                    add_url(evidence.get("url"), ip=ip, source=collection_name)
                    add(
                        ip,
                        evidence.get("port"),
                        scheme=str(evidence.get("protocol") or "").lower(),
                        source=collection_name,
                        protocol=evidence.get("protocol"),
                    )
                for port in list(item.get("ports") or []) + [item.get("port")]:
                    add(
                        ip,
                        port,
                        scheme=str(item.get("protocol") or "").lower(),
                        source=collection_name,
                        protocol=item.get("protocol"),
                    )

        for collection_name in ("port_candidate", "port_site_probe_state"):
            fields = {
                "_id": 0, "ip": 1, "port": 1, "service_name": 1,
                "protocol": 1, "site_count": 1, "confirmed": 1,
            }
            for item in utils.conn_db(collection_name).find(
                    {"task_id": self.task_id}, fields):
                if collection_name == "port_site_probe_state" and not item.get("site_count"):
                    continue
                add(
                    item.get("ip"),
                    item.get("port"),
                    source=collection_name,
                    service=item.get("service_name"),
                    protocol=item.get("protocol"),
                )

        for collection_name, fields in (
            ("url", {"_id": 0, "url": 1, "final_url": 1, "site": 1}),
            ("entry_asset", {"_id": 0, "seed": 1}),
        ):
            for item in utils.conn_db(collection_name).find(
                    {"task_id": self.task_id}, fields):
                for key in ("url", "final_url", "site", "seed"):
                    raw_url = item.get(key)
                    try:
                        parsed = urlparse(str(raw_url or ""))
                        address = ipaddress.ip_address(str(parsed.hostname or ""))
                    except (TypeError, ValueError):
                        continue
                    if address.version == 4:
                        add_url(raw_url, source=collection_name)

        endpoints = []
        for key in sorted(endpoint_map):
            row = endpoint_map[key]
            row["sources"] = sorted(row["sources"])
            row["domains"] = sorted(row["domains"])
            endpoints.append(row)
        logger.info(
            "host_collision endpoints:{} ips:{} targeted_pairs:{}".format(
                len(endpoints),
                len(targets),
                sum(len(row.get("domains") or []) for row in endpoints),
            ))
        return endpoints

    def host_collision_paths(self, domains):
        domains = set(domains or [])
        if not domains or int(getattr(Config, "HOST_COLLISION_PATH_LIMIT", 3) or 0) <= 0:
            return {}
        paths = {}
        blocked_extensions = {
            ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
            ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map", ".pdf",
            ".zip", ".rar", ".7z", ".mp3", ".mp4",
        }
        blocked_actions = ("logout", "signout", "delete", "remove", "destroy")

        def add(raw_url):
            try:
                parsed = urlparse(str(raw_url or "").strip())
            except (TypeError, ValueError):
                return
            hostname = str(parsed.hostname or "").strip(".").lower()
            if parsed.scheme not in ("http", "https") or hostname not in domains:
                return
            path = parsed.path or "/"
            if path == "/" or any(path.lower().endswith(ext) for ext in blocked_extensions):
                return
            if any(marker in path.lower() for marker in blocked_actions):
                return
            paths.setdefault(hostname, set()).add(path)

        for item in utils.conn_db("url").find(
                {"task_id": self.task_id},
                {"_id": 0, "url": 1, "final_url": 1, "site": 1, "seed_url": 1}):
            for key in ("url", "final_url", "site", "seed_url"):
                add(item.get(key))

        for item in utils.conn_db("wih").find(
                {"task_id": self.task_id, "record_type": "all_url"},
                {"_id": 0, "content": 1, "url_site": 1}):
            add(item.get("content"))
            add(item.get("url_site"))

        for item in utils.conn_db("entry_asset").find(
                {"task_id": self.task_id}, {"_id": 0, "seed": 1}):
            add(item.get("seed"))

        priority_words = (
            "login", "signin", "admin", "manage", "console", "portal",
            "swagger", "openapi", "api", "dashboard", "system", "index",
        )

        def score(path):
            lower = path.lower()
            keyword_score = sum(20 for word in priority_words if word in lower)
            depth_penalty = lower.count("/") * 2
            return (-keyword_score + depth_penalty, len(path), path)

        output = {
            domain: sorted(values, key=score)[:12]
            for domain, values in paths.items()
        }
        logger.info(
            "host_collision absolute paths hosts:{} paths:{}".format(
                len(output), sum(len(values) for values in output.values())))
        return output

    @staticmethod
    def _host_collision_endpoint_key(endpoint):
        return "{}://{}:{}".format(
            endpoint.get("scheme"), endpoint.get("ip"), endpoint.get("port"))

    def _host_collision_plan_fingerprint(self, endpoint, domains, paths):
        endpoint_domains = sorted(set(domains) | set(endpoint.get("domains") or []))
        engine = getattr(self, "_host_collision_engine_identity", None)
        if engine is None:
            engine_path = str(getattr(
                Config, "HOST_COLLISION_ENGINE_PATH", "") or "")
            engine_digest = ""
            fallback_digest = ""
            if bool(getattr(Config, "HOST_COLLISION_GO_ENGINE", True)) and engine_path:
                try:
                    digest = hashlib.sha256()
                    with open(engine_path, "rb") as engine_file:
                        for chunk in iter(
                                lambda: engine_file.read(1024 * 1024), b""):
                            digest.update(chunk)
                    engine_digest = digest.hexdigest()
                except OSError:
                    engine_digest = "unavailable"
            fallback_path = os.path.abspath(os.path.join(
                os.path.dirname(__file__), "..", "services", "findVhost.py"))
            try:
                digest = hashlib.sha256()
                with open(fallback_path, "rb") as fallback_file:
                    for chunk in iter(
                            lambda: fallback_file.read(1024 * 1024), b""):
                        digest.update(chunk)
                fallback_digest = digest.hexdigest()
            except OSError:
                fallback_digest = "unavailable"
            engine = {
                "go_enabled": bool(getattr(
                    Config, "HOST_COLLISION_GO_ENGINE", True)),
                "path": os.path.basename(engine_path),
                "sha256": engine_digest,
                "fallback_sha256": fallback_digest,
            }
            self._host_collision_engine_identity = engine
        payload = {
            "version": 6,
            "endpoint": self._host_collision_endpoint_key(endpoint),
            "domains": endpoint_domains,
            "paths": {
                domain: paths.get(domain, [])
                for domain in endpoint_domains if paths.get(domain)
            },
            "engine": engine,
            "quality": {
                "connect_timeout_ms": int(getattr(
                    Config, "HOST_COLLISION_CONNECT_TIMEOUT_MS", 1800) or 0),
                "request_timeout_ms": int(getattr(
                    Config, "HOST_COLLISION_REQUEST_TIMEOUT_MS", 6000) or 0),
                "max_body_bytes": int(getattr(
                    Config, "HOST_COLLISION_MAX_BODY_BYTES", 131072) or 0),
                "min_body_length": int(getattr(
                    Config, "HOST_COLLISION_MIN_BODY_LENGTH", 300) or 0),
                "accept_redirect": bool(getattr(
                    Config, "HOST_COLLISION_ACCEPT_REDIRECT", False)),
                "path_limit": int(getattr(
                    Config, "HOST_COLLISION_PATH_LIMIT", 3) or 0),
                "retries": int(getattr(
                    Config, "HOST_COLLISION_RETRIES", 1) or 0),
            },
        }
        return hashlib.sha256(json.dumps(
            payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def _prepare_host_collision_checkpoints(self, endpoints, domains, paths):
        if not getattr(Config, "HOST_COLLISION_CHECKPOINT_ENABLE", True):
            return endpoints, 0
        collection = utils.conn_db("host_collision_checkpoint")
        pending = []
        skipped = 0
        updates = []
        for endpoint in endpoints:
            item = dict(endpoint)
            endpoint_key = self._host_collision_endpoint_key(item)
            fingerprint = self._host_collision_plan_fingerprint(item, domains, paths)
            item["plan_fingerprint"] = fingerprint
            done = collection.find_one({
                "task_id": self.task_id,
                "endpoint_key": endpoint_key,
                "plan_fingerprint": fingerprint,
                "status": {"$in": ["done", "unreachable", "skipped"]},
            }, {"_id": 1})
            if done:
                skipped += 1
                continue
            updates.append(UpdateOne(
                {"task_id": self.task_id, "endpoint_key": endpoint_key},
                {
                    "$set": {
                        "task_id": self.task_id,
                        "target": self.base_domain,
                        "endpoint_key": endpoint_key,
                        "scheme": item.get("scheme"),
                        "ip": item.get("ip"),
                        "port": item.get("port"),
                        "plan_fingerprint": fingerprint,
                        "status": "pending",
                        "updated_at": utils.curr_date(),
                    },
                    "$setOnInsert": {"created_at": utils.curr_date()},
                    "$inc": {"attempt_count": 1},
                    "$unset": {
                        "error": "", "completed_at": "", "started_at": "",
                    },
                },
                upsert=True,
            ))
            pending.append(item)
        if updates:
            collection.bulk_write(updates, ordered=False)
        return pending, skipped

    def _start_host_collision_checkpoint(self, progress, endpoint_fingerprints):
        if not getattr(Config, "HOST_COLLISION_CHECKPOINT_ENABLE", True):
            return
        endpoint_key = str(progress.get("endpoint_key") or "")
        if not endpoint_key:
            return
        utils.conn_db("host_collision_checkpoint").update_one(
            {
                "task_id": self.task_id,
                "endpoint_key": endpoint_key,
                "plan_fingerprint": endpoint_fingerprints.get(endpoint_key),
            },
            {"$set": {
                "status": "running",
                "updated_at": utils.curr_date(),
                "started_at": utils.curr_date(),
            }},
        )

    def _update_host_collision_checkpoint(self, progress, endpoint_fingerprints):
        if not getattr(Config, "HOST_COLLISION_CHECKPOINT_ENABLE", True):
            return
        endpoint_key = str(progress.get("endpoint_key") or "")
        if not endpoint_key:
            return
        error = str(progress.get("error") or "")
        if not error:
            status = "done"
        elif error == "tcp_unreachable":
            status = "unreachable"
        elif error in (
                "no_domains", "dynamic_response_oracle",
                "runtime_dynamic_response_oracle"):
            status = "skipped"
        else:
            status = "retryable_error"
        terminal = status in ("done", "unreachable", "skipped")
        utils.conn_db("host_collision_checkpoint").update_one(
            {
                "task_id": self.task_id,
                "endpoint_key": endpoint_key,
                "plan_fingerprint": endpoint_fingerprints.get(endpoint_key),
            },
            {"$set": {
                "status": status,
                "error": error,
                "request_count": int(progress.get("request_count", 0) or 0),
                "response_count": int(progress.get("response_count", 0) or 0),
                "error_count": int(progress.get("error_count", 0) or 0),
                "result_count": int(progress.get("result_count", 0) or 0),
                "total_request_count": int(
                    progress.get("total_request_count", 0) or 0),
                "total_response_count": int(
                    progress.get("total_response_count", 0) or 0),
                "total_error_count": int(
                    progress.get("total_error_count", 0) or 0),
                "request_error_count": int(
                    progress.get("error_count", 0) or 0),
                "total_request_error_count": int(
                    progress.get("total_error_count", 0) or 0),
                "total_result_count": int(
                    progress.get("total_result_count", 0) or 0),
                "updated_at": utils.curr_date(),
                "completed_at": utils.curr_date() if terminal else "",
            }},
        )

    @staticmethod
    def _host_collision_verification_state(result):
        state = str(result.get("verification_state") or "").strip().lower()
        try:
            status_code = int(result.get("status_code") or 0)
        except (TypeError, ValueError):
            status_code = 0
        if status_code == 200 and state != "restricted_candidate":
            return "confirmed"
        return "restricted_candidate"

    def _save_host_collision_result(self, result):
        if self._host_collision_verification_state(result) != "confirmed":
            return 0
        target_allowed, target_block_reason = (
            self._host_collision_result_target_allowed(result))
        if not target_allowed:
            logger.info(
                "drop host collision result from blocked candidate ip:{} "
                "domain:{} reason:{} sources:{}".format(
                    result.get("ip"),
                    result.get("domain"),
                    target_block_reason,
                    result.get("endpoint_sources") or []))
            return 0
        collision_domain = str(
            result.get("domain") or "").strip().strip("*.").lower()
        if not collision_domain or utils.check_domain_black(collision_domain):
            return 0
        domain_row = getattr(self, "_host_collision_domain_rows", {}).get(
            collision_domain, {})
        if (domain_row.get("fresh_dns_status") not in
                HOST_COLLISION_ALLOWED_DNS_STATUSES):
            return 0
        collision_ip = str(result.get("ip") or "").strip()
        if not collision_ip:
            collision_ip = str(urlparse(
                str(result.get("url") or "")).hostname or "").strip()
        try:
            collision_address = ipaddress.ip_address(collision_ip)
            collision_ip_sort = (
                int(collision_address) if collision_address.version == 4 else None)
        except ValueError:
            collision_ip_sort = None
        verification_state = self._host_collision_verification_state(result)
        verify_obj = dict(result)
        verify_obj["verification_state"] = verification_state
        verify_obj["host_collision_policy_version"] = (
            HOST_COLLISION_POLICY_VERSION)
        verify_obj["host_sources"] = sorted(domain_row.get("sources") or [])
        observed_ips = sorted(domain_row.get("ips") or [])
        fresh_ips = sorted(domain_row.get("fresh_ips") or [])
        verify_obj.update({
            "host_observed_ips": observed_ips,
            "host_fresh_ips": fresh_ips,
            "host_dns_status": domain_row.get("fresh_dns_status", ""),
            "host_collision_reason": domain_row.get("collision_reason", ""),
            "host_ip_sources": sorted(
                (domain_row.get("ip_sources") or {}).get(collision_ip) or []),
            "historical_ip_match": bool(
                collision_ip in observed_ips and collision_ip not in fresh_ips),
        })
        save_item = {
            "plg_name": "FindVhost",
            "plg_type": "scan",
            "vul_name": "发现Host碰撞漏洞",
            "app_name": "web",
            "target": result.get("url"),
            "source": "findvhost",
            "review_status": (
                "confirmed" if verification_state == "confirmed" else "pending"),
            "pipeline_eligible": False,
            "candidate_disposition": "host_only",
            "host_collision_ip": collision_ip,
            "host_collision_ip_sort": collision_ip_sort,
            "host_collision_domain": collision_domain,
            "host_collision_port": int(result.get("port") or 0),
            "host_collision_scheme": str(result.get("scheme") or ""),
            "host_collision_quality": str(result.get("quality") or ""),
            "host_collision_signature": str(
                result.get("response_signature") or ""),
            "host_collision_policy_version": HOST_COLLISION_POLICY_VERSION,
            "host_collision_archived": False,
            "verify_data": "{}-{}-{}-{}".format(
                collision_domain,
                result.get("title", ""),
                result.get("status_code", ""),
                result.get("body_length", ""),
            ),
            "verify_obj": verify_obj,
            "task_id": self.task_id,
            "save_date": utils.curr_date(),
        }
        query = {
            "task_id": self.task_id,
            "plg_name": "FindVhost",
            "host_collision_ip": collision_ip,
            "host_collision_port": int(result.get("port") or 0),
            "host_collision_scheme": str(result.get("scheme") or ""),
            "host_collision_domain": collision_domain,
        }
        utils.conn_db("vuln").update_one(query, {"$set": save_item}, upsert=True)
        return 1

    def find_vhost_vuln(self):
        def empty_summary(host_count=0, target_count=0, checkpoint_skipped=0):
            return {
                "input_count": int(host_count or 0),
                "output_count": 0,
                "host_count": int(host_count or 0),
                "target_count": int(target_count or 0),
                "checkpoint_skipped": int(checkpoint_skipped or 0),
                "completed_endpoints": 0,
                "total_endpoints": int(target_count or 0),
                "completed_targets": 0,
                "total_targets": int(target_count or 0),
                "completion_ratio": 1.0 if not target_count else 0.0,
                "confirmed_result_count": 0,
                "saved_result_count": 0,
                "restricted_candidate_count": 0,
                "engine_result_count": 0,
                "result_count": 0,
                "total_result_count": 0,
                "request_count": 0,
                "total_request_count": 0,
                "response_count": 0,
                "total_response_count": 0,
                "request_error_count": 0,
                "total_error_count": 0,
                "endpoint_status_counts": {},
                "throughput_per_second": 0.0,
                "eta_seconds": 0.0,
            }

        utils.conn_db("vuln").update_many({
            "task_id": self.task_id,
            "source": "findvhost",
            "host_collision_policy_version": {
                "$ne": HOST_COLLISION_POLICY_VERSION,
            },
        }, {"$set": {
            "host_collision_archived": True,
            "host_collision_archive_reason": "superseded_policy",
            "host_collision_archived_at": utils.curr_date(),
        }})
        domains = self.host_collision_domains()
        targeted_domains = getattr(self, "_host_collision_targeted_domains", {})
        if not domains and not targeted_domains:
            return empty_summary()

        endpoints = self.host_collision_endpoints()
        if not endpoints:
            return empty_summary(host_count=len(domains))

        all_domains = set(domains)
        for values in targeted_domains.values():
            all_domains.update(values)
        paths = self.host_collision_paths(all_domains)
        endpoints, checkpoint_skipped = self._prepare_host_collision_checkpoints(
            endpoints, domains, paths)
        if not endpoints:
            return empty_summary(
                host_count=len(all_domains),
                checkpoint_skipped=checkpoint_skipped,
            )

        logger.info(
            "find_vhost candidates domains:{} targeted_domains:{} endpoints:{} "
            "checkpoint_skipped:{}".format(
                len(domains),
                len(all_domains) - len(domains),
                len(endpoints),
                checkpoint_skipped,
            ))
        total_targets = len(endpoints)
        endpoint_fingerprints = {
            self._host_collision_endpoint_key(endpoint): endpoint.get("plan_fingerprint")
            for endpoint in endpoints
        }
        self.base_update_task.update_stage_progress("findvhost", {
            "input_count": len(all_domains) + len(endpoints),
            "host_count": len(all_domains),
            "target_count": len(endpoints),
            "completed_targets": 0,
            "total_targets": total_targets,
            "completed_endpoints": 0,
            "total_endpoints": total_targets,
            "checkpoint_skipped": checkpoint_skipped,
            "endpoint_key": "",
            "endpoint_status_counts": {},
            "request_count": 0,
            "response_count": 0,
            "request_error_count": 0,
            "request_error_rate": 0.0,
            "throughput_per_second": 0.0,
            "eta_seconds": 0.0,
            "engine_result_count": 0,
            "confirmed_result_count": 0,
            "restricted_candidate_count": 0,
            "result_count": 0,
            "total_request_count": 0,
            "total_response_count": 0,
            "total_error_count": 0,
            "total_result_count": 0,
            "error": "",
            "skipped": False,
        })

        restricted_candidates = 0
        saved_results = 0
        saved_result_keys = set()
        endpoint_status_counts = Counter()
        run_metrics = {
            "completed_targets": 0,
            "total_targets": total_targets,
            "request_count": 0,
            "response_count": 0,
            "request_error_count": 0,
            "result_count": 0,
            "engine": "",
        }

        def save_result(result):
            nonlocal restricted_candidates, saved_results
            result_key = (
                str(result.get("scheme") or ""),
                str(result.get("ip") or ""),
                int(result.get("port") or 0),
                str(result.get("domain") or "").strip().strip("*.").lower(),
            )
            if result_key in saved_result_keys:
                return
            saved_result_keys.add(result_key)
            state = self._host_collision_verification_state(result)
            if state == "confirmed":
                saved_count = self._save_host_collision_result(result)
                saved_results += saved_count
            else:
                restricted_candidates += 1

        def update_progress(progress):
            if progress.get("type") == "start":
                self._start_host_collision_checkpoint(
                    progress, endpoint_fingerprints)
                return
            completed = int(progress.get("completed_targets", 0) or 0)
            self._update_host_collision_checkpoint(progress, endpoint_fingerprints)
            endpoint_key = str(progress.get("endpoint_key") or "")
            if endpoint_key:
                error = str(progress.get("error") or "")
                if not error:
                    endpoint_status_counts["done"] += 1
                elif error == "tcp_unreachable":
                    endpoint_status_counts["unreachable"] += 1
                elif error in (
                        "no_domains", "dynamic_response_oracle",
                        "runtime_dynamic_response_oracle"):
                    endpoint_status_counts["skipped"] += 1
                else:
                    endpoint_status_counts["retryable_error"] += 1
            run_metrics["completed_targets"] = max(
                run_metrics["completed_targets"], completed)
            run_metrics["request_count"] = max(
                run_metrics["request_count"],
                int(progress.get("total_request_count", 0) or 0),
            )
            run_metrics["response_count"] = max(
                run_metrics["response_count"],
                int(progress.get("total_response_count", 0) or 0),
            )
            run_metrics["request_error_count"] = max(
                run_metrics["request_error_count"],
                int(progress.get("total_error_count", 0) or 0),
            )
            run_metrics["result_count"] = max(
                run_metrics["result_count"],
                int(progress.get("total_result_count", 0) or 0),
            )
            if progress.get("engine"):
                run_metrics["engine"] = str(progress.get("engine"))
            if completed != total_targets and completed % 5:
                return
            payload = dict(progress)
            request_count = run_metrics["request_count"]
            request_error_count = run_metrics["request_error_count"]
            payload.update({
                "input_count": len(all_domains) + len(endpoints),
                "error_count": endpoint_status_counts.get("retryable_error", 0),
                "host_count": len(all_domains),
                "target_count": len(endpoints),
                "checkpoint_skipped": checkpoint_skipped,
                "endpoint_status_counts": dict(endpoint_status_counts),
                "request_count": run_metrics["request_count"],
                "response_count": run_metrics["response_count"],
                "request_error_count": request_error_count,
                "request_error_rate": round(
                    request_error_count / float(max(request_count, 1)), 6),
                "engine_result_count": run_metrics["result_count"],
                "result_count": int(progress.get("result_count", 0) or 0),
                "total_request_count": run_metrics["request_count"],
                "total_response_count": run_metrics["response_count"],
                "total_error_count": run_metrics["request_error_count"],
                "total_result_count": run_metrics["result_count"],
                "confirmed_result_count": saved_results,
                "restricted_candidate_count": restricted_candidates,
                "error": str(progress.get("error") or ""),
                "skipped": bool(progress.get("skipped", False)),
            })
            self.base_update_task.update_stage_progress("findvhost", payload)

        find_vhost(
            endpoints=endpoints,
            domains=domains,
            paths=paths,
            on_progress=update_progress,
            on_result=save_result,
            base_domain=self.base_domain,
        )
        unreachable_count = endpoint_status_counts.get("unreachable", 0)
        retryable_count = endpoint_status_counts.get("retryable_error", 0)
        skipped_count = endpoint_status_counts.get("skipped", 0)
        summary = {
            "input_count": len(all_domains) + len(endpoints),
            "output_count": saved_results,
            "error_count": retryable_count,
            "host_count": len(all_domains),
            "target_count": len(endpoints),
            "checkpoint_skipped": checkpoint_skipped,
            "completed_targets": run_metrics["completed_targets"],
            "total_targets": total_targets,
            "request_count": run_metrics["request_count"],
            "response_count": run_metrics["response_count"],
            "request_error_count": run_metrics["request_error_count"],
            "request_error_rate": round(
                run_metrics["request_error_count"] /
                float(max(run_metrics["request_count"], 1)), 6),
            "engine_result_count": run_metrics["result_count"],
            "saved_result_count": saved_results,
            "confirmed_result_count": saved_results,
            "restricted_candidate_count": restricted_candidates,
            "engine": run_metrics["engine"] or "unknown",
            "endpoint_status_counts": dict(endpoint_status_counts),
            "unreachable_count": unreachable_count,
            "retryable_error_count": retryable_count,
            "skipped_endpoint_count": skipped_count,
        }
        warning_parts = []
        if unreachable_count:
            warning_parts.append(
                "{} endpoints unreachable after connect retries".format(
                    unreachable_count))
        if retryable_count:
            warning_parts.append(
                "{} endpoints require retry".format(retryable_count))
        if warning_parts:
            summary.update({
                "_stage_status": "done_with_warnings",
                "completion_state": "done_with_warnings",
                "warning": "; ".join(warning_parts),
            })
        logger.info(
            "find_vhost completed hosts:{} endpoints:{} confirmed:{} restricted:{} "
            "requests:{} responses:{} request_errors:{} endpoint_status:{}".format(
                len(all_domains), len(endpoints), saved_results, restricted_candidates,
                run_metrics["request_count"], run_metrics["response_count"],
                run_metrics["request_error_count"],
                dict(endpoint_status_counts),
            ))
        return summary

    def start_find_vhost(self):
        if self.options.get("findvhost"):
            self.run_stage("findvhost", self.find_vhost_vuln)
            self.stop_if_terminal("poc_run")

    # 搜索引擎调用
    def search_engines(self):
        if not self.options.get("search_engines"):
            return

        if "{fuzz}" in self.base_domain:
            return

        self.update_task_field("status", "search_engines")
        self.base_update_task.start_stage("search_engines", input_count=1)
        t1 = time.time()
        try:
            search_engines_urls = search_engines(self.base_domain)

            urls = set()  # 保存通过搜索引擎获取到的URL
            domains = set()
            for url in search_engines_urls:
                parse = urlparse(url)
                netloc = parse.netloc
                netloc_domain = netloc.split(":")[0]

                # 只是过滤有效URL
                if netloc_domain.endswith("." + self.base_domain) or \
                        self.base_domain == netloc_domain:
                    domains.add(netloc_domain)
                else:
                    continue

                # 过滤掉路径为首页的URL
                if parse.path == "/" or parse.path == "":
                    continue

                urls.add(url)

            # 可能发现新的域名， 这里保存起来
            domain_info_list = []
            if len(domains) > 0:
                domain_info_list = self.build_domain_info(domains)
                resolved_domains = {
                    str(info.domain or "").strip(".").lower()
                    for info in domain_info_list
                    if getattr(info, "domain", "")
                }
                unresolved_domains = sorted(domains - resolved_domains)
                if self.task_tag == "task":
                    domain_info_list = self.clear_domain_info_by_record(domain_info_list)
                    self.save_domain_info_list(domain_info_list, source=CollectSource.SEARCHENGINE)
                    if unresolved_domains:
                        save_domain_documents(self.task_id, [
                            {
                                "domain": domain,
                                "type": "UNKNOWN",
                                "record": [],
                                "ips": [],
                                "resolve_status": "unresolved",
                            }
                            for domain in unresolved_domains
                        ], CollectSource.SEARCHENGINE)
                self.domain_info_list.extend(domain_info_list)
            else:
                unresolved_domains = []

            elapse = time.time() - t1
            self.update_services("search_engines", elapse, summary={
                "output_count": len(domains),
                "resolved_count": len(domain_info_list),
                "unresolved_count": len(unresolved_domains),
                "url_count": len(urls),
            })
            if self.stop_if_terminal("search_engine_page_fetch"):
                return

            logger.info(
                "search_engines {}, resolved:{} unresolved:{} url:{}".format(
                    self.base_domain,
                    len(domain_info_list),
                    len(unresolved_domains),
                    len(urls)))

            # 构建Page 信息
            if len(urls) > 0:
                page_map = services.page_fetch(urls, task_id=self.task_id)
                save_url_page_map(self.task_id, page_map, CollectSource.SEARCHENGINE)
        except Exception as e:
            elapse = time.time() - t1
            self.base_update_task.fail_stage("search_engines", e, elapsed=elapse)
            raise

    def start_wih_domain_update(self):
        domains = self.web_site_fetch.entry_tracker.pending_domains(
            self.wih_domain_set)
        if domains:
            summary = domain_site_update(
                self.task_id,
                domains,
                "wih",
                reprobe_existing_without_site=True,
                run_file_leak=False,
            )
            self.web_site_fetch.entry_tracker.finalize_domains(domains)
            self.insert_task_stat()
            return summary
        return {}

    def run_entry_feedback_round(self, baseline_sites):
        if not getattr(Config, "ENTRY_FEEDBACK_ROUND_ENABLE", True):
            return {"output_count": 0, "skipped": True}
        if not self.options.get("site_spider"):
            return {"output_count": 0, "skipped": True}

        current_sites = {
            str(item.get("site") or "").strip()
            for item in utils.conn_db("site").find(
                formal_site_query({"task_id": self.task_id}),
                {"_id": 0, "site": 1})
            if str(item.get("site") or "").strip()
        }
        feedback_sites = sorted(current_sites - set(baseline_sites or []))
        max_origins = max(int(getattr(Config, "ENTRY_FEEDBACK_MAX_ORIGINS", 100) or 0), 0)
        capped_count = 0
        if max_origins and len(feedback_sites) > max_origins:
            capped_count = len(feedback_sites) - max_origins
            feedback_sites = feedback_sites[:max_origins]
        if not feedback_sites:
            return {"input_count": 0, "output_count": 0, "capped_count": capped_count}

        feedback_fetch = WebSiteFetch(
            task_id=self.task_id,
            sites=feedback_sites,
            options=self.options,
            scope_domain=[self.base_domain],
        )
        feedback_fetch.available_sites = list(feedback_sites)
        spider_summary = self.run_stage(
            "entry_feedback_spider",
            lambda: feedback_fetch.site_spider(stage_name="entry_feedback_spider"),
            input_count=len(feedback_sites),
        )
        runtime_summary = {}
        if feedback_fetch.runtime_artifact_ready():
            runtime_summary = self.run_stage(
                "entry_feedback_runtime_artifact",
                lambda: feedback_fetch.run_runtime_artifact(
                    stage_name="entry_feedback_runtime_artifact"),
                input_count=len(feedback_fetch.runtime_artifact_targets),
            )
        if self.stop_if_terminal("entry_feedback_wih"):
            return {"input_count": len(feedback_sites), "output_count": 0}

        wih_summary = {}
        if self.options.get("web_info_hunter"):
            wih_summary = self.run_stage(
                "entry_feedback_wih",
                lambda: feedback_fetch.run_web_info_hunter(
                    stage_name="entry_feedback_wih"),
                input_count=len(feedback_fetch.site_spider_wih_targets),
            )
        if self.stop_if_terminal("entry_feedback_domain_update"):
            return {"input_count": len(feedback_sites), "output_count": 0}

        discovered_domains = set(feedback_fetch.site_spider_domain_set)
        discovered_domains.update(feedback_fetch.wih_domain_set)
        pending_domains = feedback_fetch.entry_tracker.pending_domains(discovered_domains)
        domain_summary = {}
        if pending_domains:
            domain_summary = domain_site_update(
                self.task_id,
                pending_domains,
                "entry_feedback",
                url_evidence=feedback_fetch.site_spider_domain_url_map,
                reprobe_existing_without_site=True,
                run_file_leak=False,
            ) or {}
            feedback_fetch.entry_tracker.finalize_domains(pending_domains)
        self.insert_task_stat()
        return {
            "input_count": len(feedback_sites),
            "output_count": int(domain_summary.get("output_count", 0) or 0),
            "discovered_domain_count": len(discovered_domains),
            "pending_domain_count": len(pending_domains),
            "entry_alive_count": feedback_fetch.entry_tracker.counts().get("alive_count", 0),
            "spider_output_count": int(spider_summary.get("output_count", 0) or 0),
            "runtime_artifact_output_count": int(
                runtime_summary.get("output_count", 0) or 0),
            "runtime_artifact_target_count": int(
                runtime_summary.get("target_count") or
                runtime_summary.get("input_count") or 0),
            "wih_output_count": int(wih_summary.get("output_count", 0) or 0),
            "capped_count": capped_count,
        }

    def finish_task(self):
        if not self.task_is_terminal():
            warning_stages = []
            for item in utils.conn_db("task_stage").find(
                {
                    "task_id": self.task_id,
                    "status": {"$in": ["partial", "done_with_warnings"]},
                },
                {
                    "_id": 0,
                    "stage": 1,
                    "status": 1,
                    "warning": 1,
                    "partial_reason": 1,
                    "error": 1,
                    "extra.warnings": 1,
                },
            ):
                extra = item.get("extra") or {}
                reasons = []
                for value in (
                    item.get("warning"),
                    item.get("partial_reason"),
                    item.get("error"),
                ):
                    if value:
                        reasons.append(str(value))
                reasons.extend(
                    str(value) for value in (extra.get("warnings") or [])
                    if value
                )
                warning_stages.append({
                    "stage": item.get("stage", ""),
                    "status": item.get("status", ""),
                    "reason": "; ".join(dict.fromkeys(reasons))[:1000],
                })

            now = utils.curr_date()
            fields = {
                "status": TaskStatus.DONE,
                "end_time": now,
                "completion_state": (
                    "done_with_warnings" if warning_stages else "done"),
            }
            update = {"$set": fields}
            if warning_stages:
                update["$set"]["workflow_warning"] = {
                    "count": len(warning_stages),
                    "stages": warning_stages,
                    "updated_at": now,
                }
            else:
                update["$unset"] = {"workflow_warning": ""}
            utils.conn_db("task").update_one(
                {
                    "_id": ObjectId(self.task_id),
                    "status": {"$nin": [
                        TaskStatus.DONE, TaskStatus.STOP, TaskStatus.ERROR,
                    ]},
                },
                update,
            )

    def run_light_phase(self):
        self.update_task_field("start_time", utils.curr_date())

        self.domain_fetch(include_alt=False)
        if self.stop_if_terminal("search_engines"):
            return

        # Search-engine domains are useful mutation seeds, so collect them
        # before the bounded mutation/recursive brute stage.
        self.search_engines()
        if self.stop_if_terminal("dns_auxiliary"):
            return {"next_phase": "stopped"}

        if getattr(Config, "DNS_AUXILIARY_ENABLE", True):
            self.run_stage(
                "dns_auxiliary",
                self.dns_auxiliary,
                input_count=len(self.domain_info_list),
            )
        if self.stop_if_terminal("alt_dns"):
            return {"next_phase": "stopped"}

        self.run_alt_dns_stage()
        if self.stop_if_terminal("cert_candidate_verify"):
            return {"next_phase": "stopped"}

        if self.options.get("dns_query_plugin"):
            self.run_stage(
                "cert_candidate_verify",
                self.verify_cert_query_candidates,
                input_count=utils.conn_db("asset_seed_candidate").count_documents({
                    "task_id": self.task_id,
                    "candidate_type": "cert_ip",
                }),
            )
        if self.stop_if_terminal("asset_seed_probe"):
            return {"next_phase": "stopped"}

        self.start_asset_seed_fetch()
        if self.stop_if_terminal("port_scan_top1000"):
            return {"next_phase": "stopped"}
        return {"next_phase": "heavy_top"}

    def run_heavy_top_phase(self):
        self.hydrate_from_storage()
        if self.task_is_terminal():
            return {"next_phase": "stopped"}

        self.run_top_port_phase()
        if self.stop_if_terminal("port_scan_full"):
            return {"next_phase": "stopped"}
        return {"next_phase": "heavy_full"}

    def run_heavy_full_phase(self):
        self.hydrate_from_storage()
        if self.task_is_terminal():
            return {"next_phase": "stopped", "post_required": False}

        full_port_summary = self.run_full_port_phase() or {}
        if full_port_summary.get("continuation_required"):
            return {
                "next_phase": "heavy_full",
                "full_port_continuation_required": True,
                "full_port_summary": full_port_summary,
                "post_required": False,
            }
        if self.stop_if_terminal("find_site"):
            return {"next_phase": "stopped", "post_required": False}

        delta_state = self.prepare_discovery_delta_state()
        self.start_site_fetch(include_post_discovery=False)
        if self.stop_if_terminal("post_dns_feedback"):
            return {"next_phase": "stopped", "post_required": False}

        if (
            self.options.get("alt_dns") and
            getattr(Config, "POST_DNS_FEEDBACK_ENABLE", True)
        ):
            self.run_stage(
                "post_dns_feedback",
                self.post_dns_feedback,
                input_count=len(self.post_seed_domains),
            )
        if self.stop_if_terminal("discovery_delta"):
            return {"next_phase": "stopped", "post_required": False}

        if delta_state:
            self.run_stage(
                "discovery_delta",
                lambda: self.run_discovery_delta(delta_state),
                input_count=(
                    len(self.post_seed_domains) +
                    len(getattr(self.web_site_fetch, "site_spider_domain_set", set())) +
                    len(getattr(self.web_site_fetch, "wih_domain_set", set()))
                ),
            )
        if self.stop_if_terminal("bface_discover"):
            return {"next_phase": "stopped", "post_required": False}

        if self.options.get("bface_discover"):
            self.run_stage(
                "bface_discover",
                lambda: self.run_bface_discover_stage(),
                input_count=1,
            )
        if self.stop_if_terminal("poc_context_refresh"):
            return {"next_phase": "stopped", "post_required": False}

        if getattr(self, "task_id", ""):
            self.refresh_post_discovery_context()
        if self.stop_if_terminal("poc_run"):
            return {"next_phase": "stopped", "post_required": False}

        self.start_poc_run()
        if self.stop_if_terminal("post_processing"):
            return {"next_phase": "stopped", "post_required": False}

        post_required = self.post_processing_required()
        if post_required:
            self.insert_task_stat()
            return {"next_phase": "post", "post_required": True}

        return {
            "next_phase": "post_finalize",
            "post_required": False,
            "finalize_required": True,
        }

    def run(self):
        light_result = self.run_light_phase()
        if self.task_is_terminal():
            return light_result

        top_result = self.run_heavy_top_phase()
        if self.task_is_terminal():
            return top_result

        full_result = self.run_heavy_full_phase()
        if self.task_is_terminal():
            return full_result

        if not full_result.get("post_required"):
            if full_result.get("finalize_required"):
                finalize_result = self.finalize_post_processing()
                full_result["next_phase"] = (
                    "done" if finalize_result.get("finalized") else "stopped")
            return full_result

        post_result = self.run_post_processing()
        if self.task_is_terminal():
            return post_result
        self.finalize_post_processing()
        return post_result


def domain_task(base_domain, task_id, options, phase="full"):
    d = DomainTask(base_domain=base_domain, task_id=task_id, options=options)
    try:
        phase_map = {
            "full": d.run,
            "light": d.run_light_phase,
            "heavy_top": d.run_heavy_top_phase,
            "heavy_full": d.run_heavy_full_phase,
            "post": d.run_post_processing,
            "post_finalize": d.finalize_post_processing,
        }
        runner = phase_map.get(phase)
        if runner is None:
            raise ValueError("unknown domain task phase: {}".format(phase))
        return runner()
    except Exception as e:
        logger.exception(e)
        try:
            current_stage = d.base_update_task.get_status()
            if current_stage and current_stage not in [TaskStatus.DONE, TaskStatus.STOP, TaskStatus.ERROR, TaskStatus.WAITING]:
                d.base_update_task.fail_stage(current_stage, e)
        except Exception as stage_e:
            logger.warning("mark task stage error failed task_id:{} error:{}".format(task_id, stage_e))
        try:
            d.insert_task_stat()
        except Exception as stat_e:
            logger.warning("insert task statistic error task_id:{} error:{}".format(task_id, stat_e))
        try:
            utils.conn_db("task").update_one(
                {"_id": ObjectId(task_id), "status": {"$nin": [
                    TaskStatus.DONE, TaskStatus.STOP, TaskStatus.ERROR]}},
                {"$set": {
                    "workflow_phase": "{}_error".format(phase),
                    "workflow_error": str(e)[:1000],
                }},
            )
        except Exception as workflow_e:
            logger.warning("mark workflow phase error failed task_id:{} error:{}".format(
                task_id, workflow_e))
        d.update_task_field("status", TaskStatus.ERROR)
        d.update_task_field("end_time", utils.curr_date())
        return {"next_phase": "error", "error": str(e)}
