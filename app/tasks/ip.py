from bson.objectid import  ObjectId
import copy
import time
from app import services
from app.modules import ScanPortType, TaskStatus
from app.services import fetchCert, run_risk_cruising, run_sniffer
from app import utils
from app.services.commonTask import CommonTask, BaseUpdateTask, WebSiteFetch
from app.config import Config


logger = utils.get_logger()


def ssl_cert(ip_info_list):
    try:
        targets = []
        for ip_info in ip_info_list:
            for port_info in ip_info["port_info"]:
                if port_info["port_id"] == 80:
                    continue
                targets.append("{}:{}".format(ip_info["ip"], port_info["port_id"]))

        f = fetchCert.SSLCert(targets)
        return f.run()
    except Exception as e:
        logger.exception(e)

    return {}


class IPTask(CommonTask):
    def __init__(self, ip_target=None, task_id=None, options=None):
        super().__init__(task_id=task_id)

        self.ip_target = ip_target
        self.task_id = task_id
        self.options = options
        self.ip_info_list = []
        self.ip_set = set()
        self.site_list = []
        self.cert_map = {}
        self.service_info_list = []
        self.npoc_service_target_set = set()
        # 用来区分是正常任务还是监控任务
        self.task_tag = "task"

        self.scope_id = None
        self.task_name = None
        self.asset_ip_port_set = set()
        self.asset_ip_info_map = dict()
        self.base_update_task = BaseUpdateTask(self.task_id)

    def set_asset_ip(self):
        """
        用来获取Asset_IP 中的信息，仅仅在监控阶段使用
        """
        raise NotImplementedError()

    def async_ip_info(self):
        """
        用来同步发现的 ip 中的信息（包括新添加端口），仅仅在IP 任务 监控阶段使用
        """
        raise NotImplementedError()

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

    def _merge_ip_result(self, new_info):
        for old_info in self.ip_info_list:
            if old_info.get("ip") != new_info.get("ip"):
                continue

            port_map = {}
            for port_info in list(old_info.get("port_info") or []) + list(new_info.get("port_info") or []):
                try:
                    port_id = int(port_info.get("port_id"))
                except Exception:
                    port_id = port_info.get("port_id")
                key = (port_id, port_info.get("protocol", "tcp"))
                current = port_map.get(key)
                if current is None:
                    port_map[key] = port_info
                    continue
                if port_info.get("service_name") or port_info.get("product") or port_info.get("version"):
                    port_map[key] = port_info

            old_info.update(new_info)
            old_info["port_info"] = sorted(
                port_map.values(),
                key=lambda item: int(item.get("port_id")) if str(item.get("port_id")).isdigit() else str(item.get("port_id"))
            )
            return old_info

        self.ip_info_list.append(new_info)
        return new_info

    def _save_ip_results(self, ip_port_result):
        saved = 0
        for ip_info in ip_port_result:
            curr_ip = ip_info["ip"]
            self.ip_set.add(curr_ip)
            if not utils.not_in_black_ips(curr_ip):
                continue

            ip_info = copy.deepcopy(ip_info)
            ip_info["task_id"] = self.task_id
            ip_info["ip_type"] = utils.get_ip_type(curr_ip)
            ip_info["geo_asn"] = {}
            ip_info["geo_city"] = {}

            if ip_info["ip_type"] == "PUBLIC":
                ip_info["geo_asn"] = utils.get_ip_asn(curr_ip)
                ip_info["geo_city"] = utils.get_ip_city(curr_ip)

            merged_info = self._merge_ip_result(ip_info)
            if self.task_tag == 'task':
                query = {"task_id": self.task_id, "ip": merged_info.get("ip")}
                utils.conn_db('ip').update_one(query, {"$set": merged_info}, upsert=True)
            saved += 1

        if saved and self.options.get("service_detection"):
            self.save_service_info()
        return saved

    def _run_port_scan(self, targets, scan_port_option):
        def _on_batch(ip_port_result, batch_index, total_batches, profile):
            saved = self._save_ip_results(ip_port_result)
            logger.info("ip port_scan batch saved {}/{} profile:{} result:{} task:{}".format(
                batch_index, total_batches, profile, saved, self.task_id))

        scan_port_option = copy.deepcopy(scan_port_option)
        scan_port_option["batch_callback"] = _on_batch
        ip_port_result = services.port_scan(targets, **scan_port_option)
        self._save_ip_results(ip_port_result)
        return ip_port_result

    def port_scan(self):
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
            "service_detect": self.options.get("service_detection", False),
            "os_detect": self.options.get("os_detection", False),
            "port_parallelism": self.options.get("port_parallelism", 32),
            "port_min_rate": self.options.get("port_min_rate", 64),
            "custom_host_timeout": None,
            "exclude_ports": self.options.get("exclude_ports", None),
            "task_id": self.task_id,
        }
        if self.options.get("host_timeout_type") == "custom":
            scan_port_option["custom_host_timeout"] = self.options.get("host_timeout", 60 * 15)

        targets = self.ip_target.split()
        if option_scan_port_type == "all" and Config.PORT_SCAN_TOP1000_FIRST:
            top1000_option = copy.deepcopy(scan_port_option)
            top1000_option["ports"] = ScanPortType.TOP1000
            self._run_port_scan(targets, top1000_option)

            full_option = copy.deepcopy(scan_port_option)
            full_option["ports"] = ScanPortType.ALL
            if Config.FULL_PORT_REMAINING_ONLY:
                full_option["exclude_ports"] = self._merge_exclude_ports(
                    full_option.get("exclude_ports"), Config.TOP_1000)
            self._run_port_scan(targets, full_option)
        else:
            self._run_port_scan(targets, scan_port_option)

        if self.task_tag == 'monitor':
            self.set_asset_ip()
            self.async_ip_info()

    def find_site(self):
        url_temp_list = []
        for ip_info in self.ip_info_list:
            for port_info in ip_info["port_info"]:
                curr_ip = ip_info["ip"]
                url_temp_list.extend(self.build_site_urls(curr_ip, port_info))

        alive_urls = services.httpx_probe_urls(
            list(set(url_temp_list)), task_id=self.task_id,
            base_domain="", source="ip_find_site")

        # 去除https和http相同的
        alive_site = []
        alive_set = set(alive_urls)
        for x in alive_urls:
            if x.startswith("https://"):
                alive_site.append(x)

            elif x.startswith("http://"):
                x_temp = "https://" + x[7:]
                if x_temp not in alive_set:
                    alive_site.append(x)

        self.site_list.extend(alive_site)

    @staticmethod
    def build_site_urls(host, port_info):
        port_id = int(port_info.get("port_id"))
        service_name = str(port_info.get("service_name") or "").lower()
        product = str(port_info.get("product") or "").lower()
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

    def ssl_cert(self):
        if self.options.get("port_scan"):
            self.cert_map = ssl_cert(self.ip_info_list)
        else:
            self.cert_map = ssl_cert(self.ip_set)

        for target in self.cert_map:
            if ":" not in target:
                continue
            ip = target.split(":")[0]
            port = int(target.split(":")[1])
            item = {
                "ip": ip,
                "port": port,
                "cert": self.cert_map[target],
                "task_id": self.task_id,
            }
            query = {"task_id": self.task_id, "ip": ip, "port": port}
            utils.conn_db('cert').update_one(query, {"$set": item}, upsert=True)

    def save_service_info(self):
        self.service_info_list = []
        services_list = set()
        for _data in self.ip_info_list:
            port_info_lsit = _data.get("port_info")
            for _info in port_info_lsit:
                if _info.get("service_name"):
                    if _info.get("service_name") not in services_list:
                        _result = {}
                        _result["service_name"] = _info.get("service_name")
                        _result["service_info"] = []
                        _result["service_info"].append({'ip': _data.get("ip"),
                                                        'port_id': _info.get("port_id"),
                                                        'product': _info.get("product"),
                                                        'version': _info.get("version")})
                        _result["task_id"] = self.task_id
                        self.service_info_list.append(_result)
                        services_list.add(_info.get("service_name"))
                    else:
                        for service_info in self.service_info_list:
                            if service_info.get("service_name") == _info.get("service_name"):
                                service_info['service_info'].append({'ip': _data.get("ip"),
                                                                    'port_id': _info.get("port_id"),
                                                                    'product': _info.get("product"),
                                                                    'version': _info.get("version")})
        if self.service_info_list:
            for service_info in self.service_info_list:
                query = {
                    "task_id": self.task_id,
                    "service_name": service_info.get("service_name")
                }
                utils.conn_db('service').update_one(query, {"$set": service_info}, upsert=True)

    def npoc_service_detection(self):
        targets = []
        for ip_info in self.ip_info_list:
            for port_info in ip_info["port_info"]:
                skip_port_list = [80, 443, 843]
                if port_info["port_id"] in skip_port_list:
                    continue

                targets.append("{}:{}".format(ip_info["ip"], port_info["port_id"]))

        result = run_sniffer(targets)
        for item in result:
            self.npoc_service_target_set.add(item["target"])
            item["task_id"] = self.task_id
            item["save_date"] = utils.curr_date()
            utils.conn_db('npoc_service').insert_one(item)

    def brute_config(self):
        plugins = []
        brute_config = self.options.get("brute_config")
        for x in brute_config:
            if not x.get("enable"):
                continue
            plugins.append(x["plugin_name"])

        if not plugins:
            return
        targets = self.site_list.copy()
        targets += list(self.npoc_service_target_set)
        result = run_risk_cruising(targets=targets, plugins=plugins)
        for item in result:
            item["task_id"] = self.task_id
            item["save_date"] = utils.curr_date()
            utils.conn_db('vuln').insert_one(item)

    def run(self):
        base_update = self.base_update_task
        base_update.update_task_field("start_time", utils.curr_date())
        '''***端口扫描开始***'''
        if self.options.get("port_scan"):
            base_update.update_task_field("status", "port_scan")
            t1 = time.time()
            self.port_scan()
            elapse = time.time() - t1
            base_update.update_services("port_scan", elapse)

        # 存储服务信息
        if self.options.get("service_detection"):
            self.save_service_info()

        '''***证书获取开始***'''
        if self.options.get("ssl_cert"):
            base_update.update_task_field("status", "ssl_cert")
            t1 = time.time()
            self.ssl_cert()
            elapse = time.time() - t1
            base_update.update_services("ssl_cert", elapse)

        base_update.update_task_field("status", "find_site")
        t1 = time.time()
        self.find_site()
        elapse = time.time() - t1
        base_update.update_services("find_site", elapse)

        web_site_fetch = WebSiteFetch(task_id=self.task_id,
                                      sites=self.site_list,
                                      options=self.options)
        web_site_fetch.run()

        """服务识别（python）实现"""
        if self.options.get("npoc_service_detection"):
            base_update.update_task_field("status", "npoc_service_detection")
            t1 = time.time()
            self.npoc_service_detection()
            elapse = time.time() - t1
            base_update.update_services("npoc_service_detection", elapse)

        """ *** npoc 调用 """
        if self.options.get("poc_config"):
            base_update.update_task_field("status", "poc_run")
            t1 = time.time()
            web_site_fetch.risk_cruising(self.npoc_service_target_set)
            elapse = time.time() - t1
            base_update.update_services("poc_run", elapse)

        """弱口令爆破服务"""
        if self.options.get("brute_config"):
            base_update.update_task_field("status", "weak_brute")
            t1 = time.time()
            self.brute_config()
            elapse = time.time() - t1
            base_update.update_services("weak_brute", elapse)

        # 加上统计信息
        self.insert_finger_stat()
        self.insert_cip_stat()
        self.insert_task_stat()

        # 如果有关联的资产分组就进行同步，同步这块有点乱
        if self.task_tag == "task":
            self.sync_asset()

        base_update.update_task_field("status", TaskStatus.DONE)
        base_update.update_task_field("end_time", utils.curr_date())


def ip_task(ip_target, task_id, options):
    d = IPTask(ip_target=ip_target, task_id=task_id, options=options)
    try:
        d.run()
    except Exception as e:
        logger.exception(e)
        try:
            d.insert_task_stat()
        except Exception as stat_e:
            logger.warning("insert task statistic error task_id:{} error:{}".format(task_id, stat_e))
        d.base_update_task.update_task_field("status", TaskStatus.ERROR)
        d.base_update_task.update_task_field("end_time", utils.curr_date())
