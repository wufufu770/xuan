# -*- coding:UTF-8 -*-
from urllib.parse import urlparse

from bson import ObjectId
from flask_restx import fields, Namespace

from app.config import Config
from app.utils import get_logger, auth
from app import utils
from . import ARLResource
from app.services.fofaClient import fofa_query
from app.services.dns_query_plugin.fofa import (
    FOFA_SURVEY_FIELDS, parse_fofa_result,
)

ns = Namespace('supply_chain', description="供应链横向反查")

logger = get_logger()

SUPPLY_CHAIN_TAG = "supply_chain"

DEFAULT_MAX_RECORDS = 100
MAX_RECORDS_LIMIT = 1000
MAX_PROBE_SITES = 50


def build_data(data, message="success"):
    ret = {
        "message": message,
        "code": 200,
        "data": {}
    }
    if data:
        ret["data"] = data
    return ret


def _normalize_host(value):
    value = str(value or "").strip()
    if "://" in value:
        return (urlparse(value).hostname or "").strip(".").lower()
    return value.strip(".").lower()


def _build_query_from_site(site_doc):
    """优先 favicon hash，其次标题，最后 IP。"""
    favicon = site_doc.get("favicon") or {}
    favicon_hash = favicon.get("hash") if isinstance(favicon, dict) else ""
    if favicon_hash not in (None, ""):
        return 'favicon_hash="{}"'.format(favicon_hash), "favicon_hash"

    title = str(site_doc.get("title") or "").strip()
    if title:
        return 'title="{}"'.format(title.replace('"', "")), "title"

    ip = str(site_doc.get("ip") or "").strip()
    if ip:
        return 'ip="{}"'.format(ip), "ip"

    return "", ""


@ns.route('/reverse')
class SupplyChainReverse(ARLResource):

    reverse_model = ns.model('SupplyChainReverse', {
        'site_id': fields.String(description="站点 _id（从站点信息自动构造查询）"),
        'favicon_hash': fields.String(description="FOFA favicon hash（mmh3）"),
        'title': fields.String(description="站点标题反查"),
        'ip_cidr': fields.String(description="IP 或 CIDR 反查"),
        'engine': fields.String(description="测绘引擎", enum=["fofa"], default="fofa"),
        'scope_id': fields.String(description="资产组 ID（新资产归属，可选）"),
        'max_records': fields.Integer(description="最大拉取条数", example=100),
        'probe': fields.Boolean(
            description="是否探活新站点后入库", default=True),
    })

    @auth
    @ns.expect(reverse_model)
    def post(self):
        """
        供应链横向反查（favicon hash / 标题 / IP 段）→ 新资产回流
        """
        args = self.parse_args(self.reverse_model)

        if not str(Config.FOFA_KEY or "").strip():
            return build_data({"ok": False, "message": "FOFA Key 未配置，请先在引擎配置中保存"})

        query, query_type = self._resolve_query(args)
        if not query:
            return build_data({"ok": False,
                               "message": "请提供 site_id / favicon_hash / title / ip_cidr 之一"})

        try:
            max_records = min(max(int(args.get("max_records") or DEFAULT_MAX_RECORDS), 1),
                              MAX_RECORDS_LIMIT)
        except (TypeError, ValueError):
            max_records = DEFAULT_MAX_RECORDS

        results, meta = fofa_query(
            query, fields=FOFA_SURVEY_FIELDS, max_records=max_records,
            include_meta=True)
        if meta.get("error") and not results:
            return build_data({"ok": False,
                               "message": "FOFA 查询失败：{}".format(meta["error"])})

        scope_id = str(args.get("scope_id") or "").strip()
        probe = args.get("probe") is not False

        parsed_items = []
        seen_hosts = set()
        for item in results:
            parsed = parse_fofa_result(item, "", "supply_chain", query_type)
            if not parsed:
                continue
            intel = parsed.get("intel") or {}
            host = _normalize_host(intel.get("url") or parsed.get("domain") or intel.get("ip"))
            if not host or host in seen_hosts:
                continue
            seen_hosts.add(host)
            parsed_items.append(parsed)

        new_site_count, new_domain_count, preview = self._save_new_assets(
            parsed_items, scope_id=scope_id, probe=probe)

        logger.info("supply chain reverse query_type:{} results:{} new_site:{} new_domain:{}".format(
            query_type, len(parsed_items), new_site_count, new_domain_count))

        return build_data({
            "ok": True,
            "query": query,
            "query_type": query_type,
            "result_count": len(parsed_items),
            "new_site_count": new_site_count,
            "new_domain_count": new_domain_count,
            "items": preview,
            "hint": "新资产已写入资产库并打标 supply_chain" if (new_site_count or new_domain_count)
            else "没有发现新资产",
        })

    def _resolve_query(self, args):
        site_id = str(args.get("site_id") or "").strip()
        if site_id:
            try:
                site_doc = utils.conn_db("site").find_one({"_id": ObjectId(site_id)})
            except Exception:
                site_doc = None
            if not site_doc:
                site_doc = utils.conn_db("asset_site").find_one({"_id": ObjectId(site_id)})
            if not site_doc:
                return "", ""
            return _build_query_from_site(site_doc)

        favicon_hash = str(args.get("favicon_hash") or "").strip()
        if favicon_hash:
            return 'favicon_hash="{}"'.format(favicon_hash), "favicon_hash"

        title = str(args.get("title") or "").strip()
        if title:
            return 'title="{}"'.format(title.replace('"', "")), "title"

        ip_cidr = str(args.get("ip_cidr") or "").strip()
        if ip_cidr:
            return 'ip="{}"'.format(ip_cidr), "ip"

        return "", ""

    def _save_new_assets(self, parsed_items, scope_id="", probe=True):
        now = utils.curr_date()
        probe_urls = []
        probe_map = {}

        for parsed in parsed_items:
            intel = parsed.get("intel") or {}
            url = str(intel.get("url") or "").strip()
            if url and url.startswith(("http://", "https://")):
                probe_urls.append(url)

        if probe and probe_urls:
            from app.services.fetchSite import fetch_site

            probe_urls = probe_urls[:MAX_PROBE_SITES]
            try:
                probed = fetch_site(probe_urls, concurrency=10,
                                    http_timeout=(6, 8), observer_ward_enable=False)
                for site_info in probed:
                    if site_info.get("site"):
                        probe_map[site_info["site"]] = site_info
            except Exception as e:
                logger.warning("supply chain probe failed: {}".format(e))

        site_conn = utils.conn_db("asset_site")
        domain_conn = utils.conn_db("asset_domain")

        existing_sites = set()
        existing_domains = set()
        for item in site_conn.find({}, {"_id": 0, "site": 1}).limit(50000):
            if item.get("site"):
                existing_sites.add(item["site"])
        for item in domain_conn.find({}, {"_id": 0, "domain": 1}).limit(50000):
            if item.get("domain"):
                existing_domains.add(item["domain"])

        new_site_count = 0
        new_domain_count = 0
        preview = []

        for parsed in parsed_items:
            intel = parsed.get("intel") or {}
            url = str(intel.get("url") or "").strip()
            host = parsed.get("domain") or _normalize_host(url)
            ip = str(intel.get("ip") or "").strip()

            doc_base = {
                "scope_id": scope_id,
                "source": "supply_chain",
                "sources": ["supply_chain"],
                "tag": [SUPPLY_CHAIN_TAG],
                "task_id": "",
                "save_date": now,
                "update_date": now,
            }

            if url and url.startswith(("http://", "https://")) and url not in existing_sites:
                site_info = dict(probe_map.get(url) or {})
                if site_info:
                    site_info.pop("_id", None)
                    site_info.update(doc_base)
                    site_info.setdefault("site", url)
                    site_info["tag"] = [SUPPLY_CHAIN_TAG]
                else:
                    site_info = dict(doc_base)
                    site_info.update({
                        "site": url,
                        "hostname": host,
                        "ip": ip,
                        "port": intel.get("port"),
                        "title": str(intel.get("web_title") or ""),
                        "status": 0,
                        "favicon": {},
                    })
                site_conn.insert_one(site_info)
                existing_sites.add(url)
                new_site_count += 1
                if len(preview) < 20:
                    preview.append({
                        "type": "site", "site": url,
                        "title": site_info.get("title") or "",
                        "ip": ip, "probed": bool(site_info.get("status")),
                    })

            if host and utils.is_valid_domain(host) and host not in existing_domains:
                domain_doc = dict(doc_base)
                domain_doc.update({
                    "domain": host,
                    "type": "A",
                    "record": [ip] if ip else [],
                    "ips": [ip] if ip else [],
                })
                domain_conn.insert_one(domain_doc)
                existing_domains.add(host)
                new_domain_count += 1
                if len(preview) < 20:
                    preview.append({
                        "type": "domain", "domain": host, "ip": ip,
                    })

        return new_site_count, new_domain_count, preview
