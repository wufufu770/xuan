from flask_restx import fields, Namespace

from app import utils
from app.utils import auth, get_logger
from . import FormalPipelineResource, base_query_fields, get_arl_parser
from app.services.pathDiscovery import redirect_destination_metadata


ns = Namespace("entry", description="JS 入口资产")
logger = get_logger()


base_search_fields = {
    "seed_type": fields.String(description="入口类型"),
    "seed": fields.String(description="原始种子"),
    "normalized_seed": fields.String(description="规范化种子"),
    "status": fields.String(description="探测状态"),
    "is_new": fields.Boolean(description="是否为新增资产"),
    "is_duplicate": fields.Boolean(description="是否重复"),
    "alive_url": fields.String(description="存活入口"),
    "final_url": fields.String(description="最终 URL"),
    "redirect_location": fields.String(description="原始跳转地址"),
    "redirect_url": fields.String(description="绝对跳转地址"),
    "redirect_host": fields.String(description="跳转主机"),
    "redirect_type": fields.String(description="跳转类型"),
    "redirect_system": fields.String(description="跳转系统"),
    "final_status_code": fields.Integer(description="最终状态码"),
    "final_title": fields.String(description="最终标题"),
    "final_http_server": fields.String(description="最终 Server"),
    "domain": fields.String(description="域名或主机"),
    "status_code": fields.Integer(description="状态码"),
    "title": fields.String(description="标题"),
    "content_length": fields.Integer(description="Body 长度"),
    "source": fields.String(description="采集源"),
    "include_directory": fields.Boolean(description="是否包含目录扫描晋升记录"),
    "collectors": fields.String(description="采集器"),
    "discovered_from": fields.String(description="发现自 JS"),
    "evidence_sources": fields.String(description="全部来源证据"),
    "task_id": fields.String(description="任务 ID"),
}
base_search_fields.update(base_query_fields)


def apply_entry_defaults(args):
    if args.get("status") is None:
        args["status"] = "alive"
    if args.get("is_new") is None:
        args["is_new"] = True
    if args.get("is_duplicate") is None:
        args["is_duplicate"] = False
    if args.get("include_directory") is None:
        args["include_directory"] = False
    return args


class EntryQueryMixin(object):
    def build_entry_data(self, args):
        include_directory = bool(args.pop("include_directory", False))
        default_field = self.get_default_field(args)
        page = default_field.get("page", 1)
        size = default_field.get("size", 10)
        orderby_list = default_field.get("order", [("_id", -1)])
        query = self.build_db_query(args)
        if not include_directory and not args.get("source"):
            query["source"] = {"$ne": "ffuf_path_entry"}

        for field in ("seed_type", "status"):
            value = args.get(field)
            if value:
                query[field] = value

        projection = self.get_find_projection(args, "entry_asset")
        result = (
            utils.conn_db("entry_asset")
            .find(query, projection)
            .sort(orderby_list)
            .skip(size * (page - 1))
            .limit(size)
        )
        items = self.build_return_items(result)
        for item in items:
            request_url = item.get("alive_url") or item.get("seed") or ""
            redirect_meta = redirect_destination_metadata(
                item.get("redirect_location", ""), request_url)
            for key, value in redirect_meta.items():
                if value and not item.get(key):
                    item[key] = value
            if item.get("redirect_host") and not item.get("redirect_system"):
                item["redirect_system"] = item["redirect_host"]
        return {
            "page": page,
            "size": size,
            "total": utils.conn_db("entry_asset").count_documents(query),
            "items": items,
            "query": query,
            "include_directory": include_directory,
            "code": 200,
        }


@ns.route("/")
class ARLEntry(EntryQueryMixin, FormalPipelineResource):
    parser = get_arl_parser(base_search_fields, location="args")

    @auth
    @ns.expect(parser)
    def get(self):
        """查询 JS 发现并探活后的入口资产。"""
        args = apply_entry_defaults(self.parser.parse_args())
        return self.build_entry_data(args)


@ns.route("/export/")
class ARLEntryExport(FormalPipelineResource):
    parser = get_arl_parser(base_search_fields, location="args")

    @auth
    @ns.expect(parser)
    def get(self):
        """导出筛选后的存活入口。"""
        args = apply_entry_defaults(self.parser.parse_args())
        include_directory = bool(args.pop("include_directory", False))
        self.get_default_field(args)
        query = self.build_db_query(args)
        if not include_directory and not args.get("source"):
            query["source"] = {"$ne": "ffuf_path_entry"}
        for field in ("seed_type", "status"):
            value = args.get(field)
            if value:
                query[field] = value

        values = set()
        for item in utils.conn_db("entry_asset").find(
            query, {"alive_url": 1, "seed": 1}
        ):
            value = item.get("alive_url") or item.get("seed")
            if value:
                values.add(value)
        return self.send_file(values, "entry")
