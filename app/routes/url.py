import re

from flask_restx import Resource, Api, reqparse, fields, Namespace
from app.utils import get_logger, auth
from app import utils
from . import base_query_fields, FormalPipelineResource, get_arl_parser

ns = Namespace('url', description="URL信息")

logger = get_logger()

base_search_fields = {
    'fld': fields.String(required=False, description="IP"),
    'site': fields.String(description="域名"),
    'url': fields.String(required=False, description="URL"),
    'content_length': fields.Integer(description="body 长度"),
    'status_code': fields.Integer(description="状态码"),
    'title': fields.String(description="标题"),
    'source': fields.String(description="来源"),
    'url_type': fields.String(description="URL 类型"),
    "task_id": fields.String(description="任务ID")
}

base_search_fields.update(base_query_fields)


@ns.route('/')
class ARLUrl(FormalPipelineResource):
    parser = get_arl_parser(base_search_fields, location='args')

    def build_url_data(self, args):
        default_field = self.get_default_field(args)
        page = default_field.get("page", 1)
        size = default_field.get("size", 10)
        orderby_list = default_field.get('order', [("_id", -1)])
        query = self.build_db_query(args)

        if not args.get("url_type"):
            query.setdefault("$and", []).append({
                "$or": [
                    {"url_type": {"$exists": False}},
                    {"url_type": {"$nin": ["entry_pending", "crawler_risky"]}},
                ]
            })

        projection = self.get_find_projection(args, "url")
        result = utils.conn_db("url").find(query, projection).sort(
            orderby_list).skip(size * (page - 1)).limit(size)
        count = utils.conn_db("url").count_documents(query)
        items = self.build_return_items(result)

        for key in list(query.keys()):
            raw_value = query[key]
            if isinstance(raw_value, dict) and "$not" in raw_value:
                if isinstance(raw_value["$not"], type(re.compile(""))):
                    raw_value["$not"] = raw_value["$not"].pattern

        return {
            "page": page,
            "size": size,
            "total": count,
            "items": items,
            "query": query,
            "code": 200,
        }

    @auth
    @ns.expect(parser)
    def get(self):
        """
        URL信息查询
        """
        args = self.parser.parse_args()
        data = self.build_url_data(args=args)

        return data


@ns.route('/export/')
class ARLUrlExport(FormalPipelineResource):
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        URL 导出
        """
        args = self.parser.parse_args()
        response = self.send_export_file(args=args, _type="url")

        return response
