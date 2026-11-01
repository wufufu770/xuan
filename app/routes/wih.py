from flask_restx import fields, Namespace
from app.utils import get_logger, auth
from . import ARLResource, base_query_fields, FormalPipelineResource, get_arl_parser
from bson import ObjectId
from urllib.parse import urlparse
from app.modules import ErrorMsg
from app import utils

ns = Namespace('wih', description="WEB Info Hunter 信息")

logger = get_logger()

base_search_fields = {
    'record_type': fields.String(required=False, description="记录类型"),
    'record_type__neq': fields.String(required=False, description="记录类型不等于（全匹配）"),
    'record_type__not': fields.String(required=False, description="记录类型不包含"),
    'content': fields.String(description="内容"),
    'source': fields.String(description="采集源"),
    'sources': fields.String(description="多来源"),
    'site': fields.String(description="发现自/站点URL"),
    'discovered_from': fields.String(description="真实发现来源"),
    'url_site': fields.String(description="URL归属站点"),
    'evidence_type': fields.String(description="证据类型"),
    'wih_target_source': fields.String(description="WIH输入来源"),
    'task_id': fields.String(description="任务ID"),
}


base_search_fields.update(base_query_fields)


def _url_site_from_content(content):
    parsed = urlparse(str(content or ""))
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return ""
    return "{}://{}".format(parsed.scheme, parsed.netloc)


def enrich_wih_items(items):
    for item in items or []:
        source = item.get("source", "")
        sources = item.get("sources") or []
        if isinstance(sources, str):
            sources = [sources]
        if source and source not in sources:
            sources.insert(0, source)
        if sources:
            item["sources"] = sources

        if not item.get("evidence_type"):
            if source == "katana_js":
                item["evidence_type"] = "crawler_discovered_domain"
            elif source == "katana_all_url":
                item["evidence_type"] = "hae_all_url"

        if item.get("record_type") == "all_url" and not item.get("url_site"):
            item["url_site"] = _url_site_from_content(item.get("content", ""))

        if source in ("katana_js", "katana_all_url") and not item.get("discovered_from"):
            item["discovered_from"] = "历史来源不确定"

    return items


@ns.route('/')
class ARLWebInfoHunter(FormalPipelineResource):
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        WEB Info Hunter 信息查询
        """
        args = self.parser.parse_args()
        data = self.build_data(args=args, collection='wih')
        enrich_wih_items(data.get("items", []))

        return data


@ns.route('/export/')
class ARLWihExport(FormalPipelineResource):
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        WIH 导出
        """
        args = self.parser.parse_args()
        response = self.send_export_file(args=args, _type="wih")

        return response


delete_wih_fields = ns.model('deleteWih',  {
    '_id': fields.List(fields.String(required=True, description="数据_id"))
})


@ns.route('/delete/')
class DeleteARLWIH(ARLResource):
    @auth
    @ns.expect(delete_wih_fields)
    def post(self):
        """
        删除任务中的 wih 数据
        """
        args = self.parse_args(delete_wih_fields)
        id_list = args.pop('_id', "")
        for _id in id_list:
            query = {'_id': ObjectId(_id)}
            utils.conn_db('wih').delete_one(query)

        return utils.build_ret(ErrorMsg.Success, {'_id': id_list})
