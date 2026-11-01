from bson import ObjectId
from flask_restx import Resource, Api, reqparse, fields, Namespace
from app.utils import get_logger, auth
from . import base_query_fields, ARLResource, FormalPipelineResource, get_arl_parser
from app import utils
from app.modules import ErrorMsg
from app.services.pathDiscovery import redirect_destination_metadata

ns = Namespace('fileleak', description="文件泄漏信息")

logger = get_logger()

base_search_fields = {
    'url': fields.String(required=False, description="URL"),
    'site': fields.String(description="站点"),
    'content_length': fields.Integer(description="body 长度"),
    'status_code': fields.Integer(description="状态码"),
    'title': fields.String(description="标题"),
    'redirect_location': fields.String(description="原始跳转地址"),
    'redirect_url': fields.String(description="绝对跳转地址"),
    'redirect_host': fields.String(description="跳转主机"),
    'redirect_type': fields.String(description="跳转类型"),
    'redirect_system': fields.String(description="跳转系统"),
    'final_url': fields.String(description="最终地址"),
    'final_title': fields.String(description="最终标题"),
    'include_templates': fields.Boolean(description="是否包含模板重复记录"),
    "task_id": fields.String(description="任务ID"),
    "scope_id": fields.String(description="资产组范围ID")
}

base_search_fields.update(base_query_fields)


def apply_fileleak_defaults(args):
    if args.get("include_templates") is None:
        args["include_templates"] = False
    return args


@ns.route('/')
class ARLFileLeak(FormalPipelineResource):
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        文件泄露信息查询
        """
        args = apply_fileleak_defaults(self.parser.parse_args())
        include_templates = bool(args.pop("include_templates", False))
        if not include_templates:
            args["template_hidden__neq"] = True
        data = self.build_data(args=args, collection='fileleak')
        data["include_templates"] = include_templates
        for item in data.get("items", []):
            redirect_meta = redirect_destination_metadata(
                item.get("redirect_location", ""), item.get("url", ""))
            for key, value in redirect_meta.items():
                if value and not item.get(key):
                    item[key] = value
            if item.get("redirect_host") and not item.get("redirect_system"):
                item["redirect_system"] = item["redirect_host"]

        return data


delete_fileleak_fields = ns.model('deleteFileleakFields',  {
    '_id': fields.List(fields.String(required=True, description="文件泄漏 _id"))
})


@ns.route('/delete/')
class DeleteARLFileleak(ARLResource):
    @auth
    @ns.expect(delete_fileleak_fields)
    def post(self):
        """
        删除 文件泄漏
        """
        args = self.parse_args(delete_fileleak_fields)
        id_list = args.pop('_id', [])
        for _id in id_list:
            query = {'_id': ObjectId(_id)}
            utils.conn_db('fileleak').delete_one(query)

        return utils.build_ret(ErrorMsg.Success, {'_id': id_list})
