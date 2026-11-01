"""企业情报资产检索：APP / 小程序 / ICP 备案（来源 fengniao_intel 采集库）。

统一走 /asset_ext/?kind=app|miniprogram|icp，供控制台资产检索页的
扩展维度使用；关键字同时匹配所属企业与条目名称。
情报库为按企业采集的文档（单次采集受 max_records 约束），量级可控，
直接展平后内存分页。
"""

import re

from flask_restx import Namespace, reqparse

from app import utils
from app.utils import get_logger, auth
from . import ARLResource

ns = Namespace('asset_ext', description="企业情报资产（APP/小程序/ICP 备案）")

logger = get_logger()

# kind -> (条目名主键字段, 展示列 [(字段, 展示名)])
KIND_CONF = {
    "app": ("appname", [("appname", "应用名"), ("downloadCountLevel", "下载量级"),
                        ("updateDateAndroid", "安卓更新"), ("updateDateIos", "iOS 更新")]),
    "miniprogram": ("name", [("name", "小程序名"), ("cate", "类目")]),
    "icp": ("hostname", [("hostname", "域名"), ("icpnum", "备案号"),
                         ("webname", "网站名"), ("shdate", "审核日期")]),
}

MAX_DOCS = 2000

ext_parser = reqparse.RequestParser()
ext_parser.add_argument("kind", type=str, location="args", default="app",
                        help="资产维度 app|miniprogram|icp")
ext_parser.add_argument("keyword", type=str, location="args", default="",
                        help="关键字（匹配所属企业或条目名）")
ext_parser.add_argument("page", type=int, location="args", default=1)
ext_parser.add_argument("size", type=int, location="args", default=20)


@ns.route('/')
class AssetExt(ARLResource):

    @auth
    @ns.expect(ext_parser)
    def get(self):
        """企业情报资产查询（kind=app|miniprogram|icp，keyword 匹配企业/条目名）"""
        args = ext_parser.parse_args()
        kind = str(args.get("kind") or "app").strip().lower()
        if kind not in KIND_CONF:
            return utils.build_ret("KindInvalid", {"error": "kind 须为 app|miniprogram|icp"})

        try:
            page = max(int(args.get("page") or 1), 1)
            size = min(max(int(args.get("size") or 20), 1), 200)
        except (TypeError, ValueError):
            page, size = 1, 20
        keyword = str(args.get("keyword") or "").strip()

        name_field = KIND_CONF[kind][0]
        query = {}
        if keyword:
            rx = {"$regex": re.escape(keyword), "$options": "i"}
            query = {"$or": [{"ent_name": rx},
                             {"{}.{}".format(kind, name_field): rx}]}

        coll = utils.conn_db("fengniao_intel")
        docs = list(coll.find(query).sort("_id", -1).limit(MAX_DOCS))

        items = []
        for doc in docs:
            base = {"ent_name": doc.get("ent_name"),
                    "group_id": str(doc.get("group_id") or ""),
                    "path": doc.get("path")}
            for row in (doc.get(kind) or []):
                if not isinstance(row, dict):
                    continue
                item = dict(row)
                item.update(base)
                items.append(item)

        total = len(items)
        start = (page - 1) * size
        return {"code": 200, "message": "success",
                "data": {"kind": kind, "items": items[start:start + size],
                         "total": total, "page": page, "size": size}}
