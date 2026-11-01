# -*- coding:UTF-8 -*-
"""APP 下载中心：凤鸟情报 app 列表、商店链接解析、APK 落盘下载与分发。

数据流：fengniao_intel.app[] --enrich--> app[].download（链接+可信度）
        --download job--> /opt/ARL/data/app_download/<公司>/<pkg>.apk + appdl_file 文档
前端：/appdl.html 独立页（不侵入 React bundle），Token 走 localStorage。
"""
import re
import threading

from bson.objectid import ObjectId
from flask import request, send_file
from flask_restx import fields, Namespace, reqparse

from app import utils
from app.services import app_store
from app.utils import auth, curr_date, get_logger
from . import ARLResource

ns = Namespace('appdl', description="APP 下载中心")

logger = get_logger()

_job_slots = threading.BoundedSemaphore(2)


def _ret(data=None, message="success", code=200):
    return {"code": code, "message": message, "data": data or {}}


def _safe_name(name):
    text = re.sub(r"[^\w\u4e00-\u9fff.-]+", "_", str(name or "").strip())
    return text[:60] or "unknown"


def _group_company_names(group_id):
    if not group_id:
        return []
    doc = utils.conn_db("fengniao_group").find_one({"_id": ObjectId(group_id)}) \
        if _is_oid(group_id) else None
    if not doc:
        return []
    return [c.get("entName") for c in (doc.get("companies") or []) if c.get("entName")]


def _persist_enrich(intel, app_index, result):
    """解析结果写回 fengniao_intel，并镜像到 fengniao_group（企业信息页数据源）。

    collect 流程没把 group_id 写进 intel 文档，按 entid 在最新集团文档里定位。
    """
    utils.conn_db("fengniao_intel").update_one(
        {"_id": intel["_id"]},
        {"$set": {"app.{}.download".format(app_index): result}})
    entid = str(intel.get("entid") or "")
    appname = ""
    apps = intel.get("app") or []
    if 0 <= app_index < len(apps):
        appname = str(apps[app_index].get("appname") or "")
    if not (entid and appname):
        return
    conn = utils.conn_db("fengniao_group")
    gid = intel.get("group_id")
    query = {"_id": ObjectId(gid)} if _is_oid(gid) else {"companies.entid": entid}
    doc = conn.find_one(query, {"companies": 1}, sort=[("_id", -1)])
    if not doc:
        return
    for ci, comp in enumerate(doc.get("companies") or []):
        if str(comp.get("entid") or "") != entid:
            continue
        for ai, row in enumerate(comp.get("app") or []):
            if str(row.get("appname") or "") == appname:
                conn.update_one(
                    {"_id": doc["_id"]},
                    {"$set": {"companies.{}.app.{}.download".format(ci, ai): result}})
                return


def _is_oid(value):
    try:
        ObjectId(str(value))
        return True
    except Exception:
        return False


def _app_brief(intel, index, row, file_doc):
    download = row.get("download") or {}
    android = download.get("android") or {}
    ios = download.get("ios") or {}
    return {
        "intel_id": str(intel["_id"]),
        "app_index": index,
        "ent_name": intel.get("ent_name"),
        "depth": intel.get("depth", 0),
        "appname": row.get("appname") or row.get("name") or "",
        "brief": str(row.get("brief") or "")[:120],
        "download_count": row.get("downloadCountLevel", ""),
        "update_android": row.get("updateDateAndroid"),
        "update_ios": row.get("updateDateIos"),
        "confidence": download.get("confidence", ""),
        "matched_by": android.get("matched_by", ""),
        "android_pkg": android.get("pkg", ""),
        "android_url": android.get("detail_url", ""),
        "android_version": android.get("version", ""),
        "android_size": android.get("size_text", ""),
        "developer": android.get("developer", ""),
        "ios_url": ios.get("track_url", ""),
        "ios_bundle": ios.get("bundle_id", ""),
        "local": ({
            "file_id": str(file_doc["_id"]),
            "size": file_doc.get("size"),
            "md5": file_doc.get("md5"),
            "version": file_doc.get("version", ""),
            "date": file_doc.get("create_time", ""),
        } if file_doc else None),
    }


apps_parser = reqparse.RequestParser()
apps_parser.add_argument('enrich', type=int, default=0, location='args')


@ns.route('/apps/')
class AppdlApps(ARLResource):
    @auth
    @ns.expect(apps_parser)
    def get(self):
        """凤鸟情报 app 列表（可选自动解析链接 enrich=N，未缓存的优先）。"""
        args = apps_parser.parse_args()
        # 单次最多解析 2 个：gunicorn sync worker 默认 30s 超时，超时会被强杀（502）。
        # 前端循环分批调用补完全量。
        enrich_budget = max(0, min(int(args.get('enrich') or 0), 2))

        files_by_key = {}
        for doc in utils.conn_db("appdl_file").find({}):
            files_by_key[(str(doc.get("intel_id")), int(doc.get("app_index") or 0))] = doc

        items = []
        cursor = utils.conn_db("fengniao_intel").find(
            {"app.0": {"$exists": True}}).sort("depth", 1)
        for intel in cursor:
            companies = _group_company_names(intel.get("group_id"))
            for index, row in enumerate(intel.get("app") or []):
                if enrich_budget > 0 and not row.get("download"):
                    try:
                        result = app_store.enrich_app(row, intel.get("ent_name"), companies)
                        _persist_enrich(intel, index, result)
                        row = dict(row, download=result)
                        enrich_budget -= 1
                    except Exception as exc:
                        logger.warning("appdl enrich failed %s: %s",
                                       row.get("appname"), exc)
                items.append(_app_brief(
                    intel, index, row,
                    files_by_key.get((str(intel["_id"]), index))))
        return _ret({"items": items, "total": len(items)})


enrich_model = ns.model('AppdlEnrich', {
    'intel_id': fields.String(required=True, description="fengniao_intel 文档ID"),
    'app_index': fields.Integer(required=True, description="app 数组下标"),
})


@ns.route('/enrich/')
class AppdlEnrich(ARLResource):
    @auth
    @ns.expect(enrich_model)
    def post(self):
        """强制重新解析一个 app 的商店链接（刷新缓存）。"""
        args = self.parse_args(enrich_model)
        if not _is_oid(args['intel_id']):
            return _ret({'error': 'intel_id 无效'}, message='intel_id 无效', code=400)
        intel = utils.conn_db("fengniao_intel").find_one(
            {"_id": ObjectId(args['intel_id'])})
        if not intel:
            return _ret({'error': '情报不存在'}, message='情报不存在', code=404)
        index = int(args['app_index'])
        apps = intel.get("app") or []
        if index < 0 or index >= len(apps):
            return _ret({'error': 'app_index 越界'}, message='app_index 越界', code=400)
        row = apps[index]
        result = app_store.enrich_app(
            row, intel.get("ent_name"), _group_company_names(intel.get("group_id")))
        _persist_enrich(intel, index, result)
        return _ret({"result": result})


download_model = ns.model('AppdlDownload', {
    'intel_id': fields.String(required=False, description="fengniao_intel 文档ID"),
    'app_index': fields.Integer(required=False, description="app 数组下标"),
    'ent_name': fields.String(required=False, description="按公司名定位（企业信息页内嵌按钮用）"),
    'appname': fields.String(required=False, description="按应用名定位"),
    'arch': fields.String(default="64", description="64|32 位包"),
})


def _resolve_target(args):
    """下载目标定位：intel_id+app_index，或 ent_name+appname（企业页内嵌按钮）。"""
    intel_id = str(args.get('intel_id') or '')
    app_index = args.get('app_index')
    if intel_id and app_index is not None:
        return intel_id, int(app_index), None
    ent_name = str(args.get('ent_name') or '').strip()
    appname = str(args.get('appname') or '').strip()
    if not (ent_name and appname):
        return None, None, "需要 intel_id+app_index 或 ent_name+appname"
    intel = utils.conn_db("fengniao_intel").find_one(
        {"ent_name": ent_name, "app.appname": appname})
    if not intel:
        return None, None, "没有找到该公司下的应用：{} / {}".format(ent_name, appname)
    index = next((i for i, row in enumerate(intel.get("app") or [])
                  if str(row.get("appname") or "") == appname), None)
    if index is None:
        return None, None, "应用下标解析失败"
    return str(intel["_id"]), index, None


def _set_job(job_oid, **values):
    values['update_time'] = curr_date()
    utils.conn_db('appdl_job').update_one({'_id': job_oid}, {'$set': values})


def _run_download(job_oid, intel_id, app_index, arch):
    with _job_slots:
        try:
            _set_job(job_oid, status='running', progress=0,
                     start_time=curr_date())
            intel = utils.conn_db("fengniao_intel").find_one({"_id": ObjectId(intel_id)})
            row = (intel.get("app") or [])[app_index]
            download = row.get("download") or {}
            android = download.get("android") or {}
            if not (android.get("apk_url") or android.get("apk_url64")):
                # 企业页内嵌按钮可能未解析过链接：job 内现场解析并回写
                result = app_store.enrich_app(
                    row, intel.get("ent_name"),
                    _group_company_names(intel.get("group_id")))
                _persist_enrich(intel, app_index, result)
                download = result
                android = download.get("android") or {}
            apk_url = android.get("apk_url64" if arch == "64" else "apk_url")
            if not apk_url:
                raise RuntimeError("该 app 无 Android 直链（可能仅 iOS 或未解析）")

            pkg = android.get("pkg") or "unknown"
            ent = intel.get("ent_name") or "unknown"
            if app_store._dir_size_mb(app_store.APK_DIR) > app_store.TOTAL_QUOTA_GB * 1024:
                raise RuntimeError("下载目录已超配额 {}GB".format(app_store.TOTAL_QUOTA_GB))

            dest = "{}/{}/{}_{}.apk".format(
                app_store.APK_DIR, _safe_name(ent), _safe_name(pkg),
                arch)
            expected_md5 = android.get("md5", "")

            def on_progress(done, total):
                _set_job(job_oid, progress=int(done * 100 / max(total, 1)))

            meta = app_store.download_apk(apk_url, dest, expected_md5=expected_md5,
                                          on_progress=on_progress)
            doc_id = utils.conn_db("appdl_file").insert_one({
                "intel_id": str(intel_id), "app_index": app_index,
                "ent_name": ent, "pkg": pkg,
                "appname": row.get("appname") or row.get("name") or "",
                "version": android.get("version", ""),
                "path": dest, "size": meta["size"], "md5": meta["md5"],
                "arch": arch, "source": "yyb",
                "create_time": curr_date(),
            }).inserted_id
            _set_job(job_oid, status='done', progress=100,
                     file_id=str(doc_id), end_time=curr_date())
        except Exception as exc:
            logger.warning("appdl job failed: %s", exc)
            _set_job(job_oid, status='error', error=str(exc), end_time=curr_date())


@ns.route('/download/')
class AppdlDownload(ARLResource):
    @auth
    @ns.expect(download_model)
    def post(self):
        """提交 APK 落盘下载任务（异步 job，支持 intel_id+app_index 或 公司名+应用名）。"""
        args = self.parse_args(download_model)
        intel_id, app_index, err = _resolve_target(args)
        if err:
            return _ret({'error': err}, message=err, code=400)
        arch = "64" if str(args.get("arch")) != "32" else "32"
        job_oid = ObjectId()
        utils.conn_db("appdl_job").insert_one({
            "_id": job_oid, "intel_id": intel_id,
            "app_index": int(app_index), "arch": arch,
            "status": "queued", "progress": 0,
            "create_time": curr_date(), "update_time": curr_date(),
        })
        threading.Thread(
            target=_run_download,
            args=(job_oid, intel_id, int(app_index), arch),
            daemon=True).start()
        return _ret({"job_id": str(job_oid), "status": "queued"})


job_parser = reqparse.RequestParser()
job_parser.add_argument('job_id', required=True, location='args')


@ns.route('/job/')
class AppdlJob(ARLResource):
    @auth
    @ns.expect(job_parser)
    def get(self):
        job_id = job_parser.parse_args().get('job_id')
        if not _is_oid(job_id):
            return _ret({'error': 'job_id 无效'}, message='job_id 无效', code=400)
        doc = utils.conn_db("appdl_job").find_one({"_id": ObjectId(job_id)})
        if not doc:
            return _ret({'error': '任务不存在'}, message='任务不存在', code=404)
        doc["_id"] = str(doc["_id"])
        return _ret(doc)


@ns.route('/file/')
class AppdlFile(ARLResource):
    @auth
    def get(self):
        """按文档 ID 下发本地 APK（路径只取自数据库，防穿越）。"""
        doc_id = request.args.get('doc_id') or ""
        if not _is_oid(doc_id):
            return _ret({'error': 'doc_id 无效'}, message='doc_id 无效', code=400)
        doc = utils.conn_db("appdl_file").find_one({"_id": ObjectId(doc_id)})
        if not doc or not doc.get("path"):
            return _ret({'error': '文件不存在'}, message='文件不存在', code=404)
        filename = "{}_{}{}.apk".format(
            _safe_name(doc.get("appname") or doc.get("pkg")),
            _safe_name(doc.get("pkg")), "_" + str(doc.get("arch") or ""))
        return send_file(doc["path"], as_attachment=True, download_name=filename,
                         mimetype="application/vnd.android.package-archive")


@ns.route('/downloads/')
class AppdlDownloads(ARLResource):
    @auth
    def get(self):
        """已落盘文件清单。"""
        items = []
        for doc in utils.conn_db("appdl_file").find({}).sort("_id", -1).limit(200):
            items.append({
                "file_id": str(doc["_id"]), "ent_name": doc.get("ent_name"),
                "appname": doc.get("appname"), "pkg": doc.get("pkg"),
                "version": doc.get("version", ""), "size": doc.get("size"),
                "md5": doc.get("md5"), "arch": doc.get("arch"),
                "date": doc.get("create_time"),
            })
        return _ret({"items": items, "total": len(items)})
