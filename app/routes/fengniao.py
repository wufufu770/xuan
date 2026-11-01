# -*- coding:UTF-8 -*-
"""凤鸟企业情报：凭证配置、企业搜索、控股集团异步采集与资产入组。

采集在线程内异步执行（web 不被长时间阻塞），任务进度写入 Mongo，
前端轮询 job 状态。token 每次请求直读 config.yaml，跨 gunicorn worker 生效。
"""
import json
import os
import threading
import time
from base64 import b64decode

from bson.objectid import ObjectId
from flask_restx import fields, Namespace, reqparse

from app import utils
from app.config import Config
from app.utils import auth, curr_date, get_fld, get_logger
from . import ARLResource
from .engines import _load_config, _save_config, _mask, CONFIG_PATH
from app.utils.audit import audit
from app.utils.yamlconf import locked_update as _locked_update
from app.services import fengniao

ns = Namespace('fengniao', description="美亚凤鸟企业情报")
logger = get_logger()

_job_slots = threading.BoundedSemaphore(2)


def _ret(data=None, message="success", code=200):
    return {"code": code, "message": message, "data": data or {}}


def _token_from_yaml():
    return str((_load_config().get("FENGNIAR_TOKEN") or "")).strip()


def _apply_token():
    Config.FENGNIAR_TOKEN = _token_from_yaml()


def _token_exp_text(token):
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        exp = json.loads(b64decode(payload)).get("exp", 0)
        if exp:
            return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(exp))
    except Exception:
        pass
    return ""


def _config_data():
    token = _token_from_yaml()
    return {
        "configured": bool(token),
        "masked": _mask(token),
        "exp_text": _token_exp_text(token),
    }


def _safe_int(value, default, minimum, maximum):
    try:
        value = int(value)
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(value, maximum))


def _safe_float(value, default, minimum, maximum):
    try:
        value = float(value)
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(value, maximum))


def _error(exc, code=500):
    return _ret({"error": str(exc)}, message=str(exc), code=code)


@ns.route('/config/')
class FengniaoConfig(ARLResource):
    @auth
    def get(self):
        return _ret(_config_data())

    config_model = ns.model('FengniaoConfigSave', {
        'token': fields.String(description="riskbird cookie token"),
        'clear': fields.Boolean(default=False, description="清除凭证"),
    })

    @auth
    @ns.expect(config_model)
    def post(self):
        args = self.parse_args(self.config_model)
        token = str(args.get('token') or '').strip()
        if token.lower().startswith('token='):
            token = token[6:].strip()
        clearing = bool(args.get('clear'))
        if not clearing and not token:
            return _ret({'error': 'token 不能为空'}, message='token 不能为空', code=400)
        # 只写自己关心的顶层键，避免整读整写覆盖并发保存的其他凭证
        with _locked_update(CONFIG_PATH) as data:
            data['FENGNIAR_TOKEN'] = '' if clearing else token
        _apply_token()
        audit("fengniao_token_change", detail={"clear": clearing})
        return _ret(_config_data(), message='凭证已清除' if clearing else '凭证已保存')


@ns.route('/test/')
class FengniaoTest(ARLResource):
    @auth
    def post(self):
        try:
            _apply_token()
            rows = fengniao.search_ent('科大讯飞股份有限公司', limit=1)
            return _ret({'ok': True, 'message': '连接正常，企业搜索可用',
                         'sample': rows[0]['entName'] if rows else ''})
        except Exception as exc:
            return _error(exc)


search_parser = reqparse.RequestParser()
search_parser.add_argument('keyword', required=True, location='args')


@ns.route('/search/')
class FengniaoSearch(ARLResource):
    @auth
    @ns.expect(search_parser)
    def get(self):
        keyword = str(search_parser.parse_args().get('keyword') or '').strip()
        if not keyword:
            return _ret({'items': []})
        try:
            _apply_token()
            items = fengniao.search_ent(keyword, limit=5)
            return _ret({'items': items})
        except Exception as exc:
            return _error(exc)


collect_model = ns.model('FengniaoCollect', {
    'keyword': fields.String(required=True, description="母公司名称"),
    'entid': fields.String(description="已知企业 entid"),
    'ent_name': fields.String(description="已知企业名"),
    'max_depth': fields.Integer(default=4),
    'min_ratio': fields.Float(default=100.0),
    'max_companies': fields.Integer(default=20),
    'max_records': fields.Integer(default=500),
})


def _set_job(job_oid, **values):
    values['update_time'] = curr_date()
    utils.conn_db('fengniao_job').update_one({'_id': job_oid}, {'$set': values})


def _run_collect(job_oid, keyword, entid, ent_name, params):
    with _job_slots:
        try:
            _apply_token()
            _set_job(job_oid, status='running', start_time=curr_date())
            last_write = [0.0]

            def progress(done, node):
                now = time.time()
                if now - last_write[0] < 1.0:
                    return
                last_write[0] = now
                _set_job(job_oid, progress_done=done,
                         progress_current=node.get('entName'),
                         progress_depth=node.get('depth'))

            result = fengniao.collect_group_and_save(
                keyword, entid=entid, ent_name=ent_name,
                max_depth=params['max_depth'], min_ratio=params['min_ratio'],
                max_companies=params['max_companies'],
                max_records=params['max_records'], on_progress=progress)
            group = result['group']
            group_doc = {
                'root': group['root'],
                'companies': group['companies'],
                'edges': group['edges'],
                'failed': group['failed'],
                'job_id': str(job_oid),
                'create_time': curr_date(),
            }
            gid = utils.conn_db('fengniao_group').insert_one(group_doc).inserted_id
            _set_job(job_oid, status='done', result_group_id=str(gid),
                     new_domain_count=result.get('new_domain_count', 0),
                     progress_current='', end_time=curr_date())
        except Exception as exc:
            logger.warning('fengniao job failed: %s', exc)
            _set_job(job_oid, status='error', error=str(exc), end_time=curr_date())


@ns.route('/collect/')
class FengniaoCollect(ARLResource):
    @auth
    @ns.expect(collect_model)
    def post(self):
        args = self.parse_args(collect_model)
        keyword = str(args.get('keyword') or '').strip()
        entid = str(args.get('entid') or '').strip()
        ent_name = str(args.get('ent_name') or '').strip()
        if not keyword and not entid:
            return _ret({'error': 'keyword 或 entid 至少提供一个'}, message='缺少查询企业', code=400)
        if not _token_from_yaml():
            return _ret({'error': '请先在 AI 与集成配置凤鸟 Token'}, message='未配置凤鸟 Token', code=400)
        params = {
            'max_depth': _safe_int(args.get('max_depth'), 4, 0, 4),
            'min_ratio': _safe_float(args.get('min_ratio'), 100.0, 50.0, 100.0),
            'max_companies': _safe_int(args.get('max_companies'), 20, 1, 20),
            'max_records': _safe_int(args.get('max_records'), 500, 50, 500),
        }
        job_oid = ObjectId()
        utils.conn_db('fengniao_job').insert_one({
            '_id': job_oid, 'keyword': keyword, 'entid': entid, 'ent_name': ent_name,
            'params': params, 'status': 'queued', 'progress_done': 0,
            'progress_current': '', 'create_time': curr_date(), 'update_time': curr_date(),
        })
        thread = threading.Thread(target=_run_collect,
                                  args=(job_oid, keyword, entid, ent_name, params),
                                  daemon=True)
        thread.start()
        return _ret({'job_id': str(job_oid), 'status': 'queued'})


job_parser = reqparse.RequestParser()
job_parser.add_argument('job_id', required=True, location='args')


@ns.route('/job/')
class FengniaoJob(ARLResource):
    @auth
    @ns.expect(job_parser)
    def get(self):
        job_id = job_parser.parse_args().get('job_id')
        try:
            doc = utils.conn_db('fengniao_job').find_one({'_id': ObjectId(job_id)}, {'params': 0})
        except Exception:
            doc = None
        if not doc:
            return _ret({'error': '任务不存在'}, message='任务不存在', code=404)
        doc['_id'] = str(doc['_id'])
        return _ret(doc)


groups_parser = reqparse.RequestParser()
groups_parser.add_argument('limit', type=int, default=10, location='args')


@ns.route('/groups/')
class FengniaoGroups(ARLResource):
    @auth
    def get(self):
        limit = _safe_int(groups_parser.parse_args().get('limit'), 10, 1, 30)
        items = []
        cursor = utils.conn_db('fengniao_group').find(
            {}, {'root': 1, 'companies': 1, 'failed': 1, 'create_time': 1}
        ).sort('_id', -1).limit(limit)
        for doc in cursor:
            companies = doc.get('companies') or []
            items.append({
                'id': str(doc['_id']),
                'root_name': (doc.get('root') or {}).get('entName'),
                'company_count': len(companies),
                'domain_count': sum(len(n.get('icp') or []) for n in companies),
                'app_count': sum(len(n.get('app') or []) for n in companies),
                'mini_count': sum(len(n.get('miniprogram') or []) for n in companies),
                'failed_count': len(doc.get('failed') or []),
                'create_time': doc.get('create_time'),
            })
        return _ret({'items': items})


group_parser = reqparse.RequestParser()
group_parser.add_argument('id', required=True, location='args')


@ns.route('/group/')
class FengniaoGroup(ARLResource):
    @auth
    @ns.expect(group_parser)
    def get(self):
        try:
            doc = utils.conn_db('fengniao_group').find_one(
                {'_id': ObjectId(group_parser.parse_args().get('id'))})
        except Exception:
            doc = None
        if not doc:
            return _ret({'error': '集团数据不存在'}, message='集团数据不存在', code=404)
        doc['_id'] = str(doc['_id'])
        return _ret(doc)


attach_model = ns.model('FengniaoAttach', {
    'group_doc_id': fields.String(required=True),
    'node_entid': fields.String(description="只入组该公司；为空则整个集团"),
    'include_children': fields.Boolean(default=True),
    'scope_id': fields.String(description="目标资产分组，空则新建"),
})


def _scope_roots(hostnames):
    roots = []
    for host in hostnames:
        host = str(host or '').strip().lower().strip('.')
        if not host:
            continue
        root = get_fld(host) or host
        if root not in roots:
            roots.append(root)
    return roots


@ns.route('/attach_scope/')
class FengniaoAttachScope(ARLResource):
    @auth
    @ns.expect(attach_model)
    def post(self):
        args = self.parse_args(attach_model)
        try:
            group = utils.conn_db('fengniao_group').find_one(
                {'_id': ObjectId(args['group_doc_id'])})
        except Exception:
            group = None
        if not group:
            return _ret({'error': '集团数据不存在'}, message='集团数据不存在', code=404)
        companies = group.get('companies') or []
        node_entid = str(args.get('node_entid') or '').strip()
        selected = {node_entid} if node_entid else {str(n.get('entid')) for n in companies}
        if node_entid and args.get('include_children', True):
            for node in companies:
                if str(node.get('parent_entid')) in selected:
                    selected.add(str(node.get('entid')))
        nodes = [n for n in companies if str(n.get('entid')) in selected]
        hostnames = list(dict.fromkeys(
            str(row.get('hostname') or '').strip().lower()
            for node in nodes for row in (node.get('icp') or [])
            if row.get('hostname')))
        if not hostnames:
            return _ret({'error': '所选公司没有备案域名'}, message='所选公司没有备案域名', code=400)
        roots = _scope_roots(hostnames)
        scope_id = str(args.get('scope_id') or '').strip()
        scope = None
        if scope_id:
            try:
                scope = utils.conn_db('asset_scope').find_one({'_id': ObjectId(scope_id)})
            except Exception:
                scope = None
            if not scope:
                return _ret({'error': '资产分组不存在'}, message='资产分组不存在', code=404)
        root_name = (group.get('root') or {}).get('entName') or '凤鸟集团'
        if not scope:
            scope_doc = {
                'name': root_name, 'scope_type': 'domain',
                'scope': ','.join(roots), 'scope_array': roots,
                'black_scope': '', 'black_scope_array': [],
            }
            scope_id = str(utils.conn_db('asset_scope').insert_one(scope_doc).inserted_id)
        else:
            old_roots = list(scope.get('scope_array') or [])
            merged = list(dict.fromkeys(old_roots + roots))
            utils.conn_db('asset_scope').update_one(
                {'_id': ObjectId(scope_id)},
                {'$set': {'scope_array': merged, 'scope': ','.join(merged)}})
        now = curr_date()
        task_doc = {
            'name': '凤鸟-' + root_name, 'target': roots[0], 'start_time': now,
            'end_time': now, 'status': 'done', 'type': 'domain', 'task_tag': 'fengniao',
            'options': {}, 'service': [], 'workflow_phase': 'done',
            'related_scope_id': scope_id, 'create_time': now,
        }
        task_oid = utils.conn_db('task').insert_one(task_doc).inserted_id
        task_id = str(task_oid)
        new_count = 0
        for host in hostnames:
            if utils.conn_db('domain').find_one({'task_id': task_id, 'domain': host}, {'_id': 1}):
                continue
            utils.conn_db('domain').insert_one({
                'task_id': task_id, 'domain': host, 'fld': get_fld(host) or host,
                'source': 'fengniao', 'sources': ['fengniao'], 'type': 'A',
                'record': '', 'ips': [], 'resolve_status': 'unknown',
                'related_scope_id': scope_id, 'create_time': now, 'update_date': now,
            })
            new_count += 1
        for node in nodes:
            node['asset_saved'] = True
            node['asset_scope_id'] = scope_id
        utils.conn_db('fengniao_group').update_one(
            {'_id': group['_id']}, {'$set': {'companies': companies}})
        return _ret({'scope_id': scope_id, 'task_id': task_id,
                     'new_domain_count': new_count, 'host_count': len(hostnames),
                     'company_count': len(nodes)})
