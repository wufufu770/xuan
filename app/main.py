from flask import Flask, jsonify, request
from flask_restx import Api
from bson.errors import InvalidId

from app import routes
from app.config import Config
from app.utils import arl_update, conn_db, gen_md5, user_login_header
from app.utils.user import salt

arl_app = Flask(__name__)
arl_app.config['BUNDLE_ERRORS'] = True

DOC_AUTH_PATHS = {
    "/api/doc",
    "/api/docs",
    "/api/swagger.json",
}


def _docs_basic_auth_ok():
    auth_info = request.authorization
    if not auth_info or not auth_info.username or auth_info.password is None:
        return False

    query = {
        "username": auth_info.username,
        "password": gen_md5(salt + auth_info.password),
    }
    return bool(conn_db("user").find_one(query, {"_id": 1}))


def _docs_unauthorized():
    response = jsonify({
        "message": "not login",
        "code": 401,
        "data": {},
    })
    response.status_code = 401
    response.headers["WWW-Authenticate"] = 'Basic realm="ARL API Docs"'
    return response


@arl_app.before_request
def protect_api_docs():
    path = request.path.rstrip("/") or request.path
    if path not in DOC_AUTH_PATHS:
        return None

    if not Config.AUTH:
        return None

    if user_login_header() or _docs_basic_auth_ok():
        return None

    return _docs_unauthorized()

authorizations = {
    "ApiKeyAuth": {
        "type": "apiKey",
        "in": "header",
        "name": "Token"
    }
}

api = Api(arl_app, prefix="/api", doc="/api/doc", title='ARL backend API', authorizations=authorizations,
          description='ARL（Asset Reconnaissance Lighthouse）资产侦察灯塔系统', security="ApiKeyAuth", version="2.9.0")


@api.errorhandler(InvalidId)
def handle_invalid_object_id(error):
    """Convert malformed Mongo IDs at the API boundary instead of returning HTTP 500."""
    return {
        "message": "资源 ID 格式无效",
        "code": 400,
        "data": {"error": str(error)},
    }, 400

api.add_namespace(routes.task_ns)
api.add_namespace(routes.site_ns)
api.add_namespace(routes.domain_ns)
api.add_namespace(routes.ip_ns)
api.add_namespace(routes.url_ns)
api.add_namespace(routes.user_ns)
api.add_namespace(routes.image_ns)
api.add_namespace(routes.cert_ns)
api.add_namespace(routes.service_ns)
api.add_namespace(routes.fileleak_ns)
api.add_namespace(routes.export_ns)
api.add_namespace(routes.asset_scope_ns)
api.add_namespace(routes.asset_domain_ns)
api.add_namespace(routes.asset_ip_ns)
api.add_namespace(routes.asset_site_ns)
api.add_namespace(routes.scheduler_ns)
api.add_namespace(routes.poc_ns)
api.add_namespace(routes.engines_ns)
api.add_namespace(routes.ai_judge_ns)
api.add_namespace(routes.supply_chain_ns)
api.add_namespace(routes.vuln_ns)
api.add_namespace(routes.batch_export_ns)
api.add_namespace(routes.policy_ns)
api.add_namespace(routes.npoc_service_ns)
api.add_namespace(routes.task_fofa_ns)
api.add_namespace(routes.console_ns)
api.add_namespace(routes.cip_ns)
api.add_namespace(routes.fingerprint_ns)
api.add_namespace(routes.stat_finger_ns)
api.add_namespace(routes.github_task_ns)
api.add_namespace(routes.github_result_ns)
api.add_namespace(routes.github_scheduler_ns)
api.add_namespace(routes.github_monitor_result_ns)
api.add_namespace(routes.task_schedule_ns)
api.add_namespace(routes.nuclei_result_ns)
api.add_namespace(routes.wih_ns)
api.add_namespace(routes.asset_wih_ns)
api.add_namespace(routes.project_ns)
api.add_namespace(routes.entry_ns)
api.add_namespace(routes.host_collision_ns)
api.add_namespace(routes.asset_report_ns)
api.add_namespace(routes.sensitive_interface_ns)
api.add_namespace(routes.stats_ns)
api.add_namespace(routes.fengniao_ns)
api.add_namespace(routes.appdl_ns)
api.add_namespace(routes.session_pool_ns)
api.add_namespace(routes.policy_yaml_ns)
api.add_namespace(routes.report_ns)
api.add_namespace(routes.monitor_diff_ns)
api.add_namespace(routes.notify_config_ns)
api.add_namespace(routes.asset_ext_ns)
api.add_namespace(routes.agent_ns)
api.add_namespace(routes.mcp_ns)
api.add_namespace(routes.integration_ns)
api.add_namespace(routes.plugin_update_ns)


arl_update()

if __name__ == '__main__':
    arl_app.run(debug=True, port=5018, host="0.0.0.0")
