from flask import request
from flask_restx import fields, Namespace
from app.utils import get_logger, auth
from app.utils.audit import audit
from app import utils
from . import  ARLResource
from app import modules

ns = Namespace('user', description="管理员登录认证")

logger = get_logger()

VALID_ROLES = ("admin", "operator", "auditor")


def _admin_info():
    """当前请求的管理员身份；非 admin 返回 None。"""
    info = utils.user_login_header()
    if not isinstance(info, dict) or info.get("role") != "admin":
        return None
    return info


@ns.route('/list/')
class UserListARL(ARLResource):
    @auth
    def get(self):
        """用户列表（仅 admin）"""
        if not _admin_info():
            return {"message": "admin only", "code": 403, "data": {}}
        items = []
        for doc in utils.conn_db('user').find({}, {"password": 0, "token": 0}):
            items.append({
                "username": doc.get("username"),
                "role": doc.get("role") or "admin",
                "disabled": bool(doc.get("disabled")),
                "create_date": doc.get("create_date", ""),
            })
        return {"message": "success", "code": 200, "data": {"items": items}}


add_user_fields = ns.model('AddUserARL', {
    'username': fields.String(required=True, description="用户名"),
    'password': fields.String(required=True, description="密码"),
    'role': fields.String(required=True, enum=list(VALID_ROLES), description="角色"),
})


@ns.route('/add/')
class AddUserARL(ARLResource):
    @auth
    @ns.expect(add_user_fields)
    def post(self):
        """创建用户（仅 admin；角色 admin/operator/auditor）"""
        admin = _admin_info()
        if not admin:
            return {"message": "admin only", "code": 403, "data": {}}
        args = self.parse_args(add_user_fields)
        username = str(args["username"]).strip()
        password = str(args["password"])
        role = str(args["role"]).strip()
        if not username or len(password) < 8:
            return {"message": "用户名必填且密码至少 8 位", "code": 400, "data": {}}
        if role not in VALID_ROLES:
            return {"message": "非法角色", "code": 400, "data": {}}
        if role == "admin" and not username:
            return {"message": "非法用户名", "code": 400, "data": {}}
        if utils.conn_db('user').find_one({"username": username}):
            return {"message": "用户已存在", "code": 400, "data": {}}
        utils.conn_db('user').insert_one({
            "username": username,
            "password": utils.hash_password(password),
            "role": role,
            "disabled": False,
            "create_date": utils.curr_date(),
            "creator": admin.get("username"),
        })
        audit("user_add", detail={"new_user": username, "role": role})
        return {"message": "success", "code": 200, "data": {"username": username, "role": role}}


set_role_fields = ns.model('SetRoleARL', {
    'username': fields.String(required=True, description="目标用户"),
    'role': fields.String(required=True, enum=list(VALID_ROLES), description="新角色"),
})


@ns.route('/set_role/')
class SetRoleARL(ARLResource):
    @auth
    @ns.expect(set_role_fields)
    def post(self):
        """修改用户角色（仅 admin；不可修改自己）"""
        admin = _admin_info()
        if not admin:
            return {"message": "admin only", "code": 403, "data": {}}
        args = self.parse_args(set_role_fields)
        username = str(args["username"]).strip()
        role = str(args["role"]).strip()
        if role not in VALID_ROLES:
            return {"message": "非法角色", "code": 400, "data": {}}
        if username == admin.get("username"):
            return {"message": "不能修改自己的角色", "code": 400, "data": {}}
        result = utils.conn_db('user').update_one(
            {"username": username}, {"$set": {"role": role}})
        if not result.modified_count:
            return {"message": "用户不存在", "code": 404, "data": {}}
        audit("user_set_role", detail={"target": username, "role": role})
        return {"message": "success", "code": 200, "data": {"username": username, "role": role}}


disable_fields = ns.model('DisableUserARL', {
    'username': fields.String(required=True, description="目标用户"),
    'disabled': fields.Boolean(required=True, description="true=禁用 false=启用"),
})


@ns.route('/disable/')
class DisableUserARL(ARLResource):
    @auth
    @ns.expect(disable_fields)
    def post(self):
        """禁用/启用用户（仅 admin；禁用即吊销全部在线会话）"""
        admin = _admin_info()
        if not admin:
            return {"message": "admin only", "code": 403, "data": {}}
        args = self.parse_args(disable_fields)
        username = str(args["username"]).strip()
        disabled = bool(args["disabled"])
        if username == admin.get("username"):
            return {"message": "不能禁用自己", "code": 400, "data": {}}
        result = utils.conn_db('user').update_one(
            {"username": username}, {"$set": {"disabled": disabled}})
        if not result.modified_count:
            return {"message": "用户不存在", "code": 404, "data": {}}
        if disabled:
            utils.conn_db('api_token').update_many(
                {"username": username}, {"$set": {"revoked": True}})
            utils.conn_db('user').update_one(
                {"username": username}, {"$set": {"token": None}})
        audit("user_disable" if disabled else "user_enable",
                    detail={"target": username})
        return {"message": "success", "code": 200, "data": {"username": username,
                                                            "disabled": disabled}}



login_fields = ns.model('LoginARL', {
    'username': fields.String(required=True, description="用户名"),
    'password': fields.String(required=True, description="密码"),
})


@ns.route('/login')
class LoginARL(ARLResource):

    @ns.expect(login_fields)
    def post(self):
        """
        用户登录
        """
        args = self.parse_args(login_fields)


        return build_data(utils.user_login(**args))




@ns.route('/logout')
class LogoutARL(ARLResource):

    def get(self):
        """
        用户退出
        """
        token = request.headers.get("Token")
        utils.user_logout(token)

        return build_data({})

    def post(self):
        return self.get()


change_pass_fields = ns.model('ChangePassARL', {
    'old_password': fields.String(required=True, description="旧密码"),
    'new_password': fields.String(required=True, description="新密码"),
    'check_password': fields.String(required=True, description="确认密码"),
})


@ns.route('/change_pass')
class ChangePassARL(ARLResource):
    @ns.expect(change_pass_fields)
    def post(self):
        """
        密码修改
        """
        args = self.parse_args(change_pass_fields)
        ret = {
            "message": "success",
            "code": 200,
            "data": {}
        }
        token = request.headers.get("Token")

        if args["new_password"] != args["check_password"]:
            ret["code"] = 301
            ret["message"] = "新密码和确定密码不一致"
            return ret

        if not args["new_password"]:
            ret["code"] = 302
            ret["message"] = "新密码不能为空"
            return ret

        if utils.change_pass(token, args["old_password"], args["new_password"]):
            utils.user_logout(token)
        else:
            ret["message"] = "旧密码错误"
            ret["code"] = 303

        return ret


def build_data(data):
    ret = {
        "message": "success",
        "code": 200,
        "data": {}
    }

    if data:
        ret["data"] = data
    else:
        ret["code"] = 401

    return ret


