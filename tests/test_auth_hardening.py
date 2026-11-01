"""P1 安全加固测试：argon2 口令、api_token 过期/吊销、审计日志。

conn_db 用内存假实现替换（不依赖 MongoDB）；
user_login_header 需要请求上下文，用 Flask test_request_context 构造。
"""

import time

import pytest
from flask import Flask

from app.utils import user as user_mod
from app.utils import audit as audit_mod
from app.utils.user import (
    _token_doc_valid,
    change_pass,
    hash_password,
    new_user_token,
    user_login,
    user_login_header,
    user_logout,
    verify_and_upgrade,
)
from app.utils.audit import audit


# ---------------------------------------------------------- 假 DB ----

class FakeCollection:
    def __init__(self, docs=None):
        self.docs = list(docs or [])
        self._next_id = 1

    @staticmethod
    def _match(doc, query):
        for key, cond in query.items():
            if isinstance(cond, dict):
                if "$ne" in cond and doc.get(key) == cond["$ne"]:
                    return False
                if "$in" in cond and doc.get(key) not in cond["$in"]:
                    return False
            elif doc.get(key) != cond:
                return False
        return True

    def find_one(self, query, projection=None):
        for doc in self.docs:
            if self._match(doc, query):
                return dict(doc)
        return None

    def insert_one(self, doc):
        doc = dict(doc)
        if "_id" not in doc:
            doc["_id"] = self._next_id
            self._next_id += 1
        self.docs.append(doc)
        return type("R", (), {"inserted_id": doc["_id"]})

    def update_one(self, query, update):
        set_data = update.get("$set", {})
        for doc in self.docs:
            if self._match(doc, query):
                doc.update(set_data)
                return type("R", (), {"modified_count": 1})
        return type("R", (), {"modified_count": 0})


class FakeDB:
    def __init__(self):
        self.collections = {}

    def conn_db(self, name):
        return self.collections.setdefault(name, FakeCollection())


@pytest.fixture
def db(monkeypatch):
    fake = FakeDB()
    # user 与 audit 模块各自持有 conn_db 引用，必须一起替换，
    # 否则 audit 会真连 MongoDB（无服务时阻塞至超时）
    monkeypatch.setattr(user_mod, "conn_db", fake.conn_db)
    monkeypatch.setattr(audit_mod, "conn_db", fake.conn_db)
    return fake


@pytest.fixture(autouse=True)
def _auth_on(monkeypatch):
    from app.config import Config
    monkeypatch.setattr(Config, "AUTH", True, raising=False)
    monkeypatch.setattr(Config, "API_KEY", "static-api-key", raising=False)


# ------------------------------------------------------ argon2 口令 ----

def test_hash_and_verify_round_trip(db):
    db.conn_db("user").insert_one({"_id": 1, "username": "admin",
                                   "password": hash_password("s3cret!")})
    doc = db.conn_db("user").find_one({"username": "admin"})
    assert verify_and_upgrade(doc, "s3cret!")
    assert not verify_and_upgrade(doc, "wrong")


def test_legacy_md5_transparent_upgrade(db):
    from app.utils import gen_md5
    from app.utils.user import salt
    db.conn_db("user").insert_one({"_id": 2, "username": "admin",
                                   "password": gen_md5(salt + "oldpw")})
    doc = db.conn_db("user").find_one({"username": "admin"})

    assert verify_and_upgrade(doc, "oldpw")

    upgraded = db.conn_db("user").find_one({"_id": 2})
    assert upgraded["password"].startswith("$argon2"), "验证通过后必须升级为 argon2"
    # 升级后旧口令继续可验证、错误口令拒绝
    assert verify_and_upgrade(upgraded, "oldpw")
    assert not verify_and_upgrade(upgraded, "oldpw2")


def test_change_pass_rejects_wrong_old(db):
    # 与生产一致：username/password/token 在同一个 user 文档上
    db.conn_db("user").insert_one({"_id": 3, "username": "admin",
                                   "password": hash_password("old"),
                                   "token": "tok"})
    assert change_pass("tok", "bad-old", "new") is False
    assert change_pass("tok", "old", "new") is True
    assert db.conn_db("user").find_one({"_id": 3})["password"].startswith("$argon2")


# --------------------------------------------------- api_token 生命周期 ----

def test_token_doc_valid_states():
    now = time.time()
    assert _token_doc_valid({"expires_ts": now + 100})
    assert not _token_doc_valid({"expires_ts": now - 1})
    assert not _token_doc_valid({"revoked": True})
    assert not _token_doc_valid(None)
    assert _token_doc_valid({}), "无过期时间的旧格式按有效处理"


def test_new_user_token_expiry_math(db, monkeypatch):
    db.conn_db("user").insert_one({"_id": 1, "username": "admin",
                                   "password": hash_password("pw")})
    monkeypatch.setattr(user_mod.Config, "TOKEN_EXPIRE_DAYS", 3, raising=False)
    before = time.time()
    doc = new_user_token("admin")
    assert doc["expires_ts"] - before == pytest.approx(3 * 86400, abs=5)
    assert db.conn_db("user").find_one({"username": "admin"})["token"] == doc["token"]


def _request_header(token):
    app = Flask(__name__)
    return app.test_request_context(headers={"Token": token} if token else {})


def test_login_issues_token_and_header_accepts(db):
    db.conn_db("user").insert_one({"_id": 1, "username": "admin",
                                   "password": hash_password("pw")})
    result = user_login("admin", "pw")
    assert result and result["type"] == "login"
    token = result["token"]

    with _request_header(token):
        info = user_login_header()
    assert info["username"] == "admin" and info["type"] == "login"


def test_header_rejects_expired_and_revoked_tokens(db):
    db.conn_db("user").insert_one({"_id": 1, "username": "admin",
                                   "password": hash_password("pw")})
    token = user_login("admin", "pw")["token"]

    # 过期
    db.conn_db("api_token").update_one({"token": token},
                                       {"$set": {"expires_ts": time.time() - 10}})
    with _request_header(token):
        assert user_login_header() is False

    # 重新签发后吊销：旧 user.token 兼容分支也不得放行
    token2 = user_login("admin", "pw")["token"]
    with _request_header(token2):
        user_logout(token2)          # 生产中 logout 必然发生在请求上下文内
    with _request_header(token2):
        assert user_login_header() is False


def test_header_legacy_token_only_without_api_token_record(db):
    db.conn_db("user").insert_one({"_id": 1, "username": "legacy",
                                   "password": hash_password("pw"),
                                   "token": "legacy-token"})
    with _request_header("legacy-token"):
        info = user_login_header()
    assert info and info["username"] == "legacy"

    # 一旦该 token 出现在 api_token 表（如重新签发），旧记录立即失效
    db.conn_db("api_token").insert_one({"token": "legacy-token",
                                        "revoked": True,
                                        "expires_ts": time.time() + 999})
    with _request_header("legacy-token"):
        assert user_login_header() is False


def test_static_api_key_still_accepted(db):
    with _request_header("static-api-key"):
        info = user_login_header()
    assert info["type"] == "api" and info["username"] == "ARL-API"


def test_login_failure_returns_none(db):
    db.conn_db("user").insert_one({"_id": 1, "username": "admin",
                                   "password": hash_password("pw")})
    assert user_login("admin", "wrong") is None
    assert len(db.conn_db("api_token").docs) == 0


# ----------------------------------------------------------- 审计 ----

def test_audit_writes_event(db):
    audit("login_success", username="admin", detail={"ip": "1.2.3.4"})
    doc = db.conn_db("audit_log").docs[0]
    assert doc["action"] == "login_success" and doc["username"] == "admin"


def test_audit_never_raises_on_db_failure(db, monkeypatch):
    def boom(name):
        raise RuntimeError("db down")
    monkeypatch.setattr(user_mod, "conn_db", boom)
    audit("login_failed", username="x")  # 不得抛异常
