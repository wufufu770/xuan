"""APP 商店解析逻辑测试（三方接口全部 Mock，不出网）。

覆盖：应用宝搜索解析 / 候选评分（防假冒）/ iOS bundleId 交叉印证 /
APK 下载的 MD5 落盘前校验。
"""

import hashlib

import pytest

from app.services import app_store


# ------------------------------------------------------ 名称归一/前缀 ----

def test_norm_name_strips_marketing_suffix():
    assert app_store._norm_name("讯飞听见-录音转文字") == "讯飞听见"
    assert app_store._norm_name("iFLYREC | 办公") == "iflyrec"
    assert app_store._norm_name("") == ""


def test_vendor_prefix():
    assert app_store._vendor_prefix("com.iflytek.aicloud") == "com.iflytek"
    assert app_store._vendor_prefix("single") == "single"


# ------------------------------------------------------ 候选评分 ----

def test_score_android_developer_match_wins():
    detail = {"appName": "别的名字", "developer": "科大讯飞股份有限公司",
              "author": ""}
    score, reason = app_store._score_android(detail, "讯飞听见",
                                             {"科大讯飞股份有限公司"})
    assert score == 100 and reason.startswith("developer:")


def test_score_android_name_levels():
    company = {"某某集团"}
    exact = {"appName": "讯飞听见", "developer": "", "author": ""}
    norm = {"appName": "讯飞听见-语音转文字", "developer": "", "author": ""}
    contains = {"appName": "讯飞听见Pro", "developer": "", "author": ""}
    none = {"appName": "完全无关", "developer": "", "author": ""}
    assert app_store._score_android(exact, "讯飞听见", company)[0] == 80
    assert app_store._score_android(norm, "讯飞听见", company)[0] == 70
    assert app_store._score_android(contains, "讯飞听见", company)[0] == 40
    assert app_store._score_android(none, "讯飞听见", company)[0] == 0


def test_score_android_author_beats_exact_name():
    detail = {"appName": "讯飞听见", "developer": "", "author": "科大讯飞股份有限公司"}
    score, reason = app_store._score_android(detail, "讯飞听见",
                                             {"科大讯飞股份有限公司"})
    assert score == 95 and reason.startswith("author:")


# -------------------------------------------------- resolve 组合逻辑 ----

def test_resolve_android_picks_best_and_stops_on_confirmed(monkeypatch):
    monkeypatch.setattr(app_store, "qq_search", lambda name: ["p1", "p2", "p3"])
    monkeypatch.setattr(app_store, "qq_detail", lambda pkg: {
        "p1": {"packageName": "p1", "appName": "讯飞听见Pro", "developer": "",
               "apkUrl": "http://cdn/aaa.apk"},
        "p2": {"packageName": "p2", "appName": "讯飞听见",
               "developer": "科大讯飞股份有限公司", "apkUrl": "http://cdn/bbb.apk"},
        "p3": {"packageName": "p3", "appName": "讯飞听见", "developer": "",
               "apkUrl": "http://cdn/ccc.apk"},
    }[pkg])
    monkeypatch.setattr(app_store.time, "sleep", lambda s: None)

    result = app_store.resolve_android("讯飞听见", {"科大讯飞股份有限公司"})
    assert result["pkg"] == "p2"
    assert result["score"] == 100
    assert result["matched_by"].startswith("developer:")


def test_resolve_android_none_when_no_valid_detail(monkeypatch):
    monkeypatch.setattr(app_store, "qq_search", lambda name: ["p1"])
    monkeypatch.setattr(app_store, "qq_detail", lambda pkg: None)
    assert app_store.resolve_android("任意", set()) is None


def test_resolve_ios_bundle_id_prefix_confirms(monkeypatch):
    results = [
        {"trackName": "讯飞听见", "bundleId": "com.other.app", "trackViewUrl": "u1"},
        {"trackName": "讯飞听见", "bundleId": "com.iflytek.audiocloud",
         "trackViewUrl": "u2"},
    ]
    monkeypatch.setattr(app_store, "itunes_search", lambda name, limit=5: results)
    result = app_store.resolve_ios("讯飞听见", android_pkg="com.iflytek.rec")
    assert result["bundle_id"] == "com.iflytek.audiocloud"


# ------------------------------------------------------- APK 下载 ----

class _FakeStreamResp:
    def __init__(self, chunks, status_code=200):
        self._chunks = chunks
        self.status_code = status_code
        self.headers = {}

    def iter_content(self, chunk_size):
        yield from self._chunks


def test_download_apk_md5_ok_lands_file(monkeypatch, tmp_path):
    content = b"PK\x03\x04fake-apk-bytes"
    digest = hashlib.md5(content).hexdigest()
    apk_url = "http://cdn/{0}.apk".format(digest)
    monkeypatch.setattr(app_store.requests, "get",
                        lambda url, **kw: _FakeStreamResp([content]))
    monkeypatch.setattr(app_store.time, "sleep", lambda s: None)

    dest = tmp_path / "app.apk"
    meta = app_store.download_apk(apk_url, str(dest))
    assert dest.read_bytes() == content
    assert meta["md5"] == digest and meta["md5_verified"] is True


def test_download_apk_md5_mismatch_never_lands(monkeypatch, tmp_path):
    apk_url = "http://cdn/{0}.apk".format("a" * 32)   # 期望 MD5 = aaa...
    monkeypatch.setattr(app_store.requests, "get",
                        lambda url, **kw: _FakeStreamResp([b"corrupted"]))
    monkeypatch.setattr(app_store.time, "sleep", lambda s: None)

    dest = tmp_path / "app.apk"
    with pytest.raises(RuntimeError, match="MD5 校验失败"):
        app_store.download_apk(apk_url, str(dest))
    assert not dest.exists(), "MD5 不匹配的文件不得落盘"
    assert not (tmp_path / "app.apk.part").exists()


def test_download_apk_without_expected_md5_marks_unverified(monkeypatch, tmp_path):
    content = b"plain"
    monkeypatch.setattr(app_store.requests, "get",
                        lambda url, **kw: _FakeStreamResp([content]))
    monkeypatch.setattr(app_store.time, "sleep", lambda s: None)

    dest = tmp_path / "app.apk"
    meta = app_store.download_apk("http://cdn/file.apk", str(dest),
                                  expected_md5="")
    assert meta["md5_verified"] is False
    assert meta["md5"] == hashlib.md5(content).hexdigest()
    assert dest.exists()
