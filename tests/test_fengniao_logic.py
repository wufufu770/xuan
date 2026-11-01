"""凤鸟采集逻辑契约测试（三方接口全部 Mock，不出网）。

覆盖：比例解析 / 去重计数 / JWT 过期解析 / 分页拉取 / 控股链 BFS
（min_ratio 过滤、max_companies 上限、失败节点阻断展开、entid 去重）。
"""

import base64
import json
import time

import pytest

from app.services import fengniao


@pytest.fixture(autouse=True)
def _fake_token(monkeypatch):
    """fetch_dimension/_headers 需要 config 里有 token；测试统一给一个有效 JWT。"""
    monkeypatch.setattr(fengniao.Config, "FENGNIAR_TOKEN",
                        _make_jwt(int(time.time()) + 60), raising=False)


@pytest.fixture(autouse=True)
def _no_session_pool(monkeypatch):
    """_headers 走 resolve_fengniao_token 会先查会话池；测试环境无 Mongo，
    旁路池查询避免 pymongo 30 秒连接超时拖慢整套测试。"""
    import app.services.session_pool as session_pool
    monkeypatch.setattr(session_pool, "get_cookie", lambda *a, **k: None)


# ------------------------------------------------------------- 纯函数 ----

def test_parse_ratio():
    assert fengniao.parse_ratio("100%") == 100.0
    assert fengniao.parse_ratio("80.5%") == 80.5
    assert fengniao.parse_ratio("51 %") == 51.0
    assert fengniao.parse_ratio("") is None
    assert fengniao.parse_ratio(None) is None
    assert fengniao.parse_ratio("无比例") is None


def test_distinct_hostnames_dedupes_and_skips_empty():
    rows = [{"hostname": "a.com"}, {"hostname": "a.com"}, {"hostname": ""},
            {"hostname": "b.com"}, {}]
    assert fengniao._distinct_hostnames(rows) == 2


def _make_jwt(exp):
    header = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        json.dumps({"exp": exp}).encode()).rstrip(b"=").decode()
    return "{}.{}.{}".format(header, payload, "sig")


def test_token_expire_time_parses_jwt(monkeypatch):
    exp = int(time.time()) + 3600
    monkeypatch.setattr(fengniao.Config, "FENGNIAR_TOKEN", _make_jwt(exp),
                        raising=False)
    assert abs(fengniao.token_expire_time() - exp) < 2


def test_token_expire_time_garbage_returns_zero(monkeypatch):
    monkeypatch.setattr(fengniao.Config, "FENGNIAR_TOKEN", "not-a-jwt", raising=False)
    assert fengniao.token_expire_time() == 0


def test_headers_require_token(monkeypatch):
    monkeypatch.setattr(fengniao.Config, "FENGNIAR_TOKEN", "", raising=False)
    with pytest.raises(fengniao.FengniaoError):
        fengniao._headers()


def test_headers_shape(monkeypatch):
    token = _make_jwt(int(time.time()) + 60)
    monkeypatch.setattr(fengniao.Config, "FENGNIAR_TOKEN", token, raising=False)
    headers = fengniao._headers()
    assert headers["xs-content-type"] == "application/json"
    assert "token=" + token in headers["Cookie"]
    assert headers["Cookie"].count("app-uuid=WEB-") == 1


# ------------------------------------------------------------ 分页拉取 ----

class _FakeSession:
    def __init__(self, pages):
        self.pages = pages          # endpoint -> [apiData 列表，按页]
        self.calls = []

    def post(self, url, json=None, headers=None, timeout=None):
        endpoint = url.rsplit("/", 1)[-1]
        page = json["page"]
        self.calls.append((endpoint, page, json["size"]))
        code = self.pages[endpoint].get("code", fengniao.CODE_OK)
        body = {"code": code, "msg": self.pages[endpoint].get("msg", ""),
                "data": self.pages[endpoint]["data"][page - 1]}
        return _FakeResp(body)


class _FakeResp:
    def __init__(self, body):
        self._body = body

    def json(self):
        return self._body


def test_fetch_dimension_paginates_until_total():
    sess = _FakeSession({"propertyApp": {"data": [
        {"apiData": [{"appname": "a%d" % i} for i in range(3)],
         "totalCount": 4},
        {"apiData": [{"appname": "a3"}], "totalCount": 4},
    ]}})
    rows, total = fengniao.fetch_dimension("ORDER1", "propertyApp", session=sess)
    assert [r["appname"] for r in rows] == ["a0", "a1", "a2", "a3"]
    assert total == 4
    assert [(c[1], c[2]) for c in sess.calls] == [(1, 50), (2, 50)]


def test_fetch_dimension_stops_at_max_pages(monkeypatch):
    monkeypatch.setattr(fengniao, "MAX_PAGES", 2)
    pages = {"data": [{"apiData": [{"appname": "x"}], "totalCount": 999}
                      for _ in range(5)]}
    sess = _FakeSession({"propertyIcp": pages})
    rows, total = fengniao.fetch_dimension("ORDER1", "propertyIcp", session=sess)
    assert len(rows) == 2
    assert len(sess.calls) == 2


def test_fetch_dimension_raises_on_error_code():
    sess = _FakeSession({"propertyApp": {"code": 9999, "msg": "数据错误",
                                         "data": [{"apiData": [], "totalCount": 0}]}})
    with pytest.raises(fengniao.FengniaoError):
        fengniao.fetch_dimension("ORDER1", "propertyApp", session=sess)


# -------------------------------------------------------------- BFS ----

def _patch_bfs(monkeypatch, details, investments, order_map):
    """details: entid -> {icp/app/miniprogram}; investments: entid -> children"""
    monkeypatch.setattr(fengniao, "get_order_no",
                        lambda name, entid, session=None: order_map[entid])
    monkeypatch.setattr(
        fengniao, "fetch_dimension",
        lambda order_no, endpoint, session=None, max_records=None:
            (details[order_no][endpoint], len(details[order_no][endpoint])))
    monkeypatch.setattr(
        fengniao, "fetch_investments",
        lambda order_no, session=None, max_records=None:
            investments.get(order_no, []))
    monkeypatch.setattr(fengniao.time, "sleep", lambda s: None)


def test_collect_group_bfs_min_ratio_and_dedupe(monkeypatch):
    details = {
        "O_ROOT": {"propertyIcp": [{"hostname": "root.com"}],
                   "propertyApp": [], "propertyMiniprogram": []},
        "O_CHILD": {"propertyIcp": [{"hostname": "child.com"}],
                    "propertyApp": [], "propertyMiniprogram": []},
    }
    investments = {"O_ROOT": [
        {"entName": "子公司A", "entid": "C1", "directProp": "100%",
         "allProp": "100%", "entStatus": "在业", "regionCn": "安徽", "nic": "软件"},
        {"entName": "参股B", "entid": "C2", "directProp": "30%",
         "allProp": "45%", "entStatus": "在业", "regionCn": "安徽", "nic": "软件"},
    ]}
    order_map = {"R1": "O_ROOT", "C1": "O_CHILD"}
    _patch_bfs(monkeypatch, details, investments, order_map)

    result = fengniao.collect_group("母公司", entid="R1", ent_name="母公司",
                                    max_depth=2, min_ratio=100.0)
    names = [n["entName"] for n in result["companies"]]
    assert names == ["母公司", "子公司A"]          # 30% 参股被过滤
    assert result["edges"][0]["to_entid"] == "C1"
    assert result["failed"] == []


def test_collect_group_failed_node_does_not_expand(monkeypatch):
    details = {"O_ROOT": {"propertyIcp": [{"hostname": "root.com"}],
                          "propertyApp": [], "propertyMiniprogram": []}}
    investments = {"O_R1": [
        {"entName": "坏节点", "entid": "BAD", "directProp": "100%",
         "allProp": "100%", "entStatus": "在业", "regionCn": "", "nic": ""},
    ]}

    def fake_order(name, entid, session=None):
        if entid == "BAD":
            raise fengniao.FengniaoError("token 过期")
        return "O_" + str(entid)

    monkeypatch.setattr(fengniao, "get_order_no", fake_order)
    monkeypatch.setattr(
        fengniao, "fetch_dimension",
        lambda order_no, endpoint, session=None, max_records=None:
            (details.get(order_no, {}).get(endpoint, []),
             len(details.get(order_no, {}).get(endpoint, []))))
    monkeypatch.setattr(
        fengniao, "fetch_investments",
        lambda order_no, session=None, max_records=None:
            investments.get(order_no, []))
    monkeypatch.setattr(fengniao.time, "sleep", lambda s: None)

    result = fengniao.collect_group("母公司", entid="R1", ent_name="母公司",
                                    max_depth=3)
    # 根节点成功；坏节点取 orderNo 失败 -> 记入 failed 且不展开（子树丢失须可补采）
    assert [n["entName"] for n in result["companies"]] == ["母公司", "坏节点"]
    failed_entids = [f["entid"] for f in result["failed"]]
    assert "BAD" in failed_entids
    assert [n for n in result["companies"] if n["entid"] == "BAD"][0]["error"]
    # 控股边照常登记（关系真实存在），但子树未被展开
    assert [e["to_entid"] for e in result["edges"]] == ["BAD"]


def test_collect_group_respects_max_companies(monkeypatch):
    details = {"O%d" % i: {"propertyIcp": [], "propertyApp": [],
                           "propertyMiniprogram": []} for i in range(5)}
    investments = {"O0": [
        {"entName": "子%d" % i, "entid": "C%d" % i, "directProp": "100%",
         "allProp": "100%", "entStatus": "", "regionCn": "", "nic": ""}
        for i in range(4)]}
    order_map = {"R1": "O0"}
    order_map.update({"C%d" % i: "O%d" % (i + 1) for i in range(4)})
    _patch_bfs(monkeypatch, details, investments, order_map)

    result = fengniao.collect_group("母公司", entid="R1", ent_name="母公司",
                                    max_depth=2, max_companies=2)
    assert len(result["companies"]) == 2
