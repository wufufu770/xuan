"""新增测绘平台被动收集插件测试：Shodan / Censys（不出网，mock http_req）。"""

import pytest

import app.utils as utils_pkg
from app.services.integration import TESTERS, VENDORS


class FakeResp:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


def test_shodan_registry_entry():
    spec = VENDORS["shodan"]
    assert spec["group"] == "mapping"
    assert spec["test"] == "shodan"
    assert "shodan" in TESTERS


def test_shodan_subdomains_parses_prefixes(monkeypatch):
    from app.services.dns_query_plugin import shodan as shodan_mod

    calls = {}

    def fake_req(url, method='get', **kw):
        calls["url"] = url
        return FakeResp(200, {"domain": "example.com",
                              "subdomains": ["www", "Mail", "dev"]})

    monkeypatch.setattr(utils_pkg, "http_req", fake_req)
    q = shodan_mod.Query()
    q.init_key(api_key="shd-key")
    assert q.configuration_error() == ""
    got = q.sub_domains("example.com")
    assert set(got) == {"www.example.com", "mail.example.com", "dev.example.com"}
    assert "dns/domain/example.com" in calls["url"]
    assert calls["url"].endswith("example.com")


def test_shodan_unconfigured_and_auth_error(monkeypatch):
    from app.services.dns_query_plugin import shodan as shodan_mod

    q = shodan_mod.Query()
    assert "not configured" in q.configuration_error()

    monkeypatch.setattr(utils_pkg, "http_req",
                        lambda *a, **kw: FakeResp(401, {"error": "invalid key"}))
    q.init_key(api_key="bad")
    assert q.sub_domains("example.com") == []


def test_censys_registry_entry():
    spec = VENDORS["censys"]
    assert spec["group"] == "mapping"
    assert [f[0] for f in spec["fields"]] == ["auth_email", "auth_key"]
    assert "censys" in TESTERS


def test_censys_subdomains_from_hits(monkeypatch):
    from app.services.dns_query_plugin import censys as censys_mod

    def fake_req(url, method='post', **kw):
        assert url.endswith("/api/v2/hosts/search")
        assert kw["auth"] == ("id@example.com", "secret")
        assert "dns.names: example.com" == kw["json"]["q"]
        return FakeResp(200, {
            "status": "OK",
            "result": {
                "hits": [
                    {"dns_names": ["a.example.com", "example.com", "other.net"]},
                    {"dns": {"names": ["B.Example.COM."]}},
                ],
                "links": {"next": ""},
            },
        })

    monkeypatch.setattr(utils_pkg, "http_req", fake_req)
    q = censys_mod.Query()
    q.init_key(auth_email="id@example.com", auth_key="secret")
    assert q.configuration_error() == ""
    got = q.sub_domains("example.com")
    assert set(got) == {"a.example.com", "example.com", "b.example.com"}


def test_censys_unconfigured(monkeypatch):
    from app.services.dns_query_plugin import censys as censys_mod

    q = censys_mod.Query()
    assert "not configured" in q.configuration_error()


def test_censys_cursor_pagination(monkeypatch):
    from app.services.dns_query_plugin import censys as censys_mod

    pages = {"n": 0}

    def fake_req(url, method='post', **kw):
        pages["n"] += 1
        cursor = "next-cursor" if pages["n"] == 1 else ""
        return FakeResp(200, {
            "result": {
                "hits": [{"dns_names": ["p{}.example.com".format(pages["n"])]}],
                "links": {"next": cursor},
            },
        })

    monkeypatch.setattr(utils_pkg, "http_req", fake_req)
    q = censys_mod.Query()
    q.init_key(auth_email="id@example.com", auth_key="secret", max_page=5)
    got = q.sub_domains("example.com")
    assert pages["n"] == 2          # 第二页无 cursor 后停止
    assert "p1.example.com" in got and "p2.example.com" in got
