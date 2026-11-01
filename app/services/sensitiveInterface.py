import fcntl
import gzip
import hashlib
import json
import os
import re
import tempfile
import threading
import time
from collections import Counter
from contextlib import contextmanager
from datetime import date, datetime
from functools import lru_cache
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

from app import utils
from app.utils.site_scope import formal_pipeline_query
try:
    from pymongo.errors import OperationFailure
except Exception:
    class OperationFailure(Exception):
        pass


TAG_CATALOG = [
    {"code": "ssrf", "label": "SSRF候选", "tone": "danger"},
    {"code": "file_read", "label": "文件读取候选", "tone": "warning"},
    {"code": "command_injection", "label": "命令注入候选", "tone": "danger"},
    {"code": "code_execution", "label": "代码执行候选", "tone": "danger"},
    {"code": "expression_injection", "label": "表达式执行候选", "tone": "danger"},
    {"code": "deserialization", "label": "反序列化候选", "tone": "danger"},
    {"code": "sql_injection", "label": "SQL注入候选", "tone": "danger"},
    {"code": "auth_bypass", "label": "认证绕过候选", "tone": "danger"},
    {"code": "identity_switch", "label": "身份切换候选", "tone": "danger"},
    {"code": "passwordless_auth", "label": "免密登录候选", "tone": "warning"},
    {"code": "anonymous_auth", "label": "匿名认证候选", "tone": "warning"},
    {"code": "test_credential", "label": "测试凭证候选", "tone": "warning"},
    {"code": "backdoor", "label": "后门接口候选", "tone": "danger"},
    {"code": "middleware_console", "label": "中间件组件入口", "tone": "warning"},
    {"code": "admin", "label": "后台入口", "tone": "primary"},
    {"code": "mobile", "label": "移动端接口", "tone": "info"},
    {"code": "redirect", "label": "跳转接口候选", "tone": "warning"},
    {"code": "docs", "label": "接口文档", "tone": "primary"},
    {"code": "debug", "label": "调试运维入口", "tone": "danger"},
    {"code": "export", "label": "敏感导出", "tone": "neutral"},
    {"code": "xml", "label": "XML解析候选", "tone": "warning"},
]

TAG_BY_CODE = {item["code"]: item for item in TAG_CATALOG}
VALID_LOCATIONS = {
    "all", "domain", "path", "path_endpoint", "param",
    "domain_path", "path_param",
}
VALID_MODES = {"contains", "word", "normalized"}
VALID_WEIGHTS = {5, 10, 20}
ANALYSIS_CACHE_TTL_ACTIVE = 60
ANALYSIS_CACHE_TTL_COMPLETE = 21600
ANALYSIS_CACHE_MAX_ITEMS = 16
ANALYSIS_CACHE_MAX_FILES = 64
ANALYSIS_CACHE_VERSION = 18
ANALYSIS_CACHE_DIR = os.environ.get(
    "ARL_SENSITIVE_INTERFACE_CACHE_DIR",
    os.path.abspath(os.path.join(
        os.path.dirname(__file__), "..", "tmp", "sensitive-interface-cache"
    )),
)
TERMINAL_TASK_STATUSES = {"done", "stop", "error"}
FILELEAK_REJECTED_ENTRY_TYPES = {
    "generic_error", "non_entry_response", "redirect_template",
    "template_suspect", "unverified_path",
}
IGNORED_SENSITIVE_PARAM_NAMES = {"redirect_uri", "redirect-uri", "redirecturi"}
IGNORED_SSRF_PARAM_NAMES = {"return_url", "return-url", "returnurl"}
EXTENDED_TAG_CODES = {
    "auth_bypass", "anonymous_auth", "test_credential", "backdoor",
    "command_injection", "code_execution", "expression_injection",
    "deserialization", "sql_injection", "middleware_console",
    "passwordless_auth",
}
_ANALYSIS_CACHE = {}
_ANALYSIS_CACHE_LOCK = threading.Lock()
HINT_FAILURE_MARKERS = (
    "bad hint", "hint provided", "unknown index", "index not found",
    "unable to find index", "cannot find index",
)


def _keyword_forms(*entries):
    forms = set()
    for entry in entries:
        parts = entry if isinstance(entry, (tuple, list)) else (entry,)
        parts = tuple(str(part).strip().lower() for part in parts if str(part).strip())
        if not parts:
            continue
        for separator in ("", "_", "-", "/"):
            forms.add(separator.join(parts))
    return tuple(sorted(forms))


BUILTIN_RULE_GROUPS = [
    {
        "tag_code": "ssrf", "location": "path", "weight": 28,
        "keywords": ("proxy", "fetch", "remote", "relay", "webhook", "url-preview", "url_preview"),
    },
    {
        "tag_code": "ssrf", "location": "param", "weight": 24,
        "keywords": (
            "url", "uri", "targeturl", "target_url", "proxyurl", "proxy_url", "imageurl",
            "image_url", "fileurl", "file_url", "downloadurl", "download_url", "sourceurl",
            "source_url", "remoteurl", "remote_url", "endpoint", "webhook", "callbackurl",
            "callback_url", "fetchurl", "fetch_url", "resourceurl", "resource_url",
        ),
    },
    {
        "tag_code": "ssrf", "location": "path_endpoint", "weight": 28,
        "keywords": ("tobase64",),
    },
    {
        "tag_code": "file_read", "location": "path", "weight": 22,
        "keywords": ("download", "readfile", "read-file", "file/read", "preview", "attachment", "stream"),
    },
    {
        "tag_code": "file_read", "location": "param", "weight": 20,
        "keywords": (
            "path", "filepath", "file_path", "filename", "file_name", "file", "dir", "directory",
            "template", "page", "document", "resource",
        ),
    },
    {
        "tag_code": "file_read", "location": "path", "weight": 22,
        "mode": "normalized",
        "prefilter_group": "component",
        "prefilter_keywords": (
            "onlinepreview", "attachpreview", "fileonlinepreview",
            "picturespreview", "getcorsfile",
        ),
        "keywords": _keyword_forms(
            ("online", "preview"), ("attach", "preview"),
            ("file", "online", "preview"), ("pictures", "preview"),
            ("get", "cors", "file"),
        ),
    },
    {
        "tag_code": "identity_switch", "location": "path", "weight": 38,
        "keywords": (
            "loginas", "login-as", "impersonate", "switchuser", "switch-user", "autologin",
            "auto-login", "switchaccount", "switch-account", "changetenant", "change-tenant",
            "assumerole", "assume-role", "loginbyuserid", "login-by-user-id",
            "login_by_user_id", "loginbyuid", "login-by-uid", "login_by_uid",
        ),
    },
    {
        "tag_code": "identity_switch", "location": "param", "weight": 14,
        "keywords": ("userid", "user_id", "uid", "accountid", "account_id", "memberid", "member_id", "tenantid", "tenant_id", "roleid", "role_id"),
    },
    {
        "tag_code": "auth_bypass", "location": "path", "weight": 42,
        "mode": "normalized",
        "prefilter_keywords": (
            "bypass", "skipauth", "skip_auth", "noauth", "no_auth",
            "withoutpassword", "without_password", "emergencylogin",
            "masterlogin", "superlogin", "internallogin",
        ),
        "keywords": _keyword_forms(
            ("bypass", "login"), ("bypass", "auth"), ("skip", "auth"),
            ("no", "auth"), ("login", "without", "password"),
            ("emergency", "login"), ("master", "login"),
            ("super", "login"), ("internal", "login"),
        ),
    },
    {
        "tag_code": "passwordless_auth", "location": "path", "weight": 28,
        "mode": "normalized",
        "prefilter_keywords": (
            "passwordless", "nopassword", "nopwd", "pwdless",
            "passwordfree", "withoutpassword", "oneclicklogin",
            "quicklogin", "silentlogin", "magiclink", "autologin",
            "loginbytoken", "免密登录", "无密码登录", "一键登录", "静默登录",
        ),
        "keywords": _keyword_forms(
            ("passwordless", "login"), ("passwordless", "auth"),
            ("no", "password", "login"), ("nopwd", "login"),
            ("pwdless", "login"), ("password", "free", "login"),
            ("login", "without", "password"), ("one", "click", "login"),
            ("quick", "login"), ("silent", "login"),
            ("magic", "link"), ("auto", "login"),
            ("login", "by", "token"), "免密登录", "无密码登录",
            "一键登录", "静默登录",
        ),
    },
    {
        "tag_code": "anonymous_auth", "location": "path", "weight": 36,
        "mode": "normalized",
        "prefilter_keywords": ("anonymous", "guest", "visitor", "tourist"),
        "keywords": _keyword_forms(
            ("anonymous", "login"), ("login", "anonymous"),
            ("guest", "login"), ("visitor", "login"),
            ("anonymous", "token"), ("guest", "token"),
            ("tourist", "login"),
        ),
    },
    {
        "tag_code": "test_credential", "location": "path", "weight": 32,
        "mode": "normalized",
        "prefilter_keywords": (
            "token", "testaccount", "test_account", "mockuser", "mock_user",
            "testuser", "test_user", "demoaccount", "defaultaccount",
        ),
        "keywords": _keyword_forms(
            ("get", "test", "token"), ("debug", "token"),
            ("mock", "token"), ("test", "token"),
            ("token", "by", "user", "id"), ("token", "by", "uid"),
            ("issue", "token", "for", "user"), ("generate", "token"),
            ("test", "account"), ("mock", "user"), ("test", "user"),
            ("demo", "account"), ("default", "account"),
            ("temporary", "token"), ("admin", "token"),
        ),
    },
    {
        "tag_code": "backdoor", "location": "path", "weight": 45,
        "mode": "normalized",
        "prefilter_keywords": (
            "backdoor", "webshell", "behinder", "godzilla", "antsword",
            "cmdshell", "uploadshell", "adminshell", "remoteshell",
            "testlogin", "test_login", "mocklogin", "mock_login",
            "devlogin", "dev_login",
        ),
        "keywords": _keyword_forms(
            "backdoor", "webshell", "behinder", "godzilla", "antsword",
            ("cmd", "shell"), ("upload", "shell"), ("admin", "shell"),
            ("remote", "shell"), ("backdoor", "login"),
            ("debug", "login"), ("test", "login"),
            ("mock", "login"), ("dev", "login"),
        ),
    },
    {
        "tag_code": "command_injection", "location": "path", "weight": 42,
        "mode": "normalized",
        "prefilter_keywords": ("command", "shell", "execcmd", "exec_cmd"),
        "keywords": _keyword_forms(
            ("execute", "command"), ("run", "command"),
            ("shell", "exec"), ("system", "exec"),
            ("command", "line"), ("run", "shell"),
            ("exec", "cmd"), ("remote", "command"),
            ("debug", "exec"), ("test", "command"),
            ("diagnostic", "command"),
        ),
    },
    {
        "tag_code": "command_injection", "location": "param", "weight": 25,
        "keywords": (
            "commandline", "command_line", "shell", "executable", "argv",
        ),
    },
    {
        "tag_code": "command_injection", "location": "path_endpoint", "weight": 38,
        "keywords": ("cmd", "exec", "shell", "command", "powershell", "bash"),
    },
    {
        "tag_code": "code_execution", "location": "path", "weight": 42,
        "mode": "normalized",
        "prefilter_keywords": (
            "eval", "script", "compile", "groovy", "plugin", "module",
            "extension", "jarurl", "jar_url", "packageurl", "package_url",
        ),
        "keywords": _keyword_forms(
            ("eval", "code"), ("execute", "code"), ("run", "code"),
            ("run", "script"), ("script", "engine"),
            ("dynamic", "compile"), ("groovy", "script"),
            ("upload", "and", "run"), ("install", "plugin"),
            ("upload", "plugin"), ("load", "module"),
            ("install", "extension"), ("jar", "url"),
            ("package", "url"),
        ),
    },
    {
        "tag_code": "code_execution", "location": "path_endpoint", "weight": 45,
        "keywords": (
            "rce", "runtimeexec", "runtime-exec", "processbuilder",
            "process-builder", "popen", "os.system", "os-system",
        ),
    },
    {
        "tag_code": "expression_injection", "location": "path_param", "weight": 36,
        "mode": "normalized",
        "prefilter_keywords": ("template", "expression", "spel", "ognl", "mvel"),
        "keywords": _keyword_forms(
            ("template", "eval"), ("render", "template"),
            ("evaluate", "expression"), ("expression", "eval"),
            ("groovy", "console"),
        ),
    },
    {
        "tag_code": "expression_injection", "location": "path_param", "weight": 36,
        "keywords": ("spel", "ognl", "mvel"),
    },
    {
        "tag_code": "deserialization", "location": "path_param", "weight": 40,
        "mode": "normalized",
        "prefilter_keywords": (
            "deserialize", "unserialize", "readobject", "objectinput",
            "decoder", "yamlload", "serializedobject", "objectdata",
        ),
        "keywords": _keyword_forms(
            "deserialize", "unserialize", ("read", "object"),
            ("object", "input"), ("binary", "decoder"),
            ("yaml", "load"), ("xml", "decoder"),
            ("object", "decoder"), ("serialized", "object"),
            ("object", "data"),
        ),
    },
    {
        "tag_code": "sql_injection", "location": "path_param", "weight": 38,
        "mode": "normalized",
        "prefilter_keywords": ("sql", "dbquery", "whereclause", "nativequery"),
        "keywords": _keyword_forms(
            ("execute", "sql"), ("query", "sql"), ("raw", "sql"),
            ("native", "sql"), ("sql", "query"), ("db", "query"),
            ("debug", "sql"), ("run", "sql"),
            ("sql", "statement"), ("where", "clause"),
            ("native", "query"),
        ),
    },
    {
        "tag_code": "middleware_console", "location": "path", "weight": 40,
        "keywords": (
            "actuator", "druid", "nacos", "sentinel", "jolokia",
            "geoserver", "apisix", "xxl-job", "xxljob", "jeecg-boot",
            "jeecg-data", "jmreport", "ureport", "kkfileview",
            "kkfile", "kkfive", "officeserver", "reportserver", "minio",
            "jmx.jmx", "jmx-console",
        ),
    },
    {
        "tag_code": "middleware_console", "location": "path", "weight": 24,
        "keywords": (
            "ueditor", "swagger", "swagger-resources", "api-docs",
            "api-doc", "api/doc", "apidoc", "graphql", "webservices",
            "web_services", "appwebservice",
        ),
    },
    {
        "tag_code": "middleware_console", "location": "path", "weight": 28,
        "mode": "normalized",
        "prefilter_keywords": (
            "onlinepreview", "attachpreview", "fileonlinepreview",
            "picturespreview", "getcorsfile", "queryfieldbysql",
            "cgreport", "iwebOffice", "webOffice", "ntko", "doc.html",
        ),
        "keywords": _keyword_forms(
            ("online", "preview"), ("attach", "preview"),
            ("file", "online", "preview"), ("pictures", "preview"),
            ("get", "cors", "file"), ("query", "field", "by", "sql"),
            "cgreport", ("iweb", "office"), ("web", "office"),
            "ntko", "doc.html",
        ),
    },
    {
        "tag_code": "admin", "location": "domain_path", "weight": 18,
        "keywords": ("admin", "manage", "manager", "console", "dashboard", "backend", "internal", "ops", "operation"),
    },
    {
        "tag_code": "mobile", "location": "domain_path", "weight": 12,
        "keywords": ("mobile", "wap", "h5", "miniapp", "mini-app", "miniprogram", "mini-program"),
    },
    {
        "tag_code": "redirect", "location": "path_param", "weight": 18,
        "keywords": ("redirect", "redirecturl", "redirect_url", "returnurl", "return_url", "next", "continue", "goto", "jump", "forward", "callback"),
    },
    {
        "tag_code": "docs", "location": "path", "weight": 30,
        "keywords": ("swagger", "swagger-ui", "api-docs", "openapi", "redoc", "graphql", "doc.html"),
    },
    {
        "tag_code": "debug", "location": "path", "weight": 35,
        "keywords": (
            "actuator", "heapdump", "configprops", "mappings", "threaddump",
            "debug", "trace", "prometheus", "metrics", "jolokia", "pprof",
            "phpinfo", "server-status", "graphiql", "profiler",
        ),
    },
    {
        "tag_code": "export", "location": "path_param", "weight": 16,
        "keywords": ("export", "download", "report", "excel", "csv"),
    },
    {
        "tag_code": "xml", "location": "path_param", "weight": 22,
        "keywords": ("xml", "wsdl", "soap", "xsl", "xxe"),
    },
]


CONTEXTUAL_RULES = [
    {
        "tag_code": "command_injection", "weight": 30,
        "label": "系统诊断工具与可控目标参数组合",
        "path_keywords": ("ping", "traceroute", "nslookup", "dig", "curl", "wget"),
        "param_keywords": ("host", "ip", "target", "address", "domain", "url", "args", "option"),
    },
    {
        "tag_code": "command_injection", "weight": 30,
        "label": "外部工具处理与可控输入参数组合",
        "path_keywords": (
            "ffmpeg", "convert", "unzip", "extract", "transcode", "render",
            "gitclone", "git-clone", "git_clone",
        ),
        "param_keywords": (
            "url", "fileurl", "file_url", "input", "source", "path",
            "filename", "file_name", "args", "options",
        ),
    },
    {
        "tag_code": "code_execution", "weight": 32,
        "label": "动态执行路径与代码参数组合",
        "path_keywords": ("eval", "execute", "compile", "script", "plugin", "module", "extension"),
        "param_keywords": ("code", "script", "classname", "class_name", "methodname", "method_name", "pluginurl", "plugin_url", "packageurl", "package_url"),
    },
]


PREFILTER_EXTRA_KEYWORDS = (
    "union select", "information_schema", "xp_cmdshell", "waitfor delay",
    "pg_sleep", "benchmark(", "extractvalue(", "updatexml(", "${jndi:",
)

COMMAND_PARAM_NAMES = {
    "cmd", "command", "commandline", "shell", "exec", "executable", "args", "argv",
}
COMMAND_VALUE_PATTERN = re.compile(r"(?:[;&|]{1,2}|`|\$\(|\r|\n)")
JNDI_VALUE_PATTERN = re.compile(r"\$\{\s*jndi\s*:", re.IGNORECASE)
EXPRESSION_VALUE_PATTERNS = (
    (re.compile(r"\$\{[^}]+\}"), "${...}"),
    (re.compile(r"#\{[^}]+\}"), "#{...}"),
    (re.compile(r"\{\{[^}]+\}\}"), "{{...}}"),
    (re.compile(r"<%=[\s\S]+?%>"), "<%=...%>"),
)
SQL_VALUE_PATTERNS = (
    (re.compile(r"\bunion(?:\s+all)?\s+select\b", re.IGNORECASE), "UNION SELECT"),
    (re.compile(r"\binformation_schema\b", re.IGNORECASE), "information_schema"),
    (re.compile(r"\b(?:sleep|benchmark|extractvalue|updatexml|pg_sleep)\s*\(", re.IGNORECASE), "SQL延时/报错函数"),
    (re.compile(r"\bwaitfor\s+delay\b", re.IGNORECASE), "WAITFOR DELAY"),
    (re.compile(r"\bxp_cmdshell\b", re.IGNORECASE), "xp_cmdshell"),
    (re.compile(r"(?:^|\s)['\"]?\s*or\s+['\"]?1['\"]?\s*=\s*['\"]?1\b", re.IGNORECASE), "OR 1=1"),
)


@lru_cache(maxsize=32768)
def _safe_unquote_cached(value):
    for _ in range(2):
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
    return value


def _safe_unquote(value):
    return _safe_unquote_cached(str(value or ""))


def _url_parts(raw_url):
    raw_url = str(raw_url or "").strip()
    try:
        parsed = urlsplit(raw_url)
    except ValueError:
        return None
    if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
        return None
    try:
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        return None
    if not hostname:
        return None
    scheme = parsed.scheme.lower()
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    netloc = hostname if port is None or default_port else "{}:{}".format(hostname, port)
    path = _safe_unquote(parsed.path or "/")
    params = [(_safe_unquote(key), _safe_unquote(value)) for key, value in parse_qsl(parsed.query, keep_blank_values=True)]
    return {
        "raw": raw_url,
        "scheme": scheme,
        "domain": hostname,
        "netloc": netloc,
        "path": path,
        "params": params,
        "query": parsed.query,
    }


def canonical_url(raw_url):
    parts = _url_parts(raw_url)
    if not parts:
        return ""
    normalized_query = urlencode(sorted(parts["params"]), doseq=True, quote_via=quote)
    return urlunsplit((parts["scheme"], parts["netloc"], parts["path"] or "/", normalized_query, ""))


@lru_cache(maxsize=32768)
def _segments_cached(value):
    value = _safe_unquote(value).lower()
    return tuple(part for part in re.split(r"[^a-z0-9]+", value) if part)


def _segments(value):
    return _segments_cached(str(value or ""))


@lru_cache(maxsize=32768)
def _compact_token_cached(value):
    return "".join(
        char for char in _safe_unquote(value).lower()
        if char.isalnum()
    )


def _compact_token(value):
    return _compact_token_cached(str(value or ""))


@lru_cache(maxsize=1024)
def _keyword_boundary_pattern(keyword):
    return re.compile(
        r"(?<![a-z0-9]){}(?![a-z0-9])".format(re.escape(keyword))
    )


@lru_cache(maxsize=128)
def _keyword_group_pattern(keywords, mode):
    alternatives = "|".join(
        re.escape(keyword)
        for keyword in sorted(keywords, key=lambda value: (-len(value), value))
    )
    if mode == "contains":
        return re.compile(r"(?:{})".format(alternatives))
    return re.compile(r"(?<![a-z0-9])(?:{})(?![a-z0-9])".format(alternatives))


def _contains_keyword(value, keyword, mode="word"):
    value = _safe_unquote(value).lower()
    keyword = str(keyword or "").strip().lower()
    if not keyword:
        return False
    if mode == "normalized":
        normalized_keyword = _compact_token(keyword)
        if keyword in value:
            return True
        normalized_segments = (
            _compact_token(segment)
            for segment in re.split(r"[/\\?&#.=]+", value)
        )
        return bool(
            normalized_keyword and any(
                normalized_keyword in segment
                for segment in normalized_segments if segment
            ))
    if mode == "contains":
        return keyword in value
    if keyword in _segments(value):
        return True
    return bool(_keyword_boundary_pattern(keyword).search(value))


def _location_values(parts, location, ignored_param_names=None):
    ignored_param_names = IGNORED_SENSITIVE_PARAM_NAMES.union(
        ignored_param_names or ()
    )
    param_names = [
        key for key, _ in parts["params"]
        if key.strip().lower() not in ignored_param_names
    ]
    if location == "domain":
        return [parts["domain"]]
    if location == "path":
        return [parts["path"]]
    if location == "path_endpoint":
        endpoint = parts["path"].rstrip("/").rsplit("/", 1)[-1]
        if re.search(
            r"\.(?:avif|bmp|css|eot|gif|ico|jpe?g|js|map|mp[34]|pdf|png|svg|"
            r"tiff?|webm|webp|woff2?|ttf|otf|zip)$",
            endpoint,
            re.IGNORECASE,
        ):
            return []
        return [endpoint]
    if location == "param":
        return param_names
    if location == "domain_path":
        return [parts["domain"], parts["path"]]
    if location == "path_param":
        return [parts["path"]] + param_names
    return [parts["domain"], parts["path"]] + param_names


def _matching_keywords(parts, rule):
    ignored_param_names = (
        IGNORED_SSRF_PARAM_NAMES if rule.get("tag_code") == "ssrf" else None
    )
    values = _location_values(
        parts, rule.get("location", "all"), ignored_param_names
    )
    mode = rule.get("mode", "word")
    keywords = tuple(rule.get("keywords", ()))
    if mode == "normalized":
        matched = []
        seen = set()
        for keyword in keywords:
            normalized = _compact_token(keyword)
            if not normalized or normalized in seen:
                continue
            if any(_contains_keyword(value, keyword, mode) for value in values):
                matched.append(keyword)
                seen.add(normalized)
        return matched
    pattern = _keyword_group_pattern(keywords, mode)
    if not any(pattern.search(_safe_unquote(value).lower()) for value in values):
        return []
    return [
        keyword for keyword in keywords
        if any(_contains_keyword(value, keyword, mode) for value in values)
    ]


def _matching_contextual_rule(parts, rule):
    path_keywords = tuple(rule.get("path_keywords", ()))
    if not _keyword_group_pattern(
        path_keywords, rule.get("path_mode", "word")
    ).search(_safe_unquote(parts["path"]).lower()):
        return [], []
    path_hits = [
        keyword for keyword in path_keywords
        if _contains_keyword(parts["path"], keyword, rule.get("path_mode", "word"))
    ]
    param_names = _location_values(parts, "param")
    param_keywords = tuple(rule.get("param_keywords", ()))
    param_pattern = _keyword_group_pattern(param_keywords, "word")
    if not any(
        param_pattern.search(_safe_unquote(name).lower()) for name in param_names
    ):
        return path_hits, []
    param_hits = [
        keyword for keyword in param_keywords
        if any(_contains_keyword(name, keyword, "word") for name in param_names)
    ]
    return path_hits, param_hits


def _add_tag(tags, tag_code):
    tag = TAG_BY_CODE.get(tag_code)
    if tag and not any(item["code"] == tag_code for item in tags):
        tags.append(dict(tag))


def _metadata_time(metadata):
    for field in ("update_date", "save_date", "first_save_date", "create_date"):
        value = metadata.get(field)
        if value:
            return str(value)
    object_id = metadata.get("_id")
    try:
        return object_id.generation_time.isoformat()
    except Exception:
        return ""


def analyze_sensitive_url(raw_url, custom_rules=None, metadata=None):
    parts = _url_parts(raw_url)
    if not parts:
        return None
    metadata = metadata or {}
    source = metadata.get("source_label") or "URL"
    tags = []
    evidence = []
    custom_rule_ids = []
    score = 0

    for rule in BUILTIN_RULE_GROUPS:
        matched = _matching_keywords(parts, rule)
        if not matched:
            continue
        _add_tag(tags, rule["tag_code"])
        score += int(rule["weight"]) + min(max(len(matched) - 1, 0) * 4, 12)
        location_label = {
            "domain_path": "域名/路径",
            "path_param": "路径/参数",
            "domain": "域名",
            "path": "路径",
            "path_endpoint": "路径端点",
            "param": "参数名",
        }.get(rule["location"], "URL")
        evidence.append("{}命中 {}".format(location_label, ", ".join(matched[:4])))

    for rule in CONTEXTUAL_RULES:
        path_hits, param_hits = _matching_contextual_rule(parts, rule)
        if not path_hits or not param_hits:
            continue
        _add_tag(tags, rule["tag_code"])
        score += int(rule["weight"])
        evidence.append("{}：{} + {}".format(
            rule["label"], ", ".join(path_hits[:2]), ", ".join(param_hits[:3])
        ))

    for key, value in parts["params"]:
        param_name = key.strip().lower()
        if param_name in IGNORED_SENSITIVE_PARAM_NAMES:
            continue
        decoded = _safe_unquote(value).strip()
        lower_value = decoded.lower()
        if (
            param_name not in IGNORED_SSRF_PARAM_NAMES
            and re.match(r"^(?:https?:)?//", lower_value)
        ):
            _add_tag(tags, "ssrf")
            score += 24
            evidence.append("参数 {} 的值为绝对 URL".format(key))
        if re.match(r"^(?:file:|\\\\|[a-z]:[\\/]|\.\.?[\\/]|/(?:etc|proc|sys|var|home|root|tmp)/)", lower_value):
            _add_tag(tags, "file_read")
            score += 22
            evidence.append("参数 {} 的值具有文件路径结构".format(key))
        if (
            _compact_token(param_name) in COMMAND_PARAM_NAMES
            and COMMAND_VALUE_PATTERN.search(decoded)
        ):
            _add_tag(tags, "command_injection")
            score += 38
            evidence.append("命令参数 {} 的值包含命令连接符".format(key))
        expression_labels = [
            label for pattern, label in EXPRESSION_VALUE_PATTERNS
            if pattern.search(decoded)
        ]
        if expression_labels:
            _add_tag(tags, "expression_injection")
            score += 38
            evidence.append("参数 {} 的值包含表达式结构 {}".format(
                key, ", ".join(expression_labels[:2])
            ))
        if JNDI_VALUE_PATTERN.search(decoded):
            _add_tag(tags, "code_execution")
            score += 45
            evidence.append("参数 {} 的值包含 JNDI 表达式".format(key))
        sql_labels = [
            label for pattern, label in SQL_VALUE_PATTERNS
            if pattern.search(decoded)
        ]
        if sql_labels:
            _add_tag(tags, "sql_injection")
            score += 45
            evidence.append("参数 {} 的值包含 SQL 特征 {}".format(
                key, ", ".join(sql_labels[:2])
            ))

    for custom_rule in custom_rules or []:
        if not custom_rule.get("enabled", True):
            continue
        keyword = str(custom_rule.get("keyword") or "").strip()
        ignored_param_names = (
            IGNORED_SSRF_PARAM_NAMES
            if custom_rule.get("tag_code") == "ssrf" else None
        )
        values = _location_values(
            parts, custom_rule.get("location", "all"), ignored_param_names
        )
        if not any(_contains_keyword(value, keyword, custom_rule.get("mode", "contains")) for value in values):
            continue
        tag_code = custom_rule.get("tag_code")
        _add_tag(tags, tag_code)
        weight = int(custom_rule.get("weight") or 0)
        score += weight
        evidence.append("自定义规则命中 {} (+{})".format(keyword, weight))
        if custom_rule.get("id"):
            custom_rule_ids.append(str(custom_rule["id"]))

    candidate_field = str(metadata.get("_candidate_field") or "")
    use_final_response = candidate_field == "final_url"
    status_code = metadata.get(
        "final_status_code" if use_final_response else "status_code")
    try:
        status_code = int(status_code) if status_code is not None else None
    except (TypeError, ValueError):
        status_code = None
    response_title = str(metadata.get(
        "final_title" if use_final_response else "title") or "")
    verification_status = str(metadata.get("verification_status") or "")
    verification_reason = str(metadata.get("verification_reason") or "")
    entry_type = str(metadata.get("entry_type") or "")
    content_type = str(metadata.get("content_type") or "")
    try:
        content_length = int(metadata.get("content_length"))
    except (TypeError, ValueError):
        content_length = None

    if source == "目录扫描" and verification_status == "verified":
        if status_code is not None and 200 <= status_code < 300:
            score += 12
        elif status_code in (401, 403):
            score += 8
        elif status_code is not None and 300 <= status_code < 400:
            score += 6
        else:
            score += 4
        status_label = "HTTP {}".format(status_code) if status_code is not None else "响应"
        evidence.append("目录扫描已复核 {}".format(status_label))

    if not tags:
        return None

    score = min(score, 100)
    confidence = "high" if score >= 70 else "medium" if score >= 40 else "low"
    canonical = canonical_url(raw_url)
    record_id = str(metadata.get("_id") or "")
    stable_id = hashlib.sha1(canonical.encode("utf-8")).hexdigest()
    params = list(dict.fromkeys(key for key, _ in parts["params"] if key))
    return {
        "id": stable_id,
        "url": canonical or str(raw_url),
        "method": str(metadata.get("method") or metadata.get("request_method") or "GET").upper(),
        "score": score,
        "confidence": confidence,
        "tags": tags,
        "params": params,
        "evidence": list(dict.fromkeys(evidence)),
        "custom_rule_ids": list(dict.fromkeys(custom_rule_ids)),
        "source": source,
        "sources": [source],
        "task_id": str(metadata.get("task_id") or ""),
        "record_ids": [record_id] if record_id else [],
        "discovered_from": str(metadata.get("discovered_from") or metadata.get("site") or ""),
        "discovered_at": _metadata_time(metadata),
        "status_code": status_code,
        "response_title": response_title,
        "content_length": content_length,
        "content_type": content_type,
        "verification_status": verification_status,
        "verification_reason": verification_reason,
        "entry_type": entry_type,
    }


def _merge_result(existing, incoming):
    if not existing:
        return incoming
    existing["score"] = max(existing["score"], incoming["score"])
    existing["confidence"] = "high" if existing["score"] >= 70 else "medium" if existing["score"] >= 40 else "low"
    for field in ("sources", "params", "evidence", "record_ids", "custom_rule_ids"):
        existing[field] = list(dict.fromkeys((existing.get(field) or []) + (incoming.get(field) or [])))
    for tag in incoming.get("tags") or []:
        _add_tag(existing["tags"], tag.get("code"))
    if incoming.get("discovered_at", "") > existing.get("discovered_at", ""):
        existing["discovered_at"] = incoming["discovered_at"]
    if not existing.get("discovered_from") and incoming.get("discovered_from"):
        existing["discovered_from"] = incoming["discovered_from"]
    for field in (
        "status_code", "response_title", "content_type", "content_length",
        "verification_status", "verification_reason", "entry_type",
    ):
        if incoming.get(field) not in (None, ""):
            existing[field] = incoming[field]
    return existing


def normalize_custom_rule(item):
    return {
        "id": str(item.get("_id") or item.get("id") or ""),
        "keyword": str(item.get("keyword") or ""),
        "tag_code": str(item.get("tag_code") or ""),
        "location": str(item.get("location") or "all"),
        "mode": str(item.get("mode") or "contains"),
        "weight": int(item.get("weight") or 10),
        "enabled": item.get("enabled") is not False,
        "created_by": str(item.get("created_by") or ""),
        "create_date": str(item.get("create_date") or ""),
        "update_date": str(item.get("update_date") or ""),
    }


def load_custom_rules(enabled_only=True):
    query = {"enabled": {"$ne": False}} if enabled_only else {}
    return [normalize_custom_rule(item) for item in utils.conn_db("sensitive_interface_rule").find(query).sort([("_id", -1)])]


def validate_custom_rule(data, partial=False):
    data = data or {}
    cleaned = {}
    required = ("keyword", "tag_code", "location", "mode", "weight")
    if not partial and any(data.get(field) in (None, "") for field in required):
        raise ValueError("关键词、标签、位置、匹配方式和权重不能为空")

    if "keyword" in data:
        keyword = str(data.get("keyword") or "").strip().lower()
        if len(keyword) < 2 or len(keyword) > 64:
            raise ValueError("关键词长度必须为 2-64 个字符")
        if any(char in keyword for char in ("\x00", "\r", "\n")):
            raise ValueError("关键词包含非法字符")
        cleaned["keyword"] = keyword
    if "tag_code" in data:
        tag_code = str(data.get("tag_code") or "")
        if tag_code not in TAG_BY_CODE:
            raise ValueError("未知标签")
        cleaned["tag_code"] = tag_code
    if "location" in data:
        location = str(data.get("location") or "")
        if location not in VALID_LOCATIONS:
            raise ValueError("未知匹配位置")
        cleaned["location"] = location
    if "mode" in data:
        mode = str(data.get("mode") or "")
        if mode not in VALID_MODES:
            raise ValueError("未知匹配方式")
        cleaned["mode"] = mode
    if "weight" in data:
        try:
            weight = int(data.get("weight"))
        except (TypeError, ValueError):
            raise ValueError("权重必须是 5、10 或 20")
        if weight not in VALID_WEIGHTS:
            raise ValueError("权重必须是 5、10 或 20")
        cleaned["weight"] = weight
    if "enabled" in data:
        if not isinstance(data.get("enabled"), bool):
            raise ValueError("enabled 必须是布尔值")
        cleaned["enabled"] = data["enabled"]
    return cleaned


def scope_domains(scope_id):
    """按资产组 ID 取范围域名列表（自动剥掉 *. 前缀）"""
    scope = utils.conn_db("asset_scope").find_one({"_id": _object_id(scope_id)})
    if not scope:
        raise LookupError("资产分组不存在")
    domains = scope.get("scope_array") or []
    if isinstance(scope.get("scope"), str) and scope.get("scope"):
        domains = [d.strip() for d in scope["scope"].split(",") if d.strip()]
    domains = [d.lstrip("*.").strip() for d in domains if d.strip()]
    return scope.get("name") or scope_id, domains


def task_ids_for_scope(task_id=None, project_name=None, scope_id=None):
    task_id = str(task_id or "").strip()
    project_name = str(project_name or "").strip()
    scope_id = str(scope_id or "").strip()

    # 资产分组（SRC）筛选：按分组范围匹配任务目标
    if scope_id:
        group_name, domains = scope_domains(scope_id)
        if not domains:
            return [], {"type": "scope", "name": group_name, "targets": []}
        pattern = "(?i)(^|\\.)(" + "|".join(re.escape(d) for d in domains) + ")($|\\.)"
        tasks = list(utils.conn_db("task").find(
            {"target": {"$regex": pattern}},
            {"_id": 1, "name": 1, "target": 1, "status": 1}))
        return [str(t["_id"]) for t in tasks], {
            "type": "scope",
            "name": group_name,
            "targets": list(domains),
        }

    # 全量展示：未提供任何筛选时返回全部任务
    if not task_id and not project_name:
        tasks = list(utils.conn_db("task").find(
            {}, {"_id": 1, "name": 1, "target": 1, "status": 1}).sort([("create_time", -1)]))
        return [str(t["_id"]) for t in tasks], {
            "type": "all",
            "name": "全部任务",
            "targets": [],
        }

    if bool(task_id) == bool(project_name):
        raise ValueError("task_id 和 project_name 必须且只能提供一个")
    if task_id:
        task = utils.conn_db("task").find_one(
            {"_id": _object_id(task_id)}, {"name": 1, "target": 1, "status": 1}
        )
        if not task:
            raise LookupError("任务不存在")
        return [task_id], {
            "type": "task",
            "name": task.get("name") or task.get("target") or task_id,
            "target": task.get("target") or "",
            "_cache_ttl": _cache_ttl_for_tasks([task]),
        }
    tasks = list(utils.conn_db("task").find(
        {"name": project_name}, {"_id": 1, "target": 1, "status": 1}
    ).sort([("_id", -1)]))
    if not tasks:
        raise LookupError("项目不存在")
    return [str(item["_id"]) for item in tasks], {
        "type": "project", "name": project_name,
        "targets": list(dict.fromkeys(str(item.get("target") or "") for item in tasks if item.get("target"))),
        "_cache_ttl": _cache_ttl_for_tasks(tasks),
    }


def _object_id(value):
    from bson import ObjectId
    return ObjectId(value)


def _cache_ttl_for_tasks(tasks):
    statuses = {str(item.get("status") or "").lower() for item in tasks}
    if statuses and statuses.issubset(TERMINAL_TASK_STATUSES):
        return ANALYSIS_CACHE_TTL_COMPLETE
    return ANALYSIS_CACHE_TTL_ACTIVE


def _regex_for_keywords(keywords):
    ordered = sorted(keywords, key=lambda value: (-len(value), value))
    patterns = [
        re.escape(value) if len(value) >= 3
        else r"(?:^|[./?&=_-]){}(?:[./?&=_-]|$)".format(re.escape(value))
        for value in ordered
    ]
    return "(?:{})".format("|".join(patterns))


def _candidate_patterns(custom_rules):
    base_keywords = set()
    extended_keywords = set()
    component_keywords = set()
    for group in BUILTIN_RULE_GROUPS:
        candidate_keywords = group.get("prefilter_keywords", group["keywords"])
        if (
            group.get("prefilter_group") == "component"
            or group.get("tag_code") == "middleware_console"
        ):
            target = component_keywords
        elif group.get("tag_code") in EXTENDED_TAG_CODES:
            target = extended_keywords
        else:
            target = base_keywords
        target.update(keyword for keyword in candidate_keywords if len(keyword) >= 2)
    for rule in CONTEXTUAL_RULES:
        extended_keywords.update(
            keyword for keyword in rule.get("path_keywords", ()) if len(keyword) >= 2
        )
    extended_keywords.update(PREFILTER_EXTRA_KEYWORDS)
    base_keywords.update(
        rule["keyword"] for rule in custom_rules
        if rule.get("enabled", True) and len(rule.get("keyword", "")) >= 2
    )
    return [
        _regex_for_keywords(keywords)
        for keywords in (base_keywords, extended_keywords, component_keywords)
        if keywords
    ]


def _candidate_pattern(custom_rules):
    return "(?:{})".format("|".join(_candidate_patterns(custom_rules)))


def _candidate_match_terms(custom_rules):
    keywords = set()
    for group in BUILTIN_RULE_GROUPS:
        keywords.update(group.get("prefilter_keywords", group["keywords"]))
    for rule in CONTEXTUAL_RULES:
        keywords.update(rule.get("path_keywords", ()))
    keywords.update(PREFILTER_EXTRA_KEYWORDS)
    keywords.update(
        rule["keyword"] for rule in custom_rules
        if rule.get("enabled", True) and len(rule.get("keyword", "")) >= 2
    )
    normalized = {
        str(keyword).lower() for keyword in keywords if len(str(keyword)) >= 2
    }
    return (
        tuple(sorted(
            (keyword for keyword in normalized if len(keyword) >= 3),
            key=lambda value: (-len(value), value),
        )),
        tuple(sorted(keyword for keyword in normalized if len(keyword) < 3)),
    )


def _is_candidate_url(raw_url, match_terms):
    long_terms, short_terms = match_terms
    value = _safe_unquote(raw_url).lower()
    if any(term in value for term in long_terms):
        return True
    if not short_terms:
        return False
    segments = set(_segments(value))
    return any(term in segments for term in short_terms)


def _fileleak_document_eligible(document):
    verification = str(document.get("verification_status") or "")
    if verification and verification != "verified":
        return False
    if document.get("template_detected") is True:
        return False
    if str(document.get("entry_type") or "") in FILELEAK_REJECTED_ENTRY_TYPES:
        return False
    try:
        status_code = int(document.get("status_code"))
    except (TypeError, ValueError):
        status_code = None
    return status_code != 404 and not (
        status_code is not None and 500 <= status_code < 600)


def _fileleak_candidate_eligible(document, field):
    status_field = "final_status_code" if field == "final_url" else "status_code"
    try:
        status_code = int(document.get(status_field))
    except (TypeError, ValueError):
        status_code = None
    return status_code != 404 and not (
        status_code is not None and 500 <= status_code < 600)


def _is_hint_failure(exc):
    message = str(exc or "").lower()
    return any(marker in message for marker in HINT_FAILURE_MARKERS)


def _iter_collection_documents(collection, query, projection, hint_name="task_id_1"):
    def make_cursor(use_hint):
        cursor = collection.find(query, projection)
        if use_hint and hint_name:
            cursor = cursor.hint(hint_name)
        return cursor

    try:
        for document in make_cursor(True):
            yield document
    except OperationFailure as exc:
        if not _is_hint_failure(exc):
            raise
        for document in make_cursor(False):
            yield document


def _source_specs(task_ids):
    base_query = {"task_id": {"$in": task_ids}}
    fileleak_query = dict(base_query)
    fileleak_query.update({
        "verification_status": {"$in": ["verified", None]},
        "template_detected": {"$ne": True},
        "entry_type": {"$nin": sorted(FILELEAK_REJECTED_ENTRY_TYPES)},
        "status_code": {"$nin": [404, 500, 501, 502, 503, 504, 505]},
    })
    return [
        {
            "label": "URL", "collection": "url", "fields": ("url",),
            "query": formal_pipeline_query(base_query),
            "projection": {"url": 1, "method": 1, "request_method": 1, "task_id": 1, "site": 1, "discovered_from": 1, "source": 1, "collector": 1, "save_date": 1, "update_date": 1},
        },
        {
            "label": "WIH", "collection": "wih", "fields": ("content",),
            "query": formal_pipeline_query(base_query),
            "projection": {"content": 1, "task_id": 1, "site": 1, "discovered_from": 1, "source": 1, "sources": 1, "record_type": 1, "save_date": 1, "update_date": 1},
        },
        {
            "label": "入口", "collection": "entry_asset", "fields": ("alive_url", "final_url", "seed"),
            "query": formal_pipeline_query(base_query),
            "projection": {"alive_url": 1, "final_url": 1, "seed": 1, "task_id": 1, "site": 1, "discovered_from": 1, "source": 1, "collectors": 1, "status": 1, "save_date": 1, "update_date": 1},
        },
        {
            "label": "目录扫描", "collection": "fileleak",
            "fields": ("url", "final_url"),
            "query": formal_pipeline_query(fileleak_query),
            "projection": {
                "url": 1, "final_url": 1, "task_id": 1, "site": 1,
                "status_code": 1, "final_status_code": 1,
                "title": 1, "final_title": 1, "content_type": 1, "content_length": 1,
                "verification_status": 1, "verification_reason": 1,
                "template_detected": 1, "entry_type": 1,
                "save_date": 1, "update_date": 1,
            },
            "document_filter": _fileleak_document_eligible,
            "candidate_filter": _fileleak_candidate_eligible,
        },
    ]


def collect_sensitive_interfaces(task_ids, custom_rules=None, document_limit=100000):
    custom_rules = custom_rules if custom_rules is not None else load_custom_rules(enabled_only=True)
    candidate_match_terms = _candidate_match_terms(custom_rules)
    merged = {}
    scanned = Counter()
    truncated = []
    analyzed_candidates = set()
    for spec in _source_specs(task_ids):
        collection_name = spec["collection"]
        cursor = _iter_collection_documents(
            utils.conn_db(collection_name), spec["query"], spec["projection"])
        processed_count = 0
        for document in cursor:
            document_filter = spec.get("document_filter")
            if document_filter and not document_filter(document):
                continue
            raw_urls = []
            seen_urls = set()
            candidate_filter = spec.get("candidate_filter")
            for field in spec["fields"]:
                raw_url = document.get(field)
                if (
                    not raw_url or raw_url in seen_urls or
                    (candidate_filter and not candidate_filter(document, field))
                ):
                    continue
                seen_urls.add(raw_url)
                raw_urls.append((field, raw_url))
            candidate_urls = [
                (field, raw_url)
                for field, raw_url in raw_urls
                if _is_candidate_url(raw_url, candidate_match_terms)
            ]
            if not candidate_urls:
                continue
            if processed_count >= document_limit:
                truncated.append(collection_name)
                break
            processed_count += 1
            scanned[spec["label"]] += 1
            metadata = dict(document)
            metadata["source_label"] = spec["label"]
            for field, raw_url in candidate_urls:
                analysis_key = _candidate_analysis_key(spec["label"], raw_url)
                if analysis_key in analyzed_candidates:
                    continue
                analyzed_candidates.add(analysis_key)
                metadata["_candidate_field"] = field
                result = analyze_sensitive_url(
                    raw_url, custom_rules=custom_rules, metadata=metadata
                )
                if not result:
                    continue
                merged[result["url"]] = _merge_result(
                    merged.get(result["url"]), result
                )
    return list(merged.values()), dict(scanned), truncated


def _rule_fingerprint(custom_rules):
    values = [
        "{}:{}:{}:{}:{}:{}:{}".format(
            rule.get("id", ""), rule.get("keyword", ""), rule.get("tag_code", ""),
            rule.get("location", ""), rule.get("mode", ""), rule.get("weight", ""),
            rule.get("enabled", True),
        )
        for rule in custom_rules
    ]
    return hashlib.sha1("|".join(sorted(values)).encode("utf-8")).hexdigest()


def _analysis_cache_key(task_ids, custom_rules):
    payload = "{}\x1f{}\x1f{}".format(
        ANALYSIS_CACHE_VERSION,
        _rule_fingerprint(custom_rules),
        "\x1e".join(sorted(task_ids)),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _candidate_analysis_key(source_label, raw_url):
    canonical = canonical_url(raw_url)
    return "{}\x1f{}".format(source_label or "", canonical or str(raw_url or ""))


def _shared_cache_paths(cache_key):
    return (
        os.path.join(ANALYSIS_CACHE_DIR, "{}.json.gz".format(cache_key)),
        os.path.join(ANALYSIS_CACHE_DIR, "{}.lock".format(cache_key)),
    )


def _valid_cache_payload(payload, cache_ttl, now):
    if not isinstance(payload, dict) or payload.get("version") != ANALYSIS_CACHE_VERSION:
        return False
    created_at = payload.get("created_at")
    age = now - created_at if isinstance(created_at, (int, float)) else None
    if age is None or age < -300 or age >= cache_ttl:
        return False
    return (
        isinstance(payload.get("items"), list)
        and isinstance(payload.get("scanned"), dict)
        and isinstance(payload.get("truncated"), list)
    )


def _read_shared_cache(cache_path, cache_ttl, now):
    try:
        with gzip.open(cache_path, "rt", encoding="utf-8") as cache_file:
            payload = json.load(cache_file)
    except (OSError, EOFError, ValueError, TypeError):
        return None
    return payload if _valid_cache_payload(payload, cache_ttl, now) else None


def _write_shared_cache(cache_path, payload):
    os.makedirs(ANALYSIS_CACHE_DIR, mode=0o700, exist_ok=True)
    file_descriptor, temporary_path = tempfile.mkstemp(
        prefix=".sensitive-interface-", suffix=".tmp", dir=ANALYSIS_CACHE_DIR
    )
    try:
        os.close(file_descriptor)
        with gzip.open(temporary_path, "wt", encoding="utf-8", compresslevel=5) as cache_file:
            json.dump(payload, cache_file, ensure_ascii=False, separators=(",", ":"))
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, cache_path)
    finally:
        try:
            os.unlink(temporary_path)
        except FileNotFoundError:
            pass


def _prune_shared_cache():
    try:
        cache_files = [
            os.path.join(ANALYSIS_CACHE_DIR, name)
            for name in os.listdir(ANALYSIS_CACHE_DIR)
            if name.endswith(".json.gz")
        ]
        cache_files.sort(key=os.path.getmtime, reverse=True)
        for cache_path in cache_files[ANALYSIS_CACHE_MAX_FILES:]:
            try:
                os.unlink(cache_path)
            except FileNotFoundError:
                pass
    except OSError:
        pass


@contextmanager
def _shared_cache_lock(lock_path):
    os.makedirs(ANALYSIS_CACHE_DIR, mode=0o700, exist_ok=True)
    with open(lock_path, "a+b") as lock_file:
        os.chmod(lock_path, 0o600)
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _memory_cache_get(cache_key, cache_ttl, now):
    with _ANALYSIS_CACHE_LOCK:
        cached = _ANALYSIS_CACHE.get(cache_key)
        if cached and now - cached["created_at"] < cache_ttl:
            return cached
    return None


def _memory_cache_set(cache_key, payload, now):
    with _ANALYSIS_CACHE_LOCK:
        expired = [
            key for key, value in _ANALYSIS_CACHE.items()
            if now - value["created_at"] >= ANALYSIS_CACHE_TTL_COMPLETE
        ]
        for key in expired:
            _ANALYSIS_CACHE.pop(key, None)
        if len(_ANALYSIS_CACHE) >= ANALYSIS_CACHE_MAX_ITEMS and cache_key not in _ANALYSIS_CACHE:
            oldest_key = min(_ANALYSIS_CACHE, key=lambda key: _ANALYSIS_CACHE[key]["created_at"])
            _ANALYSIS_CACHE.pop(oldest_key, None)
        _ANALYSIS_CACHE[cache_key] = payload


def _merge_sensitive_items(groups):
    merged = {}
    for items in groups:
        for item in items or []:
            key = item.get("url") or item.get("id")
            if not key:
                continue
            merged[key] = _merge_result(merged.get(key), dict(item))
    return list(merged.values())


def _merge_scanned_counts(groups):
    scanned = Counter()
    for group in groups:
        scanned.update(group or {})
    return dict(scanned)


def _task_cache_ttl_map(task_ids, default_ttl):
    default_ttl = max(int(default_ttl or ANALYSIS_CACHE_TTL_ACTIVE), 1)
    task_ids = [str(task_id) for task_id in task_ids if task_id]
    if not task_ids:
        return {}
    try:
        from bson import ObjectId
        object_ids = [
            ObjectId(task_id) for task_id in task_ids
            if ObjectId.is_valid(task_id)
        ]
    except Exception:
        object_ids = []
    if not object_ids:
        return {task_id: default_ttl for task_id in task_ids}
    ttl_map = {task_id: default_ttl for task_id in task_ids}
    for task in utils.conn_db("task").find(
        {"_id": {"$in": object_ids}}, {"status": 1}
    ):
        task_id = str(task.get("_id"))
        ttl_map[task_id] = _cache_ttl_for_tasks([task])
    return ttl_map


def _cached_collection_from_task_shards(task_ids, custom_rules, cache_ttl):
    ttl_map = _task_cache_ttl_map(task_ids, cache_ttl)
    item_groups = []
    scanned_groups = []
    truncated = []
    shard_hits = []
    for task_id in task_ids:
        items, scanned, shard_truncated, cache_hit = _cached_collection(
            [task_id],
            custom_rules,
            cache_ttl=ttl_map.get(task_id, cache_ttl),
            allow_shards=False,
        )
        item_groups.append(items)
        scanned_groups.append(scanned)
        truncated.extend(shard_truncated or [])
        shard_hits.append(cache_hit)
    return (
        _merge_sensitive_items(item_groups),
        _merge_scanned_counts(scanned_groups),
        list(dict.fromkeys(truncated)),
        all(shard_hits) if shard_hits else False,
    )


def _cached_collection(task_ids, custom_rules, cache_ttl=ANALYSIS_CACHE_TTL_ACTIVE, allow_shards=True):
    now = time.time()
    cache_ttl = max(int(cache_ttl or ANALYSIS_CACHE_TTL_ACTIVE), 1)
    task_ids = [str(task_id) for task_id in task_ids if task_id]
    cache_key = _analysis_cache_key(task_ids, custom_rules)
    cached = _memory_cache_get(cache_key, cache_ttl, now)
    if cached:
        return cached["items"], cached["scanned"], cached["truncated"], True

    cache_path, lock_path = _shared_cache_paths(cache_key)
    shared = _read_shared_cache(cache_path, cache_ttl, now)
    if shared:
        _memory_cache_set(cache_key, shared, now)
        return shared["items"], shared["scanned"], shared["truncated"], True

    payload = None
    try:
        with _shared_cache_lock(lock_path):
            now = time.time()
            shared = _read_shared_cache(cache_path, cache_ttl, now)
            if shared:
                _memory_cache_set(cache_key, shared, now)
                return shared["items"], shared["scanned"], shared["truncated"], True

            if allow_shards and len(task_ids) > 1:
                items, scanned, truncated, _shard_cache_hit = (
                    _cached_collection_from_task_shards(
                        task_ids, custom_rules, cache_ttl)
                )
            else:
                items, scanned, truncated = collect_sensitive_interfaces(
                    task_ids, custom_rules=custom_rules)
            payload = {
                "version": ANALYSIS_CACHE_VERSION,
                "created_at": time.time(),
                "items": items,
                "scanned": scanned,
                "truncated": truncated,
            }
            _write_shared_cache(cache_path, payload)
            _prune_shared_cache()
    except OSError:
        if payload is None:
            if allow_shards and len(task_ids) > 1:
                items, scanned, truncated, _shard_cache_hit = (
                    _cached_collection_from_task_shards(
                        task_ids, custom_rules, cache_ttl)
                )
            else:
                items, scanned, truncated = collect_sensitive_interfaces(
                    task_ids, custom_rules=custom_rules
                )
            payload = {
                "version": ANALYSIS_CACHE_VERSION,
                "created_at": time.time(),
                "items": items,
                "scanned": scanned,
                "truncated": truncated,
            }
    _memory_cache_set(cache_key, payload, time.time())
    return items, scanned, truncated, False


def _matches_filters(item, query="", tag_code="", source="", confidence=""):
    query = str(query or "").strip().lower()
    if query:
        haystack = " ".join([
            item.get("url", ""), item.get("discovered_from", ""),
            " ".join(item.get("params") or []), " ".join(item.get("evidence") or []),
        ]).lower()
        if query not in haystack:
            return False
    if tag_code and not any(tag.get("code") == tag_code for tag in item.get("tags") or []):
        return False
    if source and source not in (item.get("sources") or []):
        return False
    if confidence and item.get("confidence") != confidence:
        return False
    return True


def _sort_items(items, order):
    order = order or "-score"
    sort_map = {
        "-score": (lambda item: (item.get("score", 0), item.get("discovered_at", "")), True),
        "score": (lambda item: (item.get("score", 0), item.get("url", "")), False),
        "-discovered_at": (lambda item: (item.get("discovered_at", ""), item.get("score", 0)), True),
        "discovered_at": (lambda item: (item.get("discovered_at", ""), item.get("score", 0)), False),
        "url": (lambda item: item.get("url", ""), False),
        "-url": (lambda item: item.get("url", ""), True),
    }
    key, reverse = sort_map.get(order, sort_map["-score"])
    return sorted(items, key=key, reverse=reverse)


def build_summary(items):
    confidence = Counter(item.get("confidence") for item in items)
    sources = Counter(source for item in items for source in item.get("sources") or [])
    tags = Counter(tag.get("code") for item in items for tag in item.get("tags") or [])
    custom_rules = Counter(rule_id for item in items for rule_id in item.get("custom_rule_ids") or [])
    return {
        "total": len(items),
        "high": confidence.get("high", 0),
        "medium": confidence.get("medium", 0),
        "low": confidence.get("low", 0),
        "sources": dict(sources),
        "tags": dict(tags),
        "custom_rules": dict(custom_rules),
    }


def query_sensitive_interfaces(task_id=None, project_name=None, scope_id=None, page=1, size=20, query="", tag_code="", source="", confidence="", order="-score", max_size=500):
    task_ids, scope = task_ids_for_scope(task_id=task_id, project_name=project_name, scope_id=scope_id)
    cache_ttl = scope.pop("_cache_ttl", ANALYSIS_CACHE_TTL_ACTIVE)
    custom_rules = load_custom_rules(enabled_only=True)
    items, scanned, truncated, cache_hit = _cached_collection(
        task_ids, custom_rules, cache_ttl=cache_ttl
    )
    summary = build_summary(items)
    filtered = [item for item in items if _matches_filters(item, query, tag_code, source, confidence)]
    filtered = _sort_items(filtered, order)
    page = max(int(page or 1), 1)
    size = min(max(int(size or 20), 1), max(int(max_size or 500), 1))
    start = (page - 1) * size
    return {
        "code": 200,
        "page": page,
        "size": size,
        "total": len(filtered),
        "items": filtered[start:start + size],
        "summary": summary,
        "scope": {**scope, "task_count": len(task_ids)},
        "meta": {
            "scanned_candidates": scanned,
            "truncated_collections": truncated,
            "custom_rule_count": len(custom_rules),
            "cache_hit": cache_hit,
            "cache_ttl_seconds": cache_ttl,
        },
    }


def json_safe(value):
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    return value
