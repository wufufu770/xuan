import base64
import codecs
import gzip
import hashlib
from html import unescape
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from html.parser import HTMLParser
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit

import requests

from app import utils
from app.config import Config
from .baseUpdateTask import BaseUpdateTask
from .resourceBudget import acquire as acquire_resource_budget
from .siteQuality import refresh_site_quality_clusters
from app.utils.site_quality import apply_site_quality


logger = utils.get_logger()


SCRIPT_EXTENSIONS = (".js", ".mjs")
SCRIPT_CONTENT_TYPES = (
    "application/ecmascript",
    "application/javascript",
    "application/x-javascript",
    "text/ecmascript",
    "text/javascript",
    "text/x-javascript",
)
SOURCE_MAP_HEADER_NAMES = ("sourcemap", "x-sourcemap")
SOURCE_MAP_RE = re.compile(
    rb"sourceMappingURL\s*=\s*([^\s*]+)", re.IGNORECASE)
QUOTED_SCRIPT_RE = re.compile(
    rb"[\"']([^\"'\r\n]{1,768}?\.(?:m?js)(?:\?[^\"'\r\n]{0,256})?)[\"']",
    re.IGNORECASE,
)
QUOTED_CHUNK_REFERENCE_RE = re.compile(
    rb"[\"']([^\"'\s\r\n<>]{1,768}?(?:/_next/static/|/_nuxt/|/static/js/|"
    rb"/assets/|/chunks/|\.chunk\.|chunk)[^\"'\s\r\n<>]{0,256})[\"']",
    re.IGNORECASE,
)
JS_OBJECT_STRING_MAP_RE = re.compile(
    rb"[\"']?([A-Za-z0-9_$.-]{1,80})[\"']?\s*:\s*[\"']([^\"'\r\n]{1,180})[\"']"
)
WEBPACK_PREFIX_NAME_HASH_RE = re.compile(
    rb"[\"'](?P<prefix>[^\"'\r\n]{0,220}(?:js/|chunks/|assets/|static/js/))"
    rb"[\"']\s*\+\s*\(\s*(?P<name_map>\{[^{}]{1,8192}\})\s*\[\s*"
    rb"(?P<var>[A-Za-z_$][A-Za-z0-9_$]*)\s*\]\s*\|\|\s*(?P=var)\s*\)\s*"
    rb"\+\s*[\"']\.[\"']\s*\+\s*(?P<hash_map>\{[^{}]{1,8192}\})\s*\[\s*(?P=var)\s*\]"
    rb"\s*\+\s*[\"'](?P<suffix>[^\"'\r\n]{0,80}\.m?js)[\"']",
    re.IGNORECASE,
)
WEBPACK_PREFIX_ID_HASH_RE = re.compile(
    rb"[\"'](?P<prefix>[^\"'\r\n]{0,220}(?:js/|chunks/|assets/|static/js/))"
    rb"[\"']\s*\+\s*(?P<var>[A-Za-z_$][A-Za-z0-9_$]*)\s*\+\s*[\"']\.[\"']"
    rb"\s*\+\s*(?P<hash_map>\{[^{}]{1,8192}\})\s*\[\s*(?P=var)\s*\]"
    rb"\s*\+\s*[\"'](?P<suffix>[^\"'\r\n]{0,80}\.m?js)[\"']",
    re.IGNORECASE,
)
WEBPACK_PREFIX_MAP_SUFFIX_RE = re.compile(
    rb"[\"'](?P<prefix>[^\"'\r\n]{0,220}(?:js/|chunks/|assets/|static/js/))"
    rb"[\"']\s*\+\s*(?P<name_map>\{[^{}]{1,8192}\})\s*\[\s*"
    rb"[A-Za-z_$][A-Za-z0-9_$]*\s*\]\s*\+\s*[\"'](?P<suffix>[^\"'\r\n]{0,80}\.m?js)[\"']",
    re.IGNORECASE,
)
CHUNK_REFERENCE_MARKERS = (
    "/_next/static/", "/_nuxt/", "/static/js/", "/assets/",
    "/chunks/", ".chunk.", "chunk",
)
SAFE_COMPONENT_RE = re.compile(r"[^A-Za-z0-9._-]+")
BLOCKED_INTERACTION_RE = re.compile(
    r"(?:logout|log-out|signout|sign-out|delete|remove|drop|submit|save|pay|"
    r"refund|upload|download|reset|restart|shutdown|disable|unsubscribe|"
    r"confirm|approve|enable|create|start|publish|invite|execute|"
    r"install|deploy|cancel|clear|退出|注销|删除|提交|保存|支付|退款|上传|"
    r"下载|重置|确认|批准|启用|创建|发布|邀请|发送|执行|安装|部署|取消|清空)",
    re.IGNORECASE,
)
VLQ_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
VLQ_VALUES = {char: index for index, char in enumerate(VLQ_ALPHABET)}
GENERIC_BROWSER_TITLES = {
    "", "301 moved permanently", "302 found", "302 moved temporarily",
    "307 temporary redirect", "308 permanent redirect", "400 bad request",
    "401 unauthorized", "403 forbidden", "404 not found",
    "500 internal server error", "502 bad gateway", "503 service unavailable",
    "504 gateway time-out", "not found", "loading", "loading...",
    "please wait", "please wait...", "redirecting", "redirecting...",
    "加载中", "加载中...", "页面加载中", "正在加载", "跳转中",
    "页面不存在", "没有找到站点", "page not found", "未找到",
    "welcome to nginx", "welcome to openresty", "welcome to tengine",
    "welcome to centos", "apache http server test page",
    "test page for the nginx http", "405 method not allowed",
}
MAX_BROWSER_DOCUMENT_TITLE_BYTES = 2 * 1024 * 1024
SPA_SELECTION_REASONS = {
    "spa_framework", "webpack_vite_chunks", "untitled_html_shell",
    "untitled_html_title_probe", "low_yield_js",
}
EXTENDED_TITLE_SETTLE_REASONS = SPA_SELECTION_REASONS | {
    "cross_origin_sso", "login_admin_api_docs", "in_scope_redirect",
}
INITIAL_DOCUMENT_PREFETCH_REASONS = {
    "cross_origin_sso", "in_scope_redirect",
}


class RuntimeArtifactWatchdogTimeout(BaseException):
    """Raised by SIGALRM so broad target-level Exception handlers do not swallow it."""


def available_memory_bytes():
    """Read Linux MemAvailable without adding a psutil dependency."""
    try:
        with open("/proc/meminfo", "r", encoding="ascii") as handle:
            for line in handle:
                if line.startswith("MemAvailable:"):
                    value = int(line.split()[1])
                    return max(value, 0) * 1024
    except (OSError, TypeError, ValueError, IndexError):
        return 0
    return 0


RUNTIME_HOOK_SCRIPT = r"""
(() => {
  if (window.__arlRuntimeHookInstalled) return;
  window.__arlRuntimeHookInstalled = true;
  window.__arlRuntimeRequests = [];
  const limit = 2000;
  const record = (kind, method, url, body) => {
    try {
      if (!url || window.__arlRuntimeRequests.length >= limit) return;
      let bodyLength = 0;
      if (typeof body === 'string') bodyLength = body.length;
      else if (body && typeof body.byteLength === 'number') bodyLength = body.byteLength;
      window.__arlRuntimeRequests.push({
        kind: String(kind || ''),
        method: String(method || 'GET').toUpperCase(),
        url: String(url),
        body_length: bodyLength,
        ts: Date.now()
      });
    } catch (_) {}
  };

  const originalFetch = window.fetch;
  if (originalFetch) {
    window.fetch = function(input, init) {
      try {
        const url = typeof input === 'string' ? input : (input && input.url) || '';
        const method = (init && init.method) || (input && input.method) || 'GET';
        record('fetch', method, url, init && init.body);
      } catch (_) {}
      return originalFetch.apply(this, arguments);
    };
  }

  if (window.XMLHttpRequest && XMLHttpRequest.prototype) {
    const originalOpen = XMLHttpRequest.prototype.open;
    const originalSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function(method, url) {
      this.__arlRuntimeMethod = method;
      this.__arlRuntimeUrl = url;
      return originalOpen.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function(body) {
      record('xhr', this.__arlRuntimeMethod, this.__arlRuntimeUrl, body);
      return originalSend.apply(this, arguments);
    };
  }

  const hookAxios = () => {
    try {
      const axios = window.axios;
      if (!axios || axios.__arlRuntimeHooked || !axios.interceptors ||
          !axios.interceptors.request) return false;
      axios.interceptors.request.use((config) => {
        record('axios', config.method || 'GET', config.url || '', config.data);
        return config;
      });
      axios.__arlRuntimeHooked = true;
      return true;
    } catch (_) {
      return false;
    }
  };
  if (!hookAxios()) {
    let attempts = 0;
    const timer = setInterval(() => {
      attempts += 1;
      if (hookAxios() || attempts >= 10) clearInterval(timer);
    }, 500);
  }
})();
"""


RUNTIME_TITLE_OBSERVER_SCRIPT = r"""
(() => {
  if (window.__arlTitleObserverInstalled) return;
  window.__arlTitleObserverInstalled = true;
  let lastTitle = null;
  const emit = (kind) => {
    try {
      const title = String(document.title || '').replace(/\s+/g, ' ').trim();
      if (!title || title === lastTitle || typeof window.__arlReportTitle !== 'function') return;
      lastTitle = title;
      const pending = window.__arlReportTitle({
        title,
        url: String(location.href || ''),
        kind: String(kind || 'mutation'),
        ts: Date.now()
      });
      if (pending && typeof pending.catch === 'function') pending.catch(() => {});
    } catch (_) {}
  };

  // Catch a title assigned immediately before location.replace/location.href.
  // A MutationObserver alone can lose that value when navigation commits in
  // the same task.
  try {
    const descriptor = Object.getOwnPropertyDescriptor(Document.prototype, 'title');
    if (descriptor && descriptor.get && descriptor.set && descriptor.configurable) {
      Object.defineProperty(Document.prototype, 'title', {
        configurable: descriptor.configurable,
        enumerable: descriptor.enumerable,
        get: descriptor.get,
        set(value) {
          descriptor.set.call(this, value);
          emit('setter');
        }
      });
    }
  } catch (_) {}

  let titleObserver = null;
  let observedRoot = null;
  const installObserver = () => {
    try {
      const root = document.head || document.documentElement || document;
      if (!root || root === observedRoot) return;
      if (titleObserver) titleObserver.disconnect();
      titleObserver = new MutationObserver(() => {
        if (document.head && observedRoot !== document.head) installObserver();
        emit('mutation');
      });
      titleObserver.observe(root, {subtree: true, childList: true, characterData: true});
      observedRoot = root;
      window.__arlTitleMutationObserver = titleObserver;
      emit('install');
    } catch (_) {}
  };
  installObserver();
  document.addEventListener('readystatechange', () => {
    installObserver();
    emit('readystatechange');
  }, true);
  window.addEventListener('pagehide', () => emit('pagehide'), true);
})();
"""


PAGE_RESOURCE_SCRIPT = r"""
() => {
  const scriptPattern = /\.m?js(?:$|[?#])/i;
  const uniq = (values) => Array.from(new Set((values || []).filter(Boolean)));
  const scripts = Array.from(document.scripts || [])
    .map((item) => item && item.src ? String(item.src) : '')
    .filter(Boolean);
  const modulePreloads = Array.from(document.querySelectorAll(
    'link[rel="modulepreload"], link[as="script"]'
  ))
    .map((item) => item && item.href ? String(item.href) : '')
    .filter(Boolean);
  const resources = performance.getEntriesByType('resource')
    .filter((item) => item && item.name &&
      (item.initiatorType === 'script' || scriptPattern.test(item.name)))
    .map((item) => String(item.name));
  const runtime = Array.isArray(window.__arlRuntimeRequests)
    ? window.__arlRuntimeRequests.splice(0, window.__arlRuntimeRequests.length)
    : [];
  const routes = Array.from(document.querySelectorAll('a[href]'))
    .map((item) => item.href ? String(item.href) : '')
    .filter(Boolean);
  const scriptText = scripts.concat(modulePreloads, resources).join('\n').toLowerCase();
  const sameOriginRoutes = routes.filter((value) => {
    try { return new URL(value, location.href).origin === location.origin; } catch (_) { return false; }
  });
  const hashRoutes = sameOriginRoutes.filter((value) => {
    try { return !!new URL(value, location.href).hash; } catch (_) { return false; }
  });
  const routeLikeLinks = sameOriginRoutes.filter((value) => {
    try {
      const parsed = new URL(value, location.href);
      return parsed.pathname !== '/' || parsed.hash || parsed.search;
    } catch (_) { return false; }
  });
  const appRoots = Array.from(document.querySelectorAll(
    '#app, #root, #__next, #__nuxt, [data-v-app], [ng-version], [ng-app]'
  ));
  const bodyText = document.body ? String(document.body.innerText || '') : '';
  const bodyHtml = document.body ? String(document.body.innerHTML || '') : '';
  const html = document.documentElement ? String(document.documentElement.outerHTML || '') : '';
  const allElements = Array.from(document.querySelectorAll('*'));
  const moduleScriptCount = Array.from(document.scripts || [])
    .filter((item) => String(item.type || '').toLowerCase() === 'module').length;
  const chunkScriptCount = scripts.filter((value) =>
    /(?:chunk|_next\/static|_nuxt\/|\/assets\/|\/static\/js\/|webpack|vite)/i.test(value)
  ).length;
  const frameworks = [];
  const addFramework = (name, source, confidence) => {
    frameworks.push({name, source, confidence});
  };
  try {
    if (window.__NEXT_DATA__ || document.querySelector('#__next') || /\/_next\/static\//i.test(scriptText)) {
      addFramework('Next.js', window.__NEXT_DATA__ ? 'window.__NEXT_DATA__' : 'next_static', 95);
    }
    if (window.__NUXT__ || document.querySelector('#__nuxt') || /\/_nuxt\//i.test(scriptText)) {
      addFramework('Nuxt.js', window.__NUXT__ ? 'window.__NUXT__' : 'nuxt_static', 95);
    }
    if (document.querySelector('[ng-version], [ng-app]') || /\bangular(?:\.min)?\.js\b/i.test(scriptText)) {
      addFramework('Angular', document.querySelector('[ng-version]') ? 'ng-version' : 'angular_asset', 92);
    }
    if (window.__VUE__ || document.querySelector('[data-v-app], [data-vue-root]') ||
        appRoots.some((node) => node && node.__vue_app__) || /(?:vue|vue-router)[.-]/i.test(scriptText)) {
      addFramework('Vue.js', document.querySelector('[data-v-app]') ? 'data-v-app' : 'vue_runtime_or_asset', 88);
    }
    if (document.querySelector('[data-reactroot], [data-react-props]') ||
        appRoots.some((node) => node && (node._reactRootContainer || Object.keys(node).some((key) => key.startsWith('__react')))) ||
        /(?:react|react-dom|react-router)[.-]/i.test(scriptText)) {
      addFramework('React', document.querySelector('[data-reactroot]') ? 'data-reactroot' : 'react_runtime_or_asset', 86);
    }
    if (document.querySelector('[data-svelte-h]') || /svelte/i.test(scriptText)) {
      addFramework('Svelte', document.querySelector('[data-svelte-h]') ? 'data-svelte-h' : 'svelte_asset', 78);
    }
    if (window.g_umiRoutes || /(?:umi\.[a-z0-9]+\.js|\/umi(?:\.[a-z0-9]+)?\.js)/i.test(scriptText)) {
      addFramework('UmiJS', window.g_umiRoutes ? 'window.g_umiRoutes' : 'umi_asset', 86);
    }
  } catch (_) {}
  const technologies = [];
  if (Object.keys(window).some((key) => /^webpackChunk|webpackJsonp/.test(key))) technologies.push('Webpack');
  if (/(?:webpack|webpackJsonp|webpackChunk|__webpack_require__)/i.test(scriptText)) technologies.push('Webpack');
  if (/(?:\/@vite\/|vite\/client|\.vite\/|\/assets\/index-[a-z0-9_-]+\.js)/i.test(scriptText)) technologies.push('Vite');
  if (moduleScriptCount || modulePreloads.length) technologies.push('ESModule');
  const reasons = [];
  const pushReason = (condition, reason) => { if (condition) reasons.push(reason); };
  pushReason(frameworks.length > 0, 'framework_runtime_or_asset');
  pushReason(appRoots.length > 0, 'app_root_mount');
  pushReason(chunkScriptCount >= 2, 'multiple_chunks');
  pushReason(moduleScriptCount > 0 || modulePreloads.length > 0, 'module_runtime');
  pushReason(runtime.length > 0, 'runtime_requests');
  pushReason(hashRoutes.length > 0, 'hash_router');
  pushReason(routeLikeLinks.length >= 5, 'client_routes');
  pushReason(bodyText.length < 500 && scripts.length >= 2, 'thin_html_shell');
  pushReason(html.length < 80000 && bodyHtml.length > bodyText.length * 4 && scripts.length >= 2, 'script_heavy_shell');
  const knownSsr = frameworks.some((item) => item.name === 'Next.js' || item.name === 'Nuxt.js');
  const routeMode = hashRoutes.length ? 'hash' :
    routeLikeLinks.length >= 5 ? 'history' :
    knownSsr ? 'ssr_or_hybrid' : 'unknown';
  const renderMode = (
    reasons.includes('thin_html_shell') || reasons.includes('script_heavy_shell') || runtime.length > 0
  ) ? 'client_rendered' : knownSsr ? 'hybrid_or_ssr' : 'unknown';
  let score = 0;
  const addScore = (condition, value) => { if (condition) score += value; };
  addScore(frameworks.length > 0, 30);
  addScore(appRoots.length > 0, 16);
  addScore(chunkScriptCount >= 2, 18);
  addScore(moduleScriptCount > 0 || modulePreloads.length > 0, 12);
  addScore(runtime.length > 0, 16);
  addScore(hashRoutes.length > 0, 10);
  addScore(routeLikeLinks.length >= 5, 8);
  addScore(bodyText.length < 500 && scripts.length >= 2, 14);
  addScore(html.length < 80000 && bodyHtml.length > bodyText.length * 4 && scripts.length >= 2, 8);
  score = Math.max(0, Math.min(100, score));
  const confidence = score >= 80 ? 'high' : score >= 55 ? 'medium' : score >= 35 ? 'low' : 'none';
  const spaSignals = [];
  try {
    if (window.__NEXT_DATA__ || document.querySelector('#__next')) spaSignals.push('next');
    if (window.__NUXT__ || document.querySelector('#__nuxt, [data-v-app]')) spaSignals.push('nuxt');
    if (document.querySelector('[ng-version], [ng-app]')) spaSignals.push('angular');
    if (document.querySelector('[data-reactroot], [data-react-props]')) spaSignals.push('react');
    if (window.__VUE__ || document.querySelector('[data-v-app], [data-vue-root]')) spaSignals.push('vue');
    if (window.webpackChunk || window.webpackJsonp) spaSignals.push('webpack');
    if (scripts.length >= 2 && document.querySelector('#root, #app')) spaSignals.push('js_root_shell');
    if (scripts.some((value) => /(?:vite|@vite|webpack|chunk|_next\/static|_nuxt\/)/i.test(value))) {
      spaSignals.push('bundled_runtime');
    }
  } catch (_) {}
  return {
    scripts,
    modulePreloads,
    resources,
    runtime,
    routes,
    pageUrl: String(location.href || ''),
    pageTitle: String(document.title || ''),
    spaSignals: uniq(spaSignals),
    spaProfile: {
      score,
      confidence,
      framework: frameworks.length ? frameworks[0].name : '',
      frameworks,
      technologies: uniq(technologies),
      renderMode,
      routeMode,
      reasons: uniq(reasons),
      metrics: {
        scriptCount: scripts.length,
        moduleScriptCount,
        modulePreloadCount: modulePreloads.length,
        chunkScriptCount,
        runtimeRequestCount: runtime.length,
        routeCount: routes.length,
        sameOriginRouteCount: sameOriginRoutes.length,
        hashRouteCount: hashRoutes.length,
        appRootCount: appRoots.length,
        bodyTextLength: bodyText.length,
        htmlLength: html.length,
        nodeCount: allElements.length
      },
      pageUrl: String(location.href || ''),
      title: String(document.title || '')
    }
  };
}
"""


SAFE_CLICK_SCRIPT = r"""
() => {
  const blocked = /(?:logout|log-out|signout|sign-out|delete|remove|drop|submit|save|pay|refund|upload|download|reset|restart|shutdown|disable|unsubscribe|confirm|approve|enable|create|start|publish|invite|execute|install|deploy|cancel|clear|退出|注销|删除|提交|保存|支付|退款|上传|下载|重置|确认|批准|启用|创建|发布|邀请|发送|执行|安装|部署|取消|清空)/i;
  const visible = (node) => {
    const style = window.getComputedStyle(node);
    const box = node.getBoundingClientRect();
    return style.visibility !== 'hidden' && style.display !== 'none' &&
      box.width > 1 && box.height > 1;
  };
  window.__arlRuntimeClicked = window.__arlRuntimeClicked || {};
  const nodes = Array.from(document.querySelectorAll(
    '[role="tab"], [role="menuitem"], [aria-controls], nav a[href], a[href]'
  ));
  for (const node of nodes) {
    if (!visible(node)) continue;
    const text = [node.textContent, node.id, node.className, node.getAttribute('aria-label')]
      .map((value) => String(value || '')).join(' ');
    const href = node.href ? String(node.href) : '';
    if (blocked.test(text + ' ' + href)) continue;
    if (node.closest('form') && String(node.getAttribute('type') || '').toLowerCase() === 'submit') continue;
    if (href) {
      try {
        const parsed = new URL(href, location.href);
        if (!/^https?:$/.test(parsed.protocol) || parsed.origin !== location.origin) continue;
        if (node.target && node.target.toLowerCase() === '_blank') continue;
      } catch (_) { continue; }
    } else {
      const marker = String(node.getAttribute('role') || '') + ' ' + text;
      if (!/(?:tab|menu|nav|expand|collapse|drawer)/i.test(marker)) continue;
    }
    const key = node.tagName + '|' + href + '|' + text.slice(0, 160);
    if (window.__arlRuntimeClicked[key]) continue;
    window.__arlRuntimeClicked[key] = true;
    try {
      node.click();
      return {clicked: true, key, href, text: text.slice(0, 160)};
    } catch (_) {}
  }
  return {clicked: false};
}
"""


class _ScriptHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.sources = []

    def handle_starttag(self, tag, attrs):
        if str(tag or "").lower() != "script":
            return
        values = {str(name or "").lower(): value for name, value in attrs}
        source = str(values.get("src") or "").strip()
        if source:
            self.sources.append(source)


def is_script_url(value):
    try:
        path = unquote(urlsplit(str(value or "")).path or "").lower()
    except (TypeError, ValueError):
        return False
    return path.endswith(SCRIPT_EXTENSIONS)


def _decode_js_reference(value):
    value = value.decode("utf-8", errors="ignore").replace("\\/", "/")
    value = value.replace("\\u002F", "/").replace("\\u002f", "/")
    return value.strip()


def _js_object_string_map(raw):
    values = {}
    for key, value in JS_OBJECT_STRING_MAP_RE.findall(raw or b""):
        key = key.decode("ascii", errors="ignore").strip()
        value = _decode_js_reference(value)
        if key and value:
            values[key] = value
    return values


def _script_reference_url(base_url, value, allow_chunk_hint=False):
    value = str(value or "").strip()
    if not value or any(marker in value for marker in ("${", "{", "}", " + ")):
        return ""
    if value.startswith(".") and not value.startswith(("./", "../")):
        return ""
    lowered = value.lower()
    if lowered.startswith(("data:", "blob:", "javascript:", "mailto:", "#")):
        return ""
    try:
        url = urljoin(base_url, value)
        parsed = urlsplit(url)
        base = urlsplit(base_url)
    except (TypeError, ValueError):
        return ""
    if parsed.scheme not in ("http", "https") or parsed.netloc != base.netloc:
        return ""
    path = unquote(parsed.path or "").lower()
    extension = os.path.splitext(path)[1]
    if not extension and path.endswith("/"):
        return ""
    if extension and extension not in SCRIPT_EXTENSIONS:
        return ""
    if not extension and not allow_chunk_hint:
        return ""
    if not extension and not any(marker in path for marker in CHUNK_REFERENCE_MARKERS):
        return ""
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


def derived_script_reference_urls(body, base_url, max_refs=500):
    """Extract same-origin JS/chunk references from a downloaded runtime file."""
    max_refs = max(int(max_refs or 0), 0)
    refs = []
    seen = set()

    def add(value, allow_chunk_hint=False):
        if max_refs and len(refs) >= max_refs:
            return False
        url = _script_reference_url(
            base_url, value, allow_chunk_hint=allow_chunk_hint)
        if not url or url in seen:
            return False
        seen.add(url)
        refs.append(url)
        return True

    for raw in QUOTED_SCRIPT_RE.findall(body or b""):
        add(_decode_js_reference(raw), allow_chunk_hint=False)
        if max_refs and len(refs) >= max_refs:
            return refs

    for raw in QUOTED_CHUNK_REFERENCE_RE.findall(body or b""):
        add(_decode_js_reference(raw), allow_chunk_hint=True)
        if max_refs and len(refs) >= max_refs:
            return refs

    for match in WEBPACK_PREFIX_NAME_HASH_RE.finditer(body or b""):
        prefix = _decode_js_reference(match.group("prefix"))
        suffix = _decode_js_reference(match.group("suffix"))
        name_map = _js_object_string_map(match.group("name_map"))
        hash_map = _js_object_string_map(match.group("hash_map"))
        for chunk_id, chunk_hash in hash_map.items():
            chunk_name = name_map.get(chunk_id, chunk_id)
            add("{}{}.{}{}".format(prefix, chunk_name, chunk_hash, suffix), True)
            if max_refs and len(refs) >= max_refs:
                return refs

    for match in WEBPACK_PREFIX_ID_HASH_RE.finditer(body or b""):
        prefix = _decode_js_reference(match.group("prefix"))
        suffix = _decode_js_reference(match.group("suffix"))
        hash_map = _js_object_string_map(match.group("hash_map"))
        for chunk_id, chunk_hash in hash_map.items():
            add("{}{}.{}{}".format(prefix, chunk_id, chunk_hash, suffix), True)
            if max_refs and len(refs) >= max_refs:
                return refs

    for match in WEBPACK_PREFIX_MAP_SUFFIX_RE.finditer(body or b""):
        prefix = _decode_js_reference(match.group("prefix"))
        suffix = _decode_js_reference(match.group("suffix"))
        name_map = _js_object_string_map(match.group("name_map"))
        for chunk_name in name_map.values():
            add("{}{}{}".format(prefix, chunk_name, suffix), True)
            if max_refs and len(refs) >= max_refs:
                return refs

    return refs


def source_map_fallback_url(js_url):
    urls = source_map_fallback_urls(js_url)
    return urls[0] if urls else ""


def source_map_fallback_urls(js_url):
    parsed = urlsplit(str(js_url or ""))
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return []
    candidates = [urlunsplit((
        parsed.scheme,
        parsed.netloc,
        (parsed.path or "/") + ".map",
        parsed.query,
        "",
    ))]
    if parsed.query:
        candidates.append(urlunsplit((
            parsed.scheme,
            parsed.netloc,
            (parsed.path or "/") + ".map",
            "",
            "",
        )))
    return list(dict.fromkeys(candidates))


def safe_source_path(value, index=0):
    value = unquote(str(value or "")).replace("\\", "/")
    value = re.sub(r"^[A-Za-z][A-Za-z0-9+.-]*:(?://)?", "", value)
    parts = []
    for part in value.split("/"):
        part = part.strip()
        if not part or part in (".", ".."):
            continue
        part = SAFE_COMPONENT_RE.sub("_", part).strip("._")
        if part:
            parts.append(part[:120])
    if not parts:
        parts = ["source_{}".format(index)]
    if len(parts) > 8:
        parts = parts[-8:]
    return os.path.join(*parts)


def source_recovery_priority(value, index=0):
    value = unquote(str(value or "")).replace("\\", "/").lower()
    normalized = "/{}".format(value.lstrip("/"))
    dependency = any(marker in normalized for marker in (
        "/node_modules/", "/bower_components/", "/vendor/",
        "/webpack/runtime/", "/webpack/bootstrap/",
    ))
    first_party = any(marker in normalized for marker in (
        "/src/", "/app/", "/apps/", "/pages/", "/views/",
        "/components/", "/router/", "/routes/", "/store/",
        "/stores/", "/services/", "/api/", "/config/",
    ))
    code_like = os.path.splitext(value.split("?", 1)[0])[1] in {
        ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue",
        ".svelte", ".html", ".css", ".scss", ".less", ".json",
    }
    if first_party and not dependency:
        tier = 0
    elif code_like and not dependency:
        tier = 1
    elif dependency:
        tier = 3
    else:
        tier = 2
    return tier, index


def _decode_vlq_segment(segment):
    values = []
    value = 0
    shift = 0
    for char in segment:
        digit = VLQ_VALUES.get(char)
        if digit is None:
            raise ValueError("invalid base64 VLQ character")
        value += (digit & 31) << shift
        if digit & 32:
            shift += 5
            if shift > 35:
                raise ValueError("base64 VLQ segment is too large")
            continue
        negative = value & 1
        value >>= 1
        values.append(-value if negative else value)
        value = 0
        shift = 0
    if shift:
        raise ValueError("truncated base64 VLQ segment")
    return values


def iter_decoded_mappings(mappings, max_segments=250000):
    previous_source = 0
    previous_original_line = 0
    previous_original_column = 0
    previous_name = 0
    emitted = 0
    for generated_line, line in enumerate(str(mappings or "").split(";")):
        previous_generated_column = 0
        for segment in line.split(","):
            if not segment:
                continue
            values = _decode_vlq_segment(segment)
            if not values:
                continue
            if len(values) not in (1, 4, 5):
                raise ValueError("invalid source map segment width")
            previous_generated_column += values[0]
            item = {
                "generated_line": generated_line,
                "generated_column": previous_generated_column,
            }
            if len(values) >= 4:
                previous_source += values[1]
                previous_original_line += values[2]
                previous_original_column += values[3]
                item.update({
                    "source_index": previous_source,
                    "source_line": previous_original_line,
                    "source_column": previous_original_column,
                })
            if len(values) == 5:
                previous_name += values[4]
                item["name_index"] = previous_name
            yield item
            emitted += 1
            if max_segments > 0 and emitted >= max_segments:
                return


class RuntimeArtifactCollector:
    def __init__(
        self, task_id, targets, seed_js_urls=None,
        seed_map_urls=None,
        target_reasons=None, artifact_targets=None,
        stage_name="runtime_artifact",
    ):
        self.task_id = str(task_id or "").strip()
        self.stage_name = str(stage_name or "runtime_artifact")
        self.targets = self._normalize_targets(targets)
        self.target_reasons = {}
        for raw_target, raw_reasons in (target_reasons or {}).items():
            origin = self._origin(raw_target)
            if not origin:
                continue
            values = (
                raw_reasons if isinstance(raw_reasons, (list, tuple, set))
                else [raw_reasons]
            )
            self.target_reasons[origin] = {
                str(value or "").strip()
                for value in values if str(value or "").strip()
            }
        artifact_limit = max(int(getattr(
            Config, "RUNTIME_ARTIFACT_MAX_TARGETS", 8) or 0), 0)
        if artifact_targets is None:
            artifact_targets = (
                self.targets[:artifact_limit] if artifact_limit else self.targets
            )
        normalized_artifacts = self._normalize_navigation_urls(artifact_targets)
        target_set = set(self.targets)
        self.artifact_targets = [
            value for value in normalized_artifacts if value in target_set
        ]
        if artifact_limit:
            self.artifact_targets = self.artifact_targets[:artifact_limit]
        self.seed_js_urls = self._normalize_urls(seed_js_urls)
        self.seed_map_urls = self._normalize_urls(seed_map_urls)
        self.base_update_task = BaseUpdateTask(self.task_id)
        task_dir = SAFE_COMPONENT_RE.sub("_", self.task_id).strip("._") or "unknown-task"
        self.output_root = os.path.join(
            str(getattr(Config, "RUNTIME_ARTIFACT_ROOT", "/opt/ARL/data/runtime_artifacts")),
            task_dir,
        )
        self.manifest_path = os.path.join(self.output_root, "manifest.jsonl")
        self.summary_path = os.path.join(self.output_root, "summary.json")
        self.discovered_scripts = {}
        self.script_sources = defaultdict(set)
        self.script_targets = defaultdict(set)
        self.response_headers = {}
        self.downloaded_urls = set()
        self.downloaded_hashes = {}
        self.map_urls = set()
        self.map_seed_targets = defaultdict(set)
        # Queue map probes until JS/chunk download rounds finish for a target.
        self.pending_map_targets = defaultdict(set)
        self.pending_map_sources = {}
        self.map_attempts = defaultdict(int)
        self.download_attempts = defaultdict(int)
        self.target_bytes = defaultdict(int)
        self.target_files = defaultdict(int)
        self.total_bytes = 0
        self.saved_file_count = 0
        self.js_downloaded_count = 0
        self.js_duplicate_count = 0
        self.js_failed_count = 0
        self.map_probe_count = 0
        self.map_downloaded_count = 0
        self.map_failed_count = 0
        self.source_recovered_count = 0
        self.mapping_file_count = 0
        self.browser_script_urls = set()
        self.dom_script_urls = set()
        self.performance_script_urls = set()
        self.module_preload_script_urls = set()
        self.derived_script_urls = set()
        self.runtime_request_count = 0
        self.runtime_request_keys = set()
        self.page_observations = defaultdict(list)
        self.page_observation_keys = set()
        self.browser_title_observation_count = 0
        self.browser_title_enriched_site_count = 0
        self.browser_final_title_site_count = 0
        self.browser_spa_site_count = 0
        self.browser_prefetch_count = 0
        self.browser_prefetch_title_count = 0
        self.browser_prefetch_failed_count = 0
        self.browser_prefetch_skipped_count = 0
        self._browser_title_sites = set()
        self._browser_final_title_sites = set()
        self._browser_spa_sites = set()
        self.target_spa_signals = defaultdict(set)
        self.target_spa_profiles = {}
        self.quality_cluster_summary = {}
        self.interaction_count = 0
        self.route_trigger_count = 0
        self.fallback_html_count = 0
        self.completed_targets = 0
        self.failed_targets = 0
        self.title_probe_completed_targets = set()
        self.title_probe_failed_targets = set()
        self.artifact_completed_targets = set()
        self.artifact_failed_targets = set()
        self.title_probe_skipped_count = 0
        self.artifact_skipped_count = 0
        self.current_phase = ""
        self.available_memory_bytes = 0
        self.memory_guard_triggered = False
        self.warnings = []
        self.started_at = time.monotonic()
        self.deadline = None
        self.current_target_deadline = None
        self.title_probe_total_timeout = max(int(getattr(
            Config, "RUNTIME_TITLE_PROBE_TOTAL_TIMEOUT", 300) or 0), 0)
        self.artifact_total_timeout = max(int(getattr(
            Config, "RUNTIME_ARTIFACT_TOTAL_TIMEOUT", 300) or 0), 0)

    @staticmethod
    def _normalize_urls(values):
        output = []
        seen = set()
        for value in values or []:
            value = str(value or "").strip()
            try:
                parsed = urlsplit(value)
            except (TypeError, ValueError):
                continue
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                continue
            normalized = urlunsplit((
                parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/",
                parsed.query, "",
            ))
            if normalized not in seen:
                seen.add(normalized)
                output.append(normalized)
        return output

    @staticmethod
    def _normalize_navigation_urls(values):
        output = []
        seen = set()
        for value in values or []:
            value = str(value or "").strip()
            try:
                parsed = urlsplit(value)
            except (TypeError, ValueError):
                continue
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                continue
            normalized = urlunsplit((
                parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/",
                parsed.query, parsed.fragment,
            ))
            if normalized not in seen:
                seen.add(normalized)
                output.append(normalized)
        return output

    def _normalize_targets(self, values):
        output = self._normalize_navigation_urls(values)
        max_targets = max(int(getattr(
            Config, "RUNTIME_TITLE_PROBE_MAX_TARGETS", 64) or 0), 0)
        return output[:max_targets] if max_targets else output

    def _start_phase(self, phase, timeout):
        self.current_phase = str(phase or "").strip()
        timeout = max(int(timeout or 0), 0)
        self.deadline = time.monotonic() + timeout if timeout else None

    def _refresh_target_counts(self):
        successful = (
            self.title_probe_completed_targets |
            self.artifact_completed_targets
        )
        attempted_failures = (
            self.title_probe_failed_targets |
            self.artifact_failed_targets
        )
        self.completed_targets = len(successful)
        self.failed_targets = len(attempted_failures)

    def _mark_unattempted_as_skipped(self):
        title_attempted = (
            self.title_probe_completed_targets |
            self.title_probe_failed_targets
        )
        artifact_attempted = (
            self.artifact_completed_targets |
            self.artifact_failed_targets
        )
        self.title_probe_skipped_count = max(
            self.title_probe_skipped_count,
            len(self.targets) - len(title_attempted),
        )
        self.artifact_skipped_count = max(
            self.artifact_skipped_count,
            len(self.artifact_targets) - len(artifact_attempted),
        )

    def _completed_operation_count(self):
        return sum([
            len(self.title_probe_completed_targets),
            len(self.title_probe_failed_targets),
            len(self.artifact_completed_targets),
            len(self.artifact_failed_targets),
        ])

    def _runtime_enriched_site_count(self):
        return len(
            self._browser_title_sites |
            self._browser_final_title_sites |
            self._browser_spa_sites
        )

    def _effective_output_count(self):
        return self.saved_file_count + self._runtime_enriched_site_count()

    def _planned_operation_count(self):
        return len(self.targets) + len(self.artifact_targets)

    def _remaining_time(self):
        deadlines = [
            value for value in (self.deadline, self.current_target_deadline)
            if value is not None
        ]
        if not deadlines:
            return None
        return max(min(deadlines) - time.monotonic(), 0)

    def _time_exhausted(self):
        remaining = self._remaining_time()
        return remaining is not None and remaining <= 0

    def _stopped(self):
        try:
            return self.base_update_task.is_terminal()
        except Exception:
            return False

    def _add_warning(self, value):
        value = str(value or "").strip()
        if value and value not in self.warnings:
            self.warnings.append(value[:500])

    def _prepare_output(self):
        os.makedirs(self.output_root, mode=0o750, exist_ok=True)
        if not os.path.isfile(self.manifest_path):
            return
        try:
            with open(self.manifest_path, "r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    try:
                        item = json.loads(line)
                    except (TypeError, ValueError):
                        continue
                    if item.get("status") != "saved":
                        continue
                    url = str(item.get("url") or "")
                    sha256 = str(item.get("sha256") or "")
                    path = str(item.get("path") or "")
                    if url:
                        self.downloaded_urls.add(url)
                    if sha256 and path:
                        self.downloaded_hashes[sha256] = path
                    try:
                        size = int(item.get("size", 0) or 0)
                    except (TypeError, ValueError):
                        size = 0
                    size = max(size, 0)
                    if not item.get("duplicate"):
                        target = str(item.get("target") or "")
                        self.total_bytes += size
                        self.target_bytes[target] += size
                        self.target_files[target] += 1
                        self.saved_file_count += 1
                        kind = str(item.get("kind") or "")
                        if kind == "js":
                            self.js_downloaded_count += 1
                        elif kind == "maps":
                            self.map_probe_count += 1
                            self.map_downloaded_count += 1
                            if url:
                                self.map_urls.add(url)
                        elif kind == "source_map_source":
                            self.source_recovered_count += 1
                        elif kind == "source_map_mappings":
                            self.mapping_file_count += 1
                    elif str(item.get("kind") or "") == "js":
                        self.js_duplicate_count += 1
        except OSError as exc:
            self._add_warning("manifest resume failed: {}".format(exc))

        request_path = os.path.join(self.output_root, "runtime_requests.jsonl")
        try:
            with open(request_path, "r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    try:
                        item = json.loads(line)
                    except (TypeError, ValueError):
                        continue
                    key = (
                        str(item.get("kind") or "runtime"),
                        str(item.get("method") or "GET").upper()[:16],
                        str(item.get("url") or ""),
                    )
                    if key[2]:
                        self.runtime_request_keys.add(key)
            self.runtime_request_count = len(self.runtime_request_keys)
        except FileNotFoundError:
            pass
        except OSError as exc:
            self._add_warning("runtime request resume failed: {}".format(exc))

    def _append_manifest(self, item):
        item = dict(item or {})
        item.setdefault("saved_at", time.strftime("%Y-%m-%dT%H:%M:%S%z"))
        with open(self.manifest_path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(item, ensure_ascii=True, sort_keys=True) + "\n")

    @staticmethod
    def _title_from_body(body, content_type=""):
        """Extract a readable title from a bounded HTML response.

        SSO gateways in Chinese deployments still omit charset headers. A
        UTF-8-only decode turns those source titles into replacement text just
        when the browser is navigating away, so honor the response/meta
        charset and use a small, deterministic fallback set.
        """
        if not body:
            return ""
        try:
            sample = body[:16 * 1024]
            encodings = []
            charset_match = re.search(
                r"charset\s*=\s*[\"']?\s*([A-Za-z0-9._:-]+)",
                str(content_type or ""),
                re.IGNORECASE,
            )
            if charset_match:
                encodings.append(charset_match.group(1))
            meta_match = re.search(
                rb"<meta[^>]+charset\s*=\s*[\"']?\s*([A-Za-z0-9._:-]+)",
                sample,
                re.IGNORECASE,
            )
            if meta_match:
                encodings.append(
                    meta_match.group(1).decode("ascii", errors="ignore"))
            if body.startswith(codecs.BOM_UTF8):
                encodings.append("utf-8-sig")
            elif body.startswith(codecs.BOM_UTF16_LE) or body.startswith(codecs.BOM_UTF16_BE):
                encodings.append("utf-16")
            encodings.extend(("utf-8", "gb18030", "big5", "latin-1"))

            decoded = ""
            seen_encodings = set()
            for encoding in encodings:
                try:
                    normalized_encoding = codecs.lookup(encoding).name
                except (LookupError, TypeError):
                    continue
                if normalized_encoding in seen_encodings:
                    continue
                seen_encodings.add(normalized_encoding)
                try:
                    candidate = body[:2 * 1024 * 1024].decode(normalized_encoding)
                except (UnicodeDecodeError, LookupError):
                    continue
                decoded = candidate
                if "\ufffd" not in candidate:
                    break
            if not decoded:
                decoded = body[:2 * 1024 * 1024].decode(
                    "utf-8", errors="replace")

            match = re.search(
                r"<title[^>]*>(.*?)</title\s*>",
                decoded,
                re.IGNORECASE | re.DOTALL,
            )
            if not match:
                return ""
            value = re.sub(r"<[^>]+>", " ", match.group(1))
            return unescape(re.sub(r"\s+", " ", value)).strip()[:512]
        except (AttributeError, TypeError, UnicodeError, ValueError):
            return ""

    @staticmethod
    def _meaningful_title(value):
        value = re.sub(r"\s+", " ", str(value or "")).strip()
        lowered = value.lower()
        if lowered in GENERIC_BROWSER_TITLES:
            return ""
        for marker in GENERIC_BROWSER_TITLES:
            if not marker or not lowered.startswith(marker):
                continue
            suffix = lowered[len(marker):].lstrip()
            if not suffix or suffix[0] in "|_-:([{!":
                return ""
        return value

    @classmethod
    def _best_title_observation(cls, observations, origin=""):
        """Prefer the rendered main-frame title and keep its URL paired.

        A raw response title can be a bootstrap placeholder. Vue/React often
        replace it after hydration, so DOM observations outrank response-body
        observations and later observations win within the same source class.
        """
        source_priority = {
            # Setter, head mutation, and sampled DOM titles are all rendered
            # state. Keep them at the same rank so the latest hydration value
            # wins; response-body titles remain lower-confidence fallbacks.
            "browser.title_setter": 60,
            "browser.title_mutation": 60,
            "browser.dom": 60,
            "browser.goto": 55,
            "browser.domcontentloaded": 50,
            "browser.document_finished": 40,
            "browser.route_document": 35,
            # This is an out-of-band fallback for an immediate redirect. It
            # must never outrank a title observed by the real Chromium page.
            "browser.prefetch_document": 25,
            "browser.document_response": 30,
        }
        best = None
        best_rank = None
        for index, item in enumerate(observations or []):
            if not isinstance(item, dict):
                continue
            if origin and cls._origin(item.get("url")) != origin:
                continue
            title = cls._meaningful_title(item.get("title"))
            if not title:
                continue
            source = str(item.get("source") or "")
            rank = (source_priority.get(source, 10), index)
            if best_rank is None or rank > best_rank:
                best = dict(item)
                best["title"] = title
                best_rank = rank
        return best or {}

    @classmethod
    def _best_final_title_observation(cls, observations, final_url=""):
        """Choose a title from the browser's final document, not its source.

        A source SPA can expose a high-quality DOM title before a cross-origin
        SSO navigation finishes. Global source-priority selection would then
        mislabel the source title as the final login-page title.
        """
        final_url = str(final_url or "").strip()
        if not final_url:
            return {}

        def document_key(value):
            try:
                parsed = urlsplit(str(value or ""))
            except (TypeError, ValueError):
                return ""
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                return ""
            return urlunsplit((
                parsed.scheme.lower(), parsed.netloc.lower(),
                parsed.path or "/", parsed.query, "",
            ))

        target_key = document_key(final_url)
        exact = [
            item for item in observations or []
            if document_key(item.get("url")) == target_key
        ]
        result = cls._best_title_observation(exact)
        if result:
            return result
        return cls._best_title_observation(
            observations, origin=cls._origin(final_url))

    @staticmethod
    def _origin(value):
        try:
            parsed = urlsplit(str(value or ""))
        except (TypeError, ValueError):
            return ""
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return ""
        return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), "", "", ""))

    def _record_page_observation(
        self, target, url, title="", status=None, location="", source="",
    ):
        target = str(target or "").strip()
        url = str(url or target).strip()
        if not target or not url:
            return
        try:
            status = int(status) if status is not None else None
        except (TypeError, ValueError):
            status = None
        title = re.sub(r"\s+", " ", str(title or "")).strip()[:512]
        location = str(location or "").strip()[:1024]
        key = (target, url, status, title, location)
        if key in self.page_observation_keys:
            return
        self.page_observation_keys.add(key)
        observations = self.page_observations[target]
        if len(observations) >= 32:
            return
        observations.append({
            "url": url,
            "title": title,
            "status_code": status,
            "location": location,
            "source": str(source or "")[:64],
            "observed_at": time.time(),
        })
        self.browser_title_observation_count += 1

    def _prefetch_initial_document_title(self, target, timeout_ms, user_agent):
        """Read only the initial document as a title/redirect fallback.

        This request is deliberately kept outside Playwright's navigation
        path. WAFs and SPAs can vary their response by TLS, HTTP/2, cookies,
        and browser headers; fulfilling a browser document with ``requests``
        changes those semantics and can make the dynamic crawl less accurate.
        """
        session = requests.Session()
        session.verify = False
        session.trust_env = False
        self.browser_prefetch_count += 1
        response = None
        try:
            configured_timeout = float(getattr(
                Config, "RUNTIME_TITLE_PREFETCH_TIMEOUT", 3) or 0)
            if configured_timeout <= 0:
                return False
            timeout_seconds = max(min(
                float(timeout_ms or 0) / 1000.0,
                configured_timeout,
            ), 1.0)
            response = session.get(
                target,
                headers={
                    "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
                    "User-Agent": user_agent,
                },
                allow_redirects=False,
                stream=True,
                timeout=(min(timeout_seconds, 3.0), timeout_seconds),
            )
            headers = {
                str(name or "").lower(): str(value or "")
                for name, value in response.headers.items()
            }
            content_type = headers.get("content-type", "").lower()
            try:
                content_length = int(headers.get("content-length", 0) or 0)
            except (TypeError, ValueError):
                content_length = 0
            if (
                content_type and
                "html" not in content_type and
                "xhtml" not in content_type and
                not 300 <= int(response.status_code or 0) < 400
            ) or (
                content_length and
                content_length > MAX_BROWSER_DOCUMENT_TITLE_BYTES
            ):
                return False

            body = b""
            if not content_length or content_length <= MAX_BROWSER_DOCUMENT_TITLE_BYTES:
                chunks = []
                size = 0
                for chunk in response.iter_content(chunk_size=65536):
                    if not chunk:
                        continue
                    size += len(chunk)
                    if size > MAX_BROWSER_DOCUMENT_TITLE_BYTES:
                        chunks = []
                        break
                    chunks.append(chunk)
                body = b"".join(chunks)
            title = self._title_from_body(body, content_type=content_type)
            self._record_page_observation(
                target,
                response.url or target,
                title=title,
                status=response.status_code,
                location=headers.get("location", ""),
                source="browser.prefetch_document",
            )
            if title:
                self.browser_prefetch_title_count += 1
            return bool(title)
        except (requests.RequestException, OSError, TypeError, ValueError):
            self.browser_prefetch_failed_count += 1
            return False
        finally:
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass
            session.close()

    def _persist_browser_observation(self, target, result):
        target = str(target or "").strip()
        observations = list(self.page_observations.get(target, []) or [])
        if not target or not observations:
            return False
        origin = self._origin(target)
        if not origin:
            return False

        # Only same-origin titles describe the source asset. A final SSO page
        # is useful evidence, but must never become the source site's title.
        source_observation = self._best_title_observation(
            observations, origin=origin)
        final_url_hint = str(result.get("final_url") or "").strip()
        if not final_url_hint:
            for observation in reversed(observations):
                if self._origin(observation.get("url")):
                    final_url_hint = str(observation.get("url") or "").strip()
                    break
        final_observation = self._best_final_title_observation(
            observations, final_url=final_url_hint)
        browser_title = str(source_observation.get("title") or "")
        browser_title_source = str(
            source_observation.get("source") or
            ("browser.pre_redirect" if browser_title else "")
        )
        final_title = str(final_observation.get("title") or "")
        final_url = str(
            final_observation.get("url") or final_url_hint or target)
        script_count = int(result.get("script_count", 0) or 0)
        runtime_count = int(result.get("runtime_request_count", 0) or 0)
        runtime_spa_profile = self._target_spa_profile(target)
        spa_signals = []
        if script_count:
            spa_signals.append("browser_script_resources")
        if runtime_count:
            spa_signals.append("browser_runtime_requests")
        observed_origins = {
            self._origin(item.get("url")) for item in observations
            if self._origin(item.get("url"))
        }
        cross_origin_redirect = len(observed_origins) > 1
        if cross_origin_redirect:
            spa_signals.append("cross_origin_redirect_chain")
        spa_signals.extend(sorted(self.target_spa_signals.get(target, set())))
        selection_spa_reasons = sorted(
            self._target_reason_set(target).intersection(SPA_SELECTION_REASONS))
        spa_signals.extend(
            "selection_{}".format(value) for value in selection_spa_reasons)
        browser_spa_detected = bool(
            script_count >= 2 or runtime_count or
            self.target_spa_signals.get(target) or selection_spa_reasons
        )

        collection = utils.conn_db("site")
        document = collection.find_one(
            {"task_id": self.task_id, "$or": [
                {"canonical_site": origin}, {"site": origin},
            ]},
        )
        if not document:
            return False
        spa_profile = self._merge_spa_profiles(
            document.get("spa_profile"), runtime_spa_profile)
        spa_score = int(spa_profile.get("score") or document.get("spa_score") or 0)
        spa_confidence = str(
            spa_profile.get("confidence") or
            document.get("spa_confidence") or ""
        ).strip()
        if spa_profile:
            spa_signals.extend(
                "profile_{}".format(value)
                for value in (spa_profile.get("reasons") or [])
            )
            if spa_profile.get("framework"):
                spa_signals.append(
                    "framework_{}".format(
                        str(spa_profile.get("framework")).lower()))
            for value in spa_profile.get("technologies") or []:
                spa_signals.append(
                    "technology_{}".format(str(value).lower()))
        existing_browser_title = str(document.get("browser_title") or "").strip()
        existing_title_source = str(document.get("browser_title_source") or "").strip()
        existing_final_url = str(document.get("browser_final_url") or "").strip()
        # Discard the old buggy value if it was clearly a cross-origin final
        # page title; the final title remains available below.
        if (
            existing_title_source == "browser.final_page" and
            self._origin(existing_final_url) and
            self._origin(existing_final_url) != origin
        ):
            existing_browser_title = ""
            existing_title_source = ""
        browser_title = browser_title or existing_browser_title
        if not browser_title_source:
            browser_title_source = existing_title_source
        if not final_title:
            previous_final_title = str(
                document.get("browser_final_title") or "").strip()
            previous_final_url = str(
                document.get("browser_final_url") or "").strip()
            # Never pair an old SSO title with a newly observed final URL.
            if (
                previous_final_title and previous_final_url and
                (not final_url_hint or previous_final_url == final_url_hint)
            ):
                final_title = previous_final_title
                final_url = previous_final_url
            else:
                final_url = final_url_hint or target
        script_count = max(script_count, int(document.get("runtime_script_count") or 0))
        runtime_count = max(runtime_count, int(document.get("runtime_request_count") or 0))
        browser_spa_detected = bool(
            browser_spa_detected or document.get("browser_spa_detected") or
            spa_score >= 55 or spa_confidence in {"medium", "high"}
        )
        cross_origin_redirect = bool(
            cross_origin_redirect or document.get("browser_cross_origin_redirect")
        )
        old_spa_signals = document.get("spa_signals") or []
        if isinstance(old_spa_signals, str):
            old_spa_signals = [old_spa_signals]
        spa_signals = list(dict.fromkeys(
            [str(value).strip() for value in old_spa_signals if str(value).strip()] +
            [str(value).strip() for value in spa_signals if str(value).strip()]
        ))
        existing_chain = document.get("browser_title_chain") or []
        if isinstance(existing_chain, dict):
            existing_chain = [existing_chain]
        merged_chain = []
        chain_keys = set()
        for observation in list(existing_chain) + observations:
            if not isinstance(observation, dict):
                continue
            key = (
                str(observation.get("url") or ""),
                str(observation.get("status_code") or ""),
                str(observation.get("title") or ""),
                str(observation.get("location") or ""),
            )
            if key in chain_keys:
                continue
            chain_keys.add(key)
            merged_chain.append(observation)
        merged_chain = merged_chain[-64:]
        payload = {
            "browser_title": browser_title,
            "browser_title_source": browser_title_source,
            "browser_title_chain": merged_chain,
            "browser_final_title": final_title,
            "browser_final_url": final_url,
            "browser_spa_detected": browser_spa_detected,
            "browser_cross_origin_redirect": cross_origin_redirect,
            "runtime_script_count": script_count,
            "runtime_request_count": runtime_count,
            "spa_signals": spa_signals,
            "browser_enriched_at": utils.curr_date(),
        }
        if spa_profile:
            payload.update({
                "spa_profile": spa_profile,
                "spa_score": spa_score,
                "spa_confidence": spa_confidence,
                "spa_framework": spa_profile.get("framework") or "",
                "spa_render_mode": spa_profile.get("render_mode") or "",
                "spa_route_mode": spa_profile.get("route_mode") or "",
                "spa_fingerprint_updated_at": utils.curr_date(),
            })
        current_title = str(document.get("title") or "").strip()
        current_title_source = str(document.get("title_source") or "").strip()
        if browser_title and (
            not self._meaningful_title(current_title) or
            current_title_source.startswith("browser.")
        ):
            payload["title"] = browser_title
            payload["title_source"] = payload["browser_title_source"]
        # Use the cluster-aware merge so a real hydrated SPA title can lift a
        # previously collapsed placeholder immediately. The final cluster
        # rebuild remains a consistency pass, not the only chance to restore
        # the asset if the stage exits early afterward.
        payload = apply_site_quality(payload, previous=document)
        collection.update_one(
            {"_id": document["_id"]},
            {"$set": payload, "$addToSet": {"sources": "browser_runtime"}},
        )
        document_key = str(document.get("_id") or origin)
        if browser_title and document_key not in self._browser_title_sites:
            self._browser_title_sites.add(document_key)
            self.browser_title_enriched_site_count += 1
        if final_title and document_key not in self._browser_final_title_sites:
            self._browser_final_title_sites.add(document_key)
            self.browser_final_title_site_count += 1
        if browser_spa_detected and document_key not in self._browser_spa_sites:
            self._browser_spa_sites.add(document_key)
            self.browser_spa_site_count += 1
        return True

    def _update_progress(self, current_target=""):
        try:
            self.base_update_task.update_stage_progress(self.stage_name, {
                "input_count": len(self.targets),
                "output_count": self._effective_output_count(),
                "completed_targets": self._completed_operation_count(),
                "total_targets": self._planned_operation_count(),
                "failed_targets": self.failed_targets,
                "current_phase": self.current_phase,
                "title_probe_completed_count": len(
                    self.title_probe_completed_targets),
                "title_probe_failed_count": len(self.title_probe_failed_targets),
                "title_probe_skipped_count": self.title_probe_skipped_count,
                "artifact_completed_count": len(self.artifact_completed_targets),
                "artifact_failed_count": len(self.artifact_failed_targets),
                "artifact_skipped_count": self.artifact_skipped_count,
                "script_url_count": len(self.discovered_scripts),
                "js_downloaded_count": self.js_downloaded_count,
                "js_failed_count": self.js_failed_count,
                "map_downloaded_count": self.map_downloaded_count,
                "source_recovered_count": self.source_recovered_count,
                "mapping_file_count": self.mapping_file_count,
                "seed_map_url_count": len(self.seed_map_urls),
                "browser_title_observation_count": self.browser_title_observation_count,
                "browser_title_enriched_site_count": self.browser_title_enriched_site_count,
                "browser_final_title_site_count": self.browser_final_title_site_count,
                "runtime_enriched_site_count": self._runtime_enriched_site_count(),
                "spa_profile_count": len(self.target_spa_profiles),
                "spa_profile_medium_high_count": sum(
                    1 for item in self.target_spa_profiles.values()
                    if str(item.get("confidence") or "") in {"medium", "high"}
                ),
                "browser_prefetch_count": self.browser_prefetch_count,
                "browser_prefetch_title_count": self.browser_prefetch_title_count,
                "browser_prefetch_failed_count": self.browser_prefetch_failed_count,
                "browser_prefetch_skipped_count": self.browser_prefetch_skipped_count,
                "artifact_target_count": len(self.artifact_targets),
                "title_probe_target_count": len(self.targets),
                "title_only_target_count": max(
                    len(self.targets) - len(self.artifact_targets), 0),
                "bytes_written": self.total_bytes,
                "current_target": current_target,
            })
        except Exception as exc:
            logger.warning("runtime artifact progress failed task_id:{} error:{}".format(
                self.task_id, exc))

    def _remember_script(self, value, source, target, script_hint=False):
        normalized = self._normalize_urls([value])
        if not normalized:
            return False
        url = normalized[0]
        # Browser resource types and <script src> are stronger evidence than
        # filename extensions. Modern bundlers often serve executable chunks
        # from URLs such as /asset?id=123 or /chunk?hash=... . The response is
        # still content-validated before it is written to disk.
        if not script_hint and not is_script_url(url):
            return False
        is_new = url not in self.discovered_scripts
        if is_new:
            self.discovered_scripts[url] = time.time()
        if source:
            source = str(source)
            source_is_new = source not in self.script_sources[url]
            self.script_sources[url].add(source)
            if source_is_new:
                if source.startswith("browser."):
                    self.browser_script_urls.add(url)
                elif source == "document.scripts":
                    self.dom_script_urls.add(url)
                elif source == "performance.resource":
                    self.performance_script_urls.add(url)
                elif source == "document.modulepreload":
                    self.module_preload_script_urls.add(url)
                elif source == "javascript.chunk_reference":
                    self.derived_script_urls.add(url)
        if target:
            self.script_targets[url].add(str(target))
        return is_new

    def _record_runtime_requests(self, base_url, values, target=None):
        target = str(target or base_url or "")
        records = []
        max_requests = max(int(getattr(
            Config, "RUNTIME_ARTIFACT_MAX_RUNTIME_REQUESTS", 5000) or 0), 0)
        for item in values or []:
            if max_requests and self.runtime_request_count + len(records) >= max_requests:
                break
            if not isinstance(item, dict):
                continue
            raw_url = str(item.get("url") or "").strip()
            absolute = urljoin(base_url, raw_url)
            normalized = self._normalize_urls([absolute])
            if not normalized:
                continue
            key = (
                str(item.get("kind") or "runtime"),
                str(item.get("method") or "GET").upper()[:16],
                normalized[0],
            )
            if key in self.runtime_request_keys:
                continue
            self.runtime_request_keys.add(key)
            try:
                body_length = int(item.get("body_length", 0) or 0)
            except (TypeError, ValueError):
                body_length = 0
            records.append({
                "kind": str(item.get("kind") or "runtime"),
                "method": str(item.get("method") or "GET").upper()[:16],
                "url": normalized[0],
                "body_length": max(body_length, 0),
                "target": target,
            })
        if not records:
            return
        path = os.path.join(self.output_root, "runtime_requests.jsonl")
        with open(path, "a", encoding="utf-8") as handle:
            for item in records:
                handle.write(json.dumps(item, ensure_ascii=True, sort_keys=True) + "\n")
        self.runtime_request_count += len(records)

    @staticmethod
    def _clean_string_list(values, limit=32):
        output = []
        seen = set()
        for value in values or []:
            value = str(value or "").strip()
            if not value or value in seen:
                continue
            seen.add(value)
            output.append(value[:128])
            if len(output) >= limit:
                break
        return output

    @classmethod
    def _normalize_spa_profile(cls, profile):
        if not isinstance(profile, dict):
            return {}
        try:
            score = max(min(int(profile.get("score") or 0), 100), 0)
        except (TypeError, ValueError):
            score = 0
        confidence = str(profile.get("confidence") or "").strip().lower()
        if confidence not in {"high", "medium", "low", "none"}:
            confidence = (
                "high" if score >= 80 else
                "medium" if score >= 55 else
                "low" if score >= 35 else "none"
            )
        frameworks = []
        for item in profile.get("frameworks") or []:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            if not name:
                continue
            try:
                item_confidence = max(min(int(item.get("confidence") or 0), 100), 0)
            except (TypeError, ValueError):
                item_confidence = 0
            frameworks.append({
                "name": name[:64],
                "source": str(item.get("source") or "").strip()[:128],
                "confidence": item_confidence,
            })
        frameworks.sort(key=lambda item: (-item.get("confidence", 0), item.get("name", "")))
        metrics = profile.get("metrics") if isinstance(profile.get("metrics"), dict) else {}
        clean_metrics = {}
        for key in (
                "scriptCount", "moduleScriptCount", "modulePreloadCount",
                "chunkScriptCount", "runtimeRequestCount", "routeCount",
                "sameOriginRouteCount", "hashRouteCount", "appRootCount",
                "bodyTextLength", "htmlLength", "nodeCount"):
            try:
                clean_metrics[key] = max(int(metrics.get(key) or 0), 0)
            except (TypeError, ValueError):
                clean_metrics[key] = 0
        return {
            "score": score,
            "confidence": confidence,
            "framework": str(
                profile.get("framework") or
                (frameworks[0]["name"] if frameworks else "")
            ).strip()[:64],
            "frameworks": frameworks[:8],
            "technologies": cls._clean_string_list(profile.get("technologies"), 16),
            "render_mode": str(
                profile.get("renderMode") or profile.get("render_mode") or ""
            ).strip()[:64],
            "route_mode": str(
                profile.get("routeMode") or profile.get("route_mode") or ""
            ).strip()[:64],
            "reasons": cls._clean_string_list(profile.get("reasons"), 32),
            "metrics": clean_metrics,
            "page_url": str(
                profile.get("pageUrl") or profile.get("page_url") or ""
            ).strip()[:1024],
            "title": str(profile.get("title") or "").strip()[:512],
        }

    @classmethod
    def _merge_spa_profiles(cls, old_profile, new_profile):
        old_profile = cls._normalize_spa_profile(old_profile)
        new_profile = cls._normalize_spa_profile(new_profile)
        if not old_profile:
            return new_profile
        if not new_profile:
            return old_profile
        if old_profile.get("score", 0) >= new_profile.get("score", 0):
            base_source, other = old_profile, new_profile
        else:
            base_source, other = new_profile, old_profile
        base = dict(base_source)
        frameworks = []
        seen_frameworks = set()
        for item in list(base.get("frameworks") or []) + list(other.get("frameworks") or []):
            key = item.get("name")
            if not key or key in seen_frameworks:
                continue
            seen_frameworks.add(key)
            frameworks.append(item)
        technologies = cls._clean_string_list(
            list(base.get("technologies") or []) + list(other.get("technologies") or []), 24)
        reasons = cls._clean_string_list(
            list(base.get("reasons") or []) + list(other.get("reasons") or []), 40)
        metrics = dict(other.get("metrics") or {})
        for key, value in (base.get("metrics") or {}).items():
            try:
                metrics[key] = max(int(value or 0), int(metrics.get(key) or 0))
            except (TypeError, ValueError):
                metrics[key] = value
        base["frameworks"] = frameworks[:8]
        base["technologies"] = technologies
        base["reasons"] = reasons
        base["metrics"] = metrics
        if not base.get("framework") and frameworks:
            base["framework"] = frameworks[0]["name"]
        return base

    def _record_spa_profile(self, target, profile):
        profile = self._normalize_spa_profile(profile)
        if not target or not profile:
            return False
        merged = self._merge_spa_profiles(
            self.target_spa_profiles.get(target), profile)
        self.target_spa_profiles[target] = merged
        for value in merged.get("reasons") or []:
            self.target_spa_signals[target].add("profile_{}".format(value))
        for value in merged.get("technologies") or []:
            self.target_spa_signals[target].add(
                "technology_{}".format(str(value).lower()))
        if merged.get("framework"):
            self.target_spa_signals[target].add(
                "framework_{}".format(str(merged.get("framework")).lower()))
        return True

    def _target_spa_profile(self, target):
        return self._normalize_spa_profile(
            self.target_spa_profiles.get(target) or {})

    def _collect_page_resources(self, page, target):
        try:
            result = page.evaluate(PAGE_RESOURCE_SCRIPT) or {}
        except Exception as exc:
            self._add_warning("page resource collection failed {}: {}".format(target, exc))
            return [], 0
        new_count = 0
        for value in result.get("scripts", []) or []:
            if self._remember_script(
                    value, "document.scripts", target, script_hint=True):
                new_count += 1
        for value in result.get("resources", []) or []:
            if self._remember_script(
                    value, "performance.resource", target, script_hint=True):
                new_count += 1
        for value in result.get("modulePreloads", []) or []:
            if self._remember_script(
                    value, "document.modulepreload", target, script_hint=True):
                new_count += 1
        self._record_page_observation(
            target,
            result.get("pageUrl") or target,
            title=result.get("pageTitle") or "",
            source="browser.dom",
        )
        self._record_runtime_requests(
            result.get("pageUrl") or target,
            result.get("runtime", []),
            target=target,
        )
        for value in result.get("spaSignals", []) or []:
            value = str(value or "").strip().lower()
            if value:
                self.target_spa_signals[target].add(value)
        self._record_spa_profile(target, result.get("spaProfile") or {})
        return result.get("routes", []) or [], new_count

    def _target_script_count(self, target):
        return sum(
            1 for values in self.script_targets.values()
            if target in values
        )

    def _target_reason_set(self, target):
        return self.target_reasons.get(self._origin(target), set())

    def _target_has_spa_hint(self, target):
        return bool(
            self._target_reason_set(target).intersection(SPA_SELECTION_REASONS) or
            self.target_spa_signals.get(target) or
            self._target_spa_profile(target).get("score", 0) >= 45 or
            self._target_script_count(target) >= 2
        )

    def _target_needs_initial_prefetch(self, target):
        return bool(
            self._target_reason_set(target).intersection(
                INITIAL_DOCUMENT_PREFETCH_REASONS)
        )

    def _settle_browser_title(self, page, target, wait_ms, timeout_ms, title_only):
        """Collect a hydrated title without imposing a fixed delay on every page."""
        wait_ms = max(int(wait_ms or 0), 0)
        remaining = self._remaining_time()
        if remaining is not None:
            wait_ms = min(wait_ms, max(int(remaining * 1000), 0))
        if wait_ms:
            page.wait_for_timeout(wait_ms)
        self._collect_page_resources(page, target)
        extended = bool(
            self._target_reason_set(target).intersection(
                EXTENDED_TITLE_SETTLE_REASONS) or
            self._target_has_spa_hint(target)
        )
        hydration_sensitive = self._target_has_spa_hint(target)
        # Artifact targets normally continue into interaction rounds, but an
        # SPA with no clickable controls can finish those rounds immediately.
        # Keep the hydration window only for explicit SPA/SSO candidates.
        if not title_only and not extended:
            return

        max_settle_ms = min(max(int(timeout_ms or 0), 0), max(wait_ms, 4000))
        elapsed_ms = wait_ms
        last_title = self._meaningful_title(page.title())
        stable_samples = 0
        while elapsed_ms < max_settle_ms and not self._time_exhausted():
            extended = bool(
                self._target_reason_set(target).intersection(
                    EXTENDED_TITLE_SETTLE_REASONS) or
                self._target_has_spa_hint(target)
            )
            hydration_sensitive = self._target_has_spa_hint(target)
            if last_title and not extended:
                break
            remaining = self._remaining_time()
            remaining_ms = (
                max(int(remaining * 1000), 0)
                if remaining is not None else max_settle_ms - elapsed_ms
            )
            step_ms = min(400, max_settle_ms - elapsed_ms, remaining_ms)
            if step_ms <= 0:
                break
            page.wait_for_timeout(step_ms)
            elapsed_ms += step_ms
            self._collect_page_resources(page, target)
            current_title = self._meaningful_title(page.title())
            if current_title and current_title == last_title:
                stable_samples += 1
            else:
                stable_samples = 0
            last_title = current_title
            if (
                current_title and stable_samples >= 2 and
                (not hydration_sensitive or elapsed_ms >= 3200)
            ):
                break

    @staticmethod
    def _safe_route(route, current_url):
        try:
            parsed = urlsplit(urljoin(current_url, str(route or "")))
            current = urlsplit(current_url)
        except (TypeError, ValueError):
            return ""
        if parsed.scheme not in ("http", "https") or parsed.netloc != current.netloc:
            return ""
        value = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, parsed.fragment))
        if BLOCKED_INTERACTION_RE.search(value):
            return ""
        return value

    def _trigger_route(self, page, route):
        try:
            return bool(page.evaluate(
                """(route) => {
                  const target = new URL(route, location.href);
                  if (target.origin !== location.origin) return false;
                  if (target.hash && target.pathname === location.pathname && target.search === location.search) {
                    location.hash = target.hash;
                    window.dispatchEvent(new HashChangeEvent('hashchange'));
                  } else {
                    history.pushState({}, '', target.pathname + target.search + target.hash);
                    window.dispatchEvent(new PopStateEvent('popstate', {state: history.state}));
                  }
                  return true;
                }""",
                route,
            ))
        except Exception:
            return False

    def _browser_collect_target(self, browser, target, title_only=False):
        browser_user_agent = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"
        )
        context = browser.new_context(
            ignore_https_errors=True,
            viewport={"width": 1440, "height": 900},
            user_agent=browser_user_agent,
        )
        page = None

        def on_browser_title(source, payload):
            try:
                if not isinstance(payload, dict) or page is None:
                    return
                frame = (source or {}).get("frame")
                if frame is None or frame != page.main_frame:
                    return
                kind = str(payload.get("kind") or "mutation").strip().lower()
                source_name = (
                    "browser.title_setter" if kind == "setter"
                    else "browser.title_mutation"
                )
                self._record_page_observation(
                    target,
                    payload.get("url") or frame.url or target,
                    title=payload.get("title") or "",
                    source=source_name,
                )
            except Exception:
                return

        context.expose_binding("__arlReportTitle", on_browser_title)
        context.add_init_script(RUNTIME_HOOK_SCRIPT)
        context.add_init_script(RUNTIME_TITLE_OBSERVER_SCRIPT)

        def on_request(request):
            try:
                if request.resource_type == "script" or is_script_url(request.url):
                    self._remember_script(
                        request.url,
                        "browser.network",
                        target,
                        script_hint=request.resource_type == "script",
                    )
            except Exception:
                return

        def on_response(response):
            try:
                request = response.request
                # A context-level response listener also sees iframe
                # documents. Only the main frame describes the navigated
                # source; scripts from child frames are still collected below.
                is_main_document = (
                    request.resource_type == "document" and
                    request.frame is not None and
                    request.frame == page.main_frame
                )
                if is_main_document:
                    headers = {
                        str(name or "").lower(): str(value or "")
                        for name, value in (response.headers or {}).items()
                    }
                    title = ""
                    content_type = headers.get("content-type", "").lower()
                    try:
                        content_length = int(headers.get("content-length", 0) or 0)
                    except (TypeError, ValueError):
                        content_length = 0
                    if (
                        "html" in content_type or "xhtml" in content_type or
                        300 <= int(response.status or 0) < 400
                    ) and (not content_length or content_length <= 2 * 1024 * 1024):
                        try:
                            title = self._title_from_body(
                                response.body(), content_type=content_type)
                        except Exception:
                            pass
                    self._record_page_observation(
                        target,
                        response.url,
                        title=title,
                        status=response.status,
                        location=headers.get("location", ""),
                        source="browser.document_response",
                    )
                if request.resource_type == "script" or is_script_url(response.url):
                    self.response_headers[response.url] = {
                        str(name or "").lower(): str(value or "")
                        for name, value in (response.headers or {}).items()
                    }
                    self._remember_script(
                        response.url,
                        "browser.response",
                        target,
                        script_hint=request.resource_type == "script",
                    )
            except Exception:
                return

        def on_request_finished(request):
            # A synchronous location/SSO redirect can invalidate the response
            # body while the response event is still being delivered. The
            # finished event is the reliable last chance to read the completed
            # source HTML and recover its title.
            try:
                if request.resource_type != "document":
                    return
                frame = request.frame
                if frame is None or frame != page.main_frame:
                    return
                response = request.response()
                if response is None:
                    return
                headers = {
                    str(name or "").lower(): str(value or "")
                    for name, value in (response.headers or {}).items()
                }
                content_type = headers.get("content-type", "").lower()
                try:
                    content_length = int(headers.get("content-length", 0) or 0)
                except (TypeError, ValueError):
                    content_length = 0
                if (
                    ("html" not in content_type and "xhtml" not in content_type) or
                    (content_length and content_length > 2 * 1024 * 1024)
                ):
                    return
                title = self._title_from_body(
                    response.body(), content_type=content_type)
                if not title:
                    return
                self._record_page_observation(
                    target,
                    response.url,
                    title=title,
                    status=response.status,
                    location=headers.get("location", ""),
                    source="browser.document_finished",
                )
            except Exception:
                return

        context.on("request", on_request)
        context.on("response", on_response)
        page = context.new_page()
        page.on("requestfinished", on_request_finished)
        target_runtime_before = self.runtime_request_count

        def on_dom_content_loaded():
            try:
                self._record_page_observation(
                    target, page.url or target, title=page.title(),
                    source="browser.domcontentloaded",
                )
            except Exception:
                pass

        page.on("domcontentloaded", on_dom_content_loaded)
        timeout_name = (
            "RUNTIME_TITLE_PROBE_TARGET_TIMEOUT" if title_only
            else "RUNTIME_ARTIFACT_TARGET_TIMEOUT"
        )
        timeout_default = 10 if title_only else 35
        timeout_ms = max(int(getattr(
            Config, timeout_name, timeout_default) or 5), 5) * 1000
        remaining = self._remaining_time()
        if remaining is not None:
            timeout_ms = min(timeout_ms, max(int(remaining * 1000), 1))
        if (
            self._target_needs_initial_prefetch(target) and
            (title_only or target not in self.title_probe_completed_targets)
        ):
            self._prefetch_initial_document_title(
                target, timeout_ms=timeout_ms, user_agent=browser_user_agent)
        else:
            self.browser_prefetch_skipped_count += 1
        remaining = self._remaining_time()
        if remaining is not None:
            timeout_ms = min(timeout_ms, max(int(remaining * 1000), 1))
        page.set_default_timeout(min(timeout_ms, 10000))
        navigation_ok = False
        try:
            page.goto(target, wait_until="domcontentloaded", timeout=timeout_ms)
            navigation_ok = True
            self._record_page_observation(
                target, page.url or target, title=page.title(),
                source="browser.goto",
            )
        except Exception as exc:
            self._add_warning("browser navigation failed {}: {}".format(target, exc))

        if navigation_ok:
            wait_ms = max(int(getattr(
                Config, "RUNTIME_TITLE_PROBE_WAIT_MS", 1800) or 0), 0)
            try:
                self._settle_browser_title(
                    page, target, wait_ms, timeout_ms,
                    title_only=title_only,
                )
            except Exception as exc:
                self._add_warning(
                    "browser title settle failed {}: {}".format(target, exc))

        stable_rounds = max(int(getattr(
            Config, "RUNTIME_ARTIFACT_STABLE_ROUNDS", 2) or 1), 1)
        max_rounds = max(int(getattr(
            Config, "RUNTIME_ARTIFACT_MAX_ROUNDS", 4) or 1), 1)
        interaction_limit = max(int(getattr(
            Config, "RUNTIME_ARTIFACT_INTERACTION_LIMIT", 12) or 0), 0)
        route_limit = max(int(getattr(
            Config, "RUNTIME_ARTIFACT_ROUTE_LIMIT", 6) or 0), 0)
        stable = 0
        routes = []
        visited_routes = set()
        target_interactions = 0
        target_route_triggers = 0
        if navigation_ok and not title_only:
            for _ in range(max_rounds):
                if self._stopped() or self._time_exhausted():
                    break
                before = len(self.discovered_scripts)
                found_routes, _ = self._collect_page_resources(page, target)
                for value in found_routes:
                    safe = self._safe_route(value, page.url or target)
                    if safe and safe not in visited_routes and safe not in routes:
                        routes.append(safe)
                try:
                    page.evaluate("window.scrollTo(0, document.body ? document.body.scrollHeight : 0)")
                    page.wait_for_timeout(500)
                except Exception:
                    pass

                clicks_this_round = 0
                while (
                    target_interactions < interaction_limit and
                    clicks_this_round < 3 and
                    not self._time_exhausted()
                ):
                    try:
                        click_result = page.evaluate(SAFE_CLICK_SCRIPT) or {}
                        if not click_result.get("clicked"):
                            break
                        target_interactions += 1
                        clicks_this_round += 1
                        self.interaction_count += 1
                        page.wait_for_timeout(700)
                        self._collect_page_resources(page, target)
                    except Exception as exc:
                        self._add_warning("safe interaction failed {}: {}".format(target, exc))
                        break

                while routes and target_route_triggers < route_limit:
                    route = routes.pop(0)
                    if route in visited_routes:
                        continue
                    visited_routes.add(route)
                    if self._trigger_route(page, route):
                        target_route_triggers += 1
                        self.route_trigger_count += 1
                        try:
                            page.wait_for_timeout(900)
                        except Exception:
                            pass
                        self._collect_page_resources(page, target)
                    break

                if len(self.discovered_scripts) == before:
                    stable += 1
                else:
                    stable = 0
                if stable >= stable_rounds:
                    break

        cookies = []
        user_agent = ""
        try:
            cookies = context.cookies()
            user_agent = page.evaluate("navigator.userAgent") or ""
        except Exception:
            pass
        target_script_after = sum(
            1 for values in self.script_targets.values() if target in values)
        runtime_request_count = max(
            self.runtime_request_count - target_runtime_before, 0)
        final_url = str(page.url or target).strip()
        context.close()
        return {
            "navigation_ok": navigation_ok,
            "cookies": cookies,
            "user_agent": user_agent,
            # Seed scripts may already be known before the browser opens;
            # return the target total so SPA detection remains reliable.
            "script_count": max(target_script_after, 0),
            "runtime_request_count": runtime_request_count,
            "final_url": final_url,
            "spa_signals": sorted(self.target_spa_signals.get(target, set())),
            "title_only": bool(title_only),
        }

    @staticmethod
    def _session(cookies, user_agent):
        session = requests.Session()
        session.verify = False
        session.headers.update({
            "Accept": "*/*",
            "User-Agent": user_agent or "Mozilla/5.0 Chrome/151 Safari/537.36",
        })
        for item in cookies or []:
            try:
                session.cookies.set(
                    item.get("name"), item.get("value"),
                    domain=item.get("domain"), path=item.get("path") or "/",
                )
            except (KeyError, TypeError, ValueError):
                continue
        return session

    def _fallback_html_scripts(self, target, session):
        timeout = max(int(getattr(
            Config, "RUNTIME_ARTIFACT_REQUEST_TIMEOUT", 15) or 1), 1)
        remaining = self._remaining_time()
        if remaining is not None:
            if remaining <= 0:
                return 0
            timeout = min(timeout, max(remaining, 1))
        try:
            response = session.get(
                target, timeout=(min(timeout, 5), timeout),
                allow_redirects=not self._target_needs_initial_prefetch(target),
                headers={"Referer": target},
            )
            if response.status_code >= 400:
                return 0
            body = response.content[:2 * 1024 * 1024]
            parser = _ScriptHTMLParser()
            parser.feed(body.decode(response.encoding or "utf-8", errors="replace"))
        except (requests.RequestException, OSError, UnicodeError):
            return 0
        count = 0
        for source in parser.sources:
            if self._remember_script(
                    urljoin(response.url, source), "html.fallback", target,
                    script_hint=True):
                count += 1
        if count:
            self.fallback_html_count += 1
        return count

    def _budget_available(self, target, incoming=0):
        max_files = max(int(getattr(
            Config, "RUNTIME_ARTIFACT_MAX_FILES", 2400) or 0), 0)
        max_target_files = max(int(getattr(
            Config, "RUNTIME_ARTIFACT_MAX_TARGET_FILES", 300) or 0), 0)
        max_task_bytes = max(int(getattr(
            Config, "RUNTIME_ARTIFACT_MAX_TASK_BYTES", 536870912) or 0), 0)
        max_target_bytes = max(int(getattr(
            Config, "RUNTIME_ARTIFACT_MAX_TARGET_BYTES", 67108864) or 0), 0)
        min_free_bytes = max(int(getattr(
            Config, "RUNTIME_ARTIFACT_MIN_FREE_BYTES", 5368709120) or 0), 0)
        if max_target_files and self.target_files[target] >= max_target_files:
            self._add_warning(
                "runtime artifact target file limit reached: {}".format(target))
            return False
        if max_files and self.saved_file_count >= max_files:
            self._add_warning("runtime artifact file limit reached")
            return False
        if max_task_bytes and self.total_bytes + incoming > max_task_bytes:
            self._add_warning("runtime artifact task byte limit reached")
            return False
        if max_target_bytes and self.target_bytes[target] + incoming > max_target_bytes:
            self._add_warning("runtime artifact target byte limit reached: {}".format(target))
            return False
        try:
            if min_free_bytes and shutil.disk_usage(self.output_root).free - incoming < min_free_bytes:
                self._add_warning("runtime artifact stopped to preserve free disk space")
                return False
        except OSError as exc:
            self._add_warning("runtime artifact disk check failed: {}".format(exc))
            return False
        return True

    def _fetch_bytes(self, url, session, target, max_bytes, referer=""):
        timeout = max(int(getattr(
            Config, "RUNTIME_ARTIFACT_REQUEST_TIMEOUT", 15) or 1), 1)
        remaining = self._remaining_time()
        if remaining is not None:
            if remaining <= 0:
                return None, url, {}, "deadline_exhausted"
            timeout = min(timeout, max(remaining, 1))
        headers = {"Referer": referer or target}
        try:
            with session.get(
                url, stream=True, timeout=(min(timeout, 5), timeout),
                allow_redirects=True, headers=headers,
            ) as response:
                if response.status_code != 200:
                    return None, response.url, dict(response.headers), "status_{}".format(response.status_code)
                try:
                    content_length = int(response.headers.get("content-length", 0) or 0)
                except (TypeError, ValueError):
                    content_length = 0
                if content_length and content_length > max_bytes:
                    return None, response.url, dict(response.headers), "content_length_limit"
                if not self._budget_available(target, content_length):
                    return None, response.url, dict(response.headers), "budget_limit"
                chunks = []
                size = 0
                for chunk in response.iter_content(chunk_size=65536):
                    if self._time_exhausted():
                        return None, response.url, dict(response.headers), "deadline_exhausted"
                    if not chunk:
                        continue
                    size += len(chunk)
                    if size > max_bytes or not self._budget_available(target, size):
                        return None, response.url, dict(response.headers), "stream_size_limit"
                    chunks.append(chunk)
                return b"".join(chunks), response.url, dict(response.headers), ""
        except requests.RequestException as exc:
            return None, url, {}, "request_error:{}".format(exc)

    def _artifact_path(self, kind, url, suffix=""):
        parsed = urlsplit(url)
        host = SAFE_COMPONENT_RE.sub("_", parsed.netloc).strip("._") or "unknown-host"
        basename = SAFE_COMPONENT_RE.sub("_", os.path.basename(parsed.path)).strip("._")
        if not basename:
            basename = kind
        if suffix and not basename.lower().endswith(suffix.lower()):
            basename += suffix
        url_hash = hashlib.sha256(url.encode("utf-8", errors="ignore")).hexdigest()[:16]
        return os.path.join(self.output_root, kind, host, "{}-{}".format(url_hash, basename[:160]))

    def _save_bytes(self, kind, url, body, target, suffix="", extra=None):
        sha256 = hashlib.sha256(body).hexdigest()
        duplicate_path = self.downloaded_hashes.get(sha256)
        if duplicate_path:
            record = {
                "kind": kind,
                "status": "saved",
                "url": url,
                "path": duplicate_path,
                "size": 0,
                "sha256": sha256,
                "duplicate": True,
                "target": target,
            }
            record.update(extra or {})
            self._append_manifest(record)
            self.downloaded_urls.add(url)
            return record
        if not self._budget_available(target, len(body)):
            return None

        path = self._artifact_path(kind, url, suffix=suffix)
        os.makedirs(os.path.dirname(path), mode=0o750, exist_ok=True)
        fd, temp_path = tempfile.mkstemp(prefix=".partial-", dir=os.path.dirname(path))
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, path)
        finally:
            try:
                os.remove(temp_path)
            except OSError:
                pass
        relative_path = os.path.relpath(path, self.output_root)
        self.downloaded_hashes[sha256] = relative_path
        self.downloaded_urls.add(url)
        self.total_bytes += len(body)
        self.target_bytes[target] += len(body)
        self.target_files[target] += 1
        self.saved_file_count += 1
        record = {
            "kind": kind,
            "status": "saved",
            "url": url,
            "path": relative_path,
            "size": len(body),
            "sha256": sha256,
            "duplicate": False,
            "target": target,
        }
        record.update(extra or {})
        self._append_manifest(record)
        return record

    @staticmethod
    def _valid_script_body(body, content_type):
        content_type = str(content_type or "").lower().split(";", 1)[0].strip()
        prefix = body[:512].lstrip().lower()
        if not body:
            return False
        if prefix.startswith((
                b"<!doctype html", b"<html", b"<head", b"<body",
                b"<?xml", b"<svg")):
            return False
        if (
            "html" in content_type or "xml" in content_type or
            "json" in content_type or content_type.startswith((
                "image/", "audio/", "video/", "font/",
            )) or content_type in {
                "application/pdf", "application/zip", "application/gzip",
                "application/x-gzip", "application/x-rar-compressed",
            }
        ):
            return False
        if b"\x00" in body[:4096]:
            return False
        if prefix.startswith((b"{", b"[")):
            try:
                json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                pass
            else:
                return False
        if (
            content_type in SCRIPT_CONTENT_TYPES or
            "javascript" in content_type or "ecmascript" in content_type
        ):
            return True
        # Some authenticated gateways and object stores use no type,
        # text/plain, or octet-stream for valid chunks. By this point obvious
        # HTML, JSON, XML, and binary payloads have already been excluded.
        return content_type in {
            "", "text/plain", "application/octet-stream",
        }

    def _discover_script_references(self, body, base_url, target):
        max_derived = max(int(getattr(
            Config, "RUNTIME_ARTIFACT_MAX_DERIVED_JS", 500) or 0), 0)
        added = 0
        remaining = (
            max(max_derived - len(self.derived_script_urls), 0)
            if max_derived else 0
        )
        if max_derived and remaining <= 0:
            return 0
        for url in derived_script_reference_urls(
            body, base_url, max_refs=remaining or max_derived):
            if max_derived and len(self.derived_script_urls) >= max_derived:
                break
            if self._remember_script(
                    url, "javascript.chunk_reference", target,
                    script_hint=True):
                added += 1
        return added

    @staticmethod
    def _source_map_candidates(js_url, body, headers):
        candidates = []
        tail = body[-512 * 1024:]
        for match in SOURCE_MAP_RE.findall(tail):
            value = match.decode("utf-8", errors="ignore").strip().strip("\"'")
            if value and value not in candidates:
                candidates.append(value)
        normalized_headers = {
            str(name or "").lower(): str(value or "").strip()
            for name, value in (headers or {}).items()
        }
        for name in SOURCE_MAP_HEADER_NAMES:
            value = normalized_headers.get(name, "")
            if value and value not in candidates:
                candidates.append(value)
        for fallback in source_map_fallback_urls(js_url):
            if fallback and fallback not in candidates:
                candidates.append(fallback)
        output = []
        for value in candidates:
            if value.startswith("data:application/json"):
                output.append(value)
                continue
            absolute = urljoin(js_url, value)
            try:
                parsed = urlsplit(absolute)
            except (TypeError, ValueError):
                continue
            if parsed.scheme in ("http", "https") and parsed.netloc:
                output.append(urlunsplit((
                    parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, "")))
        return list(dict.fromkeys(output))

    def _write_decoded_mappings(self, map_url, map_data, target):
        mappings = str(map_data.get("mappings") or "")
        if not mappings:
            return None
        max_segments = max(int(getattr(
            Config, "RUNTIME_ARTIFACT_MAX_MAPPING_SEGMENTS", 250000) or 0), 0)
        path = self._artifact_path("mappings", map_url, suffix=".jsonl.gz")
        os.makedirs(os.path.dirname(path), mode=0o750, exist_ok=True)
        fd, temp_path = tempfile.mkstemp(prefix=".partial-", dir=os.path.dirname(path))
        os.close(fd)
        count = 0
        try:
            with gzip.open(temp_path, "wt", encoding="utf-8") as handle:
                for item in iter_decoded_mappings(mappings, max_segments=max_segments):
                    handle.write(json.dumps(item, ensure_ascii=True, sort_keys=True) + "\n")
                    count += 1
            size = os.path.getsize(temp_path)
            if not self._budget_available(target, size):
                return None
            os.replace(temp_path, path)
        except (OSError, ValueError) as exc:
            self._add_warning("source map VLQ decode failed {}: {}".format(map_url, exc))
            return None
        finally:
            try:
                os.remove(temp_path)
            except OSError:
                pass
        relative_path = os.path.relpath(path, self.output_root)
        self.total_bytes += size
        self.target_bytes[target] += size
        self.target_files[target] += 1
        self.saved_file_count += 1
        self.mapping_file_count += 1
        self._append_manifest({
            "kind": "source_map_mappings",
            "status": "saved",
            "url": map_url + "#decoded-mappings",
            "path": relative_path,
            "size": size,
            "segment_count": count,
            "target": target,
        })
        return relative_path

    def _restore_sources(self, map_url, map_data, target):
        sources = map_data.get("sources") or []
        contents = map_data.get("sourcesContent")
        source_root = str(map_data.get("sourceRoot") or "")
        recovered = 0
        if isinstance(contents, list) and any(isinstance(value, str) for value in contents):
            map_key = hashlib.sha256(map_url.encode("utf-8", errors="ignore")).hexdigest()[:16]
            entries = []
            for index, content in enumerate(contents):
                if not isinstance(content, str):
                    continue
                logical_name = sources[index] if index < len(sources) else "source_{}".format(index)
                entries.append((index, str(logical_name), content))
            entries.sort(key=lambda item: source_recovery_priority(item[1], item[0]))
            max_sources = max(int(getattr(
                Config, "RUNTIME_ARTIFACT_MAX_SOURCE_FILES_PER_MAP", 120) or 0), 0)
            for index, logical_name, content in entries:
                if max_sources and recovered >= max_sources:
                    break
                relative_source = safe_source_path(
                    "/".join(value for value in (source_root, logical_name) if value),
                    index=index,
                )
                path = os.path.join(self.output_root, "sources", map_key, relative_source)
                if os.path.exists(path):
                    path = "{}.{}".format(path, index)
                body = content.encode("utf-8", errors="replace")
                sha256 = hashlib.sha256(body).hexdigest()
                duplicate_path = self.downloaded_hashes.get(sha256)
                if duplicate_path:
                    recovered += 1
                    self.source_recovered_count += 1
                    self._append_manifest({
                        "kind": "source_map_source",
                        "status": "saved",
                        "url": map_url + "#source-{}".format(index),
                        "path": duplicate_path,
                        "size": 0,
                        "sha256": sha256,
                        "duplicate": True,
                        "source": logical_name,
                        "target": target,
                    })
                    continue
                if not self._budget_available(target, len(body)):
                    break
                os.makedirs(os.path.dirname(path), mode=0o750, exist_ok=True)
                fd, temp_path = tempfile.mkstemp(prefix=".partial-", dir=os.path.dirname(path))
                try:
                    with os.fdopen(fd, "wb") as handle:
                        handle.write(body)
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.replace(temp_path, path)
                finally:
                    try:
                        os.remove(temp_path)
                    except OSError:
                        pass
                relative_path = os.path.relpath(path, self.output_root)
                self.downloaded_hashes[sha256] = relative_path
                self.total_bytes += len(body)
                self.target_bytes[target] += len(body)
                self.target_files[target] += 1
                self.saved_file_count += 1
                self.source_recovered_count += 1
                recovered += 1
                self._append_manifest({
                    "kind": "source_map_source",
                    "status": "saved",
                    "url": map_url + "#source-{}".format(index),
                    "path": relative_path,
                    "size": len(body),
                    "sha256": sha256,
                    "duplicate": False,
                    "source": logical_name,
                    "target": target,
                })
            return recovered
        self._write_decoded_mappings(map_url, map_data, target)
        return 0

    def _decode_inline_map(self, value):
        try:
            metadata, payload = value.split(",", 1)
        except ValueError:
            return None
        try:
            if ";base64" in metadata.lower():
                return base64.b64decode(payload, validate=True)
            return unquote(payload).encode("utf-8")
        except (ValueError, UnicodeError):
            return None

    @staticmethod
    def _parse_map_json(body):
        try:
            text = body.decode("utf-8-sig", errors="strict").strip()
        except (UnicodeError, AttributeError):
            return None
        if not text.startswith("{"):
            start = text.find("{")
            if start < 0:
                return None
            text = text[start:]
        try:
            value = json.loads(text)
        except (TypeError, ValueError):
            return None
        if not isinstance(value, dict) or not isinstance(value.get("sources", []), list):
            return None
        return value

    def _download_source_map(self, map_url, session, target, source_js_url=""):
        max_map_bytes = max(int(getattr(
            Config, "RUNTIME_ARTIFACT_MAX_MAP_BYTES", 8388608) or 0), 1)
        if (
            map_url in self.map_urls or
            self.map_attempts[map_url] >= 2 or
            self._stopped() or
            self._time_exhausted()
        ):
            return False
        self.map_attempts[map_url] += 1
        self.map_probe_count += 1
        if map_url.startswith("data:application/json"):
            map_body = self._decode_inline_map(map_url)
            if map_body is not None and len(map_body) > max_map_bytes:
                map_body = None
            final_url = (source_js_url or "inline-source-map") + "#inline-source-map"
            response_headers = {}
        else:
            map_body, final_url, response_headers, _error = self._fetch_bytes(
                map_url, session, target, max_map_bytes,
                referer=source_js_url or target)
        if map_body is None:
            self.map_failed_count += 1
            return False
        map_data = self._parse_map_json(map_body)
        if map_data is None:
            self.map_failed_count += 1
            return False
        record = self._save_bytes(
            "maps", final_url, map_body, target, suffix=".map",
            extra={
                "source_js_url": source_js_url,
                "direct_map_seed": not bool(source_js_url),
                "content_type": str(response_headers.get("content-type", "")),
            },
        )
        if not record:
            self.map_failed_count += 1
            return False
        self.map_urls.add(map_url)
        if final_url:
            self.map_urls.add(final_url)
        self.map_downloaded_count += 1
        try:
            self._restore_sources(final_url, map_data, target)
        except (OSError, TypeError, ValueError) as exc:
            self._add_warning("source map recovery failed {}: {}".format(
                final_url, exc))
        return True

    def _process_source_maps(self, js_url, body, headers, session, target):
        for map_url in self._source_map_candidates(js_url, body, headers):
            self.pending_map_targets[map_url].add(target)
            self.pending_map_sources.setdefault(map_url, js_url)

    def _download_script(self, url, session, target):
        if url in self.downloaded_urls:
            return False
        if self.download_attempts[url] >= 2:
            return False
        self.download_attempts[url] += 1
        max_js_bytes = max(int(getattr(
            Config, "RUNTIME_ARTIFACT_MAX_JS_BYTES", 8388608) or 0), 1)
        body, final_url, headers, error = self._fetch_bytes(
            url, session, target, max_js_bytes, referer=target)
        if body is None:
            self.js_failed_count += 1
            return False
        content_type = str(headers.get("content-type", ""))
        if not self._valid_script_body(body, content_type):
            self.js_failed_count += 1
            return False
        record = self._save_bytes(
            "js", url, body, target, suffix=".js",
            extra={
                "final_url": final_url,
                "content_type": content_type,
                "sources": sorted(self.script_sources.get(url, set())),
            },
        )
        if not record:
            self.js_failed_count += 1
            return False
        if record.get("duplicate"):
            self.js_duplicate_count += 1
        else:
            self.js_downloaded_count += 1
        self._discover_script_references(body, final_url, target)
        combined_headers = dict(self.response_headers.get(url, {}))
        combined_headers.update({
            str(name or "").lower(): str(value or "")
            for name, value in headers.items()
        })
        self._process_source_maps(final_url, body, combined_headers, session, target)
        return True

    def _download_target_scripts(self, target, session):
        max_rounds = max(int(getattr(
            Config, "RUNTIME_ARTIFACT_MAX_ROUNDS", 4) or 1), 1)
        for _ in range(max_rounds):
            if self._stopped() or self._time_exhausted():
                break
            pending = [
                url for url in self.discovered_scripts
                if target in self.script_targets.get(url, set()) and
                url not in self.downloaded_urls and self.download_attempts[url] < 2
            ]
            if not pending:
                break
            completed = 0
            for url in pending:
                if (
                    not self._budget_available(target) or
                    self._stopped() or
                    self._time_exhausted()
                ):
                    break
                completed += int(self._download_script(url, session, target))
            if not completed:
                break

    def _download_target_maps(self, target, session):
        pending = [
            url for url in self.seed_map_urls
            if target in self.map_seed_targets.get(url, set()) and
            url not in self.map_urls and self.map_attempts[url] < 2
        ]
        pending.extend(
            url for url, targets in self.pending_map_targets.items()
            if target in targets and
            url not in self.map_urls and self.map_attempts[url] < 2
        )
        for url in dict.fromkeys(pending):
            if (
                not self._budget_available(target) or
                self._stopped() or
                self._time_exhausted()
            ):
                break
            self._download_source_map(
                url, session, target,
                source_js_url=self.pending_map_sources.get(url, ""),
            )

    def _seed_target_scripts(self):
        if not self.targets:
            return
        for url in self.seed_js_urls:
            target = self.targets[0]
            try:
                script_host = urlsplit(url).hostname or ""
                for candidate in self.targets:
                    target_host = urlsplit(candidate).hostname or ""
                    if script_host == target_host:
                        target = candidate
                        break
            except (TypeError, ValueError):
                pass
            self._remember_script(url, "katana.seed", target, script_hint=True)

    def _seed_target_maps(self):
        if not self.targets:
            return
        for url in self.seed_map_urls:
            target = self.targets[0]
            try:
                map_host = urlsplit(url).hostname or ""
                for candidate in self.targets:
                    target_host = urlsplit(candidate).hostname or ""
                    if map_host == target_host:
                        target = candidate
                        break
            except (TypeError, ValueError):
                pass
            self.map_seed_targets[url].add(target)

    def _summary(self):
        summary = {
            "input_count": len(self.targets),
            "output_count": self._effective_output_count(),
            "target_count": len(self.targets),
            "completed_target_count": self.completed_targets,
            "failed_target_count": self.failed_targets,
            "planned_operation_count": self._planned_operation_count(),
            "completed_operation_count": self._completed_operation_count(),
            "title_probe_target_count": len(self.targets),
            "title_probe_completed_count": len(
                self.title_probe_completed_targets),
            "title_probe_failed_count": len(self.title_probe_failed_targets),
            "title_probe_skipped_count": self.title_probe_skipped_count,
            "artifact_completed_count": len(self.artifact_completed_targets),
            "artifact_failed_count": len(self.artifact_failed_targets),
            "artifact_skipped_count": self.artifact_skipped_count,
            "current_phase": self.current_phase,
            "script_url_count": len(self.discovered_scripts),
            "browser_script_count": len(self.browser_script_urls),
            "dom_script_count": len(self.dom_script_urls),
            "performance_script_count": len(self.performance_script_urls),
            "module_preload_script_count": len(self.module_preload_script_urls),
            "derived_script_count": len(self.derived_script_urls),
            "js_downloaded_count": self.js_downloaded_count,
            "js_duplicate_count": self.js_duplicate_count,
            "js_failed_count": self.js_failed_count,
            "map_probe_count": self.map_probe_count,
            "map_downloaded_count": self.map_downloaded_count,
            "map_failed_count": self.map_failed_count,
            "seed_map_url_count": len(self.seed_map_urls),
            "source_recovered_count": self.source_recovered_count,
            "mapping_file_count": self.mapping_file_count,
            "runtime_request_count": self.runtime_request_count,
            "browser_title_observation_count": self.browser_title_observation_count,
            "browser_title_enriched_site_count": self.browser_title_enriched_site_count,
            "browser_final_title_site_count": self.browser_final_title_site_count,
            "browser_spa_site_count": self.browser_spa_site_count,
            "spa_profile_count": len(self.target_spa_profiles),
            "spa_profile_medium_high_count": sum(
                1 for item in self.target_spa_profiles.values()
                if str(item.get("confidence") or "") in {"medium", "high"}
            ),
            "runtime_enriched_site_count": self._runtime_enriched_site_count(),
            "browser_prefetch_count": self.browser_prefetch_count,
            "browser_prefetch_title_count": self.browser_prefetch_title_count,
            "browser_prefetch_failed_count": self.browser_prefetch_failed_count,
            "browser_prefetch_skipped_count": self.browser_prefetch_skipped_count,
            "browser_navigation_mode": "native_with_sidecar_prefetch",
            "artifact_target_count": len(self.artifact_targets),
            "title_only_target_count": max(
                len(self.targets) - len(self.artifact_targets), 0),
            "execution_strategy": "title_probe_all_then_artifact",
            "available_memory_bytes": self.available_memory_bytes,
            "memory_guard_triggered": self.memory_guard_triggered,
            "quality_cluster_count": int(
                self.quality_cluster_summary.get("cluster_count", 0) or 0),
            "quality_collapsed_count": int(
                self.quality_cluster_summary.get("collapsed_count", 0) or 0),
            "interaction_count": self.interaction_count,
            "route_trigger_count": self.route_trigger_count,
            "fallback_html_count": self.fallback_html_count,
            "saved_file_count": self.saved_file_count,
            "bytes_written": self.total_bytes,
            "artifact_root": self.output_root,
            "elapsed_seconds": round(time.monotonic() - self.started_at, 2),
            "warnings": self.warnings[:20],
            "warning_count": len(self.warnings),
            "matching_pipeline_unchanged": True,
        }
        if self.warnings or self.failed_targets:
            summary.update({
                "_stage_status": "done_with_warnings",
                "completion_state": "done_with_warnings",
                "warning": "; ".join(self.warnings[:5]),
            })
        return summary

    def _write_summary(self, summary):
        os.makedirs(self.output_root, mode=0o750, exist_ok=True)
        fd, temp_path = tempfile.mkstemp(prefix=".summary-", dir=self.output_root)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(summary, handle, ensure_ascii=True, indent=2, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, self.summary_path)
        finally:
            try:
                os.remove(temp_path)
            except OSError:
                pass
        return summary

    def _close_browser_contexts(self, browser):
        for context in list(getattr(browser, "contexts", []) or []):
            try:
                context.close()
            except Exception:
                pass

    def _run_browser_phase(self, browser, targets, title_only):
        phase = "title_probe" if title_only else "artifact"
        self.current_phase = phase
        phase_timeout = (
            self.title_probe_total_timeout if title_only
            else self.artifact_total_timeout
        )
        self._start_phase(phase, phase_timeout)
        attempted = set()
        for target in targets:
            if target in attempted:
                continue
            if self._stopped():
                break
            if self._time_exhausted():
                self._add_warning(
                    "runtime {} total timeout reached".format(phase))
                break
            attempted.add(target)
            self._update_progress(current_target=target)
            timeout_name = (
                "RUNTIME_TITLE_PROBE_TARGET_TIMEOUT" if title_only
                else "RUNTIME_ARTIFACT_TARGET_TIMEOUT"
            )
            timeout_default = 10 if title_only else 35
            target_timeout = max(int(getattr(
                Config, timeout_name, timeout_default) or 0), 0)
            self.current_target_deadline = (
                time.monotonic() + target_timeout if target_timeout else None
            )
            try:
                result = self._browser_collect_target(
                    browser, target, title_only=title_only)
                self._persist_browser_observation(target, result)
                if not result.get("navigation_ok"):
                    raise RuntimeError("navigation did not complete")
                if not title_only:
                    session = self._session(
                        result.get("cookies"), result.get("user_agent"))
                    try:
                        if result.get("script_count", 0) <= 0:
                            self._fallback_html_scripts(target, session)
                        self._download_target_scripts(target, session)
                        self._download_target_maps(target, session)
                    finally:
                        session.close()
                if title_only:
                    self.title_probe_completed_targets.add(target)
                else:
                    self.artifact_completed_targets.add(target)
                if (
                    self.current_target_deadline is not None and
                    time.monotonic() >= self.current_target_deadline
                ):
                    self._add_warning(
                        "runtime {} target timeout reached: {}".format(
                            phase, target))
            except Exception as exc:
                if title_only:
                    self.title_probe_failed_targets.add(target)
                else:
                    self.artifact_failed_targets.add(target)
                self._add_warning(
                    "runtime {} target failed {}: {}".format(
                        phase, target, exc))
                logger.warning(
                    "runtime {} target failed task_id:{} target:{} error:{}".format(
                        phase, self.task_id, target, exc))
                self._close_browser_contexts(browser)
            finally:
                self.current_target_deadline = None
                self._refresh_target_counts()
            self._update_progress(current_target=target)

        skipped = max(len(list(targets or [])) - len(attempted), 0)
        if title_only:
            self.title_probe_skipped_count += skipped
        else:
            self.artifact_skipped_count += skipped
        self._refresh_target_counts()
        self.current_target_deadline = None
        self.deadline = None
        self._update_progress()

    def run(self):
        self._prepare_output()
        self._seed_target_scripts()
        self._seed_target_maps()
        if not self.targets:
            return self._write_summary(self._summary())
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self._add_warning("playwright dependency is unavailable")
            self.title_probe_skipped_count = len(self.targets)
            self.artifact_skipped_count = len(self.artifact_targets)
            return self._write_summary(self._summary())

        chrome_path = str(getattr(Config, "KATANA_CHROME_PATH", "") or "").strip()
        if not chrome_path or not os.path.isfile(chrome_path):
            self._add_warning("configured Chromium is unavailable")
            self.title_probe_skipped_count = len(self.targets)
            self.artifact_skipped_count = len(self.artifact_targets)
            return self._write_summary(self._summary())

        self.available_memory_bytes = available_memory_bytes()
        min_available_memory = max(int(getattr(
            Config, "RUNTIME_ARTIFACT_MIN_AVAILABLE_MEMORY", 536870912) or 0), 0)
        if (
            min_available_memory and
            self.available_memory_bytes and
            self.available_memory_bytes < min_available_memory
        ):
            self.memory_guard_triggered = True
            self._add_warning(
                "runtime artifact skipped by memory guard: available={} threshold={}".format(
                    self.available_memory_bytes, min_available_memory))
            self.title_probe_skipped_count = len(self.targets)
            self.artifact_skipped_count = len(self.artifact_targets)
            summary = self._summary()
            summary["skip_reason"] = "memory_guard"
            self._write_summary(summary)
            self._update_progress()
            return summary

        self._update_progress()
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(
                    executable_path=chrome_path,
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                        "--disable-extensions",
                        "--disable-background-networking",
                        "--disable-component-update",
                        "--renderer-process-limit=2",
                    ],
                )
                try:
                    # Every selected candidate receives the cheap title pass.
                    # JS/chunk/source-map retrieval is isolated to the smaller
                    # explicit artifact subset after that pass completes.
                    self._run_browser_phase(browser, self.targets, title_only=True)
                    if not self._stopped():
                        self._run_browser_phase(
                            browser, self.artifact_targets, title_only=False)
                    else:
                        self._mark_unattempted_as_skipped()
                finally:
                    browser.close()
        except Exception as exc:
            self._add_warning("runtime browser failed: {}".format(exc))
            logger.warning("runtime artifact browser failed task_id:{} error:{}".format(
                self.task_id, exc))
            self._mark_unattempted_as_skipped()

        self.current_phase = "complete"
        self.deadline = None
        self._refresh_target_counts()

        try:
            self.quality_cluster_summary = refresh_site_quality_clusters(
                self.task_id)
        except Exception as exc:
            self._add_warning("site quality cluster refresh failed: {}".format(exc))
        summary = self._summary()
        self._write_summary(summary)
        self._update_progress()
        return summary


def _runtime_checkpoint_id(task_id, stage_name, target):
    value = "{}\n{}\n{}".format(task_id, stage_name, target)
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def _runtime_checkpoint(task_id, stage_name, target):
    return utils.conn_db("runtime_artifact_checkpoint").find_one({
        "_id": _runtime_checkpoint_id(task_id, stage_name, target),
    })


def _write_json_atomic(path, value):
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o750, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=".json-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=True, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    finally:
        try:
            os.remove(temp_path)
        except OSError:
            pass


def _runtime_artifact_worker(payload_path, result_path):
    """Run one target in a fresh interpreter so native browser hangs are killable."""
    try:
        with open(payload_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        summary = RuntimeArtifactCollector(**payload).run()
        result = {"ok": True, "summary": summary}
    except BaseException as exc:
        logger.exception("isolated runtime artifact worker failed: {}".format(exc))
        result = {
            "ok": False,
            "error": "{}: {}".format(type(exc).__name__, exc)[:1000],
        }
    try:
        _write_json_atomic(result_path, result)
    except Exception as exc:
        logger.warning("isolated runtime result write failed path:{} error:{}".format(
            result_path, exc))


def _terminate_process_group(process, grace_seconds=3.0):
    if process is None or process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except OSError as exc:
        logger.warning("runtime process group terminate failed pid:{} error:{}".format(
            process.pid, exc))
        try:
            process.terminate()
        except OSError:
            pass
    try:
        process.wait(timeout=max(float(grace_seconds), 0.1))
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    except OSError as exc:
        logger.warning("runtime process group kill failed pid:{} error:{}".format(
            process.pid, exc))
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        logger.error("runtime process group did not exit pid:{}".format(process.pid))


def _run_isolated_runtime_target(payload, timeout_seconds, output_root):
    worker_root = os.path.join(output_root, ".workers")
    os.makedirs(worker_root, mode=0o750, exist_ok=True)
    payload_fd, payload_path = tempfile.mkstemp(
        prefix="payload-", suffix=".json", dir=worker_root)
    result_fd, result_path = tempfile.mkstemp(
        prefix="result-", suffix=".json", dir=worker_root)
    os.close(result_fd)
    try:
        with os.fdopen(payload_fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=True, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.remove(result_path)
        except OSError:
            pass

        project_root = os.path.abspath(os.path.join(
            os.path.dirname(__file__), os.pardir, os.pardir))
        process = subprocess.Popen(
            [
                sys.executable,
                "-m", "app.services.runtimeArtifact",
                "--isolated-worker", payload_path, result_path,
            ],
            cwd=project_root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )
        try:
            process.wait(timeout=max(float(timeout_seconds), 1.0))
        except subprocess.TimeoutExpired:
            _terminate_process_group(process)
            return {
                "ok": False,
                "timed_out": True,
                "error": "isolated target timeout after {}s".format(
                    int(timeout_seconds)),
            }

        if not os.path.isfile(result_path):
            return {
                "ok": False,
                "error": "isolated worker exited {} without a result".format(
                    process.returncode),
            }
        try:
            with open(result_path, "r", encoding="utf-8") as handle:
                result = json.load(handle)
        except (OSError, TypeError, ValueError) as exc:
            return {
                "ok": False,
                "error": "isolated result is invalid: {}".format(exc),
            }
        if process.returncode not in (0, None) and result.get("ok"):
            result["ok"] = False
            result["error"] = "isolated worker exited {}".format(
                process.returncode)
        return result
    finally:
        for path in (payload_path, result_path):
            try:
                os.remove(path)
            except OSError:
                pass


_ISOLATED_SUM_FIELDS = (
    "browser_title_observation_count",
    "browser_title_enriched_site_count",
    "browser_final_title_site_count",
    "browser_spa_site_count",
    "browser_prefetch_count",
    "browser_prefetch_title_count",
    "browser_prefetch_failed_count",
    "browser_prefetch_skipped_count",
    "interaction_count",
    "route_trigger_count",
    "fallback_html_count",
)

_ISOLATED_MAX_FIELDS = (
    "saved_file_count",
    "script_url_count",
    "browser_script_count",
    "dom_script_count",
    "performance_script_count",
    "module_preload_script_count",
    "derived_script_count",
    "js_downloaded_count",
    "js_duplicate_count",
    "js_failed_count",
    "map_probe_count",
    "map_downloaded_count",
    "map_failed_count",
    "source_recovered_count",
    "mapping_file_count",
    "runtime_request_count",
    "bytes_written",
)


def _aggregate_isolated_runtime_results(
    task_id, targets, artifact_targets, results, watchdog_seconds,
    elapsed_seconds, skipped_targets=0,
):
    target_results = list(results or [])
    summary = {
        "input_count": len(targets),
        "target_count": len(targets),
        "artifact_target_count": len(artifact_targets),
        "title_probe_target_count": len(targets),
        "title_only_target_count": max(len(targets) - len(artifact_targets), 0),
        "planned_operation_count": len(targets) + len(artifact_targets),
        "completed_operation_count": 0,
        "completed_target_count": 0,
        "failed_target_count": 0,
        "timed_out_target_count": 0,
        "resumed_target_count": 0,
        "isolated_target_count": 0,
        "skipped_target_count": max(int(skipped_targets or 0), 0),
        "execution_strategy": "isolated_per_target",
        "isolated_processes": True,
        "watchdog_seconds": watchdog_seconds,
        "elapsed_seconds": round(max(float(elapsed_seconds or 0), 0.0), 2),
        "artifact_root": os.path.join(
            str(getattr(Config, "RUNTIME_ARTIFACT_ROOT", "/opt/ARL/data/runtime_artifacts")),
            SAFE_COMPONENT_RE.sub("_", str(task_id or "")).strip("._") or "unknown-task",
        ),
        "matching_pipeline_unchanged": True,
    }
    warnings = []
    for item in target_results:
        item = dict(item or {})
        target = str(item.get("target") or "")
        child = dict(item.get("summary") or {})
        if item.get("resumed"):
            summary["resumed_target_count"] += 1
        else:
            summary["isolated_target_count"] += 1
        operation_count = 2 if item.get("artifact") else 1
        summary["completed_operation_count"] += operation_count
        if item.get("timed_out"):
            summary["timed_out_target_count"] += 1
            summary["failed_target_count"] += 1
        elif item.get("ok") and not child.get("failed_target_count"):
            summary["completed_target_count"] += 1
        else:
            summary["failed_target_count"] += 1

        for field in _ISOLATED_SUM_FIELDS:
            try:
                summary[field] = summary.get(field, 0) + max(
                    int(child.get(field, 0) or 0), 0)
            except (TypeError, ValueError):
                continue
        for field in _ISOLATED_MAX_FIELDS:
            try:
                summary[field] = max(
                    summary.get(field, 0), int(child.get(field, 0) or 0))
            except (TypeError, ValueError):
                continue

        error = str(item.get("error") or "").strip()
        child_warnings = list(child.get("warnings") or [])
        if child.get("warning"):
            child_warnings.append(child.get("warning"))
        if error:
            child_warnings.insert(0, error)
        for warning in child_warnings:
            warning = str(warning or "").strip()
            if not warning:
                continue
            value = "{}: {}".format(target, warning) if target else warning
            if value not in warnings:
                warnings.append(value[:500])

    planned = max(int(summary["planned_operation_count"] or 0), 0)
    completed = min(int(summary["completed_operation_count"] or 0), planned)
    summary["completed_operation_count"] = completed
    summary["completion_ratio"] = round(completed / planned, 4) if planned else 1.0
    runtime_enriched = sum(
        max(int(summary.get(field, 0) or 0), 0)
        for field in (
            "browser_title_enriched_site_count",
            "browser_final_title_site_count",
            "browser_spa_site_count",
        )
    )
    summary["runtime_enriched_site_count"] = runtime_enriched
    summary["output_count"] = max(
        int(summary.get("saved_file_count", 0) or 0), 0) + runtime_enriched
    summary["warnings"] = warnings[:20]
    summary["warning_count"] = len(warnings)
    if (
        warnings or summary["failed_target_count"] or
        summary["skipped_target_count"]
    ):
        summary.update({
            "_stage_status": "done_with_warnings",
            "completion_state": "done_with_warnings",
            "warning": "; ".join(warnings[:5]) or "runtime targets were incomplete",
        })
    return summary


def _update_isolated_progress(
    task_id, stage_name, total_operations, completed_operations,
    failed_targets, current_target, summary=None,
):
    fields = dict(summary or {})
    fields.update({
        "completed_targets": completed_operations,
        "total_targets": total_operations,
        "failed_targets": failed_targets,
        "current_target": current_target,
        "current_phase": "isolated_target",
        "execution_strategy": "isolated_per_target",
    })
    try:
        BaseUpdateTask(str(task_id or "")).update_stage_progress(
            stage_name, fields)
    except Exception as exc:
        logger.warning("isolated runtime progress failed task_id:{} error:{}".format(
            task_id, exc))


def runtime_artifact_collect(
    task_id, targets, seed_js_urls=None, seed_map_urls=None,
    target_reasons=None, artifact_targets=None,
    stage_name="runtime_artifact",
):
    template = RuntimeArtifactCollector(
        task_id=task_id,
        targets=list(targets or []),
        seed_js_urls=seed_js_urls,
        seed_map_urls=seed_map_urls,
        target_reasons=target_reasons,
        artifact_targets=list(artifact_targets or []),
        stage_name=stage_name,
    )
    targets = list(template.targets)
    artifact_targets = list(template.artifact_targets)
    artifact_set = set(artifact_targets)
    configured_watchdog = max(int(getattr(
        Config, "RUNTIME_ARTIFACT_WATCHDOG_TIMEOUT", 0) or 0), 0)
    if configured_watchdog:
        watchdog_seconds = configured_watchdog
    else:
        watchdog_seconds = max(
            template.title_probe_total_timeout +
            (template.artifact_total_timeout if artifact_targets else 0) + 90,
            120,
        )
    total_operations = len(targets) + len(artifact_targets)
    output_root = template.output_root
    started_at = time.monotonic()
    deadline = started_at + watchdog_seconds
    completed_operations = 0
    failed_targets = 0
    results = []
    skipped_targets = 0
    checkpoint_collection = utils.conn_db("runtime_artifact_checkpoint")
    max_attempts = max(int(getattr(
        Config, "RUNTIME_ARTIFACT_CHECKPOINT_MAX_ATTEMPTS", 2) or 1), 1)

    with acquire_resource_budget(
        "tool:runtime_artifact", task_id=task_id, stage=stage_name,
        max_concurrency=1,
    ):
        for index, target in enumerate(targets):
            if BaseUpdateTask(str(task_id or "")).is_terminal():
                skipped_targets = len(targets) - index
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                skipped_targets = len(targets) - index
                break

            is_artifact = target in artifact_set
            operation_count = 2 if is_artifact else 1
            checkpoint_id = _runtime_checkpoint_id(task_id, stage_name, target)
            checkpoint = _runtime_checkpoint(task_id, stage_name, target) or {}
            checkpoint_status = str(checkpoint.get("status") or "")
            attempt_count = max(int(checkpoint.get("attempt_count", 0) or 0), 0)
            if checkpoint_status in ("done", "done_with_warnings"):
                item = {
                    "target": target,
                    "artifact": is_artifact,
                    "ok": checkpoint_status == "done",
                    "resumed": True,
                    "summary": dict(checkpoint.get("summary") or {}),
                    "error": checkpoint.get("error", ""),
                }
                results.append(item)
                completed_operations += operation_count
                failed_targets += int(not item["ok"])
                _update_isolated_progress(
                    task_id, stage_name, total_operations,
                    completed_operations, failed_targets, target,
                )
                continue
            if checkpoint_status in ("timed_out", "error") and attempt_count >= max_attempts:
                item = {
                    "target": target,
                    "artifact": is_artifact,
                    "ok": False,
                    "resumed": True,
                    "timed_out": checkpoint_status == "timed_out",
                    "summary": dict(checkpoint.get("summary") or {}),
                    "error": checkpoint.get("error") or "retry limit reached",
                }
                results.append(item)
                completed_operations += operation_count
                failed_targets += 1
                _update_isolated_progress(
                    task_id, stage_name, total_operations,
                    completed_operations, failed_targets, target,
                )
                continue

            now = utils.curr_date()
            checkpoint_collection.update_one(
                {"_id": checkpoint_id},
                {
                    "$set": {
                        "task_id": str(task_id or ""),
                        "stage": stage_name,
                        "target": target,
                        "artifact": is_artifact,
                        "status": "running",
                        "started_at": now,
                        "updated_at": now,
                    },
                    "$inc": {"attempt_count": 1},
                },
                upsert=True,
            )
            _update_isolated_progress(
                task_id, stage_name, total_operations,
                completed_operations, failed_targets, target,
            )

            title_timeout = max(int(getattr(
                Config, "RUNTIME_TITLE_PROBE_TARGET_TIMEOUT", 10) or 0), 1)
            artifact_timeout = max(int(getattr(
                Config, "RUNTIME_ARTIFACT_TARGET_TIMEOUT", 35) or 0), 1)
            close_grace = max(int(getattr(
                Config, "RUNTIME_ARTIFACT_PROCESS_GRACE_TIMEOUT", 20) or 0), 5)
            target_timeout = title_timeout + close_grace
            if is_artifact:
                target_timeout += artifact_timeout
            target_timeout = max(min(target_timeout, remaining), 1)

            payload = {
                "task_id": str(task_id or ""),
                "targets": [target],
                "seed_js_urls": list(template.seed_js_urls),
                "seed_map_urls": list(template.seed_map_urls),
                "target_reasons": {
                    key: sorted(value)
                    for key, value in template.target_reasons.items()
                },
                "artifact_targets": [target] if is_artifact else [],
                "stage_name": stage_name,
            }
            item = _run_isolated_runtime_target(
                payload, target_timeout, output_root)
            item.update({"target": target, "artifact": is_artifact})
            results.append(item)
            completed_operations += operation_count
            if not item.get("ok"):
                failed_targets += 1

            child_summary = dict(item.get("summary") or {})
            if item.get("timed_out"):
                checkpoint_status = "timed_out"
            elif item.get("ok") and not child_summary.get("_stage_status"):
                checkpoint_status = "done"
            elif item.get("ok"):
                checkpoint_status = "done_with_warnings"
            else:
                checkpoint_status = "error"
            checkpoint_collection.update_one(
                {"_id": checkpoint_id},
                {"$set": {
                    "status": checkpoint_status,
                    "summary": child_summary,
                    "error": str(item.get("error") or "")[:1000],
                    "finished_at": utils.curr_date(),
                    "updated_at": utils.curr_date(),
                }},
            )
            _update_isolated_progress(
                task_id, stage_name, total_operations,
                completed_operations, failed_targets, target,
                summary={
                    "output_count": child_summary.get("output_count", 0),
                    "js_downloaded_count": child_summary.get(
                        "js_downloaded_count", 0),
                    "map_downloaded_count": child_summary.get(
                        "map_downloaded_count", 0),
                    "browser_title_enriched_site_count": child_summary.get(
                        "browser_title_enriched_site_count", 0),
                },
            )

    elapsed = time.monotonic() - started_at
    summary = _aggregate_isolated_runtime_results(
        task_id, targets, artifact_targets, results,
        watchdog_seconds, elapsed, skipped_targets=skipped_targets,
    )
    if skipped_targets:
        message = "runtime watchdog stopped {} unattempted targets".format(
            skipped_targets)
        warnings = list(summary.get("warnings") or [])
        if message not in warnings:
            warnings.insert(0, message)
        summary.update({
            "warnings": warnings[:20],
            "warning_count": len(warnings),
            "warning": "; ".join(warnings[:5]),
            "watchdog_timeout": True,
            "_stage_status": "done_with_warnings",
            "completion_state": "done_with_warnings",
        })
    _write_json_atomic(template.summary_path, summary)
    _update_isolated_progress(
        task_id, stage_name, total_operations,
        summary.get("completed_operation_count", 0),
        summary.get("failed_target_count", 0), "", summary=summary,
    )
    return summary


def _module_main(argv=None):
    argv = list(argv or sys.argv[1:])
    if len(argv) == 3 and argv[0] == "--isolated-worker":
        _runtime_artifact_worker(argv[1], argv[2])
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(_module_main())
