import time
import json
from app import utils
from app.config import Config
from app.modules import SiteAutoTag
from app.services.assetPolicy import is_transient_block_page
logger = utils.get_logger()


class AutoTag:
    # 影子资产关键词：测试环境/废弃系统/临时服务
    SHADOW_TITLE_KEYWORDS = [
        "test", "dev", "uat", "sit", "demo", "beta", "gray", "pre-prod",
        "sandbox", "staging", "内部", "测试", "开发", "演示", "预发",
        "灰度", "废弃", "临时", "旧版", "停用", "过期",
    ]

    def __init__(self, site_info):
        self.site_info = site_info
        self.status = self.site_info.get("status", 0)
        try:
            self.status = int(self.status)
        except (TypeError, ValueError):
            self.status = 0
        self.title = self.site_info.get("title", "")
        self.headers = self.site_info.get("headers", "")

    def run(self):
        body_length = self.site_info.get("body_length", 0)

        if is_transient_block_page(self.site_info):
            # Do not persist a stale entry/invalid verdict for retryable block
            # pages. The site remains visible and can be retried later.
            self.site_info["tag"] = []
            return

        if (
            getattr(Config, "RESTRICTED_HTTP_DISCOVERY", True) and
            self.status in (401, 403)
        ):
            self._set_entry_tag()
            self._apply_shadow_keyword_tag()
            return

        if self.is_invalid_title():
            self._set_invalid_tag()
            self._apply_shadow_keyword_tag()
            return

        if not self.title and "/html" in self.headers:
            if body_length >= 200 and self.status == 200:
                self._set_entry_tag()
                self._apply_shadow_keyword_tag()
                return

        if body_length <= 300:
            if not self.is_redirected() and not self.title:
                self._set_invalid_tag()
                self._apply_shadow_keyword_tag()
                return

        if body_length <= 1000:
            if self.is_40x() or self.is_50x():
                self._set_invalid_tag()
                self._apply_shadow_keyword_tag()
                return

        if self.is_redirected():
            if not self.is_out():
                self._set_invalid_tag()
                self._apply_shadow_keyword_tag()
                return

            if "Location: https://url.cn/sorry" in self.headers:
                self._set_invalid_tag()
                self._apply_shadow_keyword_tag()
                return

            header_split = self.headers.split("\n")
            for line in header_split:
                if "Location:" in line:
                    hostname = self.site_info.get("hostname")
                    if hostname and hostname in line:
                        return self._set_invalid_and_shadow()
                    else:
                        return self._set_entry_and_shadow()

            self._set_invalid_tag()
            self._apply_shadow_keyword_tag()
            return

        self._set_entry_tag()
        self._apply_shadow_keyword_tag()

    def is_shadow_asset(self):
        """标题或主机名命中测试/废弃/临时语义 → 影子资产。"""
        title = str(self.title or "").lower()
        hostname = str(self.site_info.get("hostname") or "").lower()
        for keyword in self.SHADOW_TITLE_KEYWORDS:
            lowered = keyword.lower()
            if lowered in title or lowered in hostname:
                return True
        return False

    def _apply_shadow_keyword_tag(self):
        if self.is_shadow_asset():
            tag = self.site_info.get("tag")
            tag_list = list(tag) if isinstance(tag, list) else []
            if "shadow" not in tag_list:
                tag_list.append("shadow")
            self.site_info["tag"] = tag_list

    def _set_entry_and_shadow(self):
        self._set_entry_tag()
        self._apply_shadow_keyword_tag()

    def _set_invalid_and_shadow(self):
        self._set_invalid_tag()
        self._apply_shadow_keyword_tag()

    def is_redirected(self):
        if self.status in [301, 302, 303]:
            return True
        else:
            return False

    def is_40x(self):
        if self.status in [401, 403, 404]:
            return True
        else:
            return False

    def is_50x(self):
        if self.status in [500, 501, 502, 503, 504]:
            return True
        else:
            return False

    def _set_entry_tag(self):
        """
        打标签为入口
        """
        self.site_info["tag"] = [SiteAutoTag.ENTRY]

    def _set_invalid_tag(self):
        """
        打标签为无效
        """
        self.site_info["tag"] = [SiteAutoTag.INVALID]

    def is_invalid_title(self):
        """
        判断是否是默认无效标题
        """
        invalid_title = ["Welcome to nginx", "IIS7", "Apache Tomcat"]
        invalid_title.extend(["Welcome to CentOS", "Apache HTTP Server Test Page"])
        invalid_title.extend(["Test Page for the Nginx HTTP"])
        invalid_title.extend(["500 Internal Server Error"])
        invalid_title.extend(["Error 404--Not Found"])
        invalid_title.extend(["Welcome to OpenResty"])
        invalid_title.extend(["没有找到站点", "404 not found"])
        invalid_title.extend(["页面不存在", "访问拦截", "403 Forbidden"])
        invalid_title.extend(["Page Not Found"])
        
        for t in invalid_title:
            if t in self.title:
                return True

        return False

    def is_out(self):
        out = ["Location: https://", "Location: http://", "Location: //"]
        for o in out:
            if o in self.headers:
                return True

        return False


def auto_tag(site_info):
    if isinstance(site_info, list):
        for info in site_info:
            a = AutoTag(info)
            a.run()
        return site_info

    if isinstance(site_info, dict):
        a = AutoTag(site_info)
        a.run()
        return site_info
