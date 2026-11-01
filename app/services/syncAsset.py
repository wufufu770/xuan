import copy
import re
from pymongo.errors import DuplicateKeyError
from app.utils import conn_db as conn
from app import utils
from app.utils.site_quality import apply_site_quality, site_is_display_eligible
from app.utils.site_scope import formal_site_query
logger = utils.get_logger()


BROWSER_SITE_SCALAR_FIELDS = (
    "browser_title", "browser_title_source", "browser_final_title",
    "browser_final_url", "browser_enriched_at", "spa_confidence",
    "spa_framework", "spa_render_mode", "spa_route_mode",
    "spa_fingerprint_updated_at",
)
BROWSER_SITE_COUNT_FIELDS = (
    "runtime_script_count", "runtime_request_count", "spa_score",
)


class SyncAsset(object):
    def __init__(self, task_id, scope_id, update_flag=False,  category=None, task_name=""):
        self.available_category = ["site", "domain", "ip", "wih"]

        if category is None:
            self.category_list = self.available_category
        else:
            self.category_list = category

        self.task_id = task_id
        self.scope_id = scope_id
        self.task_name = task_name
        self.update_flag = update_flag

        self.new_asset_map = {
            "site": [],
            "domain": [],
            "ip": [],
            "task_name": task_name,
            "wih": []
        }

        self.new_asset_counter = {
            "site": 0,
            "domain": 0,
            "ip": 0,
            "wih": 0
        }
        self.max_record_asset_count = 10

    @staticmethod
    def _merge_list_values(old_value, new_value):
        values = []
        for raw in (old_value, new_value):
            if isinstance(raw, list):
                values.extend(raw)
            elif raw:
                values.append(raw)
        return list(dict.fromkeys(values))

    @staticmethod
    def _best_spa_profile(old_value, new_value):
        def score(value):
            if not isinstance(value, dict):
                return 0
            try:
                return int(value.get("score") or 0)
            except (TypeError, ValueError):
                return 0

        if score(new_value) >= score(old_value):
            return new_value if isinstance(new_value, dict) else old_value
        return old_value if isinstance(old_value, dict) else new_value

    def _update_existing_asset(self, collection, query, old, data, category):
        update_data = copy.deepcopy(data)
        for field in ("_id", "save_date", "scope_id", "tag"):
            update_data.pop(field, None)

        if category == "ip":
            update_data["domain"] = self._merge_list_values(
                old.get("domain"), update_data.get("domain"))

        merged_sources = self._merge_list_values(
            old.get("sources") or old.get("source"),
            update_data.get("sources") or update_data.get("source"),
        )
        if merged_sources:
            update_data["sources"] = merged_sources

        update_data["update_date"] = utils.curr_date_obj()
        collection.update_one(query, {"$set": update_data})

    def _update_existing_site_quality(self, collection, query, old, data):
        update_data = {}
        quality_data = apply_site_quality(copy.deepcopy(data), previous=old)
        for field in (
            "quality_state", "display_eligible", "pipeline_mode",
            "quality_reason", "quality_evidence", "quality_version",
            "asset_quality", "asset_visibility", "quality_score",
            "noise_reasons", "evidence_sources", "verification_status",
            "policy_version", "quality_cluster_key",
            "quality_cluster_size", "quality_cluster_representative",
        ):
            if field in quality_data:
                update_data[field] = quality_data[field]

        # A project may already contain this origin from an older task. Keep
        # the raw asset row stable, but merge newer browser evidence so HTTPX
        # title gaps, hydrated SPA titles, and SSO final-page titles are not
        # lost merely because the origin was seen before.
        for field in BROWSER_SITE_SCALAR_FIELDS:
            value = quality_data.get(field)
            if value not in (None, ""):
                update_data[field] = value
        for field in BROWSER_SITE_COUNT_FIELDS:
            try:
                incoming = int(quality_data.get(field) or 0)
            except (TypeError, ValueError):
                incoming = 0
            try:
                existing = int(old.get(field) or 0)
            except (TypeError, ValueError):
                existing = 0
            if incoming or existing:
                update_data[field] = max(incoming, existing)
        for field in (
            "browser_spa_detected", "browser_cross_origin_redirect",
        ):
            if quality_data.get(field) or old.get(field):
                update_data[field] = True

        spa_signals = self._merge_list_values(
            old.get("spa_signals"), quality_data.get("spa_signals"))
        if spa_signals:
            update_data["spa_signals"] = spa_signals

        spa_profile = self._best_spa_profile(
            old.get("spa_profile"), quality_data.get("spa_profile"))
        if spa_profile:
            update_data["spa_profile"] = spa_profile
            if spa_profile.get("framework"):
                update_data["spa_framework"] = spa_profile.get("framework")
            if spa_profile.get("confidence"):
                update_data["spa_confidence"] = spa_profile.get("confidence")
            if spa_profile.get("render_mode"):
                update_data["spa_render_mode"] = spa_profile.get("render_mode")
            if spa_profile.get("route_mode"):
                update_data["spa_route_mode"] = spa_profile.get("route_mode")

        chain = []
        chain_keys = set()
        for raw in (
            old.get("browser_title_chain"),
            quality_data.get("browser_title_chain"),
        ):
            values = raw if isinstance(raw, list) else [raw] if raw else []
            for observation in values:
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
                chain.append(observation)
        if chain:
            update_data["browser_title_chain"] = chain[-64:]

        browser_title = str(
            quality_data.get("browser_title") or "").strip()
        title_source = str(
            quality_data.get("title_source") or
            quality_data.get("browser_title_source") or ""
        ).strip()
        if browser_title and title_source.startswith("browser."):
            update_data["title"] = browser_title
            update_data["title_source"] = title_source
        update_data["update_date"] = utils.curr_date_obj()
        collection.update_one(query, {"$set": update_data})

    def site_in_asset_site(self, site: str) -> bool:
        """站点包含? 和 ; 非严格判断站点是否在资产组里面"""

        # "?" 和 ";"不在就返回False
        if "?" not in site and ";" not in site:
            return False

        site = site.split("?")[0]
        site = site.split(";")[0]

        query = {"scope_id": self.scope_id, "site": {"$regex": "^" + re.escape(site)}}
        item = conn("asset_site").find_one(query)
        if item is None:
            return False
        return True

    def sync_by_category(self, category):
        dist_collection = 'asset_{}'.format(category)
        source_query = {"task_id": self.task_id}
        if category == "site":
            # Keep the complete formal evidence set in project storage. The
            # project API applies the default visibility filter at read time.
            source_query = formal_site_query(source_query)
        for data in conn(category).find(source_query):
            data_content = data.get(category)
            query = {"scope_id": self.scope_id, category: data_content}

            if category == "wih":
                query = {"scope_id": self.scope_id, "fnv_hash": data["fnv_hash"]}
                data_content = data["fnv_hash"]

            del data["_id"]
            data["scope_id"] = self.scope_id
            if category == "site":
                apply_site_quality(data)

            # 如果site存在就先粗暴跳过
            if category == "site" and self.site_in_asset_site(data["site"]):
                continue

            old = conn(dist_collection).find_one(query)
            if old is None:
                data["save_date"] = utils.curr_date_obj()
                data["update_date"] = data["save_date"]
                logger.debug("sync {}, insert {}  {} -> {}".format(
                    category, data_content, self.task_id, self.scope_id))

                inserted = False
                try:
                    conn(dist_collection).insert_one(data)
                    inserted = True
                except DuplicateKeyError:
                    old = conn(dist_collection).find_one(query)

                user_visible = (
                    category != "site" or site_is_display_eligible(data))
                if inserted and category in self.new_asset_map and user_visible:
                    if self.new_asset_counter[category] < self.max_record_asset_count:
                        new_item = copy.deepcopy(data)
                        new_item.pop("_id", None)
                        self.new_asset_map[category].append(new_item)
                    self.new_asset_counter[category] += 1

            if old and category == "site" and not self.update_flag:
                self._update_existing_site_quality(
                    conn(dist_collection), query, old, data)

            if old and self.update_flag:
                if category == "site":
                    apply_site_quality(data, previous=old)
                logger.debug("sync {}, update {}  {} -> {}".format(
                    category, data_content, self.task_id, self.scope_id))
                self._update_existing_asset(
                    conn(dist_collection), query, old, data, category)

    def run(self):
        logger.info("start sync {} -> {}".format(self.task_id, self.scope_id))
        for category in self.category_list:
            if category not in self.available_category:
                logger.warning("not found {} category in {}".format(category, self.available_category))
                continue

            self.sync_by_category(category)

        logger.info("end sync {} -> {}, result: {}".format(self.task_id, self.scope_id, self.new_asset_counter))

        return self.new_asset_map, self.new_asset_counter


def sync_asset(task_id, scope_id, update_flag=False,  category=None, push_flag=False, task_name=""):
    sync = SyncAsset(task_id=task_id, scope_id=scope_id,
                     update_flag=update_flag, category=category, task_name=task_name)
    new_asset_map, new_asset_counter = sync.run()
    if 'ip' in new_asset_map:
        new_asset_map.pop('ip')

    if 'ip' in new_asset_counter:
        new_asset_counter.pop('ip')

    if push_flag:
        utils.message_push(asset_map=new_asset_map, asset_counter=new_asset_counter)
