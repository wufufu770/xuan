from flask_restx import Resource, Namespace

from . import ARLResource
from app.utils import conn_db as conn, auth
from app.utils.site_scope import visible_site_query
from app.services.system_health import collect_health

ns = Namespace('stats', description="仪表盘统计聚合")


@ns.route('/summary/')
class StatsSummary(ARLResource):
    @auth
    def get(self):
        """仪表盘统计聚合：卡片计数 + 解析漏斗 + 指纹去重"""
        def count(collection, query=None):
            try:
                return conn(collection).count_documents(query or {})
            except Exception:
                return 0

        resolved_domains = count('domain', {"resolve_status": "resolved"})
        vulns = count('vulnerability') + count('nuclei_vul')
        try:
            tasks = conn('task').count_documents({})
            running_tasks = conn('task').count_documents({
                "status": {"$nin": ["done", "error", "stop"]}})
        except Exception:
            tasks = running_tasks = 0
        fingerprints = 0
        try:
            rows = list(conn('site').aggregate([
                {"$unwind": "$finger"},
                {"$group": {"_id": {"$ifNull": ["$finger.name", "$finger"]}}},
                {"$count": "n"},
            ], maxTimeMS=15000))
            fingerprints = int(rows[0]["n"]) if rows else 0
        except Exception:
            fingerprints = 0
        judged_sites = count('site', {"ai_state": "judged"})

        data = {
            "domains": count('domain'),
            "resolved_domains": resolved_domains,
            "ips": count('ip'),
            "sites": count('site', visible_site_query({})),
            "urls": count('fileleak'),
            "certs": count('cert'),
            "wih": count('wih'),
            "vulns": vulns,
            "tasks": tasks,
            "running_tasks": running_tasks,
            "fingerprints": fingerprints,
            "judged_sites": judged_sites,
            "health": collect_health(),
        }
        return {"code": 200, "message": "success", "data": data}
