"""检查历史 asset_domain 中凤鸟来源的遗留数据（默认仅报告）。

背景：fengniao 采集流程曾按 group_id 写 asset_domain，但该流程没有
task_id/scope_id，写入记录对资产域不可见，属死数据；现采集阶段不再写
asset_domain，域名落库统一由 attach_scope 写 domain 集合完成。

用法（部署机）：
    cd /opt/ARL && sudo -u root venv/bin/python scripts/migrate_fengniao_domains.py
    cd /opt/ARL && sudo -u root venv/bin/python scripts/migrate_fengniao_domains.py --archive
      --archive 将 source=fengniao 的遗留文档转移到 asset_domain_legacy_fengniao
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import utils  # noqa: E402

LEGACY_COLLECTION = "asset_domain_legacy_fengniao"


def main():
    archive = "--archive" in sys.argv
    legacy_query = {"source": "fengniao"}
    conn = utils.conn_db("asset_domain")
    total = conn.count_documents({})
    legacy_total = conn.count_documents(legacy_query)
    print("asset_domain 总数={}，凤鸟来源遗留={}".format(total, legacy_total))
    if not legacy_total:
        print("无需处理")
        return
    if not archive:
        print("如需转移这些死数据到 {} 请追加 --archive".format(LEGACY_COLLECTION))
        return
    legacy_conn = utils.conn_db(LEGACY_COLLECTION)
    moved = 0
    for doc in conn.find(legacy_query):
        doc["_moved_from"] = "asset_domain"
        legacy_conn.insert_one(doc)
        conn.delete_one({"_id": doc["_id"]})
        moved += 1
    print("已转移 {} 条到 {}".format(moved, LEGACY_COLLECTION))


if __name__ == "__main__":
    main()
