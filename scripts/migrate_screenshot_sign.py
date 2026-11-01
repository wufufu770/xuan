"""存量 site.screenshot 截图签名迁移（幂等）。

storage.py 新数据落库时已带 ?sign=<hmac>；本脚本为存量记录补签，
使 image.py 的签名校验上线后旧记录仍可访问。

用法（部署机）：
    cd /opt/ARL && sudo -u root venv/bin/python scripts/migrate_screenshot_sign.py [--dry-run]
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import utils  # noqa: E402
from app.utils import signing  # noqa: E402

URL_RE = re.compile(r"^/image/([^/]+)/([^/?]+)$")


def main():
    dry_run = "--dry-run" in sys.argv
    conn = utils.conn_db("site")
    docs = list(conn.find(
        {"screenshot": {"$exists": True, "$ne": ""}}, {"screenshot": 1}))
    scanned = updated = already_signed = unparseable = 0
    updates = []
    for doc in docs:
        scanned += 1
        match = URL_RE.match(doc.get("screenshot") or "")
        if not match:
            unparseable += 1
            continue
        task_id, file_name = match.group(1), match.group(2)
        if "sign=" in file_name:
            already_signed += 1
            continue
        updates.append((doc["_id"], signing.sign_image_url(task_id, file_name)))
    if not dry_run:
        for doc_id, url in updates:
            conn.update_one({"_id": doc_id}, {"$set": {"screenshot": url}})
    print("scanned={} updated={} already_signed={} unparseable={} dry_run={}".format(
        scanned, len(updates), already_signed, unparseable, dry_run))


if __name__ == "__main__":
    main()
