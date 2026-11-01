"""测试共享的内存版 Mongo 假实现（无 pymongo 依赖）。"""
import re


class FakeCursor(list):
    """list 的游标包装：支持 pymongo 风格 .limit() / .sort()。"""

    def limit(self, n):
        return FakeCursor(self[:max(int(n), 0)])

    def sort(self, key, direction=1):
        reverse = direction < 0
        return FakeCursor(sorted(
            self, key=lambda d: str(d.get(key, "")), reverse=reverse))


class FakeCollection:
    def __init__(self, docs=None):
        self.docs = list(docs or [])
        self._next_id = 1

    @classmethod
    def _candidates(cls, doc, key):
        """点路径候选值（对齐 Mongo 数组穿透语义：app.appname 匹配任意元素）。"""
        vals = [doc]
        for part in key.split("."):
            nxt = []
            for cur in vals:
                if isinstance(cur, dict):
                    if part in cur:
                        nxt.append(cur[part])
                elif isinstance(cur, list):
                    for el in cur:
                        if isinstance(el, dict) and part in el:
                            nxt.append(el[part])
            vals = nxt
            if not vals:
                return []
        return vals

    @classmethod
    def _match(cls, doc, query):
        for key, cond in query.items():
            if key == "$or":
                if not any(cls._match(doc, sub) for sub in cond):
                    return False
                continue
            cands = cls._candidates(doc, key) if "." in key else [doc.get(key)]
            if isinstance(cond, dict):
                if "$regex" in cond:
                    flags = re.I if "i" in str(cond.get("$options", "")) else 0
                    if not any(re.search(cond["$regex"],
                                         str(v if v is not None else ""), flags)
                               for v in cands):
                        return False
                    continue
                if "$ne" in cond and any(v == cond["$ne"] for v in cands):
                    return False
                if "$in" in cond and not any(v in cond["$in"] for v in cands):
                    return False
                if "$gt" in cond and not any((v or 0) > cond["$gt"] for v in cands):
                    return False
                if "$exists" in cond and (key in doc) != bool(cond["$exists"]):
                    return False
            elif hasattr(cond, "search"):
                # pymongo 语义：正则条件对字符串字段做 search
                if not any(cond.search(str(v if v is not None else "")) for v in cands):
                    return False
            elif not any(v == cond for v in cands):
                return False
        return True

    def find_one(self, query=None, projection=None):
        if query is None:
            return dict(self.docs[0]) if self.docs else None
        for doc in self.docs:
            if self._match(doc, query):
                return dict(doc)
        return None

    def find(self, query=None, projection=None):
        results = []
        for doc in self.docs:
            if self._match(doc, query or {}):
                results.append(self._project(doc, projection))
        return FakeCursor(results)

    @staticmethod
    def _project(doc, projection):
        """最小投影实现：仅支持 {field: 0} 排除语法（与调用方用法一致）。"""
        if not projection:
            return dict(doc)
        excluded = {k for k, v in projection.items() if v == 0}
        return {k: v for k, v in doc.items() if k not in excluded}

    def insert_one(self, doc):
        # 与 pymongo 行为一致：就地给原 dict 回填 _id（ARL 代码依赖此语义）；
        # 缺省 _id 用 ObjectId（与真实 Mongo 一致）
        if "_id" not in doc:
            from bson import ObjectId
            doc["_id"] = ObjectId()
        self.docs.append(doc)
        return type("R", (), {"inserted_id": doc["_id"]})

    def insert_many(self, docs):
        for doc in docs:
            self.insert_one(doc)

    def update_one(self, query, update, upsert=False):
        set_data = update.get("$set", {})
        for doc in self.docs:
            if self._match(doc, query):
                doc.update(set_data)
                return type("R", (), {"modified_count": 1, "upserted_id": None})
        if upsert:
            new_doc = dict(query)
            new_doc.update(set_data)
            result = self.insert_one(new_doc)
            return type("R", (), {"modified_count": 0,
                                  "upserted_id": result.inserted_id})
        return type("R", (), {"modified_count": 0, "upserted_id": None})

    def update_many(self, query, update):
        set_data = update.get("$set", {})
        modified = 0
        for doc in self.docs:
            if self._match(doc, query):
                doc.update(set_data)
                modified += 1
        return type("R", (), {"modified_count": modified})

    def delete_one(self, query):
        for i, doc in enumerate(self.docs):
            if self._match(doc, query):
                del self.docs[i]
                return type("R", (), {"deleted_count": 1})
        return type("R", (), {"deleted_count": 0})

    def delete_many(self, query):
        before = len(self.docs)
        self.docs = [d for d in self.docs if not self._match(d, query)]
        return type("R", (), {"deleted_count": before - len(self.docs)})

    def count_documents(self, query=None):
        return len(self.find(query))

    def estimated_document_count(self):
        return len(self.docs)

    def aggregate(self, pipeline):
        """仅支持测试用到的最小组合法：$sort(_id) + $limit + $group($sum)。"""
        docs = sorted(self.docs, key=lambda d: str(d.get("_id")), reverse=True)
        stage = iter(pipeline)
        for s in stage:
            if "$sort" in s:
                continue
            if "$limit" in s:
                docs = docs[:s["$limit"]]
            if "$group" in s:
                group_spec = s["$group"]["_id"]
                if isinstance(group_spec, dict):
                    key_expr = group_spec.get("$ifNull", [None])[0]
                else:
                    key_expr = group_spec
                if isinstance(key_expr, str):
                    key_expr = key_expr.lstrip("$")
                groups = {}
                for d in docs:
                    value = d.get(key_expr) if key_expr else None
                    if value is None and isinstance(group_spec, dict) \
                            and len(group_spec.get("$ifNull", [])) > 1:
                        value = group_spec["$ifNull"][1]
                    groups[value] = groups.get(value, 0) + 1
                return [{"_id": k, "n": v} for k, v in groups.items()]
        return []


class FakeDB:
    def __init__(self):
        self.collections = {}

    def conn_db(self, name):
        return self.collections.setdefault(name, FakeCollection())
