"""美亚凤鸟（riskbird.com）企业情报采集。

逆向结论（2026-10-27 实测验证）：
1. 公司名 -> entid：GET /riskbird-api/api/v1/companies/fast-search?key=<kw>&queryType=1&limit=5
   注意 POST /api/v1/companies/search 被 WAF 拦截（脚本请求即使参数/cookie 完全一致也返回
   code=3000000 "暂时没有找到相关数据"），必须走 fast-search。
2. entid -> orderNo：GET https://www.riskbird.com/ent/<urlencode(企业名)>.html?entid=<entid>
   orderNo 是服务端生成并绑定到该企业的，SSR 时嵌入页面 payload，正则 WEB\\d{21} 提取。
   客户端自造 orderNo 会返回 code=9999 "数据错误"。
3. orderNo -> 数据：POST /riskbird-api/api/v1/companies/dimension/list/<ep>
   body {"filterCnd":0,"page":n,"size":50,"orderNo":...,"sortField":"","filterMap":{}}
   必须带请求头 xs-content-type: application/json（否则后端按 form 解析报 500）。
   ep 取值：propertyIcp(备案网站) / propertyApp(APP) / propertyMiniprogram(小程序)

字段映射（科大讯飞实测）：
  propertyIcp:      hostname=域名, icpnum=备案号, webname=网站名, shdate=审核日期,
                    province=省份, enttype=企业类型
  propertyApp:      appname=应用名, downloadCountLevel=下载量级, updateDateAndroid/Ios=更新日期,
                    brief=简介, iconUrl=图标
  propertyMiniprogram: name=名称, cate=类目, logo, qrcode
  companyInvestDirect: entName/entid=被投企业, directProp=直接持股比例, allProp=穿透合计,
                    entStatus=经营状态, regionCn=地区, nic=行业

控股集团采集：collect_group 以对外投资（companyInvestDirect）做 BFS，逐层沿
directProp >= min_ratio（默认 100%，即百分百控股）向下穿透，最多 max_depth 层
（讯飞 -> 讯飞xx -> 讯飞xxx ...），每家企业都拉取备案网站/APP/小程序。

凭证：Config.FENGNIAR_TOKEN，取浏览器 www.riskbird.com 的 token cookie（JWT，
短期有效，过期后需重新登录浏览器刷新）。
"""

import json
import re
import time
from base64 import b64decode
from urllib.parse import quote

import requests

from app import utils
from app.config import Config

logger = utils.get_logger()

FENGNIAR_TAG = "fengniao"

BASE = "https://www.riskbird.com"
ORDER_NO_RE = re.compile(r"WEB\d{21}")
CODE_OK = 20000

PAGE_SIZE = 50
MAX_PAGES = 20
REQUEST_TIMEOUT = 30
REQUEST_INTERVAL = 1.0
NODE_INTERVAL = 0.8
INVEST_ENDPOINT = "companyInvestDirect"


def parse_ratio(value):
    """"100%" -> 100.0，"80.5%" -> 80.5，空/非法返回 None。"""
    if not value:
        return None
    match = re.search(r"([\d.]+)\s*%", str(value))
    return float(match.group(1)) if match else None


class FengniaoError(Exception):
    pass


def resolve_fengniao_token():
    """token 供给顺序：会话池（真源）-> config.yaml（过渡兼容）。

    池侧任何异常都回退 config，绝不影响采集主流程。
    """
    try:
        from app.services.session_pool import get_cookie
        token = get_cookie("fengniao", "default", "token")
        if token:
            return token
    except Exception as exc:
        logger.warning("session_pool resolve failed: %s", exc)
    return getattr(Config, "FENGNIAR_TOKEN", "") or ""


def _headers():
    token = resolve_fengniao_token()
    if not token:
        raise FengniaoError("FENGNIAR_TOKEN 未配置（浏览器登录 riskbird.com 后取 token cookie）")
    return {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36",
        "Accept": "application/json",
        "app-device": "WEB",
        "xs-content-type": "application/json",
        "Content-Type": "application/json;charset=UTF-8",
        "Origin": BASE,
        "Referer": BASE + "/",
        "Cookie": "app-uuid=WEB-" + token[-32:].upper() + "; app-device=WEB; token=" + token,
    }


def token_expire_time(token=None):
    """解析 JWT 过期时间戳，便于提前预警；解析失败返回 0。
    token 缺省时按供给顺序解析（会话池 -> config）。"""
    token = token or resolve_fengniao_token()
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(b64decode(payload)).get("exp", 0)
    except Exception:
        return 0


def search_ent(keyword, limit=5):
    """公司名/关键词 -> [{entName, entid, entStatus}]，精确匹配排最前。"""
    url = BASE + "/riskbird-api/api/v1/companies/fast-search"
    resp = requests.get(url, params={"limit": limit, "queryType": 1, "key": keyword},
                        headers=_headers(), timeout=REQUEST_TIMEOUT)
    data = resp.json().get("data") or []
    keyword = (keyword or "").strip()
    data.sort(key=lambda x: 0 if x.get("entName") == keyword else 1)
    return [{"entName": x.get("entName"), "entid": x.get("entid"),
             "entStatus": x.get("entStatus")} for x in data]


def get_order_no(ent_name, entid, session=None):
    """打开企业 SSR 页换取绑定了该企业的 orderNo。"""
    sess = session or requests
    url = "{}/ent/{}.html".format(BASE, quote(ent_name))
    resp = sess.get(url, params={"entid": entid},
                    headers={"User-Agent": _headers()["User-Agent"],
                             "Cookie": _headers()["Cookie"]},
                    timeout=REQUEST_TIMEOUT)
    match = ORDER_NO_RE.search(resp.text)
    if not match:
        raise FengniaoError("企业页未返回 orderNo（token 可能过期或企业不可见）：{}".format(ent_name))
    return match.group(0)


def fetch_dimension(order_no, endpoint, session=None, max_records=None):
    """拉取一个 dimension 的全量分页数据，返回 (rows, totalCount)。"""
    sess = session or requests
    max_records = max_records or PAGE_SIZE * MAX_PAGES
    rows, total, page = [], None, 1
    while len(rows) < max_records and page <= MAX_PAGES:
        body = {"filterCnd": 0, "page": page, "size": PAGE_SIZE,
                "orderNo": order_no, "sortField": "", "filterMap": {}}
        resp = sess.post(BASE + "/riskbird-api/api/v1/companies/dimension/list/" + endpoint,
                         json=body, headers=_headers(), timeout=REQUEST_TIMEOUT)
        result = resp.json()
        code = result.get("code")
        if code != CODE_OK:
            raise FengniaoError("{} 第{}页失败 code={} msg={}".format(
                endpoint, page, code, result.get("msg")))
        data = result.get("data") or {}
        total = data.get("totalCount", total)
        api_data = data.get("apiData") or []
        rows.extend(api_data)
        if not api_data or len(rows) >= int(total or 0):
            break
        page += 1
        time.sleep(REQUEST_INTERVAL)
    return rows, total


def fetch_investments(order_no, session=None, max_records=None):
    """对外投资列表，返回 [{entName, entid, directProp, allProp, entStatus, regionCn, nic}]。"""
    rows, _ = fetch_dimension(order_no, INVEST_ENDPOINT, session=session, max_records=max_records)
    return [{
        "entName": r.get("entName"),
        "entid": r.get("entid"),
        "directProp": r.get("directProp"),
        "allProp": r.get("allProp"),
        "entStatus": r.get("entStatus"),
        "regionCn": r.get("regionCn"),
        "nic": r.get("nic"),
    } for r in rows if r.get("entTypeCode", "ent") == "ent" and r.get("entid")]


def _collect_node(ent_name, entid, session, max_records=None):
    """采集单家企业：orderNo + 三类数据。失败抛 FengniaoError。"""
    order_no = get_order_no(ent_name or entid, entid, session=session)
    node_data = {"entid": entid, "entName": ent_name,
                 "icp": [], "app": [], "miniprogram": []}
    for field, endpoint in [("icp", "propertyIcp"),
                            ("app", "propertyApp"),
                            ("miniprogram", "propertyMiniprogram")]:
        rows, total = fetch_dimension(order_no, endpoint, session=session, max_records=max_records)
        node_data[field] = rows
        time.sleep(REQUEST_INTERVAL)
    return node_data, order_no


def collect_group(keyword, entid=None, ent_name=None, max_depth=4, min_ratio=100.0,
                  max_companies=None, max_records=None, on_progress=None):
    """控股集团 BFS 采集：沿 100%（可调）控股链向下穿透，最多 max_depth 层。

    每层节点都采集 备案网站/APP/小程序；非叶子层继续展开对外投资里
    directProp >= min_ratio 的企业。按 entid 去重，单家企业失败不中断整体。

    返回 {"root": {...}, "companies": [节点列表], "edges": [{from,to,directProp,allProp}], "failed": [...]}
    节点结构：{entid, entName, depth, parent_entid, path, invest_ratio, icp, app, miniprogram, error}
    """
    if not entid:
        candidates = search_ent(keyword, limit=3)
        exact = [c for c in candidates if c.get("entName") == (ent_name or keyword)]
        if not candidates:
            raise FengniaoError("凤鸟未找到企业：{}".format(keyword))
        picked = exact[0] if exact else candidates[0]
        entid, ent_name = picked["entid"], picked["entName"]

    session = requests.Session()
    root_name = ent_name or keyword
    results, edges, failed = [], [], []
    visited = {entid}
    queue = [(entid, root_name, 0, None, "", None)]
    total_companies = 0

    while queue:
        cur_entid, cur_name, depth, parent_entid, path, invest_ratio = queue.pop(0)
        if max_companies and total_companies >= max_companies:
            logger.info("fengniao group 达到 max_companies=%s，停止展开", max_companies)
            break
        total_companies += 1
        node_path = "{} > {}".format(path, cur_name) if path else cur_name
        logger.info("fengniao group [%d/%d] depth=%d %s", total_companies, len(queue) + 1, depth, node_path)

        node = {"entid": cur_entid, "entName": cur_name, "depth": depth,
                "parent_entid": parent_entid, "path": node_path,
                "invest_ratio": invest_ratio, "icp": [], "app": [],
                "miniprogram": [], "error": None}
        try:
            node_data, order_no = _collect_node(cur_name, cur_entid, session, max_records=max_records)
            node.update({k: node_data[k] for k in ("icp", "app", "miniprogram")})
        except Exception as exc:
            node["error"] = str(exc)
            failed.append({"entid": cur_entid, "entName": cur_name, "error": str(exc)})
            logger.warning("fengniao group 节点失败 {}: {}".format(node_path, exc))
        results.append(node)
        if on_progress:
            try:
                on_progress(total_companies, node)
            except Exception:
                pass

        # 叶子层不再展开；采集失败的节点无法拿 orderNo，也无法展开
        if depth < max_depth and not node["error"]:
            try:
                children = fetch_investments(order_no, session=session)
                for child in children:
                    ratio = parse_ratio(child.get("directProp"))
                    if ratio is None or ratio < float(min_ratio):
                        continue
                    child_entid = child["entid"]
                    edges.append({"from_entid": cur_entid, "from_name": cur_name,
                                  "to_entid": child_entid, "to_name": child["entName"],
                                  "directProp": child.get("directProp"),
                                  "allProp": child.get("allProp")})
                    if child_entid in visited:
                        continue
                    visited.add(child_entid)
                    queue.append((child_entid, child["entName"], depth + 1,
                                  cur_entid, node_path, child.get("directProp")))
                time.sleep(NODE_INTERVAL)
            except Exception as exc:
                logger.warning("fengniao group 展开失败 {}: {}".format(node_path, exc))

    logger.info("fengniao group done: %d 家（失败 %d），边 %d 条",
                len(results), len(failed), len(edges))
    return {"root": {"entid": entid, "entName": root_name, "keyword": keyword},
            "companies": results, "edges": edges, "failed": failed}


def collect_company(keyword, entid=None, ent_name=None, max_records=None):
    """采集一家企业的 备案网站/APP/小程序 数据。

    keyword: 公司名（用于搜索和兜底）；entid/ent_name 已知时可省一次搜索。
    返回 {"keyword", "entid", "entName", "icp": [...], "app": [...], "miniprogram": [...]}
    """
    if not entid:
        candidates = search_ent(keyword, limit=3)
        exact = [c for c in candidates if c.get("entName") == (ent_name or keyword)]
        if not candidates:
            raise FengniaoError("凤鸟未找到企业：{}".format(keyword))
        picked = exact[0] if exact else candidates[0]
        entid, ent_name = picked["entid"], picked["entName"]

    session = requests.Session()
    order_no = get_order_no(ent_name or keyword, entid, session=session)
    logger.info("fengniao collect {} entid={} orderNo={}".format(ent_name, entid, order_no))

    result = {"keyword": keyword, "entid": entid, "entName": ent_name,
              "icp": [], "app": [], "miniprogram": []}
    for field, endpoint in [("icp", "propertyIcp"),
                            ("app", "propertyApp"),
                            ("miniprogram", "propertyMiniprogram")]:
        rows, total = fetch_dimension(order_no, endpoint, session=session, max_records=max_records)
        result[field] = rows
        logger.info("fengniao {} {}: {} 条（total={}）".format(ent_name, field, len(rows), total))
        time.sleep(REQUEST_INTERVAL)
    return result


def _distinct_hostnames(rows):
    """ICP 记录去重域名数（仅统计；域名落库统一发生在 attach_scope -> domain 集合）。

    历史版本曾在此写入 asset_domain 集合，但 collect 流程没有 task_id/scope_id，
    写入的记录与资产域（按 task_id/scope_id 查询）永远关联不上，属死数据，已移除。
    """
    return len({r.get("hostname") for r in rows if r.get("hostname")})


def collect_and_save(keyword, group_id=None, entid=None, ent_name=None, max_records=None):
    """采集并入库：原始情报 -> fengniao_intel 集合。

    ICP 域名随情报存于 fengniao_intel.icp；进入资产库（domain 集合）
    统一由 routes/fengniao.attach_scope 在入组时完成。
    返回 {"collect": collect_company 结果, "new_domain_count": n, "intel_id": str}
    """
    data = collect_company(keyword, entid=entid, ent_name=ent_name, max_records=max_records)

    new_domains = _distinct_hostnames(data["icp"])

    intel_doc = {
        "entid": data["entid"],
        "ent_name": data["entName"],
        "group_id": group_id,
        "icp": data["icp"],
        "app": data["app"],
        "miniprogram": data["miniprogram"],
        "token_exp": token_expire_time(),
        "create_time": utils.curr_date(),
    }
    intel_id = utils.conn_db("fengniao_intel").insert_one(intel_doc).inserted_id
    logger.info("fengniao saved {} -> intel={}, new_domains={}".format(
        data["entName"], intel_id, new_domains))
    return {"collect": data, "new_domain_count": new_domains, "intel_id": str(intel_id)}


def collect_group_and_save(keyword, entid=None, ent_name=None, group_id=None,
                           max_depth=4, min_ratio=100.0,
                           max_companies=None, max_records=None, on_progress=None):
    """控股集团采集并入库。

    每家企业一份 fengniao_intel（带 depth/path/chain）；ICP 域名进入资产库
    （domain 集合）统一由 attach_scope 入组时完成，这里仅统计去重数量。
    返回 {"group": collect_group 结果（精简）, "saved": 汇总}
    """
    group = collect_group(keyword, entid=entid, ent_name=ent_name,
                          max_depth=max_depth, min_ratio=min_ratio,
                          max_companies=max_companies, max_records=max_records,
                          on_progress=on_progress)
    saved, all_new_domains = [], 0
    for node in group["companies"]:
        if node["error"] and not (node["icp"] or node["app"] or node["miniprogram"]):
            continue
        new_domains = _distinct_hostnames(node["icp"])
        all_new_domains += new_domains
        intel_id = utils.conn_db("fengniao_intel").insert_one({
            "entid": node["entid"],
            "ent_name": node["entName"],
            "group_id": group_id,
            "depth": node["depth"],
            "path": node["path"],
            "invest_ratio": node["invest_ratio"],
            "icp": node["icp"],
            "app": node["app"],
            "miniprogram": node["miniprogram"],
            "error": node["error"],
            "token_exp": token_expire_time(),
            "create_time": utils.curr_date(),
        }).inserted_id
        saved.append({"entName": node["entName"], "depth": node["depth"],
                      "intel_id": str(intel_id), "new_domain_count": new_domains})
    logger.info("fengniao group saved: %d 家情报, 新增域名 %d",
                len(saved), all_new_domains)
    return {"group": group, "saved": saved, "new_domain_count": all_new_domains}


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "科大讯飞股份有限公司"
    depth = int(sys.argv[2]) if len(sys.argv) > 2 else 4
    cap = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    group = collect_group(target, max_depth=depth, min_ratio=100.0,
                          max_companies=cap or None,
                          on_progress=lambda n, node: print(
                              "[{}] d{} {} (icp={} app={} mp={})".format(
                                  n, node["depth"], node["entName"],
                                  len(node["icp"]), len(node["app"]),
                                  len(node["miniprogram"]))))
    print("共 {} 家, 失败 {}, 控股边 {} 条".format(
        len(group["companies"]), len(group["failed"]), len(group["edges"])))
