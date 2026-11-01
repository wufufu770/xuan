# 方案：平台 Agent（悬浮窗 + 会话管理 + 对外 MCP）与 会话池自动抓取网关

> 调研与设计定稿：2026-10-31。对应需求：①资产检索扩展 APP/小程序（M1，已上线）；
> ②会话池「窗口登录 + 静默抓取 + 自动续期」（M3）；③平台 Agent + 对外 MCP（M2）。

## 〇、调研结论

### 同类产品与理念
- **安全平台 Copilot 化**是行业主线（微软 Security Copilot、各 SOC 厂商 AI 助手）：
  通用形态 = 聊天入口 + 平台工具调用（function calling）+ 会话历史。玄览 Agent 与之对齐：
  Agent 了解平台资产/任务/风险模型，用户以自然语言布置任务，Agent 直接调平台功能执行。
- **MCP（Model Context Protocol）** 已是 AI 工具生态事实标准：Shodan/nuclei 等
  安全工具的 MCP Server 是热度最高的一批集成（见 awesomeclaude/mcp.so 收录）。
  把玄览能力做成 MCP Server，外部 Agent（Claude/Cursor/DeepSeek 网页等）即可直接驱
  动本平台——这是「以玄览为中心」的生态位。
- 风险共识：MCP 把工具暴露给模型即扩大攻击面，须做 **Token 鉴权 + 工具白名单 +
  破坏性操作二次确认 + 全量审计**。

### 会话保活技术选型（窗口登录 + 静默抓取）
| 方案 | 特点 | 结论 |
|---|---|---|
| [Neko](https://github.com/m1k1o/neko) | WebRTC 虚拟浏览器，多人共享 | 重，定位多人观看，不合 |
| [Kasm Workspaces/KasmVNC](https://blog.send.win/container-streaming-platform-complete-guide-2026) | 容器流平台，功能全但体系重 | 不引入整套平台 |
| [Browserless](https://browserless.io)（自托管） | 无头 API 抓取强，无可视登录 | 仅作参考 |
| **noVNC + Xvfb + Chromium sidecar** | 单容器：有头浏览器投到网页 iframe；supervisor 以 playwright 连同实例抓 cookie | ✅ **选定**：最轻、可控、与现有 session_pool/storage_state/探活体系无缝 |

### 家底盘点（降低工作量的既有资产）
- **凤鸟已完成接口逆向**（fast-search → orderNo → dimension/list 三步，含 WAF 规避、
  xs-content-type 头），ICP/APP/小程序三维度采集落库 `fengniao_intel` —— **任务时无需浏览器**，
  cookie 只用于维持登录态。
- `session_pool` 已有：storage_state 加密入池、探活（必需 cookie 判定）、storage_state JSON 导入。
- `scripts/session_login.py` 已实现「有头浏览器人工登录→入池→探活」CLI——M3 就是把它平台化。
- playwright==1.62.0 已在依赖锁内（容器尚缺浏览器二进制与 Xvfb，由 sidecar 镜像解决）。

## 一、M1 资产检索扩展（已上线 ✅）
- 后端 `/asset_ext/?kind=app|miniprogram|icp`（fengniao_intel 展平检索 + 关键字 + 分页）；
- 前端资产检索新增 **APP / 小程序 / ICP 备案** 三个维度（搜索/筛选/详情抽屉/CSV 全量复用）；
- **快应用**：凤鸟采集端无此维度，列入待逆向清单（与公众号同批确认）。

## 二、M2 平台 Agent + 对外 MCP（设计定稿）

### 架构
```
┌─ console 悬浮窗 ─┐  SSE   ┌──────────── 后端 ────────────┐      外部 Agent
│  会话面板(同组件) │◀──────▶│ /agent/chat （SSE 流式）      │      (Claude/Cursor/
└─ 侧栏·智能助手  ─┘        │   ├ LLM(复用 AI 供应商配置)   │       DeepSeek...)
                            │   ├ 工具循环(function calling)│      ┌──────────┐
                            │   └ agent_conversations 会话库│◀─────│ /api/mcp │
                            │ agent_tools 工具注册表(共享)──┼──────▶│ MCP Server│
                            └───────────────────────────────┘      └──────────┘
```
- **agent_tools.py（核心）**：一份工具注册表，MCP 与内部 Agent 共用。每工具 =
  {name, description, input_schema, handler, danger: bool}。首批工具（10 个）：
  `search_assets(kind,q)`、`asset_ext_query(kind,q)`、`submit_task(target,template)`、
  `task_status(task_id)`、`list_tasks(status)`、`create_scope(name,scope)`、
  `list_risks(severity,size)`、`schedule_scan(...)`、`generate_report(scope_id)`、
  `platform_overview()`（看板摘要）。
- **MCP Server**：`/api/mcp`（Streamable HTTP，JSON-RPC 2.0：initialize/tools/list/
  tools/call），API Key 鉴权；danger 工具默认对 MCP 关闭（白名单开关）。
- **Agent 后端**：会话管理（新建/重命名/删除/历史，DeepSeek 式）+ SSE 流式回复 +
  工具调用步骤可见（"正在调用 资产检索…"）+ 每次工具调用记 audit；破坏性操作在
  聊天内返回确认卡片，用户点确认才执行。
- **前端**：右下角悬浮球 → 展开会话面板；侧栏新增「智能助手」页 = 会话列表 + 聊天区；
  两处共用同一 JS 组件与后端状态。

### 验收
1. 悬浮窗/侧栏输入"帮我看看 example.com 的风险并生成报告"→ Agent 依次调用
   风险检索 + 报告生成，步骤与结果在会话中可见；
2. 外部 MCP 客户端连接 `/api/mcp` 能 tools/list 出 10 个工具并成功调用只读工具；
3. 会话持久化，刷新后历史可续聊。

## 三、M3 会话池自动抓取网关（设计定稿）

### 架构（新增 sidecar 服务 session-gateway）
```
会话池页「窗口登录」按钮
   └▶ 弹窗 iframe ──▶ noVNC(ws) ──▶ session-gateway 容器
                                    ├ Xvfb + Chromium(有头, 按会话独立 profile)
                                    ├ x11vnc + websockify(7900/会话)
                                    ├ supervisor API(:8090)
                                    │   POST /session/open {source,account,login_url}
                                    │   POST /session/capture {source,account} → storage_state
                                    │   POST /session/close
                                    └ 抓取: playwright connect CDP 到同一 Chromium
                                            导出 storage_state → POST web /session_pool/import_state
                                            （复用现有入池+探活）
```
- **登录窗口**：会话池页每账号卡「窗口登录」→ 打开该账号的 noVNC 视图，用户在里面
  正常登录目标站；点「完成并抓取」→ capture → 入池 → 探活 → 卡片状态灯变绿。
- **使用期间固定**：profile 目录按 (source, account) 持久化卷，容器/浏览器生命周期内
  会话不丢；不使用时容器可休眠（profile 在盘）。
- **自动续期**：celery beat 周期任务（默认 6h，按源配置）→ headless 在同 profile 打
  轻量页刷新 cookie → 调 session_pool 探活 → 结果回写卡片；
  **探活失败** → 通知渠道推送「XX 会话过期，点击重登」（含打开窗口深链）。
- **静默逆向路线**（登录窗口只是兜底，最终目标是纯 API）：
  凤鸟已达成；按同方法逐源逆向 爱企查/天眼查/快查 的数据接口（用网关会话抓包定位），
  逆向完成后任务执行完全脱离浏览器，仅剩 cookie 续期依赖网关。
- **部署**：docker-compose 新增 session-gateway 服务（python+playwright+chromium+xvfb
  +x11vnc+novnc，~800MB 镜像）；nginx `/gateway/` 反代 supervisor 与 noVNC websocket。

### 验收
1. 会话池页打开窗口登录凤鸟 → 完成抓取后卡片变绿，采集任务可跑；
2. 手工让 cookie 过期 → 6h 内自动续期成功；无法自动续期时收到通知；
3. 爱企查窗口登录同流程可用。

## 四、排期与依赖
| 里程碑 | 依赖 | 工作量估计 |
|---|---|---|
| M1 资产检索扩展 | 无（已上线） | ✅ |
| M2 Agent+MCP | AI 供应商已就绪 | 2-3 天 |
| M3 会话网关 | 新增 sidecar 容器（需确认镜像体积/资源） | 3-5 天 |
| M4 逐源静默逆向 | M3 网关就绪后逐源推进 | 持续 |
