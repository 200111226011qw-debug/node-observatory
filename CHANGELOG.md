# Changelog

## 3.9.0
- 顶层 catch 只对“缺表需跑迁移”这类纯配置错误回传 hint，其余内部 500 一律不外露内部信息。
- 修复 `/api/status` 运行锁解析：锁值含唯一 token（`<epoch-ms>:<uuid>`），先切出时间前缀再比较，否则 `Number("…:uuid")` 为 NaN 导致恒显示“未运行”。
- `/admin/network-summary` 复用一次 `getConfig(env)`。
- `ensureSchema`：batch 失败后逐条重试，容忍并发冷启动下的 `duplicate column name`。
- 共享 `NODE_UPSERT_SQL` + `upsertNodeStmt()`，消除 `scanRepos` / `scanUpstreamSubscriptions` 的节点 SQL 重复。
- 收紧 VLESS `flow` 白名单（仅 `xtls-rprx-vision` / `xtls-rprx-vision-udp443`）；使用已废弃 flow 的存量节点将在下一轮扫描后因解析失败退出 active，可用 `SELECT COUNT(*) FROM nodes WHERE canonical LIKE '%xtls-rprx-%'` 评估影响面。
- IPv6 公网判定补齐 Teredo / NAT64 / ORCHID / discard-only 等保留前缀，覆盖压缩写法（如 `2001::1`），且避免第一段后直接 `::` 压缩的公网地址被误判为非公网。
- `scripts/public-probe.py` 初筛基准分下调至发布阈值（`PUBLISH_MIN_SCORE=50`）以下（40/45），仅凭经代理拿到出口 IP 不再自动发布节点。
- `/admin/health-report` 成功上报（`ok:true`）不再按 `last_seen` 过期而停用节点：成功检测视为节点可用的更强证据。
- `maintenance` 按时间过期停用时同样认 `last_success`：最近 24 小时内有成功检测的节点不被来源过期误杀，与 `ok:true` 语义自洽；无外部检测器持续续命时，节点无来源存活上限由 72h 放宽至约 96h。
- 新增回归测试（36 项），覆盖 flow 白名单、IPv6 特殊前缀、health 成功语义与 maintenance `last_success` 守卫。

## 3.8.1
- P0 修复：数值字段校验显式排除 `null`、`undefined` 和空字符串，避免 `Number(null) === 0` 将未知指标写成实测 0。
- 未提供 riskScore 时不再因 null 被当成 0 分而写入风险评估；未提供的风险指标保持 NULL。
- P1 修复：`RISK_MAX_AGE_DAYS=0` 在 `/admin/network-summary` 中按不限有效期统计已评估节点。
- P2 修复：运行锁包含唯一 owner token，结束时仅释放当前运行持有的锁，避免超时接管后误删新任务的锁。
- 新增 P0/P1 回归测试；部署前请在测试环境验证 D1 兼容性。

## 3.7.0
- 新增订阅密钥输入、Clash/Mihomo 与 v2rayNG 二维码生成和复制链接。
- 新增本机浏览器公网出口与 WebRTC ICE 候选诊断，并在界面明确标注其不能替代代理出口检测。
- 扩展 `/admin/health-report`，接收 HTTP 丢包、抖动、测速、DNS/IPv6 泄漏、代理识别、数据中心属性、黑名单命中、质量分和检测说明。
- 新增 D1 网络质量字段、旧库启动时自动补列和 `/admin/network-summary` 管理汇总接口。
- 缺少显式 `riskScore` 时，只有收到部分检测指标才进行保守估算；未知指标保持未知。
- 增加网络质量上报回归测试；30 项测试全部通过。
- 限制并更新 CSP 以允许二维码库 CDN 和浏览器出口查询服务。

## 3.6.0
- 将项目包与运行时版本标识统一升级为 3.6.0。
- 保留 v3.4 中已有的 KV 登录会话、登录失败限流、自定义订阅域名显示与混淆构建配置。
- 本次为基于原上传包的版本整理，不宣称新增未经实现或验证的功能；部署前请运行测试并核对 Cloudflare D1/KV 绑定。

## 3.5.0
- 版本号阶段记录：未在原上传包中发现独立的 v3.5 功能变更，因此不虚构功能差异。

## 3.3.0
- 新增可选上游订阅导入器，默认关闭，仅允许固定的 morpheusadam/v2ray-config mini.txt URL。
- 外部来源复用严格节点解析、去重和风险门槛；导入不代表节点通过真实代理验证。
- 增加上游候选统计与回归测试；本地自动化测试 28 项通过。
- 由于公开 mini.txt 样本存在大量协议前缀与参数不一致的条目，未默认启用该来源。

## 3.2.0

### 修复（原版会直接出错的问题）
- `/api/nodes`、`/admin/candidates` 查询了表里不存在的 `server`、`port` 列（500 / `no such column`）。现在建表即包含这两列，入库时写入，旧库由 Worker 自动补列并回填。
- `/admin/health-report` 成功分支的 SQL 有 9 个占位符却只绑定 8 个值，必然报错；且 `ok` 与风险分错误耦合。已重写。
- 风险过滤“死锁”：新节点默认未评估，下一轮扫描就被置为停用，于是永远进不了 `/admin/candidates`，检测器无从评估，订阅永远为空。现在 `active` 只表示生命周期，是否发布由 `active + risk_score + 评估是否过期` 决定。
- 健康上报接口现在真正接收 `riskScore` / `riskReasons`（README 早有描述，代码一直没实现）。
- `ss://` SIP002（`base64(method:pass)@host:port`，最常见的写法）此前无法解析。
- IPv6 服务器地址带方括号，导致探测与导出出错。
- 不支持的传输（kcp/quic/httpupgrade 等）被静默导出成 tcp，生成连不上的节点；现在直接拒收。
- 模块顶层计算 GitHub 搜索日期，隔离体长期存活后日期会过期；改为每次运行时计算。
- TCP 探测超时后不关闭 socket、不清定时器。
- 任务异常时 `runs.error` 从不写入，且无并发保护（定时与手动可同时运行）。

### 安全加固
- 订阅密钥 / 管理员令牌改为常量时间比较；两者相同时拒绝管理接口。
- `/api/nodes` 需要管理员令牌（原先任何人可读全部节点地址，等于绕过订阅密钥）。
- 面板加 CSP 等响应头；订阅与 API 响应 `no-store` + `noindex`。
- 拒收：私网/保留/环回地址（含 IPv6、十六进制/八进制写法）、常见服务端口（22/25/3306…）、无 TLS 的 VLESS、`allowInsecure`、SS 插件与老旧流加密。可用 `ALLOW_INSECURE=1` 放行明文/跳过证书校验的节点。
- TCP 探测：同一主机每轮最多 3 个、每轮上限 300 个，避免公开列表被投毒后把 Worker 变成端口扫描器。
- 风险评估有有效期（默认 7 天，`RISK_MAX_AGE_DAYS`）：节点运营者可能更换，过期评估不再发布。

### 效率与可靠性
- 数据库写入改为 D1 `batch` + `ON CONFLICT` upsert（原版每个 URI 两次查询）；TCP 探测并发 6。
- 子请求预算 `SUBREQUEST_BUDGET`：按仓库评分优先扫描，预算不足时优雅收尾并在运行记录里标注。
- GitHub 限流 / 失败写入运行记录；本轮没有任何仓库扫描成功时，不执行“72 小时过期”，避免 GitHub 故障时误杀全部节点。
- 24 小时内已有外部检测结果的节点不再被 TCP 探测覆盖，避免 TCP 成功冲掉外部检测的失败计数。
- 自动清理 30 天未出现的停用节点/仓库，保留最近 200 条运行记录（`PRUNE_DAYS=0` 关闭）。

### 新功能
- 支持整体 base64 编码的订阅文件；过滤 `package-lock.json` 等无关文件。
- 面板：已发布 / 待评估计数、风险等级中文标签与评估时间、手动扫描改为异步（202 + 轮询）、配置告警（仅管理员可见）。
- Clash 输出：支持 `alpn` 等数组字段、空对象/数组、`profile-update-interval` 响应头。
- 本地测试：`npm test`（27 个用例，用 `node:sqlite` 模拟 D1、模拟 GitHub 与 TCP）。

### 行为变化（升级前请留意）
`/api/nodes` 需令牌；`/admin/run` 异步返回 202；发布要求风险评估未过期；解析更严格（见上）。


## v3.4.0
- 新增基于 KV 的网站密码登录：8 小时 HttpOnly/Secure/SameSite=Strict 会话，支持退出撤销。
- 新增登录失败的 IP 维度尽力限流。
- 管理网站支持 `PUBLIC_BASE_URL` 展示自定义域名订阅链接。
- 增加 Terser 压缩/局部变量混淆构建脚本与独立 wrangler 配置。
- 新增网站登录与会话测试。
