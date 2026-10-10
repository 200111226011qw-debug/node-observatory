# Node Observatory v3.9.0 — 网络质量指标与订阅二维码版

从 GitHub 公开仓库采集节点 URI，去重、初筛、风险过滤后，通过固定订阅地址发布。运行在 Cloudflare Worker + D1，Cron 每 12 小时一次。

本版本基于 v3.3，保留 KV 会话、网站密码登录、自定义公开域名显示与 Terser 混淆构建流程；新增订阅二维码、本机浏览器出口/WebRTC诊断、外部检测器网络质量指标存储、风险分保守估算与管理摘要接口。

本 v3.9.0 包基于上传的 v3.8.1 项目进行增量升级整理，保留原有功能与数据库迁移；本次版本号更新不代表新增了未实现的监控能力。**从旧版升级只需替换 `src/index.js` 并重新部署**，Worker 会自动补齐缺失的数据库列（先备份 D1 更稳妥）。

## v3.9.0 新增功能与边界
- 订阅面板可输入 `SUBSCRIPTION_KEY`，生成 Clash/Mihomo 与 v2rayNG 订阅链接及二维码。二维码库通过 jsDelivr 加载；订阅密钥仅在当前浏览器拼接，不上传到二维码服务。若 CDN 被屏蔽，二维码不会生成，但复制链接仍可使用。
- 本机网络诊断检查浏览器可访问的公网出口与 WebRTC ICE 候选。这些结果只描述打开面板的设备，**不代表节点代理出口**，也不能单独证明 DNS 或 IPv6 无泄漏。
- `/admin/health-report` 接收外部检测器的 HTTP 丢包、抖动、测速、DNS/IPv6 泄漏、代理识别、数据中心属性、黑名单命中、质量分和检查说明。字段见下方接口示例。D1 旧库启动时会自动补列；如果想手动迁移，请在部署新 Worker 前执行 `migrations/0005_network_quality_metrics.sql`，不要在自动补列后重复执行。
- 如果没有显式 `riskScore`，但上报了部分风险指标，Worker 会按保守规则估算风险分。它不是第三方信誉数据库的替代品，数据中心属性也不等于恶意；正式使用前应按自己的检测器和风险政策校准。
- Worker 仍然不运行 Mihomo，也不能仅凭远程 TCP 探测验证代理协议、出口 IP、DNS 泄漏或黑名单。要填充这些字段，需将可信外部检测器的真实结果提交到 `/admin/health-report`。

### 从 3.8.x 升级到 3.9.0
- **VLESS flow 收紧**：仅接受 `xtls-rprx-vision` / `xtls-rprx-vision-udp443`。使用已废弃 flow（`xtls-rprx-direct/origin/splice`）的存量节点将在下一轮扫描后因解析失败退出订阅，可用 `SELECT COUNT(*) FROM nodes WHERE canonical LIKE '%xtls-rprx-%'` 评估影响面。
- **节点存活上限 72h → 约 96h**：无来源刷新时最多存活 72h + 24h（最近成功检测的宽限），外部检测器持续上报成功时不受此上限约束（详见「工作方式 · 发布」与「重要的准确性与安全边界」）。
- **`scripts/public-probe.py` 基准分 60/80 → 40/45**（低于发布阈值 50）：单靠探针上报不再触发发布，必须由更完整的检测器给出合格 `riskScore`。

## 工作方式
1. **发现**：GitHub 搜索热门且近期更新的仓库，加上 `GITHUB_REPOS` 手动指定的源；按仓库评分排序，优先扫描。
2. **提取**：每个仓库按路径优先级最多读 18 个文件，识别 `vmess / vless / trojan / ss` URI（也支持整体 base64 的订阅文件）。
3. **过滤**：拒收私网/保留地址、危险端口、明文或跳过证书校验的节点、无法无损转换的传输（kcp/quic/httpupgrade 等）、SS 插件与老旧流加密；VLESS `flow` 仅接受 `xtls-rprx-vision` / `xtls-rprx-vision-udp443`（老式 `xtls-rprx-origin/direct/splice` 拒收）。
4. **去重**：以协议、服务器、端口、凭据与传输参数的 SHA-256 指纹为准，名称不参与去重。
5. **初筛**：内置 TCP 端口探测（仅证明端口可连）。
6. **风险评估**：由**你信任的外部检测器**通过 `/admin/health-report` 上报 `riskScore`。
7. **发布**：只有同时满足下列条件的节点进入订阅：`active=1`、`risk_score ≥ 50`、风险评估未过期（默认 7 天）。

> **默认订阅是空的**：没有任何节点会在“未评估”状态下发布。必须接入外部检测器（或自行写入风险分）后才会有内容——这是有意的安全设计。

## 重要的准确性与安全边界
1. 内置检测只是 TCP 端口初筛，不证明凭据、TLS/Reality、协议握手、DNS 或真实出口可用。
2. 完整检测请部署你信任的外部 Mihomo/Clash 检测器，用 `ADMIN_TOKEN` 调用接口。检测器应遵守来源的使用条款，限制并发、超时和出站目标，避免 SSRF 与资源滥用。
3. `GET /admin/candidates` 返回带凭据的原始 URI：只走 HTTPS，不要写入日志，不要把令牌放进 URL。
4. 风险评估只能降低明显风险，无法证明公开代理可信。公开节点可能记录流量、篡改内容或突然更换运营者——因此评估有有效期。
5. 目前只支持常见的 VMess / VLESS / Trojan / Shadowsocks 写法；SSR、Hysteria/Hysteria2、TUIC、SS 插件、kcp/quic 等不会进入订阅。
6. 72 小时过期基于“最后一次被扫描到”，但**最近 24 小时内有成功检测（`last_success`）的节点不会被时间过期停用**——成功检测是比来源发现更强的存活信号。无来源刷新时存活上限约为 **72h + 24h = 96h**（内置 TCP 探测在 72h 后不再覆盖该节点，`last_success` 随之停止刷新；若外部检测器持续上报成功，节点会一直保持 active，不会超期下线）。
7. 不会替你部署到 Cloudflare 账户，请按下方步骤手动部署。

## 部署（Cloudflare Dashboard）

### 1. 创建 D1
Dashboard → Storage & databases → D1 → Create database，命名 `node-observatory`；在 Console 执行 `migrations/0001_init.sql` 全部内容。

已有旧库？先备份。**通常什么都不用做**——Worker 启动时自动补列。想手动执行时：

| 当前版本 | 手动迁移 |
|---|---|
| v2 | `0002_upgrade_from_v2.sql`，再执行 `0004_server_port_risk_time.sql` |
| 早期 v3（缺风险列） | `0003_risk_filter.sql`，再执行 `0004_…` |
| v3.0 / v3.1（已有风险列） | 只执行 `0004_…` |

某条语句提示 `duplicate column name` 说明该列已存在，跳过即可。

### 2. 创建 KV（网站登录必需）
Cloudflare Dashboard → Storage & databases → KV → Create namespace，命名例如 `node-observatory-sessions`。记录 namespace ID，填入 `wrangler.toml` 的 `[[kv_namespaces]]` 中，绑定名称必须是 `KV`。KV 用于存放 8 小时登录会话和登录失败计数，不替代 D1 节点数据库。

### 3. 创建 Worker
Workers & Pages → Create → Worker，把 `src/index.js` **整个**粘贴进在线编辑器并部署（单文件、无依赖）。Settings → Bindings → Add D1 database，变量名 `DB`。

也可用 CLI：`npm i && npx wrangler deploy`（先在 `wrangler.toml` 填入 `database_id`）。

### 4. 变量与密钥（Settings → Variables and Secrets）
| 名称 | 类型 | 说明 |
|---|---|---|
| `SUBSCRIPTION_KEY` | Secret | 订阅专用随机密钥，建议 ≥ 24 字符 |
| `ADMIN_TOKEN` | Secret | 外部检测器调用管理 API 的令牌，**必须与订阅密钥不同** |
| `ADMIN_PASSWORD` | Secret | 网站管理面板登录密码；建议使用密码管理器生成的长随机密码 |
| `PUBLIC_BASE_URL` | Text（可选） | 面板显示订阅链接时使用的 HTTPS 自定义域名，例如 `https://nodes.example.com`；仍需先在 Cloudflare 为 Worker 绑定该域名 |
| `GITHUB_TOKEN` | Secret | 强烈建议：未认证的 GitHub API 配额很低，容易被限流 |
| `GITHUB_REPOS` | Text | 逗号分隔的 `owner/repo`，优先扫描 |
| `GITHUB_SEARCH_QUERIES` | Text | 用 `||` 分隔的搜索表达式，覆盖默认值 |
| `UPSTREAM_SUBSCRIPTION_URLS` | Text（可选） | 经人工验收后启用的上游订阅 URL；当前只允许指定的 `morpheusadam/v2ray-config` `mini.txt` 固定地址，多个值用 `||` 分隔 |

### 5. 定时触发
Settings → Triggers → Cron Triggers：`0 0,12 * * *`（UTC）。

### 6. 验证
- `/health`、`/api/status`
- 面板 `/`：使用 `ADMIN_PASSWORD` 登录；会话通过 HttpOnly、Secure、SameSite=Strict Cookie + KV 保存，8 小时过期；点击“退出登录”可立即撤销
- 外部检测器仍使用 `Authorization: Bearer ADMIN_TOKEN`，不要把网站密码用作检测器令牌
- 手动扫描：`POST /admin/run`，Header `Authorization: Bearer ADMIN_TOKEN`，返回 `202`，进度看 `/api/status` 的 `running` 与 `lastRunSummary`
- 订阅：`/sub/clash?key=…`、`/sub/v2rayng?key=…`

## 配置项（均为可选）
| 变量 | 默认 | 作用 |
|---|---|---|
| `MAX_REPOS` | 60 | 每轮最多处理的仓库数（1–200） |
| `MAX_FILES_PER_REPO` | 18 | 每个仓库最多读取的文件数 |
| `SUBREQUEST_BUDGET` | 900 | 每轮外部请求 + D1 请求的预算，用尽即收尾（见下方“套餐限制”） |
| `PROBE_LIMIT` | 300 | 每轮 TCP 探测上限；`0` 关闭内置探测 |
| `PROBE_TIMEOUT_MS` | 2500 | 单次探测超时 |
| `RISK_MAX_AGE_DAYS` | 7 | 风险评估有效期；`0` 表示不限 |
| `MAX_PUBLISHED` | 1000 | 订阅最多输出节点数 |
| `PRUNE_DAYS` | 30 | 清理多少天未出现的停用节点/仓库；`0` 关闭 |
| `ALLOW_INSECURE` | 关 | 设为 `1` 才接受明文 VLESS / 跳过证书校验的节点（不建议） |

### 套餐限制
Worker 每次调用允许的子请求数与 CPU 时间取决于套餐，Free 计划的额度远低于完整扫描所需，通常需要 Workers Paid；D1 请求也可能计入子请求限额，所以写入已合并为 batch。`SUBREQUEST_BUDGET` 默认 900 是按“付费计划约 1000 次”估的保守值——**请以 Cloudflare 官方文档的当前额度为准**，Free 计划请把它与 `MAX_REPOS`、`PROBE_LIMIT` 调小。这些额度本版本未在真实账户上实测。

## 外部订阅源（v3.3）

上游候选源：
`https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/mini.txt`

**默认关闭，不会自动抓取。** 原因是当前公开文件样本中出现大量 `ss://` 前缀但携带 VLESS/Reality 参数的条目，和标准 Shadowsocks URI 不一致；不能仅凭上游声称“已检测”就直接信任。只有在你接受其质量风险并希望把它作为候选来源时，才在 Worker 的 Variables 中设置：

`UPSTREAM_SUBSCRIPTION_URLS=https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/mini.txt`

当前实现仅允许该精确 HTTPS 主机与路径，拒绝任意 URL，避免把 Worker 变成通用抓取代理。导入器会复用现有严格解析器，格式不合法、私网/保留地址、危险端口、不支持协议和不允许的不安全配置都会被拒收；来源节点只是进入候选数据库，仍然默认 `risk_score=0`，**不会因此自动进入订阅**。必须由外部检测器完成真实代理验证并上报合格风险分后，才可能发布。

扫描摘要会记录 `upstreamSources`、`upstreamCandidates`、`parseRejected`。外部来源导入会消耗每轮请求预算；如果预算不足会提前停止。

## 风险等级与订阅准入
风险分 0–100，**越高风险越低**：`80–100` 低风险；`50–79` 中性；`25–49` 高风险；`0–24` 严重风险。分数 `≥ 50` 且评估未过期的活跃节点才会发布；其余保留在库里供分析。

## 外部检测器接口
所有 `/admin/*` 请求头：`Authorization: Bearer ADMIN_TOKEN`。

**获取候选** `GET /admin/candidates?limit=2000`：返回活跃节点（**不按风险过滤**，否则未评估节点永远得不到检测），未评估/评估最久的排在前面。

**上报结果** `POST /admin/health-report`（一次最多 1000 条）：
```json
{
  "results": [
    {
      "fingerprint": "candidates 返回的 64 位 SHA-256 指纹",
      "ok": true,
      "latencyMs": 180,
      "exitIp": "203.0.113.10",
      "country": "US",
      "method": "mihomo-url-test",
      "riskScore": 85,
      "riskReasons": ["出口 IP 已通过多个来源核验"],
      "httpLoss": 0.02,
      "jitterMs": 35,
      "speedKbps": 2048,
      "dnsLeak": false,
      "ipv6Leak": false,
      "proxyDetected": false,
      "blacklistHits": 0,
      "isDatacenter": true,
      "qualityScore": 91,
      "checkDetails": ["HTTP 多目标成功", "出口 IP 已复核"]
    },
    {
      "fingerprint": "另一个指纹",
      "ok": false,
      "reason": "handshake timeout",
      "method": "mihomo-url-test"
    }
  ]
}
```
- `riskScore`（可选）：写入风险分与等级，并刷新评估时间。省略则不改变风险字段。
- `ok:true`：清零失败次数、更新最后成功时间；`ok:false`：失败计数 +1，连续 3 次停用。
- `exitIp` 应是检测器实测的出口地址，不要填节点服务器 IP。
- 24 小时内有外部检测结果的节点，不会再被内置 TCP 探测覆盖。

## 公共检测器（v3.8）

仓库新增 `scripts/public-probe.py`，用于通过**一个明确指定的代理**请求固定公共出口检测端点，并将实测结果上报到 `/admin/health-report`。它不会自动解析并并发连接所有订阅节点；建议先在受控环境中逐个代理运行，或用 Mihomo/Clash 外部调度器将候选节点逐个映射到本地代理端口。

依赖：`python -m pip install 'requests[socks]'`。可选设置 `PROXYCHECK_API_KEY` 以查询代理信誉。GeoIP 使用 IP-API 的免费端点，须遵守其服务条款和速率限制。示例：

```bash
export ADMIN_TOKEN='替换为独立的管理令牌'
export PROXYCHECK_API_KEY='可选的代理信誉 API Key'
python scripts/public-probe.py \
  --proxy 'socks5h://127.0.0.1:1080' \
  --fingerprint '从 /admin/candidates 获取的64位指纹' \
  --report-url 'https://你的Worker域名'
```

重要限制：
- 出口 IP 通过代理访问 ipify 与 Cloudflare trace 实测；若两个来源结果不一致，不会把其中一个当成确定出口 IP。
- GeoIP/托管网络字段来自公共数据库，可能误判；数据中心属性不等于恶意或不纯净。
- 只有提供了可用的 ProxyCheck API Key 时才尝试其代理识别；第三方失败时保留未知状态。
- 此脚本**不会声称已验证 DNS 泄漏、IPv6 泄漏或黑名单**，这些字段只有在接入专门测试端点/可靠信誉源后才会上报。未知不等于通过。
- 此脚本的初筛风险分低于发布阈值（`PUBLISH_MIN_SCORE=50`），仅凭经代理拿到出口 IP 不会让节点进入订阅；仍需更完整的外部检测器上报合格风险分后才可能发布。
- 该脚本一次只检测一个代理。请控制并发、遵守公共 API 限额，并且只测试你有权使用的代理。

## 网站登录与安全说明（v3.6）
- 必须设置 Secret `ADMIN_PASSWORD` 并绑定 KV（`KV`）。没有两者时，网站密码登录会明确返回配置错误；管理 API 仍可由独立 `ADMIN_TOKEN` 调用。
- 登录会话 8 小时自动过期，退出会删除对应 KV 会话。登录失败计数按来源 IP 做 15 分钟窗口的尽力限流（KV 为最终一致存储，不能视为金融级原子限流）。
- 网站密码只在登录请求中通过 HTTPS 发送；不要把密码写进 `wrangler.toml`、仓库或前端代码。建议为 Worker 绑定自定义域名并启用 Cloudflare 的安全规则。
- `PUBLIC_BASE_URL` 只控制面板展示的订阅地址，不会替你创建 DNS 记录或绑定 Custom Domain。

## 混淆/压缩构建
本包提供 `scripts/build-obfuscated.mjs`，用 Terser 压缩并混淆局部变量名，关闭 source map。它主要用于减少源码可读性与体积，**不是加密，也不能阻止有经验的人逆向**。本交付环境无法下载 Terser，因此未预生成或验证 `dist/worker.obfuscated.js`；请在可联网的本地环境执行：

```bash
npm install
npm run check
npm test
npm run build:obfuscated
npx wrangler deploy --config wrangler-obfuscated.toml
```

部署前需把 `wrangler-obfuscated.toml` 中的 D1 和 KV ID 替换为自己的值，并确认绑定与正式 Worker 一致。建议先用普通源码版部署验收，再部署混淆构建版。

## UUID 与自定义域名的区别
当前 Node Observatory 是**订阅采集与发布器**，不运行 VLESS/Trojan 代理服务，因此在这里设置 UUID 不会凭空创建代理节点，也不会让收集到的节点改用你的 UUID。自定义域名可以通过 Cloudflare Custom Domain + `PUBLIC_BASE_URL` 用于展示订阅地址。如果你说的 UUID 是想部署“自己的 VLESS/WS/TLS 代理入口”，那是另一个 Worker/代理服务，需要单独的配置与安全审查，不应把它伪装成订阅采集器功能。

## 本地开发与测试
```bash
npm run check   # 语法检查
npm test        # 29 个用例（需 Node ≥ 22.13）
```
测试用 `node:sqlite` 模拟 D1（绑定数量与 D1 一样严格校验），模拟 GitHub 与 TCP 连接，覆盖解析、去重、风险过滤、认证、并发锁、过期、预算、旧库升级等。

## 当前验证状态
- 已通过：语法检查、36 个本地测试、Clash 输出经 PyYAML 解析、面板脚本在桩 DOM 中实跑。
- **未做**：真实 Cloudflare 部署与套餐限额实测；真实 GitHub API 采集覆盖率；真实 Mihomo 握手与出口 IP 检测；Clash / v2rayNG 客户端导入测试。
