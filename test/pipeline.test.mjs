import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadWorker, makeDb, mockGithub, b64, UUID } from "./harness.mjs";

const w = await loadWorker();
const here = path.dirname(fileURLToPath(import.meta.url));
const DAY = 86_400_000;
const GOOD_A = "trojan://pw1@a.example.com:443?sni=a.example.com#node-a";
const GOOD_B = `vless://${UUID}@b.example.com:443?security=tls&sni=b.example.com#node-b`;
const BAD_PRIVATE = "trojan://pw@192.168.1.5:443#private";
const INSECURE = "trojan://pw@c.example.com:443?allowInsecure=1#insecure";
const REPO_FILES = {
  "sub/nodes.txt": [GOOD_A, GOOD_B, BAD_PRIVATE, INSECURE].join("\n"),
  "sub/encoded.txt": b64(`trojan://pw3@d.example.com:443#node-d\n`),
  "package-lock.json": GOOD_A + " in lock file should be ignored"
};

function setup({ repos = { "o/r": { files: REPO_FILES } }, env = {}, migrations, connectOk = () => true } = {}) {
  const { DB, sqlite, log } = makeDb(migrations);
  const calls = mockGithub(repos);
  const probed = [];
  globalThis.__connect = ({ hostname, port }) => {
    probed.push(`${hostname}:${port}`);
    const ok = connectOk(hostname, port);
    return { opened: ok ? Promise.resolve() : Promise.reject(new Error("refused")), close: async () => {} };
  };
  const pending = [];
  const e = { DB, SUBSCRIPTION_KEY: "sub-key-0123456789-abcdefghij", ADMIN_TOKEN: "admin-token-xyz", ...env };
  const ctx = { waitUntil: p => pending.push(p) };
  const call = async (p, init = {}) => w.default.fetch(new Request("https://w.test" + p, init), e, ctx);
  const admin = { authorization: "Bearer admin-token-xyz" };
  return { env: e, DB, sqlite, log, calls, probed, pending, ctx, call, admin };
}
const rows = (t, sql, ...a) => t.sqlite.prepare(sql).all(...a);
const report = (t, results) => t.call("/admin/health-report", { method: "POST", headers: t.admin, body: JSON.stringify({ results }) });

test("首次运行：入库、server/port 回填、过滤私网/明文/lock 文件，base64 文件被解码", async () => {
  const t = setup();
  const s = await w.runPipeline(t.env, "test");
  assert.equal(s.ok, true, JSON.stringify(s));
  assert.equal(s.inserted, 3);                       // a, b, d
  assert.equal(s.parseRejected, 2);                  // private + insecure
  const nodes = rows(t, "SELECT server,port,scheme,active,risk_level FROM nodes ORDER BY server");
  assert.deepEqual(nodes.map(n => `${n.server}:${n.port}`), ["a.example.com:443", "b.example.com:443", "d.example.com:443"]);
  assert.ok(nodes.every(n => n.active === 1 && n.risk_level === "unassessed"));
  assert.ok(!t.calls.some(u => u.includes("package-lock")));
  const repo = rows(t, "SELECT * FROM repositories")[0];
  assert.equal(repo.files_found, 2); assert.equal(repo.nodes_found, 3); assert.equal(repo.last_error, null);
  assert.equal(rows(t, "SELECT COUNT(*) n FROM meta WHERE key='run_lock'")[0].n, 0);   // 锁已释放
  assert.equal(rows(t, "SELECT error FROM runs")[0].error, null);
});

test("上游订阅导入：只允许固定 mini.txt 地址；格式错误条目拒收，入库后仍需风险评估", async () => {
  const upstreamUrl = "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/mini.txt";
  const t = setup({ env: { UPSTREAM_SUBSCRIPTION_URLS: upstreamUrl } });
  const baseFetch = globalThis.fetch;
  const upstreamNode = "trojan://upstream-pw@up.example.com:443?sni=up.example.com#upstream";
  globalThis.fetch = async (input, init) => {
    if (String(input) === upstreamUrl) return new Response(`${upstreamNode}\nss://11111111-2222-3333-4444-555555555555@bad.example.com:443?security=reality&encryption=none`);
    return baseFetch(input, init);
  };
  try {
    const summary = await w.runPipeline(t.env, "test");
    assert.equal(summary.upstreamSources, 1);
    assert.equal(summary.upstreamCandidates, 2);
    assert.equal(summary.parseRejected, 3); // repository 的两条拒收 + upstream 的一条
    const imported = rows(t, "SELECT source_repo,active,risk_score,risk_assessed_at FROM nodes WHERE server='up.example.com'")[0];
    assert.equal(imported.source_repo, "subscription:morpheusadam/v2ray-config:mini");
    assert.deepEqual([imported.active, imported.risk_score, imported.risk_assessed_at], [1, 0, null]);
    assert.equal((await w.runPipeline(t.env, "test")).ok, true);
  } finally { globalThis.fetch = baseFetch; }
});

test("回归：未评估节点不会在下一轮被停用，且会出现在 /admin/candidates（原版死锁）", async () => {
  const t = setup();
  await w.runPipeline(t.env, "test");
  await w.runPipeline(t.env, "test");
  assert.equal(rows(t, "SELECT COUNT(*) n FROM nodes WHERE active=1")[0].n, 3);
  const r = await (await t.call("/admin/candidates", { headers: t.admin })).json();
  assert.equal(r.candidates.length, 3);
  assert.ok(r.candidates.every(c => c.server && c.port));
});

test("回归：/api/nodes 与 /admin/candidates 不再因缺列而抛错（原版 no such column: server）", async () => {
  const t = setup();
  await w.runPipeline(t.env, "test");
  assert.equal((await t.call("/api/nodes", { headers: t.admin })).status, 200);
  assert.equal((await t.call("/admin/candidates", { headers: t.admin })).status, 200);
});

test("风险过滤：riskScore ≥ 50 才发布；<50、未评估、评估过期都不发布", async () => {
  const t = setup();
  await w.runPipeline(t.env, "test");
  const fp = Object.fromEntries(rows(t, "SELECT server,fingerprint FROM nodes").map(r => [r.server, r.fingerprint]));
  const sub = async p => (await t.call(`${p}?key=${t.env.SUBSCRIPTION_KEY}`)).text();
  assert.equal(Buffer.from(await sub("/sub/v2rayng"), "base64").toString(), "");            // 默认无任何发布
  assert.match(await sub("/sub/clash"), /proxies: \[\]/);

  const res = await (await report(t, [
    { fingerprint: fp["a.example.com"], ok: true, latencyMs: 120, exitIp: "203.0.113.10", country: "US", method: "mihomo-url-test", riskScore: 85, riskReasons: ["clean exit ip"] },
    { fingerprint: fp["b.example.com"], ok: true, latencyMs: 90, method: "mihomo-url-test", riskScore: 30, riskReasons: ["injects content"] },
    { fingerprint: "not-a-fingerprint", ok: true }
  ])).json();
  assert.deepEqual([res.received, res.accepted, res.updated], [3, 2, 2]);

  const lines = Buffer.from(await sub("/sub/v2rayng"), "base64").toString().split("\n");
  assert.deepEqual(lines, [GOOD_A]);
  const clash = await sub("/sub/clash");
  assert.match(clash, /node-a/); assert.doesNotMatch(clash, /node-b/);
  const a = rows(t, "SELECT risk_level,risk_reasons,exit_ip,country FROM nodes WHERE server='a.example.com'")[0];
  assert.deepEqual([a.risk_level, a.exit_ip, a.country, a.risk_reasons], ["low", "203.0.113.10", "US", '["clean exit ip"]']);
  assert.equal(rows(t, "SELECT risk_level FROM nodes WHERE server='b.example.com'")[0].risk_level, "high");

  // 评估 8 天前 → 超过默认 7 天有效期，自动撤下
  t.sqlite.prepare("UPDATE nodes SET risk_assessed_at=? WHERE server='a.example.com'").run(Date.now() - 8 * DAY);
  assert.equal(Buffer.from(await sub("/sub/v2rayng"), "base64").toString(), "");
  t.env.RISK_MAX_AGE_DAYS = "0";                      // 0 = 不限有效期
  assert.equal(Buffer.from(await sub("/sub/v2rayng"), "base64").toString(), GOOD_A);
});

test("健康上报：ok:true 不因 last_seen 过期而停用节点（成功检测=更强证据）", async () => {
  const t = setup();
  await w.runPipeline(t.env, "test");
  const fp = rows(t, "SELECT fingerprint FROM nodes WHERE server='a.example.com'")[0].fingerprint;
  t.sqlite.prepare("UPDATE nodes SET last_seen=? WHERE fingerprint=?").run(Date.now() - 4 * DAY, fp);   // 来源过期（>72h）
  const res = await report(t, [{ fingerprint: fp, ok: true, latencyMs: 120, riskScore: 85 }]);
  assert.equal(res.status, 200);
  const n = rows(t, "SELECT active,risk_score,risk_assessed_at FROM nodes WHERE fingerprint=?", fp)[0];
  assert.equal(n.active, 1);            // 成功检测不因来源过期而停用
  assert.equal(n.risk_score, 85);
});

test("维护：last_seen 过期但 last_success 在 24h 内 → 不停用（成功信号强于来源）", async () => {
  const t = setup();
  await w.runPipeline(t.env, "test");
  const fp = rows(t, "SELECT fingerprint FROM nodes WHERE server='a.example.com'")[0].fingerprint;
  // a 来源过期（>72h），但最近 1 小时内有成功检测：maintenance 不应按来源过期停用。
  t.sqlite.prepare("UPDATE nodes SET last_seen=?, last_success=? WHERE fingerprint=?").run(Date.now() - 4 * DAY, Date.now() - 3600_000, fp);
  mockGithub({ "o/r": { files: { "sub/nodes.txt": GOOD_B } } });   // 本轮仓库里已没有 a
  const s = await w.runPipeline(t.env, "test");
  assert.equal(s.reposScanned, 1);
  assert.equal(rows(t, "SELECT active FROM nodes WHERE fingerprint=?", fp)[0].active, 1);
});

test("健康上报：失败累计 3 次停用；ok 上报不再与风险分耦合（原版绑定数量 9≠8）", async () => {
  const t = setup();
  await w.runPipeline(t.env, "test");
  const fp = rows(t, "SELECT fingerprint FROM nodes WHERE server='a.example.com'")[0].fingerprint;
  for (let i = 0; i < 3; i++) await report(t, [{ fingerprint: fp, ok: false, reason: "handshake timeout", method: "mihomo-url-test" }]);
  const n = rows(t, "SELECT active,fail_count,last_error FROM nodes WHERE fingerprint=?", fp)[0];
  assert.deepEqual([n.active, n.fail_count, n.last_error], [0, 3, "handshake timeout"]);
});

test("网络质量上报：保存丢包/抖动/测速/DNS/IPv6/黑名单并计算保守风险分", async () => {
  const t = setup();
  await w.runPipeline(t.env, "test");
  const fp = rows(t, "SELECT fingerprint FROM nodes WHERE server='a.example.com'")[0].fingerprint;
  const r = await report(t, [{ fingerprint: fp, ok: true, latencyMs: 123, httpLoss: 0.05, jitterMs: 42,
    speedKbps: 2048, dnsLeak: false, ipv6Leak: false, proxyDetected: false, blacklistHits: 0,
    isDatacenter: true, qualityScore: 91, checkDetails: ["HTTP 多目标通过", "出口 IP 已复核"] }]);
  assert.equal(r.status, 200);
  const n = rows(t, "SELECT http_loss,jitter_ms,speed_kbps,dns_leak,ipv6_leak,proxy_detected,blacklist_hits,is_datacenter,quality_score,risk_score,risk_level,check_details FROM nodes WHERE fingerprint=?", fp)[0];
  assert.equal(n.http_loss, 0.05);
  assert.equal(n.jitter_ms, 42);
  assert.equal(n.speed_kbps, 2048);
  assert.equal(n.dns_leak, 0);
  assert.equal(n.ipv6_leak, 0);
  assert.equal(n.proxy_detected, 0);
  assert.equal(n.blacklist_hits, 0);
  assert.equal(n.is_datacenter, 1);
  assert.equal(n.quality_score, 91);
  assert.equal(n.risk_score, 89); // 100 - 5% loss penalty - datacenter penalty (rounded)
  assert.equal(n.risk_level, "low");
  assert.match(n.check_details, /HTTP 多目标通过/);
  const sum = await t.call("/admin/network-summary", { headers: t.admin });
  assert.equal(sum.status, 200);
  assert.equal((await sum.json()).summary.dns_leaks, 0);
});

test("回归 P0：JSON null 数值保持未知，不生成虚假的低风险评分", async () => {
  const t = setup();
  await w.runPipeline(t.env, "test");
  const fp = rows(t, "SELECT fingerprint FROM nodes WHERE server='a.example.com'")[0].fingerprint;
  t.sqlite.prepare("UPDATE nodes SET risk_assessed_at=NULL WHERE fingerprint=?").run(fp);
  const res = await report(t, [{ fingerprint: fp, ok: true, latencyMs: null, httpLoss: null,
    jitterMs: null, speedKbps: null, blacklistHits: null, qualityScore: null, riskScore: null }]);
  assert.equal(res.status, 200);
  const n = rows(t, "SELECT latency_ms,http_loss,jitter_ms,speed_kbps,blacklist_hits,quality_score,risk_score,risk_assessed_at FROM nodes WHERE fingerprint=?", fp)[0];
  assert.equal(n.latency_ms, null);
  assert.equal(n.http_loss, null);
  assert.equal(n.jitter_ms, null);
  assert.equal(n.speed_kbps, null);
  assert.equal(n.blacklist_hits, null);
  assert.equal(n.quality_score, null);
  assert.equal(n.risk_assessed_at, null);
});

test("回归 P1：RISK_MAX_AGE_DAYS=0 时网络汇总统计所有已评估节点", async () => {
  const t = setup({ env: { RISK_MAX_AGE_DAYS: "0" } });
  await w.runPipeline(t.env, "test");
  const fp = rows(t, "SELECT fingerprint FROM nodes WHERE server='a.example.com'")[0].fingerprint;
  await report(t, [{ fingerprint: fp, ok: true, latencyMs: 80, riskScore: 90 }]);
  t.sqlite.prepare("UPDATE nodes SET risk_assessed_at=? WHERE fingerprint=?").run(Date.now() - 100 * DAY, fp);
  const res = await t.call("/admin/network-summary", { headers: t.admin });
  assert.equal(res.status, 200);
  assert.equal((await res.json()).summary.assessed, 1);
});

test("网站密码登录：KV 会话可访问管理接口、登出后立即失效", async () => {
  const data = new Map();
  const KV = {
    async get(k) { return data.has(k) ? data.get(k) : null; },
    async put(k, v) { data.set(k, String(v)); },
    async delete(k) { data.delete(k); }
  };
  const t = setup({ env: { KV, ADMIN_PASSWORD: "a-long-test-password" } });
  const bad = await t.call("/auth/login", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ password: "wrong" }) });
  assert.equal(bad.status, 401);
  const ok = await t.call("/auth/login", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ password: "a-long-test-password" }) });
  assert.equal(ok.status, 200);
  const cookie = ok.headers.get("set-cookie").split(";")[0];
  assert.match(ok.headers.get("set-cookie"), /HttpOnly/);
  assert.match(ok.headers.get("set-cookie"), /SameSite=Strict/);
  assert.equal((await t.call("/admin/candidates", { headers: { cookie } })).status, 200);
  await t.call("/auth/logout", { method: "POST", headers: { cookie } });
  assert.equal((await t.call("/admin/candidates", { headers: { cookie } })).status, 401);
});

test("认证：订阅密钥/管理员令牌错误 → 401；ADMIN_TOKEN 与 SUBSCRIPTION_KEY 相同 → 管理接口拒绝", async () => {
  const t = setup();
  await w.runPipeline(t.env, "test");
  assert.equal((await t.call("/sub/clash")).status, 401);
  assert.equal((await t.call("/sub/clash?key=wrong")).status, 401);
  assert.equal((await t.call("/api/nodes")).status, 401);
  assert.equal((await t.call("/admin/candidates", { headers: { authorization: "Bearer nope" } })).status, 401);
  assert.equal((await t.call("/admin/run", { method: "POST" })).status, 401);
  assert.equal((await t.call("/admin/run", { headers: t.admin })).status, 405);
  const same = { ...t.env, ADMIN_TOKEN: t.env.SUBSCRIPTION_KEY };
  const r = await w.default.fetch(new Request("https://w.test/admin/candidates", { headers: { authorization: "Bearer " + t.env.SUBSCRIPTION_KEY } }), same, t.ctx);
  assert.equal(r.status, 401);
  const st = await (await t.call("/api/status")).json();
  assert.equal(st.configWarnings, undefined);                       // 公开状态不泄露配置告警
  assert.ok((await (await t.call("/api/status", { headers: t.admin })).json()).configWarnings.length >= 1);   // 管理员可见（如缺 GITHUB_TOKEN）
});

test("手动扫描：202 异步启动；运行中再次触发 → 409；并发 runPipeline 被跳过", async () => {
  const t = setup();
  const r1 = await t.call("/admin/run", { method: "POST", headers: t.admin });
  assert.equal(r1.status, 202);
  await Promise.all(t.pending);
  assert.equal(rows(t, "SELECT COUNT(*) n FROM runs")[0].n, 1);
  t.sqlite.prepare("INSERT INTO meta(key,value) VALUES('run_lock',?)").run(String(Date.now()));
  assert.equal((await t.call("/admin/run", { method: "POST", headers: t.admin })).status, 409);
  assert.equal((await w.runPipeline(t.env, "test")).skipped, "another run is in progress");
  t.sqlite.prepare("UPDATE meta SET value=? WHERE key='run_lock'").run(String(Date.now() - 31 * 60_000));   // 过期锁可被接管
  assert.equal((await w.runPipeline(t.env, "test")).ok, true);
});

test("过期：72 小时未重新发现且无近期成功检测 → 停用；GitHub 整体失败时不误杀", async () => {
  const t = setup();
  await w.runPipeline(t.env, "test");
  // a 上一轮 TCP 探测成功过（last_success 新鲜）。这里把 last_seen 与 last_success 一起拨旧，
  // 让该用例只覆盖“既未重新发现、也无近期成功检测”的节点（maintenance 以 last_success 为更强存活信号）。
  t.sqlite.prepare("UPDATE nodes SET last_seen=?, last_success=? WHERE server='a.example.com'").run(Date.now() - 4 * DAY, Date.now() - 4 * DAY);
  mockGithub({});                                                    // 本轮搜索不到任何仓库
  const s = await w.runPipeline(t.env, "test");
  assert.equal(s.reposScanned, 0);
  assert.equal(rows(t, "SELECT active FROM nodes WHERE server='a.example.com'")[0].active, 1);
  mockGithub({ "o/r": { files: REPO_FILES } });
  t.sqlite.prepare("UPDATE nodes SET last_seen=? WHERE server='b.example.com'").run(Date.now() - 4 * DAY);
  // 有扫描成功的仓库但文件里已没有 a 节点：a 无来源也无近期成功 → 过期停用；b 仍被发现，刷新 last_seen
  mockGithub({ "o/r": { files: { "sub/nodes.txt": GOOD_B } } });
  await w.runPipeline(t.env, "test");
  assert.equal(rows(t, "SELECT active FROM nodes WHERE server='a.example.com'")[0].active, 0);
  assert.equal(rows(t, "SELECT active FROM nodes WHERE server='b.example.com'")[0].active, 1);
});

test("TCP 探测：失败 3 次停用；外部检测 24h 内的节点不被 TCP 覆盖；同主机最多 3 个", async () => {
  const t = setup({ connectOk: host => host !== "b.example.com" });
  await w.runPipeline(t.env, "test");                                // 第 1 次：b 失败
  await w.runPipeline(t.env, "test");
  await w.runPipeline(t.env, "test");
  assert.equal(rows(t, "SELECT active,fail_count FROM nodes WHERE server='b.example.com'")[0].active, 0);
  assert.equal(rows(t, "SELECT active,check_method FROM nodes WHERE server='a.example.com'")[0].check_method, "tcp");

  const t2 = setup();
  await w.runPipeline(t2.env, "test");
  const fp = rows(t2, "SELECT fingerprint FROM nodes WHERE server='a.example.com'")[0].fingerprint;
  await report(t2, [{ fingerprint: fp, ok: true, method: "mihomo-url-test", riskScore: 80 }]);
  t2.probed.length = 0;
  await w.runPipeline(t2.env, "test");
  assert.ok(!t2.probed.some(p => p.startsWith("a.example.com")), "已被外部检测的节点不应再 TCP 探测");

  const many = Array.from({ length: 6 }, (_, i) => `trojan://pw@same.example.com:${9000 + i}#p${i}`).join("\n");
  const t3 = setup({ repos: { "o/r": { files: { "x.txt": many } } } });
  await w.runPipeline(t3.env, "test");
  assert.equal(t3.probed.length, 3);
});

test("预算：SUBREQUEST_BUDGET 很小时提前收尾，不崩溃且释放锁", async () => {
  const files = Object.fromEntries(Array.from({ length: 15 }, (_, i) => [`sub/f${i}.txt`, `trojan://pw@h${i}.example.com:443#n${i}`]));
  const t = setup({ repos: { "o/r": { files } }, env: { SUBREQUEST_BUDGET: "20" } });
  const s = await w.runPipeline(t.env, "test");
  assert.equal(s.ok, true, JSON.stringify(s));
  assert.equal(s.stoppedEarly, "budget");
  assert.ok(s.filesRead < 15 && s.filesRead > 0, "filesRead=" + s.filesRead);
  assert.ok(s.subrequestsUsed <= 20 + 4, "used=" + s.subrequestsUsed);          // 收尾写库允许小幅超出
  assert.equal(rows(t, "SELECT COUNT(*) n FROM meta WHERE key='run_lock'")[0].n, 0);
});

test("批量写入：D1 请求数远小于节点数（原版每个 URI 2 次查询）", async () => {
  const many = Array.from({ length: 300 }, (_, i) => `trojan://pw${i}@h${i}.example.com:443#n${i}`).join("\n");
  const t = setup({ repos: { "o/r": { files: { "x.txt": many } } }, env: { PROBE_LIMIT: "0" } });
  const s = await w.runPipeline(t.env, "test");
  assert.equal(s.inserted, 300);
  assert.ok(t.log.queries + t.log.batches < 40, `queries=${t.log.queries} batches=${t.log.batches}`);
});

test("旧库自动补列：v3.0/3.1 的 0001 schema 无需手工迁移", async () => {
  const legacy = path.join(here, "fixtures/legacy-0001_init.sql");
  const { DB, sqlite, log } = makeDb([]);
  sqlite.exec(fs.readFileSync(legacy, "utf8"));
  sqlite.prepare("INSERT INTO nodes(fingerprint,canonical,uri,scheme,first_seen,last_seen,last_checked,risk_score,risk_level) VALUES('f1','c',?,'trojan',1,?,5,70,'neutral')")
    .run(GOOD_A, Date.now());
  mockGithub({ "o/r": { files: { "x.txt": GOOD_B } } });
  globalThis.__connect = () => ({ opened: Promise.resolve(), close: async () => {} });
  const env = { DB, SUBSCRIPTION_KEY: "k".repeat(30), ADMIN_TOKEN: "t" };
  const s = await w.runPipeline(env, "test");
  assert.equal(s.ok, true, JSON.stringify(s));
  const cols = sqlite.prepare("PRAGMA table_info(nodes)").all().map(c => c.name);
  for (const c of ["server", "port", "risk_assessed_at"]) assert.ok(cols.includes(c), c);
  const old = sqlite.prepare("SELECT server,port,risk_assessed_at FROM nodes WHERE fingerprint='f1'").get();
  assert.deepEqual([old.server, old.port, old.risk_assessed_at], ["a.example.com", 443, 5]);   // 回填 + 已有风险分视为已评估
});

test("缺表时给出明确错误，而不是神秘 500", async () => {
  const { DB } = makeDb([]);
  const r = await w.default.fetch(new Request("https://w.test/api/status"), { DB }, { waitUntil() {} });
  assert.equal(r.status, 500);
  assert.match((await r.json()).hint, /0001_init\.sql/);
});

test("仪表盘：/health 与 / 可访问，带 CSP，令牌不进入 HTML", async () => {
  const t = setup();
  assert.equal((await t.call("/health")).status, 200);
  const r = await t.call("/");
  const html = await r.text();
  assert.match(r.headers.get("content-security-policy"), /default-src 'none'/);
  assert.ok(!html.includes("admin-token-xyz") && !html.includes(t.env.SUBSCRIPTION_KEY));
  const script = html.split("<script>")[1].split("</script>")[0];
  new Function(script);                                              // 内嵌脚本语法必须合法
  assert.match(script, /\\x60/);
  assert.match(html, /二维码/);
  assert.match(html, /runBrowserDiagnostics/);                                     // 正则里的反引号转义保持原样
});
