import { connect } from "cloudflare:sockets";

// ───────────────────────────── 常量与配置 ─────────────────────────────
const VERSION = "3.9.0";
const DAY = 86_400_000;
const EXPIRE_MS = 3 * DAY;            // 72 小时未被重新发现 → 停用
const PUBLISH_MIN_SCORE = 50;         // 风险分 >= 50 才允许进入订阅
const MAX_FILE_BYTES = 1_500_000;
const MAX_URI_LENGTH = 8192;
const LOCK_TTL_MS = 30 * 60_000;
const UA = "github-node-subscription-worker/" + VERSION;
const ALLOWED_SCHEMES = new Set(["vmess", "vless", "trojan", "ss"]);
// 常见数据库/邮件/远程管理端口：公开列表里出现这些端口基本是扫描诱饵，直接拒收。
const BLOCKED_PORTS = new Set([22, 23, 25, 110, 143, 445, 3306, 3389, 5432, 6379, 9200, 11211, 27017]);
// 仅接受 AEAD / SS2022；RC4、CFB 等老旧流加密不进入订阅。
const SS_CIPHERS = new Set([
  "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
  "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"
]);
const VMESS_CIPHERS = new Set(["auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"]);
const FILE_RE = /\.(txt|ya?ml|json|conf|list)$/i;
const SKIP_PATH_RE = /(^|\/)(node_modules|\.github|vendor)\/|(^|\/)(package(-lock)?\.json|tsconfig[^/]*\.json|composer\.json|renovate\.json|\.eslintrc[^/]*)$/i;
// 发布条件：活跃 + 风险分达标 + 风险评估未过期（参数顺序：最低分、评估时间下限）
const PUBLISHABLE = "active=1 AND risk_score>=? AND risk_assessed_at IS NOT NULL AND risk_assessed_at>=?";
// VLESS flow 白名单：仅接受当前推荐的 vision 系；老式 xtls-rprx-origin/direct/splice 等不再发布。
const FLOW_WHITELIST = new Set(["xtls-rprx-vision", "xtls-rprx-vision-udp443"]);

// 采集写入路径共享的 upsert：scanRepos 与 scanUpstreamSubscriptions 唯一差别是 source。
// 11 个占位符：INSERT 的 9 个 + ON CONFLICT 里两个 last_seen<?。
const NODE_UPSERT_SQL = `INSERT INTO nodes(fingerprint,canonical,uri,scheme,server,port,source_repo,first_seen,last_seen,last_checked,last_success,active,fail_count)
  VALUES(?,?,?,?,?,?,?,?,?,0,NULL,1,0)
  ON CONFLICT(fingerprint) DO UPDATE SET last_seen=excluded.last_seen,source_repo=excluded.source_repo,uri=excluded.uri,server=excluded.server,port=excluded.port,
    active=CASE WHEN nodes.last_seen<? THEN 1 ELSE nodes.active END,
    fail_count=CASE WHEN nodes.last_seen<? THEN 0 ELSE nodes.fail_count END`;
function upsertNodeStmt(env, fp, canonical, uri, parsed, source, now) {
  return env.DB.prepare(NODE_UPSERT_SQL)
    .bind(fp, canonical, uri, parsed.type, parsed.server, parsed.port, source, now, now, now - EXPIRE_MS, now - EXPIRE_MS);
}

function intEnv(v, def, min, max) {
  const n = Number.parseInt(v, 10);
  return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : def;
}
function getConfig(env) {
  return {
    maxRepos: intEnv(env.MAX_REPOS, 60, 1, 200),
    filesPerRepo: intEnv(env.MAX_FILES_PER_REPO, 18, 1, 60),
    subrequestBudget: intEnv(env.SUBREQUEST_BUDGET, 900, 20, 9000),
    probeLimit: intEnv(env.PROBE_LIMIT, 300, 0, 2000),
    probeTimeoutMs: intEnv(env.PROBE_TIMEOUT_MS, 2500, 500, 10000),
    pruneDays: intEnv(env.PRUNE_DAYS, 30, 0, 365),
    riskMaxAgeDays: intEnv(env.RISK_MAX_AGE_DAYS, 7, 0, 90),
    maxPublished: intEnv(env.MAX_PUBLISHED, 1000, 1, 5000),
    allowInsecure: env.ALLOW_INSECURE === "1" || env.ALLOW_INSECURE === "true",
    searches: (env.GITHUB_SEARCH_QUERIES || "").split("||").map(s => s.trim()).filter(Boolean),
    upstreamSubscriptionUrls: (env.UPSTREAM_SUBSCRIPTION_URLS || "").split("||").map(s => s.trim()).filter(Boolean)
  };
}
function defaultSearches(now) {
  // 放在函数里计算：Worker 隔离体可能存活很久，模块顶层的日期会过期。
  const cutoff = new Date(now - 30 * DAY).toISOString().slice(0, 10);
  return [
    `proxy subscription stars:>100 pushed:>${cutoff}`,
    `clash nodes stars:>50 pushed:>${cutoff}`,
    `v2ray config stars:>50 pushed:>${cutoff}`
  ];
}
function riskLevel(score) {
  return score >= 80 ? "low" : score >= PUBLISH_MIN_SCORE ? "neutral" : score >= 25 ? "high" : "critical";
}
function publishCutoff(cfg, now) { return cfg.riskMaxAgeDays ? now - cfg.riskMaxAgeDays * DAY : 0; }

// ───────────────────────────── 入口与路由 ─────────────────────────────
export default {
  async fetch(request, env, ctx) {
    try { return await route(request, env, ctx); }
    catch (err) {
      console.error("unhandled", err?.stack || err);
      const msg = String(err?.message || err);
      // 只对“缺表需跑迁移”这类纯配置错误回传提示；其余内部错误一律不外露。
      const hint = /D1 schema missing/.test(msg) ? msg.slice(0, 200) : undefined;
      return json(hint ? { ok: false, error: "internal_error", hint } : { ok: false, error: "internal_error" }, 500);
    }
  },
  async scheduled(controller, env, ctx) {
    ctx.waitUntil(runPipeline(env, "cron").catch(err => console.error("cron run failed", err?.stack || err)));
  }
};

async function route(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname;
  if (path === "/") return dashboard(env.PUBLIC_BASE_URL && /^https:\/\/[A-Za-z0-9.-]+(?::\d+)?\/?$/i.test(env.PUBLIC_BASE_URL) ? env.PUBLIC_BASE_URL.replace(/\/+$/, "") : url.origin);
  if (path === "/health") return json({ ok: true, version: VERSION, now: new Date().toISOString() });
  if (path === "/auth/login") return login(request, env);
  if (path === "/auth/logout") return logout(request, env);
  if (path === "/auth/session") return json({ ok: true, authenticated: await hasSession(request, env) }, 200, { "cache-control": "no-store" });

  await ensureSchema(env);
  const cfg = getConfig(env);
  const now = Date.now();

  if (path === "/api/status") {
    const [counts, last, repos, run, lock] = await Promise.all([
      env.DB.prepare(`SELECT COUNT(*) n_total, SUM(active=1) n_active, SUM(${PUBLISHABLE}) n_published,
          SUM(active=1 AND risk_assessed_at IS NULL) n_unassessed, SUM(active=1 AND last_seen>?) n_fresh FROM nodes`)
        .bind(PUBLISH_MIN_SCORE, publishCutoff(cfg, now), now - EXPIRE_MS).first(),
      env.DB.prepare("SELECT value FROM meta WHERE key='last_run'").first(),
      env.DB.prepare("SELECT COUNT(*) n FROM repositories WHERE last_seen>?").bind(now - EXPIRE_MS).first(),
      env.DB.prepare("SELECT result_json,finished_at,error FROM runs ORDER BY id DESC LIMIT 1").first(),
      env.DB.prepare("SELECT value FROM meta WHERE key='run_lock'").first()
    ]);
    const body = {
      version: VERSION,
      activeNodes: counts?.n_active || 0,
      publishedNodes: counts?.n_published || 0,
      unassessedNodes: counts?.n_unassessed || 0,
      totalNodes: counts?.n_total || 0,
      freshActiveNodes: counts?.n_fresh || 0,
      activeSources: repos?.n || 0,
      lastRun: last?.value || null,
      // 锁值格式为 "<epoch-ms>:<uuid>"：必须先切出时间前缀再比较，否则 Number("...:uuid") 为 NaN。
      running: !!lock && Number(String(lock.value).split(":", 1)[0]) > now - LOCK_TTL_MS,
      lastRunSummary: run?.result_json ? safeJson(run.result_json) : null,
      lastRunError: run?.error || null
    };
    if (await isAdmin(request, env)) body.configWarnings = configWarnings(env);
    return json(body);
  }
  if (path === "/api/repositories") {
    const rows = await env.DB.prepare("SELECT repo,stars,pushed_at,last_seen,last_checked,score,files_found,nodes_found,last_error FROM repositories ORDER BY score DESC, pushed_at DESC LIMIT 100").all();
    return json({ repositories: rows.results || [] });
  }
  if (path === "/api/runs") {
    const rows = await env.DB.prepare("SELECT id,started_at,finished_at,result_json,error FROM runs ORDER BY id DESC LIMIT 20").all();
    return json({ runs: (rows.results || []).map(r => ({ id: r.id, started_at: r.started_at, finished_at: r.finished_at, error: r.error, result: safeJson(r.result_json) })) });
  }
  if (path === "/api/nodes") {
    // 节点服务器地址、出口 IP 属于敏感数据：不再对公网开放，需要管理员令牌。
    if (!(await isAdmin(request, env))) return unauthorized();
    const limit = Math.min(500, Math.max(1, Number(url.searchParams.get("limit")) || 100));
    const rows = await env.DB.prepare(`SELECT fingerprint,scheme,server,port,source_repo,first_seen,last_seen,last_checked,last_success,active,fail_count,
        latency_ms,exit_ip,country,check_method,last_error,risk_score,risk_level,risk_reasons,risk_assessed_at,
        http_loss,jitter_ms,speed_kbps,dns_leak,ipv6_leak,proxy_detected,blacklist_hits,is_datacenter,quality_score,check_details
      FROM nodes ORDER BY active DESC,last_success DESC,last_seen DESC LIMIT ?`).bind(limit).all();
    return json({ nodes: (rows.results || []).map(r => ({ ...r, risk_reasons: safeJson(r.risk_reasons) })) });
  }

  if (path === "/sub/clash" || path === "/sub/v2rayng") {
    if (!(await hasSubscriptionKey(url, env))) return unauthorized();
    const rows = await env.DB.prepare(`SELECT uri,fingerprint FROM nodes WHERE ${PUBLISHABLE} ORDER BY last_success DESC,last_seen DESC LIMIT ?`)
      .bind(PUBLISH_MIN_SCORE, publishCutoff(cfg, now), cfg.maxPublished).all();
    const proxies = [];
    const used = new Set();
    const uris = [];
    for (const row of rows.results || []) {
      const p = parseNode(row.uri);
      if (!p || (p.insecure && !cfg.allowInsecure)) continue;   // 老数据里的明文/跳过证书节点也不发布
      uris.push(row.uri);
      p.name = uniqueName(p.name || p.type, row.fingerprint, used);
      proxies.push(p);
    }
    const common = { "cache-control": "no-store", "x-robots-tag": "noindex", "profile-update-interval": "12" };
    if (path === "/sub/clash")
      return new Response(serializeClash(proxies), { headers: { ...common, "content-type": "text/yaml; charset=utf-8" } });
    return new Response(toBase64Utf8(uris.join("\n")), { headers: { ...common, "content-type": "text/plain; charset=utf-8" } });
  }

  if (path.startsWith("/admin/")) {
    if (!(await isAdmin(request, env))) return unauthorized();

    if (path === "/admin/candidates") {
      if (request.method !== "GET") return methodNotAllowed();
      const limit = Math.min(5000, Math.max(1, Number(url.searchParams.get("limit")) || 2000));
      // 未评估/评估最久的排在前面，方便检测器优先处理；不按风险分过滤，否则未评估节点永远得不到检测。
      const rows = await env.DB.prepare(`SELECT fingerprint,uri,scheme,server,port,source_repo,last_seen,risk_score,risk_assessed_at
        FROM nodes WHERE active=1 ORDER BY risk_assessed_at IS NOT NULL, risk_assessed_at ASC, last_seen DESC LIMIT ?`).bind(limit).all();
      return json({ candidates: rows.results || [], note: "Contains node credentials. Use a trusted checker over HTTPS; never log this response." });
    }
    if (path === "/admin/health-report") {
      if (request.method !== "POST") return methodNotAllowed();
      return healthReport(request, env, now);
    }
    if (path === "/admin/network-summary") {
      if (request.method !== "GET") return methodNotAllowed();
      const ncfg = getConfig(env);
      const row = await env.DB.prepare(`SELECT COUNT(*) total,
        SUM(active=1) active,
        SUM(active=1 AND risk_assessed_at IS NOT NULL AND (?=0 OR risk_assessed_at>=?)) assessed,
        AVG(latency_ms) avg_latency, AVG(http_loss) avg_http_loss, AVG(jitter_ms) avg_jitter,
        AVG(speed_kbps) avg_speed, SUM(CASE WHEN dns_leak=1 THEN 1 ELSE 0 END) dns_leaks,
        SUM(CASE WHEN ipv6_leak=1 THEN 1 ELSE 0 END) ipv6_leaks,
        SUM(CASE WHEN proxy_detected=1 THEN 1 ELSE 0 END) proxy_detected,
        SUM(CASE WHEN blacklist_hits>0 THEN 1 ELSE 0 END) blacklisted
        FROM nodes WHERE active=1`).bind(ncfg.riskMaxAgeDays, publishCutoff(ncfg, now)).first();
      return json({ ok: true, summary: row || {}, note: "统计来自外部检测器上报；未上报的指标不代表通过检测。" });
    }
    if (path === "/admin/run") {
      if (request.method !== "POST") return methodNotAllowed();
      const lock = await env.DB.prepare("SELECT value FROM meta WHERE key='run_lock'").first();
      if (lock && Number(String(lock.value).split(":", 1)[0]) > now - LOCK_TTL_MS) return json({ ok: false, error: "already_running" }, 409);
      ctx.waitUntil(runPipeline(env, "manual").catch(err => console.error("manual run failed", err?.stack || err)));
      return json({ ok: true, started: true }, 202);
    }
  }
  return new Response("Not found", { status: 404 });
}

async function healthReport(request, env, now) {
  if (Number(request.headers.get("content-length") || 0) > 2_000_000) return json({ ok: false, error: "payload_too_large" }, 413);
  let payload;
  try { payload = await request.json(); } catch { return json({ ok: false, error: "Invalid JSON" }, 400); }
  const results = Array.isArray(payload?.results) ? payload.results.slice(0, 1000) : [];
  const stmts = [];
  for (const r of results) {
    if (!r || typeof r.fingerprint !== "string" || !/^[0-9a-f]{64}$/.test(r.fingerprint)) continue;
    const method = typeof r.method === "string" ? clean(r.method, 40) : "external";
    // 外部检测器可报告质量指标；未报告的字段保持 NULL，绝不把“未知”当成通过。
    const hasNum = v => v !== null && v !== undefined && v !== "" && Number.isFinite(Number(v));
    const num = (v, min, max) => hasNum(v) ? Math.max(min, Math.min(max, Number(v))) : null;
    const bool = v => v === true ? 1 : v === false ? 0 : null;
    const httpLoss = num(r.httpLoss, 0, 1);
    const jitterMs = num(r.jitterMs, 0, 600000);
    const speedKbps = num(r.speedKbps, 0, 100000000);
    const dnsLeak = bool(r.dnsLeak), ipv6Leak = bool(r.ipv6Leak), proxyDetected = bool(r.proxyDetected), isDatacenter = bool(r.isDatacenter);
    const blacklistHits = hasNum(r.blacklistHits) ? Math.max(0, Math.min(1000, Math.round(Number(r.blacklistHits)))) : null;
    const qualityScore = hasNum(r.qualityScore) ? Math.round(Math.max(0, Math.min(100, Number(r.qualityScore)))) : null;
    const details = Array.isArray(r.checkDetails) ? JSON.stringify(r.checkDetails.slice(0, 12).map(x => clean(x, 160)).filter(Boolean)) : null;
    const metricSql = `,http_loss=COALESCE(?,http_loss),jitter_ms=COALESCE(?,jitter_ms),speed_kbps=COALESCE(?,speed_kbps),
      dns_leak=COALESCE(?,dns_leak),ipv6_leak=COALESCE(?,ipv6_leak),proxy_detected=COALESCE(?,proxy_detected),
      blacklist_hits=COALESCE(?,blacklist_hits),is_datacenter=COALESCE(?,is_datacenter),quality_score=COALESCE(?,quality_score),check_details=COALESCE(?,check_details)`;
    const metricArgs = [httpLoss, jitterMs, speedKbps, dnsLeak, ipv6Leak, proxyDetected, blacklistHits, isDatacenter, qualityScore, details];
    // riskScore 优先使用受信任检测器的显式分数；否则只有指标充分时才自动估算风险分。
    let computedRisk = hasNum(r.riskScore) ? Math.round(Math.max(0, Math.min(100, Number(r.riskScore)))) : null;
    if (computedRisk === null && r.ok === true && [httpLoss, jitterMs, dnsLeak, ipv6Leak, proxyDetected, blacklistHits, isDatacenter].some(v => v !== null)) {
      let score = 100;
      if (httpLoss !== null) score -= Math.round(httpLoss * 25);
      if (jitterMs !== null) score -= Math.round(Math.min(1, jitterMs / 1000) * 10);
      if (dnsLeak === 1) score -= 20;
      if (ipv6Leak === 1) score -= 15;
      if (proxyDetected === 1) score -= 10;
      if (isDatacenter === 1) score -= 10;
      if (blacklistHits !== null) score -= Math.min(40, blacklistHits * 20);
      computedRisk = Math.max(0, Math.min(100, score));
    }
    let riskSql = "", riskArgs = [];
    if (computedRisk !== null) {
      const reasons = Array.isArray(r.riskReasons) ? r.riskReasons.slice(0, 8).map(x => clean(x, 120)).filter(Boolean) : [];
      riskSql = ",risk_score=?,risk_level=?,risk_reasons=?,risk_assessed_at=?";
      riskArgs = [computedRisk, riskLevel(computedRisk), JSON.stringify(reasons), now];
    }
    if (r.ok === true) {
      const latency = hasNum(r.latencyMs) ? Math.max(0, Math.min(600000, Math.round(Number(r.latencyMs)))) : null;
      const exitIp = typeof r.exitIp === "string" && /^[0-9a-fA-F:.]{2,45}$/.test(r.exitIp) ? r.exitIp : null;
      const country = typeof r.country === "string" ? clean(r.country, 80) || null : null;
      // 成功检测是“可用”的更强证据：即使 last_seen 因来源过期而不新鲜，也不据此停用该节点。
      stmts.push(env.DB.prepare(`UPDATE nodes SET last_checked=?,last_success=?,fail_count=0,
          active=1,latency_ms=?,exit_ip=?,country=?,check_method=?,last_error=NULL${metricSql}${riskSql} WHERE fingerprint=?`)
        .bind(now, now, latency, exitIp, country, method, ...metricArgs, ...riskArgs, r.fingerprint));
    } else {
      const reason = typeof r.reason === "string" ? clean(r.reason, 300) : null;
      stmts.push(env.DB.prepare(`UPDATE nodes SET last_checked=?,fail_count=fail_count+1,
          active=CASE WHEN last_seen<? OR fail_count+1>=3 THEN 0 ELSE active END,check_method=?,last_error=?${metricSql}${riskSql} WHERE fingerprint=?`)
        .bind(now, now - EXPIRE_MS, method, reason, ...metricArgs, ...riskArgs, r.fingerprint));
    }
  }
  let updated = 0;
  for (let i = 0; i < stmts.length; i += 50) {
    const res = await env.DB.batch(stmts.slice(i, i + 50));
    for (const x of res) updated += x?.meta?.changes || 0;
  }
  return json({ ok: true, received: results.length, accepted: stmts.length, updated, at: new Date(now).toISOString() });
}

// ───────────────────────────── 认证 ─────────────────────────────
async function safeEqual(a, b) {
  const enc = new TextEncoder();
  const [x, y] = await Promise.all([crypto.subtle.digest("SHA-256", enc.encode(String(a))), crypto.subtle.digest("SHA-256", enc.encode(String(b)))]);
  const ax = new Uint8Array(x), ay = new Uint8Array(y); let diff = 0;
  for (let i = 0; i < ax.length; i++) diff |= ax[i] ^ ay[i];
  return diff === 0;
}
function cookieValue(request, name) {
  const raw = request.headers.get("cookie") || "";
  for (const part of raw.split(";")) { const i = part.indexOf("="); if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim(); }
  return "";
}
async function digestHex(value) {
  const bytes = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
  return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}
function randomToken(bytes = 32) {
  const a = new Uint8Array(bytes); crypto.getRandomValues(a);
  return btoa(String.fromCharCode(...a)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
async function hasSession(request, env) {
  if (!env.KV) return false;
  const token = cookieValue(request, "no_session");
  if (!/^[A-Za-z0-9_-]{40,60}$/.test(token)) return false;
  try { return (await env.KV.get("session:" + await digestHex(token))) === "1"; } catch { return false; }
}
async function login(request, env) {
  if (request.method !== "POST") return methodNotAllowed();
  if (!env.ADMIN_PASSWORD || !env.KV) return json({ ok: false, error: "login_not_configured", hint: "Set ADMIN_PASSWORD and bind KV" }, 503, { "cache-control": "no-store" });
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const rateKey = "login-rate:" + await digestHex(ip);
  try {
    const rate = Number(await env.KV.get(rateKey) || 0);
    if (rate >= 8) return json({ ok: false, error: "too_many_attempts" }, 429, { "cache-control": "no-store", "retry-after": "900" });
    let body; try { body = await request.json(); } catch { return json({ ok: false, error: "invalid_json" }, 400); }
    if (typeof body?.password !== "string" || body.password.length > 1024 || !(await safeEqual(body.password, env.ADMIN_PASSWORD))) {
      await env.KV.put(rateKey, String(rate + 1), { expirationTtl: 900 });
      return json({ ok: false, error: "invalid_credentials" }, 401, { "cache-control": "no-store" });
    }
    await env.KV.delete(rateKey);
    const token = randomToken();
    await env.KV.put("session:" + await digestHex(token), "1", { expirationTtl: 8 * 60 * 60 });
    return json({ ok: true, expiresIn: 28800 }, 200, { "cache-control": "no-store", "set-cookie": `no_session=${token}; Path=/; Max-Age=28800; HttpOnly; Secure; SameSite=Strict` });
  } catch (err) { console.error("login storage error", err); return json({ ok: false, error: "session_storage_error" }, 503, { "cache-control": "no-store" }); }
}
async function logout(request, env) {
  if (request.method !== "POST") return methodNotAllowed();
  const token = cookieValue(request, "no_session");
  if (env.KV && /^[A-Za-z0-9_-]{40,60}$/.test(token)) {
    try { await env.KV.delete("session:" + await digestHex(token)); } catch {}
  }
  return json({ ok: true }, 200, { "cache-control": "no-store", "set-cookie": "no_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict" });
}
async function isAdmin(request, env) {
  if (await hasSession(request, env)) return true;
  if (!env.ADMIN_TOKEN) return false;
  if (env.SUBSCRIPTION_KEY && env.ADMIN_TOKEN === env.SUBSCRIPTION_KEY) return false;
  const h = request.headers.get("authorization") || "";
  return h.startsWith("Bearer ") && await safeEqual(h.slice(7), env.ADMIN_TOKEN);
}
async function hasSubscriptionKey(url, env) {
  const key = url.searchParams.get("key");
  return !!env.SUBSCRIPTION_KEY && !!key && await safeEqual(key, env.SUBSCRIPTION_KEY);
}
function configWarnings(env) {
  const w = [];
  if (!env.SUBSCRIPTION_KEY) w.push("SUBSCRIPTION_KEY 未设置：订阅地址不可用");
  else if (env.SUBSCRIPTION_KEY.length < 24) w.push("SUBSCRIPTION_KEY 少于 24 个字符，建议使用更长的随机值");
  if (!env.ADMIN_TOKEN) w.push("ADMIN_TOKEN 未设置：外部检测器管理接口不可用");
  if (!env.ADMIN_PASSWORD) w.push("ADMIN_PASSWORD 未设置：网站密码登录不可用");
  if (!env.KV) w.push("未绑定 KV：网站密码登录会不可用");
  if (env.ADMIN_TOKEN && env.ADMIN_TOKEN === env.SUBSCRIPTION_KEY) w.push("ADMIN_TOKEN 与 SUBSCRIPTION_KEY 相同：管理接口已被拒绝，请改成不同的值");
  if (!env.GITHUB_TOKEN) w.push("未配置 GITHUB_TOKEN：GitHub API 配额很低，扫描容易中途被限流");
  if (env.PUBLIC_BASE_URL && !/^https:\/\//i.test(env.PUBLIC_BASE_URL)) w.push("PUBLIC_BASE_URL 应使用 HTTPS 完整域名");
  return w;
}
function unauthorized() { return new Response("Unauthorized", { status: 401, headers: { "cache-control": "no-store" } }); }
function methodNotAllowed() { return new Response("Method not allowed", { status: 405 }); }

// ───────────────────────────── 数据库自检 ─────────────────────────────
// 只做“补列/补表”，不会删除或改写任何旧数据，让 v2 / 早期 v3 的库无需手工迁移也能运行。
const NODE_COLUMNS = {
  server: "TEXT", port: "INTEGER", latency_ms: "INTEGER", exit_ip: "TEXT", country: "TEXT", check_method: "TEXT", last_error: "TEXT",
  risk_score: "INTEGER NOT NULL DEFAULT 0", risk_level: "TEXT NOT NULL DEFAULT 'unassessed'", risk_reasons: "TEXT", risk_assessed_at: "INTEGER",
  http_loss: "REAL", jitter_ms: "REAL", speed_kbps: "REAL", dns_leak: "INTEGER", ipv6_leak: "INTEGER", proxy_detected: "INTEGER",
  blacklist_hits: "INTEGER", is_datacenter: "INTEGER", quality_score: "INTEGER", check_details: "TEXT"
};
const REPO_COLUMNS = {
  score: "INTEGER NOT NULL DEFAULT 0", files_found: "INTEGER NOT NULL DEFAULT 0", nodes_found: "INTEGER NOT NULL DEFAULT 0", last_error: "TEXT"
};
const schemaCache = new WeakMap();   // 以 D1 绑定对象为键：同一数据库只自检一次
function ensureSchema(env) {
  let ready = schemaCache.get(env.DB);
  if (ready) return ready;
  ready = (async () => {
    const cols = async table => new Set(((await env.DB.prepare(`PRAGMA table_info(${table})`).all()).results || []).map(c => c.name));
    const nodeCols = await cols("nodes");
    if (!nodeCols.size) throw new Error("D1 schema missing: run migrations/0001_init.sql in the D1 console first");
    const repoCols = await cols("repositories");
    if (!repoCols.size) throw new Error("D1 schema missing: table repositories not found (run migrations/0001_init.sql)");
    const stmts = [];
    for (const [c, def] of Object.entries(NODE_COLUMNS)) if (!nodeCols.has(c)) stmts.push(env.DB.prepare(`ALTER TABLE nodes ADD COLUMN ${c} ${def}`));
    for (const [c, def] of Object.entries(REPO_COLUMNS)) if (!repoCols.has(c)) stmts.push(env.DB.prepare(`ALTER TABLE repositories ADD COLUMN ${c} ${def}`));
    stmts.push(
      env.DB.prepare("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"),
      env.DB.prepare("CREATE TABLE IF NOT EXISTS runs (id INTEGER PRIMARY KEY AUTOINCREMENT, started_at TEXT NOT NULL, finished_at TEXT, result_json TEXT, error TEXT)")
    );
    if (!nodeCols.has("risk_assessed_at"))   // 旧库里已有人工写入风险分的节点：以最近检测时间作为评估时间，避免被误判为“未评估”
      stmts.push(env.DB.prepare("UPDATE nodes SET risk_assessed_at=last_checked WHERE risk_score>0 AND last_checked>0"));
    stmts.push(
      env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_nodes_active ON nodes(active)"),
      env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_nodes_last_seen ON nodes(last_seen)"),
      env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_nodes_publish ON nodes(active, risk_score)"),
      env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_repositories_score ON repositories(score DESC)"),
      env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_runs_started ON runs(started_at DESC)")
    );
    // 注意顺序：补列必须先于建索引/回填。
    // 并发冷启动时另一个隔离体可能已补列：batch 整体失败后逐条重试，容忍 duplicate column。
    // 逐条重试是幂等的（ALTER 重复报错被吞掉，CREATE INDEX IF NOT EXISTS / 回填 UPDATE 均幂等）。
    try {
      await env.DB.batch(stmts);
    } catch (err) {
      if (!/duplicate column name/i.test(String(err?.message || err))) throw err;
      for (const s of stmts) {
        try { await s.run(); }
        catch (e) { if (!/duplicate column name/i.test(String(e?.message || e))) throw e; }
      }
    }
  })().catch(err => { schemaCache.delete(env.DB); throw err; });
  schemaCache.set(env.DB, ready);
  return ready;
}

// ───────────────────────────── 采集流水线 ─────────────────────────────
function makeBudget(total) {
  return {
    total, left: total,
    take(n = 1) { if (this.left < n) return false; this.left -= n; return true; },
    force(n = 1) { this.left -= n; },
    get used() { return this.total - this.left; }
  };
}

async function runPipeline(env, trigger = "manual") {
  await ensureSchema(env);
  const cfg = getConfig(env);
  const now = Date.now();
  const lockToken = `${now}:${crypto.randomUUID()}`;
  const lock = await env.DB.prepare("INSERT INTO meta(key,value) VALUES('run_lock',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value WHERE CAST(substr(meta.value,1,instr(meta.value || ':',':')-1) AS INTEGER)<?")
    .bind(lockToken, now - LOCK_TTL_MS).run();
  if (!(lock.meta?.changes > 0)) return { ok: false, skipped: "another run is in progress" };

  const startedAt = new Date(now).toISOString();
  const budget = makeBudget(cfg.subrequestBudget);
  const stats = {
    trigger, reposDiscovered: 0, reposScanned: 0, filesRead: 0, upstreamSources: 0, upstreamCandidates: 0, candidates: 0, parseRejected: 0, inserted: 0,
    checked: 0, disabled: 0, pruned: 0, stoppedEarly: null, rateLimited: false, truncatedTrees: 0, errors: []
  };
  let runId = null, fatal = null;
  try {
    const ins = await env.DB.prepare("INSERT INTO runs(started_at) VALUES(?)").bind(startedAt).run();
    runId = ins.meta?.last_row_id ?? null;
    await backfillServerPort(env, budget);
    const repos = await discoverRepos(env, cfg, budget, now, stats);
    stats.reposDiscovered = repos.length;
    await scanRepos(env, cfg, budget, now, stats, repos);
    await scanUpstreamSubscriptions(env, cfg, budget, now, stats);
    await probeNodes(env, cfg, budget, now, stats);
    await maintenance(env, cfg, now, stats);
  } catch (err) {
    fatal = String(err?.message || err).slice(0, 300);
    stats.errors.push("fatal: " + fatal);
    console.error("pipeline failed", err?.stack || err);
  } finally {
    const finishedAt = new Date().toISOString();
    stats.errors = stats.errors.slice(0, 10);
    const summary = { ok: !fatal, ...stats, subrequestsUsed: budget.used, finishedAt };
    try {
      await env.DB.batch([
        env.DB.prepare("INSERT INTO meta(key,value) VALUES('last_run',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(finishedAt),
        env.DB.prepare("UPDATE runs SET finished_at=?,result_json=?,error=? WHERE id=?").bind(finishedAt, JSON.stringify(summary), fatal, runId),
        env.DB.prepare("DELETE FROM meta WHERE key='run_lock' AND value=?").bind(lockToken)
      ]);
    } catch (err) {
      console.error("failed to finalize run", err?.stack || err);
      try { await env.DB.prepare("DELETE FROM meta WHERE key='run_lock' AND value=?").bind(lockToken).run(); } catch {}
    }
    stats.summary = summary;
  }
  return stats.summary;
}

async function backfillServerPort(env, budget) {
  const rows = (await env.DB.prepare("SELECT fingerprint,uri FROM nodes WHERE server IS NULL LIMIT 1000").all()).results || [];
  budget.force(1);
  if (!rows.length) return;
  const stmts = rows.map(r => {
    const p = parseNode(r.uri);   // 解析失败的写入空串，避免每次运行重复扫描
    return env.DB.prepare("UPDATE nodes SET server=?,port=? WHERE fingerprint=?").bind(p ? p.server : "", p ? p.port : 0, r.fingerprint);
  });
  await flush(env, stmts, budget);
}

function githubHeaders(env) {
  const h = { "Accept": "application/vnd.github+json", "User-Agent": UA };
  if (env.GITHUB_TOKEN) h.Authorization = `Bearer ${env.GITHUB_TOKEN}`;
  return h;
}
function fetchT(url, init = {}, ms = 15000) { return fetch(url, { ...init, signal: AbortSignal.timeout(ms) }); }
function noteGithubFailure(stats, res, label) {
  if (stats.errors.length < 10) stats.errors.push(`${label}: HTTP ${res.status}`);
  if (res.status === 429 || (res.status === 403 && res.headers.get("x-ratelimit-remaining") === "0")) stats.rateLimited = true;
}
function repoScore(stars, pushed, now) {
  const ageDays = pushed ? Math.max(0, (now - pushed) / DAY) : 365;
  return Math.round(Math.min(100, Math.log10(stars + 1) * 12 + Math.max(0, 35 - ageDays) * 1.4));
}

async function discoverRepos(env, cfg, budget, now, stats) {
  const headers = githubHeaders(env);
  const found = new Map();
  const queries = cfg.searches.length ? cfg.searches : defaultSearches(now);
  for (const q of queries.slice(0, 6)) {
    if (stats.rateLimited) break;
    if (!budget.take()) { stats.stoppedEarly ||= "budget"; break; }
    try {
      const res = await fetchT("https://api.github.com/search/repositories?q=" + encodeURIComponent(q) + "&sort=stars&order=desc&per_page=30", { headers });
      if (!res.ok) { noteGithubFailure(stats, res, "search"); continue; }
      const data = await res.json();
      for (const r of data.items || []) if (r.full_name && r.default_branch) found.set(r.full_name, { ...r, explicit: false });
    } catch (err) { stats.errors.push("search: " + String(err?.message || err).slice(0, 100)); }
  }
  for (const name of (env.GITHUB_REPOS || "").split(",").map(s => s.trim()).filter(Boolean)) {
    if (!/^[\w.-]+\/[\w.-]+$/.test(name) || stats.rateLimited) continue;
    if (!budget.take()) { stats.stoppedEarly ||= "budget"; break; }
    try {
      const res = await fetchT(`https://api.github.com/repos/${name}`, { headers });
      if (!res.ok) { noteGithubFailure(stats, res, "repo " + name); continue; }
      const r = await res.json();
      if (r.full_name && r.default_branch) found.set(r.full_name, { ...r, explicit: true });
    } catch (err) { stats.errors.push(`repo ${name}: ` + String(err?.message || err).slice(0, 100)); }
  }
  // 手动指定的源优先；其余按评分从高到低，预算有限时先扫最值得扫的仓库。
  return [...found.values()]
    .map(r => ({ ...r, _score: repoScore(r.stargazers_count || 0, r.pushed_at ? Date.parse(r.pushed_at) : 0, now) }))
    .sort((a, b) => (b.explicit - a.explicit) || (b._score - a._score))
    .slice(0, cfg.maxRepos);
}

async function scanRepos(env, cfg, budget, now, stats, repos) {
  const headers = githubHeaders(env);
  const known = new Set(((await env.DB.prepare("SELECT fingerprint FROM nodes").all()).results || []).map(r => r.fingerprint));
  budget.force(1);
  const seenThisRun = new Set();
  const scanFloor = Math.ceil(budget.total * 0.3);   // 给探测与收尾留出 30% 预算
  const repoSql = `INSERT INTO repositories(repo,stars,pushed_at,last_seen,last_checked,score,files_found,nodes_found,last_error) VALUES(?,?,?,?,?,?,?,?,?)
    ON CONFLICT(repo) DO UPDATE SET stars=excluded.stars,pushed_at=excluded.pushed_at,last_seen=excluded.last_seen,last_checked=excluded.last_checked,score=excluded.score,
      files_found=CASE WHEN ?=1 THEN excluded.files_found ELSE repositories.files_found END,
      nodes_found=CASE WHEN ?=1 THEN excluded.nodes_found ELSE repositories.nodes_found END,
      last_error=excluded.last_error`;

  for (const repo of repos) {
    if (stats.rateLimited) { stats.stoppedEarly ||= "github_rate_limit"; break; }
    if (budget.left <= scanFloor) { stats.stoppedEarly ||= "budget"; break; }
    const name = repo.full_name;
    const pushed = repo.pushed_at ? Date.parse(repo.pushed_at) : 0;
    const stmts = [];
    let scanned = false, filesFound = 0, nodesFound = 0, error = null;
    try {
      // 超过 30 天未推送的源只保留元数据，不再采集。
      if (pushed && now - pushed <= 30 * DAY) {
        budget.force(1);
        const treeRes = await fetchT(`https://api.github.com/repos/${name}/git/trees/${encodeURIComponent(repo.default_branch)}?recursive=1`, { headers });
        if (!treeRes.ok) { noteGithubFailure(stats, treeRes, "tree " + name); error = "tree HTTP " + treeRes.status; }
        else {
          const tree = await treeRes.json();
          if (tree.truncated) stats.truncatedTrees++;
          const files = (tree.tree || [])
            .filter(x => x.type === "blob" && FILE_RE.test(x.path) && !SKIP_PATH_RE.test(x.path) && (x.size || 0) <= MAX_FILE_BYTES)
            .sort((a, b) => scorePath(a.path) - scorePath(b.path)).slice(0, cfg.filesPerRepo);
          scanned = true;
          stats.reposScanned++;
          for (const file of files) {
            if (budget.left <= scanFloor) { stats.stoppedEarly ||= "budget"; break; }
            budget.force(1);
            try {
              const path = file.path.split("/").map(encodeURIComponent).join("/");
              const res = await fetchT(`https://raw.githubusercontent.com/${name}/${encodeURIComponent(repo.default_branch)}/${path}`, { headers: { "User-Agent": UA } });
              if (!res.ok) continue;
              stats.filesRead++;
              const { nodes, rejected, matched } = extractNodes((await res.text()).slice(0, MAX_FILE_BYTES), cfg);
              stats.candidates += matched;
              stats.parseRejected += rejected;
              if (nodes.length) filesFound++;
              for (const { uri, parsed } of nodes) {
                nodesFound++;
                const canonical = canonicalKey(parsed);
                const fp = await sha256(canonical);
                if (seenThisRun.has(fp)) continue;
                seenThisRun.add(fp);
                if (!known.has(fp)) { known.add(fp); stats.inserted++; }
                stmts.push(upsertNodeStmt(env, fp, canonical, uri, parsed, name, now));
              }
            } catch { /* 单个文件失败不影响其他文件 */ }
          }
        }
      }
    } catch (err) { error = String(err?.message || err).slice(0, 300); }
    const flag = scanned ? 1 : 0;
    stmts.push(env.DB.prepare(repoSql).bind(name, repo.stargazers_count || 0, repo.pushed_at || null, now, now, repo._score, filesFound, nodesFound, error, flag, flag));
    try { await flush(env, stmts, budget); }
    catch (err) { stats.errors.push(`db ${name}: ` + String(err?.message || err).slice(0, 100)); }
  }
}

// 可选的外部订阅导入。为避免把 Worker 变成任意 URL 抓取器，当前只允许
// morpheusadam/v2ray-config 的 mini.txt；需要先人工验收，再通过环境变量启用。
function allowedUpstreamSubscriptionUrl(value) {
  try {
    const u = new URL(value);
    return u.protocol === "https:" && u.hostname === "raw.githubusercontent.com" &&
      u.pathname === "/morpheusadam/v2ray-config/main/subs/bundles/mini.txt" &&
      !u.username && !u.password && !u.search && !u.hash;
  } catch { return false; }
}

async function scanUpstreamSubscriptions(env, cfg, budget, now, stats) {
  const urls = [...new Set(cfg.upstreamSubscriptionUrls)];
  if (!urls.length) return;
  const known = new Set(((await env.DB.prepare("SELECT fingerprint FROM nodes").all()).results || []).map(r => r.fingerprint));
  budget.force(1);
  const seenThisRun = new Set();
  for (const url of urls.slice(0, 2)) {
    if (!allowedUpstreamSubscriptionUrl(url)) {
      stats.errors.push("upstream: rejected URL (only the reviewed mini.txt source is allowed)");
      continue;
    }
    if (!budget.take()) { stats.stoppedEarly ||= "budget"; break; }
    try {
      const res = await fetchT(url, { headers: { "User-Agent": UA, "Accept": "text/plain" }, redirect: "manual" }, 12000);
      if (!res.ok) { stats.errors.push(`upstream mini.txt: HTTP ${res.status}`); continue; }
      const declared = Number(res.headers.get("content-length") || 0);
      if (declared > MAX_FILE_BYTES) { stats.errors.push("upstream mini.txt: response too large"); continue; }
      const text = (await res.text()).slice(0, MAX_FILE_BYTES);
      const { nodes, rejected, matched } = extractNodes(text, cfg);
      stats.upstreamSources++;
      stats.upstreamCandidates += matched;
      stats.candidates += matched;
      stats.parseRejected += rejected;
      const stmts = [];
      for (const { uri, parsed } of nodes) {
        const canonical = canonicalKey(parsed);
        const fp = await sha256(canonical);
        if (seenThisRun.has(fp)) continue;
        seenThisRun.add(fp);
        if (!known.has(fp)) { known.add(fp); stats.inserted++; }
        stmts.push(upsertNodeStmt(env, fp, canonical, uri, parsed, "subscription:morpheusadam/v2ray-config:mini", now));
      }
      if (stmts.length) await flush(env, stmts, budget);
    } catch (err) {
      stats.errors.push("upstream mini.txt: " + String(err?.message || err).slice(0, 120));
    }
  }
}

async function flush(env, stmts, budget) {
  for (let i = 0; i < stmts.length; i += 50) {
    await env.DB.batch(stmts.slice(i, i + 50));
    budget.force(1);
  }
}

// 内置检测只是 TCP 端口初筛：不能证明凭据、TLS/Reality、协议握手或真实出网可用。
async function probeNodes(env, cfg, budget, now, stats) {
  if (!cfg.probeLimit) return;
  // 24 小时内已有外部检测器结果的节点不再做 TCP 探测，否则 TCP 成功会冲掉外部检测的失败计数。
  const rows = (await env.DB.prepare(`SELECT fingerprint,uri,fail_count FROM nodes
    WHERE active=1 AND last_seen>=? AND NOT (check_method IS NOT NULL AND check_method!='tcp' AND last_checked>?)
    ORDER BY last_checked ASC LIMIT ?`).bind(now - EXPIRE_MS, now - DAY, cfg.probeLimit).all()).results || [];
  budget.force(1);
  // 同一主机每轮最多探测 3 个端口，防止公开列表被投毒后把 Worker 变成端口扫描器。
  const perHost = new Map();
  const todo = [];
  for (const row of rows) {
    const p = parseNode(row.uri);
    if (!p) continue;
    const key = p.server.toLowerCase();
    const n = perHost.get(key) || 0;
    if (n >= 3) continue;
    perHost.set(key, n + 1);
    todo.push({ row, p });
  }
  const stmts = [];
  await mapPool(todo, 6, async ({ row, p }) => {
    if (!budget.take()) { stats.stoppedEarly ||= "budget"; return; }
    stats.checked++;
    if (await tcpProbe(p.server, p.port, cfg.probeTimeoutMs)) {
      stmts.push(env.DB.prepare("UPDATE nodes SET last_checked=?,last_success=?,fail_count=0,check_method='tcp',last_error=NULL WHERE fingerprint=?").bind(now, now, row.fingerprint));
    } else {
      if ((row.fail_count || 0) + 1 >= 3) stats.disabled++;
      stmts.push(env.DB.prepare("UPDATE nodes SET last_checked=?,fail_count=fail_count+1,active=CASE WHEN fail_count+1>=3 THEN 0 ELSE 1 END,check_method='tcp',last_error='TCP port probe failed' WHERE fingerprint=?").bind(now, row.fingerprint));
    }
  });
  await flush(env, stmts, budget);
}

async function tcpProbe(host, port, timeoutMs) {
  let socket, timer;
  try {
    socket = connect({ hostname: host, port }, { secureTransport: "off", allowHalfOpen: false });
    socket.opened.catch(() => {});
    await Promise.race([socket.opened, new Promise((_, rej) => { timer = setTimeout(() => rej(new Error("timeout")), timeoutMs); })]);
    return true;
  } catch { return false; }
  finally {
    clearTimeout(timer);
    try { await socket?.close(); } catch {}
  }
}

async function mapPool(items, limit, fn) {
  let i = 0;
  const worker = async () => { while (i < items.length) await fn(items[i++]); };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
}

async function maintenance(env, cfg, now, stats) {
  // 本轮一个仓库都没扫成功（GitHub 故障/限流）时，不执行“按时间过期”，避免误杀全部节点。
  if (stats.reposScanned > 0) {
    // 仅按来源过期停用；最近 24h 内有成功检测（last_success）的节点视为“已确证可用”，不被时间过期误杀。
    // 与 probeNodes 的“24h 内已有外部检测结果不做 TCP 覆盖”哲学一致，last_success 是比 last_seen 更强的存活信号。
    const exp = await env.DB.prepare("UPDATE nodes SET active=0 WHERE active=1 AND last_seen<? AND NOT (last_success IS NOT NULL AND last_success>?)")
      .bind(now - EXPIRE_MS, now - DAY).run();
    stats.disabled += exp.meta?.changes || 0;
  }
  if (cfg.pruneDays) {
    const cut = now - cfg.pruneDays * DAY;
    const [a, b] = await env.DB.batch([
      env.DB.prepare("DELETE FROM nodes WHERE active=0 AND last_seen<?").bind(cut),
      env.DB.prepare("DELETE FROM repositories WHERE last_seen<?").bind(cut)
    ]);
    stats.pruned = (a?.meta?.changes || 0) + (b?.meta?.changes || 0);
  }
  await env.DB.prepare("DELETE FROM runs WHERE id <= (SELECT MAX(id) FROM runs) - 200").run();
}

// ───────────────────────────── 节点提取与解析 ─────────────────────────────
function scorePath(path) {
  const p = path.toLowerCase();
  return (/(sub|proxy|node|config|clash|v2ray|singbox)/.test(p) ? 0 : 10) + (p.split("/").length > 3 ? 3 : 0);
}
const URI_RE = /(?<![A-Za-z0-9+.\-])(?:vmess|vless|trojan|ss):\/\/[^\s"'<>`]+/gi;

function extractNodes(text, cfg = {}) {
  const out = new Map();
  let matched = 0, rejected = 0;
  const scan = body => {
    for (const m of body.matchAll(URI_RE)) {
      matched++;
      const uri = m[0].replace(/[),;}\]]+$/g, "");
      if (out.has(uri)) continue;
      const parsed = uri.length < MAX_URI_LENGTH ? parseNode(uri) : null;
      if (!parsed || (parsed.insecure && !cfg.allowInsecure)) { rejected++; continue; }
      out.set(uri, parsed);
    }
  };
  scan(text);
  if (!matched) {
    // 很多公开订阅文件是整体 base64 编码的 URI 列表。
    const decoded = tryDecodeBlob(text);
    if (decoded) scan(decoded);
  }
  return { nodes: [...out].map(([uri, parsed]) => ({ uri, parsed })), matched, rejected };
}
function tryDecodeBlob(text) {
  const compact = text.replace(/\s+/g, "");
  if (compact.length < 40 || !/^[A-Za-z0-9+/_\-]+={0,2}$/.test(compact)) return null;
  try {
    const s = decodeBase64Utf8(compact);
    return s.includes("://") ? s : null;
  } catch { return null; }
}

function parseNode(uri) {
  try {
    if (typeof uri !== "string" || uri.length > MAX_URI_LENGTH) return null;
    const i = uri.indexOf("://");
    const scheme = i > 0 ? uri.slice(0, i).toLowerCase() : "";
    if (!ALLOWED_SCHEMES.has(scheme)) return null;
    if (scheme === "vmess") return parseVmess(uri);
    if (scheme === "ss") return parseSs(uri);
    return parseUrlStyle(uri, scheme);
  } catch { return null; }
}

function parseVmess(uri) {
  const j = JSON.parse(decodeBase64Utf8(uri.slice(8).split("#")[0]));
  if (!j || typeof j !== "object") return null;
  const server = normalizeHost(j.add), port = Number(j.port), uuid = String(j.id || "").trim();
  if (!validServerPort(server, port) || !uuid) return null;
  const cipher = String(j.scy || "auto").toLowerCase();
  if (!VMESS_CIPHERS.has(cipher)) return null;
  const net = String(j.net || "tcp").toLowerCase();
  // kcp / quic / httpupgrade / http 伪装等无法无损转换，直接拒收，避免导出一个连不上的节点。
  if (!["tcp", "ws", "grpc", "h2"].includes(net)) return null;
  if (net === "tcp" && String(j.type || "none") !== "none") return null;
  const p = { name: cleanName(j.ps, "vmess-" + server), type: "vmess", server, port, uuid, alterId: Number(j.aid || 0) || 0, cipher, udp: true };
  if (net !== "tcp") p.network = net;
  const host = j.host ? String(j.host) : "";
  if (net === "ws") p["ws-opts"] = { path: String(j.path || "/"), headers: host ? { Host: host } : {} };
  if (net === "grpc") p["grpc-opts"] = { "grpc-service-name": String(j.path || "") };
  if (net === "h2") p["h2-opts"] = { host: host ? [host] : [], path: String(j.path || "/") };
  if (String(j.tls || "") === "tls") {
    p.tls = true;
    if (j.sni) p.servername = String(j.sni);
    if (j.fp) p["client-fingerprint"] = String(j.fp);
    if (truthy(j.allowInsecure) || truthy(j["skip-cert-verify"])) p.insecure = true;
  }
  return p;
}

function parseSs(uri) {
  let rest = uri.slice(5);
  const hash = rest.indexOf("#");
  let tag = "";
  if (hash >= 0) { tag = rest.slice(hash + 1); rest = rest.slice(0, hash); }
  const qm = rest.indexOf("?");
  let query = new URLSearchParams();
  if (qm >= 0) { query = new URLSearchParams(rest.slice(qm + 1)); rest = rest.slice(0, qm); }
  if (query.has("plugin")) return null;               // obfs / v2ray-plugin 等插件暂不支持
  rest = rest.replace(/\/+$/, "");
  let cred, hostport;
  const at = rest.lastIndexOf("@");
  if (at >= 0) {
    // SIP002：userinfo@host:port，userinfo 为 base64url(method:password) 或百分号编码的 method:password（SS2022）
    const userinfo = rest.slice(0, at);
    hostport = rest.slice(at + 1);
    cred = userinfo.includes(":") ? decodeURIComponent(userinfo) : decodeBase64Utf8(userinfo);
  } else {
    // 旧格式：base64(method:password@host:port)
    const decoded = decodeBase64Utf8(rest);
    const a = decoded.lastIndexOf("@");
    if (a < 0) return null;
    cred = decoded.slice(0, a);
    hostport = decoded.slice(a + 1);
  }
  const c = cred.indexOf(":");
  if (c < 1) return null;
  const method = cred.slice(0, c).toLowerCase(), password = cred.slice(c + 1);
  const hp = splitHostPort(hostport);
  if (!hp || !SS_CIPHERS.has(method) || !password) return null;
  const [server, port] = hp;
  if (!validServerPort(server, port)) return null;
  let label = "ss-" + server;
  try { label = decodeURIComponent(tag) || label; } catch {}
  return { name: cleanName(label, "ss-" + server), type: "ss", server, port, cipher: method, password, udp: true };
}

function parseUrlStyle(uri, scheme) {
  const u = new URL(uri);
  const server = normalizeHost(u.hostname), port = Number(u.port), q = u.searchParams;
  if (!validServerPort(server, port)) return null;
  let fallback = scheme + "-" + server, name = fallback;
  try { name = decodeURIComponent((u.hash || "").replace(/^#/, "")) || fallback; } catch {}
  name = cleanName(name, fallback);
  const credential = u.username ? decodeURIComponent(u.username + (u.password ? ":" + u.password : "")) : "";
  if (!credential) return null;
  const net = (q.get("type") || "tcp").toLowerCase();
  if ((q.get("headerType") || "none").toLowerCase() !== "none") return null;   // TCP http 伪装暂不支持
  const alpn = (q.get("alpn") || "").split(",").map(s => s.trim()).filter(Boolean).slice(0, 4);
  const transport = (p, allowed) => {
    if (!allowed.includes(net)) return false;
    if (net !== "tcp") p.network = net;
    if (net === "ws") p["ws-opts"] = { path: q.get("path") || "/", headers: q.get("host") ? { Host: q.get("host") } : {} };
    if (net === "grpc") p["grpc-opts"] = { "grpc-service-name": q.get("serviceName") || q.get("service_name") || "" };
    if (net === "h2") p["h2-opts"] = { host: q.get("host") ? [q.get("host")] : [], path: q.get("path") || "/" };
    if (net === "xhttp") p["xhttp-opts"] = { path: q.get("path") || "/", host: q.get("host") || undefined, mode: q.get("mode") || "auto" };
    return true;
  };
  if (scheme === "vless") {
    const security = (q.get("security") || "none").toLowerCase();
    if (!["none", "tls", "reality"].includes(security)) return null;
    const enc = q.get("encryption");
    if (enc && enc !== "none") return null;               // VLESS 后量子/自带加密暂不支持
    const p = { name, type: "vless", server, port, uuid: credential, udp: true };
    if (!transport(p, ["tcp", "ws", "grpc", "h2", "xhttp"])) return null;
    if (security === "none") p.insecure = true;           // 无 TLS/Reality 的 VLESS 是明文传输
    else {
      p.tls = true;
      const sni = q.get("sni") || q.get("servername");
      if (sni) p.servername = sni;
      if (q.get("fp")) p["client-fingerprint"] = q.get("fp");
      if (alpn.length) p.alpn = alpn;
      if (truthy(q.get("allowInsecure")) || truthy(q.get("insecure"))) p.insecure = true;
    }
    if (q.get("flow")) {
      if (!FLOW_WHITELIST.has(q.get("flow").toLowerCase())) return null;
      p.flow = q.get("flow");
    }
    if (security === "reality") {
      const pub = q.get("pbk");
      if (!pub) return null;
      p["reality-opts"] = { "public-key": pub, "short-id": q.get("sid") || "" };
    }
    return stripUndefined(p);
  }
  // trojan
  const p = { name, type: "trojan", server, port, password: credential, tls: true, udp: true };
  if (!transport(p, ["tcp", "ws", "grpc"])) return null;
  const sni = q.get("sni") || q.get("peer");
  if (sni) p.servername = sni;
  if (alpn.length) p.alpn = alpn;
  if (truthy(q.get("allowInsecure")) || truthy(q.get("insecure"))) p.insecure = true;
  return p;
}

function truthy(v) { return v === true || v === 1 || /^(1|true|yes)$/i.test(String(v ?? "")); }
function normalizeHost(h) { return String(h ?? "").trim().replace(/^\[|\]$/g, "").replace(/\.$/, ""); }
function splitHostPort(s) {
  let m = /^\[([^\]]+)\]:(\d{1,5})$/.exec(s);
  if (m) return [m[1], Number(m[2])];
  m = /^([^:\[\]]+):(\d{1,5})$/.exec(s);
  return m ? [m[1], Number(m[2])] : null;
}
function cleanName(v, fallback) {
  const s = String(v ?? "").replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, 80);
  return s || fallback;
}
function clean(v, max) { return String(v ?? "").replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, max); }

function validServerPort(host, port) {
  return typeof host === "string" && host.length > 0 && host.length < 254 &&
    Number.isInteger(port) && port > 0 && port <= 65535 && !BLOCKED_PORTS.has(port) && isPublicHost(host);
}
function isPublicHost(raw) {
  const h = raw.toLowerCase();
  if (h.includes(":")) return isPublicIPv6(h);
  if (/^[0-9.]+$/.test(h)) return isPublicIPv4(h);
  if (!/^[a-z0-9_.-]+$/.test(h) || !h.includes(".")) return false;      // 单标签名/奇怪字符
  if (/(^|\.)0x[0-9a-f]*(\.|$)/.test(h)) return false;                    // 十六进制 IP 写法
  return !/(^|\.)(localhost|local|internal|lan|home|corp|intranet|test|invalid|example|arpa)$/.test(h);
}
function isPublicIPv4(h) {
  const o = h.split(".");
  if (o.length !== 4 || !o.every(x => /^(0|[1-9]\d{0,2})$/.test(x) && Number(x) <= 255)) return false;
  const [a, b, c] = o.map(Number);
  return !(a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0 && c === 0) || (a === 192 && b === 168) || (a === 198 && (b === 18 || b === 19)));
}
function isPublicIPv6(h) {
  if (!/^[0-9a-f:.]+$/.test(h) || h.startsWith("::")) return false;       // ::、::1、IPv4 映射等
  const parts = h.split(":");
  const first = parseInt(parts[0] || "0", 16);
  if (!Number.isFinite(first)) return false;
  // 仅依赖第一个 hextet 的保留前缀：ULA、link-local、组播、文档地址、discard-only 一律不视为公网。
  if ((first >= 0xfc00 && first <= 0xfdff) || (first & 0xffc0) === 0xfe80 || (first & 0xff00) === 0xff00 ||
      first === 0x0100 || h.startsWith("2001:db8:")) return false;
  // 依赖第二个 hextet 的保留前缀：Teredo 2001::/32、ORCHIDv1 2001:10::/28、ORCHIDv2 2001:20::/28、NAT64 64:ff9b::/96。
  // 第二段缺失（"2001::1" 这类压缩写法）按 0 处理：2001::/32 是 Teredo、低 32 位可内嵌私网 IPv4，
  // 压缩写法不能绕过；其余非特殊前缀（如 2606::1）不受影响。
  // 注意：文档地址 2001:db8::/32 由上方 startsWith("2001:db8:") 命中，而前导零写法 2001:0db8::/32
  // 由下方 second===0x0db8 分支命中（两条路径语义重叠、均拒收），因此将来删掉 startsWith 也不漏判。
  const second = Number.isFinite(parseInt(parts[1] || "", 16)) ? parseInt(parts[1], 16) : 0;
  if ((first === 0x2001 && second === 0x0000) || (first === 0x2001 && (second & 0xfff0) === 0x0010) ||
      (first === 0x2001 && (second & 0xfff0) === 0x0020) || (first === 0x0064 && second === 0xff9b)) return false;
  return true;
}

function canonicalKey(p) {
  // 去重键：不含名称；凭据、传输与 TLS 参数都是节点身份的一部分。
  const relevant = { type: p.type, server: String(p.server).toLowerCase(), port: Number(p.port) };
  for (const k of ["uuid", "password", "cipher", "alterId", "network", "servername", "flow", "encryption", "tls", "client-fingerprint", "alpn", "insecure",
    "ws-opts", "grpc-opts", "h2-opts", "xhttp-opts", "reality-opts"]) if (p[k] !== undefined) relevant[k] = p[k];
  return stableStringify(relevant);
}
function stableStringify(value) {
  if (Array.isArray(value)) return "[" + value.map(stableStringify).join(",") + "]";
  if (value && typeof value === "object")
    return "{" + Object.keys(value).sort().filter(k => value[k] !== undefined).map(k => JSON.stringify(k) + ":" + stableStringify(value[k])).join(",") + "}";
  return JSON.stringify(value);
}
async function sha256(s) {
  const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, "0")).join("");
}

// ───────────────────────────── Clash 输出 ─────────────────────────────
function serializeClash(proxies) {
  const lines = ["# Generated by node-observatory " + VERSION, "mixed-port: 7890", "allow-lan: false", "mode: rule", "log-level: warning"];
  if (!proxies.length) lines.push("proxies: []");
  else {
    lines.push("proxies:");
    for (const p of proxies) {
      lines.push("  - name: " + yamlScalar(p.name), "    type: " + yamlScalar(p.type), "    server: " + yamlScalar(p.server), "    port: " + p.port);
      for (const [k, v] of Object.entries(p)) {
        if (k === "name" || k === "type" || k === "server" || k === "port" || k === "insecure") continue;
        lines.push(...yamlLines(k, v, 4));
      }
      if (p.insecure) lines.push("    skip-cert-verify: true");
    }
  }
  lines.push("proxy-groups:", "  - name: AUTO", "    type: select", "    proxies:");
  for (const p of proxies) lines.push("      - " + yamlScalar(p.name));
  lines.push("      - DIRECT", "rules:", "  - MATCH,AUTO");
  return lines.join("\n") + "\n";
}
function yamlLines(key, value, indent) {
  const pad = " ".repeat(indent);
  if (value === undefined || value === null) return [];
  if (Array.isArray(value)) return value.length ? [pad + key + ":", ...value.map(x => pad + "  - " + yamlScalar(x))] : [pad + key + ": []"];
  if (typeof value === "object") {
    const entries = Object.entries(value).filter(([, v]) => v !== undefined && v !== null);
    return entries.length ? [pad + key + ":", ...entries.flatMap(([k, v]) => yamlLines(k, v, indent + 2))] : [pad + key + ": {}"];
  }
  return [pad + key + ": " + yamlScalar(value)];
}
function yamlScalar(v) { return typeof v === "boolean" || typeof v === "number" ? String(v) : JSON.stringify(String(v)); }
function uniqueName(name, fp, used) {
  const base = String(name).slice(0, 70) || "node";
  let n = base, i = 2;
  if (used.has(n)) n = `${base.slice(0, 60)}-${fp.slice(0, 6)}`;
  while (used.has(n)) n = `${base.slice(0, 56)}-${fp.slice(0, 6)}-${i++}`;
  used.add(n);
  return n;
}
function stripUndefined(o) { for (const k of Object.keys(o)) if (o[k] === undefined) delete o[k]; return o; }

// ───────────────────────────── 通用工具 ─────────────────────────────
function decodeBase64Utf8(s) {
  let b = String(s).trim().replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  if (b.length % 4 === 1) throw new Error("bad base64");
  b += "=".repeat((4 - (b.length % 4)) % 4);
  const bin = atob(b);
  return new TextDecoder().decode(Uint8Array.from(bin, c => c.charCodeAt(0)));
}
function toBase64Utf8(s) {
  const bytes = new TextEncoder().encode(s);
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}
function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data, null, 2), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...extraHeaders } });
}
function safeJson(s) { try { return JSON.parse(s || "null"); } catch { return null; } }

// ───────────────────────────── 管理面板 ─────────────────────────────
function dashboard(origin) {
  const originJs = JSON.stringify(origin).replace(/</g, "\\u003c");
  return new Response(String.raw`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><script src="https://cdn.jsdelivr.net/npm/qrcode@1.5.4/build/qrcode.min.js" defer></script><title>Node Observatory · 节点订阅管理</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#131b2f;--line:#26324c;--text:#edf2ff;--muted:#9aa8c4;--accent:#7c9cff;--good:#4bd6a0;--warn:#f4c76b;--bad:#ff8a8a}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at top,#172545 0,#0b1020 55%);color:var(--text);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1120px;margin:auto;padding:28px 18px 56px}.top{display:flex;gap:20px;justify-content:space-between;align-items:center;flex-wrap:wrap}.brand{display:flex;gap:12px;align-items:center}.logo{width:44px;height:44px;border-radius:14px;background:linear-gradient(135deg,#7597ff,#54d6bd);display:grid;place-items:center;color:#091120;font-weight:900;font-size:21px}
h1{font-size:24px;margin:0}h2{font-size:16px;margin:0 0 12px}.muted{color:var(--muted)}.tiny{font-size:12px;color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:22px 0}.panel,.stat{background:linear-gradient(160deg,#151f35,#11182a);border:1px solid var(--line);border-radius:16px;padding:16px;min-width:0}.stat .num{font-size:27px;font-weight:750;letter-spacing:-.5px}.stat .label{color:var(--muted);font-size:13px}.layout{display:grid;grid-template-columns:1.1fr .9fr;gap:14px}.links{display:grid;grid-template-columns:1fr 1fr;gap:10px}.sub{border:1px solid #344568;background:#101a30;border-radius:12px;padding:13px;min-width:0}.sub strong{display:block;margin-bottom:5px}.sub code{overflow-wrap:anywhere;color:#b9ccff;font-size:12px}.btn{border:1px solid #405681;border-radius:9px;padding:9px 12px;background:#1b2a49;color:var(--text);cursor:pointer}.btn:hover{background:#263b65}.btn.on{border-color:var(--accent);background:#263b65}.btn:disabled{opacity:.5;cursor:default}.field{background:#0b1324;border:1px solid var(--line);color:var(--text);padding:10px;border-radius:9px;min-width:0;width:100%}.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.row .field{flex:1}.tablewrap{overflow:auto}table{border-collapse:collapse;width:100%;font-size:12px}th,td{text-align:left;border-bottom:1px solid var(--line);padding:9px 8px;white-space:nowrap}th{color:var(--muted);font-weight:600}.pill{display:inline-block;padding:2px 7px;border-radius:20px;background:#173b37;color:var(--good)}.pill.off{background:#3c2b22;color:var(--warn)}.pill.bad{background:#40242a;color:var(--bad)}.tabs{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}.hidden{display:none}.notice{border-left:3px solid var(--warn);padding:8px 12px;background:#30291b;color:#e9d8ad;border-radius:4px;font-size:12px;margin-top:8px}.toast{color:var(--good);font-size:13px;min-height:20px}
@media(max-width:800px){.layout{grid-template-columns:1fr}.links{grid-template-columns:1fr}}@media(max-width:420px){main{padding:18px 12px}.stat .num{font-size:22px}}
</style></head><body><main>
<header class="top"><div class="brand"><div class="logo">N</div><div><h1>Node Observatory</h1><div class="muted">GitHub 发现 · 节点检测 · 风险过滤 · 订阅发布</div></div></div><div class="row"><button class="btn" onclick="refreshAll()">刷新数据</button><button class="btn" id="scanBtn" onclick="runScan()">立即扫描</button></div></header>
<section class="grid">
<div class="stat"><div class="label">已发布</div><div class="num" id="published">—</div><div class="tiny">活跃 + 风险分 ≥ 50 + 评估未过期</div></div>
<div class="stat"><div class="label">活跃节点</div><div class="num" id="active">—</div><div class="tiny">72 小时内仍被发现且未连续失败</div></div>
<div class="stat"><div class="label">待评估</div><div class="num" id="unassessed">—</div><div class="tiny">需外部检测器上报风险分</div></div>
<div class="stat"><div class="label">节点总量</div><div class="num" id="total">—</div><div class="tiny">含停用与历史节点</div></div>
<div class="stat"><div class="label">近期仓库</div><div class="num" id="repos">—</div><div class="tiny">近 72 小时发现或更新</div></div>
<div class="stat"><div class="label">最近运行</div><div class="num" id="last" style="font-size:14px;margin-top:9px">—</div><div class="tiny" id="lastSub">自动任务每 12 小时</div></div>
</section>
<section class="panel"><h2>固定订阅地址与二维码</h2><p class="tiny">订阅密钥只在当前浏览器内拼接地址；二维码本地生成库由 jsDelivr 加载。二维码含订阅密钥，请勿分享。</p><div class="row" style="margin-bottom:12px"><input id="subKeyInput" class="field" type="password" autocomplete="off" placeholder="输入 Cloudflare Secret：SUBSCRIPTION_KEY"><button class="btn" onclick="updateSubscriptionLinks()">生成订阅地址</button></div><div class="links"><div class="sub"><strong>Clash / Mihomo</strong><code id="clash"></code><div class="row" style="margin-top:10px"><button class="btn" onclick="copyUrl('clash')">复制地址</button><button class="btn" onclick="showQr('clash')">显示二维码</button></div></div><div class="sub"><strong>v2rayNG</strong><code id="v2ray"></code><div class="row" style="margin-top:10px"><button class="btn" onclick="copyUrl('v2ray')">复制地址</button><button class="btn" onclick="showQr('v2ray')">显示二维码</button></div></div></div><div id="qrPanel" class="sub hidden" style="margin-top:12px;text-align:center"><strong id="qrTitle">订阅二维码</strong><br><canvas id="qrCanvas" style="background:white;padding:10px;max-width:100%"></canvas><p class="tiny">二维码内含订阅密钥。请只用可信客户端扫码。</p><button class="btn" onclick="hideQr()">关闭二维码</button></div></section>
<section class="panel" style="margin-top:14px"><h2>本机网络诊断（浏览器）</h2><p class="tiny">只检测当前浏览器的公网出口与 WebRTC 候选；这不等于检测服务器上每个代理节点。DNS/IPv6 泄漏和 IP 信誉需要外部检测器从代理出口实测。</p><div class="row"><button class="btn" onclick="runBrowserDiagnostics()">检测本机网络</button><button class="btn" onclick="loadNetworkSummary()">查看节点质量汇总</button><span id="diagStatus" class="muted"></span></div><div id="diagResult" class="tiny" style="margin-top:8px;overflow-wrap:anywhere"></div></section>
<div class="layout" style="margin-top:14px"><section class="panel"><h2>订阅内容快速分析（浏览器本地）</h2><p class="tiny">粘贴 URI 列表，统计协议与去重数量；不会上传到服务器，也不会验证代理是否可用。</p><textarea class="field" id="importText" rows="6" placeholder="vmess://…&#10;vless://…&#10;trojan://…"></textarea><div class="row" style="margin-top:8px"><button class="btn" onclick="analyzeText()">分析并去重</button><span id="analysisResult" class="muted"></span></div></section>
<section class="panel"><h2>管理登录</h2><p class="tiny">使用 Cloudflare Secret 中配置的 ADMIN_PASSWORD 登录。登录会话存于 KV，8 小时过期；外部检测器仍使用 ADMIN_TOKEN。</p><input id="adminToken" class="field" type="password" autocomplete="current-password" placeholder="网站登录密码"><div class="row" style="margin-top:8px"><button class="btn" onclick="saveToken()">登录</button><button class="btn" onclick="clearToken()">退出登录</button></div><p id="adminMsg" class="toast"></p><div id="warnings"></div><div class="notice">Worker 的内置 TCP 检测仅证明端口可连接，不等于代理认证、TLS 握手或实际出网成功。可接入外部 Mihomo 检测器并上报 riskScore。</div></section></div>
<section class="panel" style="margin-top:14px"><div class="tabs"><button class="btn on" id="tabbtn-nodes" onclick="showTab('nodes')">节点</button><button class="btn" id="tabbtn-repos" onclick="showTab('repos')">仓库评分</button><button class="btn" id="tabbtn-runs" onclick="showTab('runs')">任务记录</button></div>
<div id="tab-nodes"><div class="row" style="margin-bottom:10px"><input class="field" id="nodeFilter" placeholder="筛选协议 / 服务器 / 仓库" oninput="renderNodes()"><span class="tiny" id="nodeCount"></span></div><div class="tablewrap"><table><thead><tr><th>状态</th><th>协议</th><th>服务器</th><th>端口</th><th>来源</th><th>最后发现</th><th>检测方式</th><th>延迟</th><th>风险等级</th><th>风险分</th><th>质量分</th><th>HTTP 丢包</th><th>抖动</th><th>测速 KB/s</th><th>DNS 泄漏</th><th>IPv6 泄漏</th><th>黑名单</th><th>评估时间</th></tr></thead><tbody id="nodesBody"><tr><td colspan="18" class="muted">节点详情包含服务器地址，需先登录才会加载。</td></tr></tbody></table></div></div>
<div id="tab-repos" class="hidden"><div class="tablewrap"><table><thead><tr><th>仓库</th><th>评分</th><th>Stars</th><th>最近推送</th><th>发现文件</th><th>候选节点</th><th>错误</th></tr></thead><tbody id="reposBody"></tbody></table></div></div>
<div id="tab-runs" class="hidden"><div class="tablewrap"><table><thead><tr><th>开始</th><th>结束</th><th>结果</th><th>错误</th></tr></thead><tbody id="runsBody"></tbody></table></div></div>
</section><p class="tiny" style="margin-top:18px">只从公开来源采集；公开节点可能不安全或随时失效。不要把敏感流量交给不信任的节点。v${VERSION}</p></main>
<script>
var ORIGIN=${originJs};var nodes=[],token='',scanning=false;fetch('/auth/session').then(function(r){return r.json()}).then(function(s){if(s.authenticated){token='cookie';refreshAll()}}).catch(function(){});
var RISK={low:'低风险',neutral:'中性',high:'高风险',critical:'严重风险',unassessed:'未评估'};
function $(id){return document.getElementById(id)}
function fmt(v){if(!v)return '—';try{return new Date(v).toLocaleString()}catch(e){return String(v)}}
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function msg(t){$('adminMsg').textContent=t}
function copyUrl(which){var t=$(which).textContent;if(!t||t.indexOf('YOUR_KEY')>=0){msg('请先输入 SUBSCRIPTION_KEY 并生成地址');return}if(navigator.clipboard)navigator.clipboard.writeText(t).then(function(){msg('订阅地址已复制')},function(){msg('复制失败，请长按地址手动复制')})}
function updateSubscriptionLinks(){var key=$('subKeyInput').value.trim();if(!key){msg('请先输入 SUBSCRIPTION_KEY');return}if(key.length>512){msg('密钥长度不正确');return}$('clash').textContent=ORIGIN+'/sub/clash?key='+encodeURIComponent(key);$('v2ray').textContent=ORIGIN+'/sub/v2rayng?key='+encodeURIComponent(key);msg('订阅地址已在当前浏览器生成；密钥未保存')}
function showQr(which){var value=$(which).textContent;if(!value||value.indexOf('YOUR_KEY')>=0){msg('请先输入 SUBSCRIPTION_KEY 并生成地址');return}if(!window.QRCode||!QRCode.toCanvas){msg('二维码组件加载失败，请检查网络后刷新页面');return}$('qrTitle').textContent=which==='clash'?'Clash / Mihomo 订阅二维码':'v2rayNG 订阅二维码';$('qrPanel').classList.remove('hidden');QRCode.toCanvas($('qrCanvas'),value,{width:240,margin:2,errorCorrectionLevel:'M'},function(err){if(err)msg('二维码生成失败：'+err.message)})}
function hideQr(){$('qrPanel').classList.add('hidden')}
async function loadNetworkSummary(){try{var r=await api('/admin/network-summary');var s=r.summary||{};$('diagStatus').textContent='节点统计：活跃 '+(s.active||0)+'；已评估 '+(s.assessed||0)+'；平均延迟 '+(s.avg_latency==null?'未知':Math.round(s.avg_latency)+' ms')+'；DNS 泄漏 '+(s.dns_leaks||0)+'；IPv6 泄漏 '+(s.ipv6_leaks||0)+'；黑名单命中 '+(s.blacklisted||0)}catch(e){$('diagStatus').textContent='节点汇总读取失败：请先登录'}}
async function runBrowserDiagnostics(){var out=[];$('diagStatus').textContent='检测中…';$('diagResult').textContent='';var r;try{r=await fetch('https://api.ipify.org?format=json',{cache:'no-store'});if(r.ok){var d=await r.json();out.push('公网 IPv4：'+(d.ip||'未识别'))}else out.push('公网 IPv4：查询失败')}catch(e){out.push('公网 IPv4：查询失败（可能被网络策略拦截）')}try{var r6=await fetch('https://api64.ipify.org?format=json',{cache:'no-store'});if(r6.ok){var d6=await r6.json();out.push('IPv6/双栈出口：'+(d6.ip||'未识别'))}else out.push('IPv6/双栈出口：不可用或查询失败')}catch(e){out.push('IPv6/双栈出口：不可用或查询失败')}try{if(window.RTCPeerConnection){var pc=new RTCPeerConnection({iceServers:[]});pc.createDataChannel('diag');await pc.setLocalDescription(await pc.createOffer());var ips=new Set();await new Promise(function(resolve){var timer=setTimeout(resolve,1800);pc.onicecandidate=function(ev){if(!ev.candidate){clearTimeout(timer);resolve();return}var m=ev.candidate.candidate.match(/(?:\d{1,3}\.){3}\d{1,3}|[0-9a-f:]{3,}/i);if(m)ips.add(m[0])}});pc.close();out.push('WebRTC 候选：'+(ips.size?[...ips].join(', '):'未发现候选地址'))}else out.push('WebRTC：浏览器不支持')}catch(e){out.push('WebRTC：检测被浏览器限制')} $('diagResult').textContent=out.join('；');$('diagStatus').textContent='完成（仅代表本机浏览器）'}
async function saveToken(){var password=$('adminToken').value;msg('正在登录…');try{var r=await fetch('/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({password:password})});var d=await r.json();if(!r.ok)throw new Error(d.error||r.status);token=d.ok?'cookie':'';$('adminToken').value='';msg(token?'登录成功（会话 8 小时后过期）':'登录失败');if(token)refreshAll()}catch(e){token='';msg('登录失败：'+e.message)}}
async function clearToken(){try{await fetch('/auth/logout',{method:'POST'})}catch(e){}token='';$('adminToken').value='';nodes=[];renderNodes();$('warnings').innerHTML='';msg('已退出登录')}
async function api(path,opts){opts=opts||{};var headers=Object.assign({},opts.headers||{});if(token&&token!=='cookie')headers.Authorization='Bearer '+token;var r=await fetch(path,Object.assign({},opts,{headers:headers,credentials:'same-origin'}));if(!r.ok)throw new Error(r.status+' '+r.statusText);return r.json()}
async function refreshStatus(){
  var s=await api('/api/status');
  $('published').textContent=s.publishedNodes;$('active').textContent=s.activeNodes;$('unassessed').textContent=s.unassessedNodes;$('total').textContent=s.totalNodes;$('repos').textContent=s.activeSources;
  $('last').textContent=fmt(s.lastRun);$('lastSub').textContent=s.running?'正在运行…':(s.lastRunError?'上次失败：'+s.lastRunError:'自动任务每 12 小时');
  if(!$('clash').textContent){$('clash').textContent=ORIGIN+'/sub/clash?key=YOUR_KEY';$('v2ray').textContent=ORIGIN+'/sub/v2rayng?key=YOUR_KEY';}
  $('warnings').innerHTML=(s.configWarnings||[]).map(function(w){return '<div class="notice">'+esc(w)+'</div>'}).join('');
  return s;
}
async function refreshAll(){
  try{await refreshStatus()}catch(e){$('last').textContent='暂不可用';msg('读取状态失败：'+e.message);return}
  try{var r=await api('/api/repositories');$('reposBody').innerHTML=(r.repositories||[]).map(function(x){return '<tr><td>'+esc(x.repo)+'</td><td>'+x.score+'</td><td>'+x.stars+'</td><td>'+esc(x.pushed_at||'—')+'</td><td>'+x.files_found+'</td><td>'+x.nodes_found+'</td><td>'+esc(x.last_error||'—')+'</td></tr>'}).join('')}catch(e){}
  try{var u=await api('/api/runs');$('runsBody').innerHTML=(u.runs||[]).map(function(x){return '<tr><td>'+esc(fmt(x.started_at))+'</td><td>'+esc(fmt(x.finished_at))+'</td><td>'+esc(JSON.stringify(x.result||{}))+'</td><td>'+esc(x.error||'—')+'</td></tr>'}).join('')}catch(e){}
  if(token){try{var n=await api('/api/nodes?limit=300');nodes=n.nodes||[];renderNodes()}catch(e){msg('读取节点失败：'+e.message+'（令牌是否正确？）')}}
}
function renderNodes(){
  if(!token){return}
  var f=($('nodeFilter').value||'').toLowerCase();
  var rows=nodes.filter(function(n){return (n.scheme+' '+n.server+' '+n.source_repo).toLowerCase().indexOf(f)>=0});
  $('nodeCount').textContent=rows.length+' 条';
  $('nodesBody').innerHTML=rows.map(function(n){
    var lvl=n.risk_level||'unassessed',cls=(lvl==='high'||lvl==='critical')?'bad':(n.active?'':'off');
    return '<tr><td><span class="pill '+(n.active?'':'off')+'">'+(n.active?'活跃':'停用')+'</span></td><td>'+esc(n.scheme)+'</td><td>'+esc(n.server||'—')+'</td><td>'+esc(n.port||'—')+'</td><td>'+esc(n.source_repo||'—')+'</td><td>'+esc(fmt(n.last_seen))+'</td><td>'+esc(n.check_method||'—')+'</td><td>'+(n.latency_ms==null?'—':n.latency_ms+' ms')+'</td><td><span class="pill '+cls+'">'+esc(RISK[lvl]||lvl)+'</span></td><td>'+(lvl==='unassessed'?'—':n.risk_score)+'</td><td>'+(n.quality_score==null?'—':n.quality_score)+'</td><td>'+(n.http_loss==null?'—':Math.round(n.http_loss*100)+'%')+'</td><td>'+(n.jitter_ms==null?'—':Math.round(n.jitter_ms)+' ms')+'</td><td>'+(n.speed_kbps==null?'—':Math.round(n.speed_kbps))+'</td><td>'+(n.dns_leak==null?'未知':n.dns_leak?'是':'否')+'</td><td>'+(n.ipv6_leak==null?'未知':n.ipv6_leak?'是':'否')+'</td><td>'+(n.blacklist_hits==null?'未知':n.blacklist_hits)+'</td><td>'+esc(fmt(n.risk_assessed_at))+'</td></tr>'
  }).join('');
}
function showTab(t){['nodes','repos','runs'].forEach(function(id){$('tab-'+id).classList.toggle('hidden',id!==t);$('tabbtn-'+id).classList.toggle('on',id===t)})}
async function runScan(){
  if(!token){msg('请先登录管理面板');return}
  if(scanning)return;
  try{
    scanning=true;$('scanBtn').disabled=true;msg('已提交扫描任务…');
    await api('/admin/run',{method:'POST'});
    for(var i=0;i<150;i++){await new Promise(function(r){setTimeout(r,4000)});var s=await refreshStatus();msg('扫描运行中…（已等待 '+(i+1)*4+' 秒）');if(!s.running)break}
    await refreshAll();var sum=(await api('/api/status')).lastRunSummary;
    msg(sum?'完成：扫描 '+sum.reposScanned+' 个仓库，新增 '+sum.inserted+' 个节点'+(sum.stoppedEarly?'（因 '+sum.stoppedEarly+' 提前结束）':''):'完成');
  }catch(e){msg('扫描失败：'+e.message)}finally{scanning=false;$('scanBtn').disabled=false}
}
function analyzeText(){
  var raw=$('importText').value;
  var found=raw.match(/(?:vmess|vless|trojan|ss|ssr|hysteria2?|tuic):\/\/[^\s"'<>\x60]+/gi)||[];
  var uniq=Array.from(new Set(found.map(function(x){return x.replace(/[),;\]}]+$/,'')})));
  var counts={};uniq.forEach(function(u){var p=u.split(':')[0].toLowerCase();counts[p]=(counts[p]||0)+1});
  $('analysisResult').textContent=found.length+' 条识别结果，去重后 '+uniq.length+' 条；'+Object.keys(counts).map(function(k){return k+': '+counts[k]}).join('、');
}
refreshAll();
</script></body></html>`, {
    headers: {
      "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer", "x-robots-tag": "noindex",
      "content-security-policy": "default-src 'none'; script-src 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'unsafe-inline'; connect-src 'self' https://api.ipify.org https://api64.ipify.org; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    }
  });
}
