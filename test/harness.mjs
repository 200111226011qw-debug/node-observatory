// 测试工具：把 Worker 源码里的 cloudflare:sockets 换成桩，再用 node:sqlite 模拟 D1。
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
let counter = 0;

export async function loadWorker() {
  let src = fs.readFileSync(path.join(root, "src/index.js"), "utf8");
  src = src.replace(/^import .*cloudflare:sockets.*$/m, "const connect = (...a) => globalThis.__connect(...a);");
  src += "\nexport { parseNode, extractNodes, canonicalKey, serializeClash, runPipeline, riskLevel, isPublicHost, tryDecodeBlob };\n";
  const file = path.join(os.tmpdir(), `worker-under-test-${process.pid}-${counter++}.mjs`);
  fs.writeFileSync(file, src);
  return import(pathToFileURL(file).href);
}

class Stmt {
  constructor(db, sql, log) { this.db = db; this.sql = sql; this.args = []; this.log = log; }
  bind(...a) {
    if (a.some(v => v === undefined)) throw new Error("D1_TYPE_ERROR: undefined binding");
    this.args = a; return this;
  }
  _check() {
    const n = (this.sql.match(/\?/g) || []).length;           // 与 D1 一样严格：绑定数量必须一致
    if (n !== this.args.length) throw new Error(`D1_ERROR: expected ${n} bindings, got ${this.args.length}\n${this.sql}`);
  }
  _exec(kind, counted = true) {
    this._check(); if (counted) this.log.queries++;
    const st = this.db.prepare(this.sql);
    if (kind === "first") return st.get(...this.args) ?? null;
    if (kind === "all") return { results: st.all(...this.args) };
    const r = st.run(...this.args);
    return { meta: { last_row_id: Number(r.lastInsertRowid), changes: r.changes } };
  }
  async first() { return this._exec("first"); }
  async all() { return this._exec("all"); }
  async run() { return this._exec("run"); }
}

export function makeDb(migrations = ["0001_init.sql"]) {
  const sqlite = new DatabaseSync(":memory:");
  for (const m of migrations) sqlite.exec(fs.readFileSync(path.join(root, "migrations", m), "utf8"));
  const log = { queries: 0, batches: 0 };
  const DB = {
    prepare: sql => new Stmt(sqlite, sql, log),
    async batch(stmts) {
      log.batches++;
      sqlite.exec("BEGIN");
      try { const out = stmts.map(s => s._exec("run", false)); sqlite.exec("COMMIT"); return out; }
      catch (e) { sqlite.exec("ROLLBACK"); throw e; }
    }
  };
  return { DB, sqlite, log };
}

// 模拟 GitHub：repos = { "owner/name": { stars, pushedDaysAgo, files: { "path": "content" } } }
export function mockGithub(repos) {
  const calls = [];
  globalThis.fetch = async (input) => {
    const url = String(input); calls.push(url);
    const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json" } });
    if (url.startsWith("https://api.github.com/search/repositories"))
      return json({ items: Object.entries(repos).map(([full_name, r]) => ({
        full_name, default_branch: "main", stargazers_count: r.stars ?? 200,
        pushed_at: new Date(Date.now() - (r.pushedDaysAgo ?? 1) * 86_400_000).toISOString() })) });
    let m = /^https:\/\/api\.github\.com\/repos\/([^/]+\/[^/]+)\/git\/trees\//.exec(url);
    if (m) {
      const r = repos[m[1]]; if (!r) return json({}, 404);
      return json({ tree: Object.entries(r.files).map(([p, c]) => ({ type: "blob", path: p, size: c.length })) });
    }
    m = /^https:\/\/raw\.githubusercontent\.com\/([^/]+\/[^/]+)\/main\/(.+)$/.exec(url);
    if (m) { const f = repos[m[1]]?.files[decodeURIComponent(m[2])]; return f == null ? new Response("nf", { status: 404 }) : new Response(f); }
    return json({}, 404);
  };
  return calls;
}

export const b64 = s => Buffer.from(s).toString("base64");
export const b64url = s => Buffer.from(s).toString("base64url");
export const UUID = "11111111-2222-3333-4444-555555555555";
