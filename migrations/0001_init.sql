-- 全新安装：一次性执行本文件即可（已包含 v3.2 的全部列）。
CREATE TABLE IF NOT EXISTS repositories (
  repo TEXT PRIMARY KEY,
  stars INTEGER NOT NULL DEFAULT 0,
  pushed_at TEXT,
  last_seen INTEGER NOT NULL,
  last_checked INTEGER NOT NULL,
  score INTEGER NOT NULL DEFAULT 0,
  files_found INTEGER NOT NULL DEFAULT 0,
  nodes_found INTEGER NOT NULL DEFAULT 0,
  last_error TEXT
);
CREATE TABLE IF NOT EXISTS nodes (
  fingerprint TEXT PRIMARY KEY,
  canonical TEXT NOT NULL,
  uri TEXT NOT NULL,
  scheme TEXT NOT NULL,
  server TEXT,
  port INTEGER,
  source_repo TEXT,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  last_checked INTEGER NOT NULL DEFAULT 0,
  last_success INTEGER,
  active INTEGER NOT NULL DEFAULT 1,
  fail_count INTEGER NOT NULL DEFAULT 0,
  latency_ms INTEGER,
  exit_ip TEXT,
  country TEXT,
  check_method TEXT,
  last_error TEXT,
  risk_score INTEGER NOT NULL DEFAULT 0,
  risk_level TEXT NOT NULL DEFAULT 'unassessed',
  risk_reasons TEXT,
  risk_assessed_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_nodes_active ON nodes(active);
CREATE INDEX IF NOT EXISTS idx_nodes_last_seen ON nodes(last_seen);
CREATE INDEX IF NOT EXISTS idx_nodes_publish ON nodes(active, risk_score);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  result_json TEXT,
  error TEXT
);
CREATE INDEX IF NOT EXISTS idx_repositories_score ON repositories(score DESC);
CREATE INDEX IF NOT EXISTS idx_runs_started ON runs(started_at DESC);
