-- 仅适用于 v2 → v3：补列并建表。已经是 v3.x 的库请勿执行（会报 duplicate column）。
-- v3.2 的 Worker 会自动补齐缺失的列，通常无需手动执行任何迁移。
ALTER TABLE repositories ADD COLUMN score INTEGER NOT NULL DEFAULT 0;
ALTER TABLE repositories ADD COLUMN files_found INTEGER NOT NULL DEFAULT 0;
ALTER TABLE repositories ADD COLUMN nodes_found INTEGER NOT NULL DEFAULT 0;
ALTER TABLE repositories ADD COLUMN last_error TEXT;
ALTER TABLE nodes ADD COLUMN latency_ms INTEGER;
ALTER TABLE nodes ADD COLUMN exit_ip TEXT;
ALTER TABLE nodes ADD COLUMN country TEXT;
ALTER TABLE nodes ADD COLUMN check_method TEXT;
ALTER TABLE nodes ADD COLUMN last_error TEXT;
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  result_json TEXT,
  error TEXT
);
CREATE INDEX IF NOT EXISTS idx_repositories_score ON repositories(score DESC);
CREATE INDEX IF NOT EXISTS idx_runs_started ON runs(started_at DESC);

ALTER TABLE nodes ADD COLUMN risk_score INTEGER NOT NULL DEFAULT 0;
ALTER TABLE nodes ADD COLUMN risk_level TEXT NOT NULL DEFAULT 'unassessed';
ALTER TABLE nodes ADD COLUMN risk_reasons TEXT;
