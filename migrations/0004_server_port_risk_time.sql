-- 适用于已部署 v3.0/v3.1 的数据库：补上 /api/nodes 与 /admin/candidates 需要的 server、port，
-- 以及风险评估时间。v3.2 的 Worker 会在启动时自动补列，本文件只是手动执行的等价版本。
-- 如果某条语句报 "duplicate column name"，说明该列已存在，跳过那一条即可。
ALTER TABLE nodes ADD COLUMN server TEXT;
ALTER TABLE nodes ADD COLUMN port INTEGER;
ALTER TABLE nodes ADD COLUMN risk_assessed_at INTEGER;
UPDATE nodes SET risk_assessed_at = last_checked WHERE risk_score > 0 AND last_checked > 0;
CREATE INDEX IF NOT EXISTS idx_nodes_publish ON nodes(active, risk_score);
