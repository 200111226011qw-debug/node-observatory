-- 仅适用于早期 v3（缺少风险列）的库；会把所有节点重置为“未评估”。v3.2 的 Worker 会自动补列，通常无需手动执行。
ALTER TABLE nodes ADD COLUMN risk_score INTEGER NOT NULL DEFAULT 0;
ALTER TABLE nodes ADD COLUMN risk_level TEXT NOT NULL DEFAULT 'unassessed';
ALTER TABLE nodes ADD COLUMN risk_reasons TEXT;
UPDATE nodes SET risk_score=0, risk_level='unassessed', risk_reasons='["Needs external risk assessment"]';
