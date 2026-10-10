-- v3.7 network diagnostics and quality metrics; safe additive migration.
ALTER TABLE nodes ADD COLUMN http_loss REAL;
ALTER TABLE nodes ADD COLUMN jitter_ms REAL;
ALTER TABLE nodes ADD COLUMN speed_kbps REAL;
ALTER TABLE nodes ADD COLUMN dns_leak INTEGER;
ALTER TABLE nodes ADD COLUMN ipv6_leak INTEGER;
ALTER TABLE nodes ADD COLUMN proxy_detected INTEGER;
ALTER TABLE nodes ADD COLUMN blacklist_hits INTEGER;
ALTER TABLE nodes ADD COLUMN is_datacenter INTEGER;
ALTER TABLE nodes ADD COLUMN quality_score INTEGER;
ALTER TABLE nodes ADD COLUMN check_details TEXT;
