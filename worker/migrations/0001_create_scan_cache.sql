CREATE TABLE IF NOT EXISTS scan_cache (
    cache_key   TEXT PRIMARY KEY,
    sha256      TEXT NOT NULL,
    result      TEXT NOT NULL,
    file_id     TEXT NOT NULL,
    risk_level  TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    access_count INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_scan_cache_sha256  ON scan_cache(sha256);
CREATE INDEX IF NOT EXISTS idx_scan_cache_created ON scan_cache(created_at);
