-- =========================================================================================================
-- SCANS TABLE — Permanent scan history (VirusTotal-style)
-- =========================================================================================================
-- Stores full scan results permanently for history, search, and re-scanning.
-- Separate from scan_cache which has a 30-day TTL for performance caching.
--
-- Applied with: npx wrangler d1 migrations apply vrcstorage-scanner
-- =========================================================================================================

CREATE TABLE IF NOT EXISTS scans (
    sha256           TEXT PRIMARY KEY,
    filename         TEXT NOT NULL,
    file_size        INTEGER NOT NULL,
    upload_date      INTEGER NOT NULL,
    risk_level       TEXT NOT NULL,
    total_score      INTEGER NOT NULL,
    duration_ms      INTEGER NOT NULL,
    result_json      TEXT NOT NULL,
    file_tree_json   TEXT,
    finding_count    INTEGER DEFAULT 0,
    critical_count   INTEGER DEFAULT 0,
    high_count       INTEGER DEFAULT 0,
    medium_count     INTEGER DEFAULT 0,
    low_count        INTEGER DEFAULT 0,
    access_count     INTEGER DEFAULT 1,
    last_accessed    INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scans_date     ON scans(upload_date DESC);
CREATE INDEX IF NOT EXISTS idx_scans_risk     ON scans(risk_level);
CREATE INDEX IF NOT EXISTS idx_scans_filename ON scans(filename);
