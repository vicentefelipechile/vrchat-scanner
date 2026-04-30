// =========================================================================================================
// SCAN CACHE — D1 Helpers
// =========================================================================================================
// VirusTotal-style caching for scan results.
// - Keys are SHA-256 + query params (format, min_severity, verbose).
// - Entries expire after 30 days.
// - Access counts are bumped on every cache hit for telemetry.
//
// Tables are created via ./migrations/0001_create_scan_cache.sql
// applied with: npx wrangler d1 migrations apply vrcstorage-scan-cache
// =========================================================================================================

// =========================================================================================================
// Imports & Types
// =========================================================================================================

export interface CachedScan {
	result: string;
	access_count: number;
}

// =========================================================================================================
// Constants
// =========================================================================================================

const TTL_30_DAYS_MS = 30 * 24 * 60 * 60 * 1000;

// =========================================================================================================
// Helpers
// =========================================================================================================

/**
 * Builds a deterministic cache key from the file hash and request parameters.
 *
 * Format: `sha256|format|min_severity|verbose`
 * This ensures that different query-param combinations (e.g. verbose vs non-verbose)
 * produce distinct cache entries for the same file.
 */
export function buildCacheKey(
	sha256: string,
	format: string,
	minSeverity: string,
	verbose: string,
): string {
	return `${sha256}|${format}|${minSeverity}|${verbose}`;
}

// =========================================================================================================
// Queries
// =========================================================================================================

/**
 * Looks up a scan result in the cache.
 *
 * Returns the cached `ScanResponse` JSON and current access count if the entry
 * exists and has not expired (30 day TTL).  Returns `null` on cache miss or
 * stale entry.  Access count is bumped atomically on every hit for telemetry.
 */
export async function getCachedScan(
	db: D1Database,
	cacheKey: string,
): Promise<CachedScan | null> {
	const minCreatedAt = Date.now() - TTL_30_DAYS_MS;

	const row = await db
		.prepare(
			'SELECT result, access_count FROM scan_cache WHERE cache_key = ? AND created_at >= ?',
		)
		.bind(cacheKey, minCreatedAt)
		.first<{ result: string; access_count: number }>();

	if (!row) return null;

	// Bump access count — fire-and-forget, no need to await before returning.
	db.prepare(
		'UPDATE scan_cache SET access_count = access_count + 1 WHERE cache_key = ?',
	)
		.bind(cacheKey)
		.run();

	return { result: row.result, access_count: row.access_count + 1 };
}

/**
 * Stores a scan result in the cache.
 *
 * Uses `INSERT OR REPLACE` so re-scanning the same file with the same params
 * simply refreshes the timestamp and resets the access counter.
 */
export async function putCachedScan(db: D1Database, cacheKey: string, sha256: string, resultJson: string, fileId: string, riskLevel: string): Promise<boolean> {
	const stmt = await db.prepare(`
		INSERT OR REPLACE INTO scan_cache (
			cache_key,
			sha256,
			result,
			file_id,
			risk_level,
			created_at,
			access_count
		) VALUES (?, ?, ?, ?, ?, ?, 1)`);

	try {
		const result = await stmt
			.bind(cacheKey, sha256, resultJson, fileId, riskLevel, Date.now())
			.run();
		
		return result.success;
	} catch (e) {
		console.error('Failed to put cache entry', e);
		return false;
	}
}

// =========================================================================================================
// Stats
// =========================================================================================================

/**
 * Returns aggregate cache statistics from D1.
 *
 * Queried by the SPA's Cache Stats panel and the `/api/cache-stats` endpoint.
 * Includes total entries, oldest and newest timestamps.
 */
export interface CacheStats {
	total: number;
	oldest_ms: number;
	newest_ms: number;
}

export async function getCacheStats(db: D1Database): Promise<CacheStats> {
	const row = await db
		.prepare(
			'SELECT COUNT(*) as total, MIN(created_at) as oldest, MAX(created_at) as newest FROM scan_cache',
		)
		.first<{ total: number; oldest: number | null; newest: number | null }>();

	return {
		total: (row?.total as number) ?? 0,
		oldest_ms: (row?.oldest as number) ?? 0,
		newest_ms: (row?.newest as number) ?? 0,
	};
}
