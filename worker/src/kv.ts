// =========================================================================================================
// KV CACHE LAYER
// =========================================================================================================
// Workers KV sits in front of D1 for read-heavy endpoints.
// D1 remains the source of truth; KV is a fast read-through cache.
//
// TTLs:
//   KV_TTL_SCAN    = 24 h  — individual scan results (scan cache hit + detail view)
//   KV_TTL_STATS   = 60 s  — aggregate platform stats (changes per new scan)
//   KV_TTL_CSTATS  = 30 s  — D1 scan_cache stats (lightweight)
//
// Key schema:
//   scan:{cacheKey}     → raw scan result JSON string (same cacheKey as D1)
//   detail:{sha256}     → full ScanDetail JSON object
//   stats:global        → GlobalStats JSON object
//   cache_stats         → CacheStats JSON object
// =========================================================================================================

// ── TTLs (seconds) ────────────────────────────────────────────────────────────

export const KV_TTL_SCAN   = 24 * 60 * 60; // 24 h
export const KV_TTL_STATS  = 60;            // 60 s
export const KV_TTL_CSTATS = 30;            // 30 s

// ── Key builders ──────────────────────────────────────────────────────────────

export const kvKeyScan       = (cacheKey: string) => `scan:${cacheKey}`;
export const kvKeyDetail     = (sha256: string)   => `detail:${sha256}`;
export const kvKeyStats      = ()                 => 'stats:global';
export const kvKeyCacheStats = ()                 => 'cache_stats';

// ── Generic helpers ───────────────────────────────────────────────────────────

/**
 * Reads a JSON value from KV. Returns null on miss or error.
 * Never throws — KV errors are non-fatal (fall through to D1).
 */
export async function kvGet<T>(kv: KVNamespace, key: string): Promise<T | null> {
	try {
		return await kv.get<T>(key, 'json');
	} catch {
		return null;
	}
}

/**
 * Reads a raw string from KV. Returns null on miss or error.
 */
export async function kvGetText(kv: KVNamespace, key: string): Promise<string | null> {
	try {
		return await kv.get(key, 'text');
	} catch {
		return null;
	}
}

/**
 * Writes a value to KV with a TTL. Fire-and-forget safe — errors are logged
 * but never propagated to the caller.
 */
export async function kvPut(
	kv: KVNamespace,
	key: string,
	value: unknown,
	ttlSeconds: number,
): Promise<void> {
	try {
		const serialized = typeof value === 'string' ? value : JSON.stringify(value);
		await kv.put(key, serialized, { expirationTtl: Math.max(60, ttlSeconds) });
	} catch (e) {
		console.error('[KV] put failed', key, e);
	}
}

/**
 * Deletes a KV key. Fire-and-forget safe.
 */
export async function kvDelete(kv: KVNamespace, key: string): Promise<void> {
	try {
		await kv.delete(key);
	} catch { /* best effort */ }
}
