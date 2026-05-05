// =========================================================================================================
// DATA CACHE
// =========================================================================================================
// A two-layer, in-memory + localStorage caching utility for the frontend SPA.
//
// Cache resolution order for every `fetch()` call:
//   1. In-memory Map (fastest, ephemeral — cleared on page reload)
//   2. localStorage (survives page reload, keyed as `cache:<url>`)
//   3. Live network fetch (deduplicates concurrent in-flight requests)
//
// Entries are stored with a Unix timestamp and considered valid while `Date.now() - timestamp < ttl`.
// Persistent entries skip the TTL check and are kept until explicitly cleared via `clear()`.
// =========================================================================================================

// =========================================================================================================
// Time Unit Constants
// =========================================================================================================

const TimeUnit = Object.freeze({
	Second: 1000,
	Minute: 60 * 1000,
	Hour:   60 * 60 * 1000,
	Day:    24 * 60 * 60 * 1000,
	Week:   7 * 24 * 60 * 60 * 1000,
});

// =========================================================================================================
// Helpers
// =========================================================================================================

/** localStorage key prefix used for all cache entries. Centralised to avoid scattered literals. */
const CACHE_PREFIX = 'cache:';

/**
 * Normalises the `options` argument accepted by `fetch()` and `prefetch()`.
 *
 * Accepts either:
 *   - A plain number (treated as the TTL in milliseconds).
 *   - An options object with optional `ttl`, `persistent`, and `type` fields.
 *
 * Returns a fully-resolved options object with no optional fields.
 *
 * @param {CacheOptions|number} options
 * @returns {{ ttl: number, persistent: boolean, type: 'json'|'text' }}
 */
function resolveOptions(options) {
	if (typeof options === 'object' && options !== null) {
		return {
			ttl:        options.ttl        ?? 60_000,
			persistent: options.persistent ?? false,
			type:       options.type       ?? 'json',
		};
	}
	return { ttl: options, persistent: false, type: 'json' };
}

/**
 * Writes a cache entry to localStorage under `cache:<url>`.
 * Handles `QuotaExceededError` by evicting all `cache:*` keys and retrying once.
 * If the retry also fails, the data is silently kept in-memory only.
 *
 * @param {string} url   - The URL that was fetched, used as part of the storage key.
 * @param {{ data: unknown, timestamp: number }} entry - The cache entry to serialise and store.
 */
function persistToStorage(url, entry) {
	const serialised = JSON.stringify(entry);
	try {
		localStorage.setItem(`${CACHE_PREFIX}${url}`, serialised);
	} catch (e) {
		if (e instanceof DOMException && e.name === 'QuotaExceededError') {
			// Storage is full — evict all cached entries and retry once.
			console.warn('[DataCache] localStorage full, clearing old entries…');
			Object.keys(localStorage)
				.filter((k) => k.startsWith(CACHE_PREFIX))
				.forEach((k) => localStorage.removeItem(k));
			try {
				localStorage.setItem(`${CACHE_PREFIX}${url}`, serialised);
			} catch (retryErr) {
				// Still fails after cleanup — data lives in memory only for this session.
				console.warn('[DataCache] localStorage still full after cleanup', retryErr);
			}
		} else {
			console.warn('[DataCache] localStorage write error', e);
		}
	}
}

// =========================================================================================================
// DataCache
// =========================================================================================================

/**
 * Two-layer, in-memory + localStorage cache with in-flight request deduplication.
 *
 * @example
 * // Basic fetch with a 30-second TTL
 * const data = await DataCache.fetch('/api/stats', 30_000);
 *
 * @example
 * // Persistent fetch that survives page reloads, 5-minute TTL
 * const config = await DataCache.fetch('/api/config', { ttl: 300_000, persistent: true });
 *
 * @example
 * // Prefetch speculatively on hover
 * DataCache.prefetch('/api/history');
 *
 * @example
 * // Invalidate a single URL after a write operation
 * DataCache.clear('/api/history');
 *
 * @example
 * // Full cache flush
 * DataCache.clear();
 */
// Exposed as a global so all plain <script> modules can access it without a bundler.
const DataCache = window.DataCache = {
	/**
	 * In-memory cache layer. Maps a URL string to its cached entry.
	 * This map is the fastest lookup path and is checked before localStorage.
	 * Cleared on every full page navigation (not preserved across reloads).
	 *
	 * @type {Map<string, { data: unknown, timestamp: number }>}
	 */
	cache: new Map(),

	/**
	 * In-flight request deduplication map. Maps a URL string to its pending Promise.
	 * If two callers request the same URL simultaneously, only one HTTP request is made
	 * and both callers receive the same Promise. The entry is deleted once the request settles.
	 *
	 * @type {Map<string, Promise<unknown>>}
	 */
	pending: new Map(),

	// =========================================================================================================
	// fetch(url, options?)
	// Resolves data for a given URL through the two-layer cache, then falls back to a live network request.
	// =========================================================================================================

	/**
	 * Fetches data for the given URL, returning a cached result when available and still valid.
	 *
	 * Resolution order:
	 *   1. In-memory `cache` Map — returned immediately if the entry exists and has not expired.
	 *   2. `localStorage` — deserialized and promoted to in-memory if not expired; stale entries are pruned.
	 *   3. Network — a real `fetch()` call is made. Concurrent requests for the same URL are deduplicated
	 *      via the `pending` map so only one HTTP request is ever in flight at a time.
	 *
	 * After a successful network response the result is stored in:
	 *   - `this.cache` (always)
	 *   - `localStorage` (only when `persistent: true`; TTL is still enforced on subsequent reads)
	 *
	 * @param {string}                 url     - The URL to fetch. Used as the cache key.
	 * @param {CacheOptions|number}    options - CacheOptions object or plain TTL in ms. Defaults to 60 000 ms.
	 * @returns {Promise<unknown>} Resolves to a parsed JSON object or raw text string depending on `options.type`.
	 * @throws Re-throws any network error or non-OK HTTP response as an `Error`.
	 */
	async fetch(url, options = 60_000) {
		const now = Date.now();
		const { ttl, persistent, type } = resolveOptions(options);

		// 1. Memory cache — fastest path, no I/O required.
		if (this.cache.has(url)) {
			const { data, timestamp } = this.cache.get(url);
			// `persistent` only controls storage location, not expiry — TTL is always enforced.
			if (now - timestamp < ttl) return data;
			// Entry has expired — evict from memory so the network fetch can refresh it.
			this.cache.delete(url);
		}

		// 2. localStorage cache — survives page reloads but requires JSON parsing.
		try {
			const cached = localStorage.getItem(`${CACHE_PREFIX}${url}`);
			if (cached) {
				const parsed = JSON.parse(cached);
				const age = now - parsed.timestamp;
				if (age < ttl) {
					// Promote the valid entry to in-memory so subsequent reads skip localStorage.
					this.cache.set(url, parsed);
					return parsed.data;
				} else {
					// Prune the stale entry immediately to keep localStorage tidy.
					localStorage.removeItem(`${CACHE_PREFIX}${url}`);
				}
			}
		} catch (e) {
			console.warn('[DataCache] localStorage read error', e);
		}

		// 3. Deduplicate in-flight requests — if the same URL is already being fetched, reuse its Promise.
		if (this.pending.has(url)) return this.pending.get(url);

		const promise = (async () => {
			try {
				const res = await fetch(url);
				if (!res.ok) throw new Error(`[DataCache] Fetch error: ${res.status} ${res.statusText}`);

				// Parse the response body according to the requested type.
				const data = type === 'text' ? await res.text() : await res.json();
				const entry = { data, timestamp: Date.now() };

				// Always store in memory.
				this.cache.set(url, entry);

				// Optionally persist across page reloads via localStorage.
				if (persistent) persistToStorage(url, entry);

				return data;
			} finally {
				// Always remove from pending map once the request settles (success or error).
				this.pending.delete(url);
			}
		})();

		this.pending.set(url, promise);
		return promise;
	},

	// =========================================================================================================
	// prefetch(url, options?)
	// Warms the cache for a URL without returning the result.
	// =========================================================================================================

	/**
	 * Warms the cache for the given URL without returning the fetched data.
	 * Intended to be called speculatively (e.g. on hover or route transition) so that a subsequent
	 * `fetch()` call for the same URL can be served instantly from the in-memory or localStorage cache.
	 *
	 * Resolution order mirrors `fetch()`:
	 *   1. If a valid in-memory entry already exists, returns immediately (no-op).
	 *   2. If a valid localStorage entry exists, promotes it to memory and returns (no-op).
	 *   3. Otherwise, delegates to `fetch()` in fire-and-forget mode (errors are swallowed).
	 *
	 * @param {string}              url     - The URL to prefetch. Used as the cache key.
	 * @param {CacheOptions|number} options - CacheOptions object or plain TTL in ms. Defaults to 60 000 ms.
	 */
	prefetch(url, options = 60_000) {
		const now = Date.now();
		const { ttl } = resolveOptions(options);

		// 1. In-memory check — nothing to do if the entry is still valid.
		if (this.cache.has(url)) {
			const { timestamp } = this.cache.get(url);
			if (now - timestamp < ttl) return;
			// Entry has expired — evict so the fire-and-forget fetch can refresh it.
			this.cache.delete(url);
		}

		// 2. localStorage check — promote to memory if the entry is still valid (avoids a network round-trip).
		try {
			const cached = localStorage.getItem(`${CACHE_PREFIX}${url}`);
			if (cached) {
				const parsed = JSON.parse(cached);
				if (now - parsed.timestamp < ttl) {
					this.cache.set(url, parsed);
					return;
				} else {
					// Prune the stale entry immediately to keep localStorage tidy.
					localStorage.removeItem(`${CACHE_PREFIX}${url}`);
				}
			}
		} catch (e) {
			console.warn('[DataCache] localStorage read error', e);
		}

		// 3. Fire-and-forget fetch — errors are intentionally swallowed; callers do not need to await.
		this.fetch(url, options).catch((err) => console.error('[DataCache] Prefetch failed', err));
	},

	// =========================================================================================================
	// clear(url?)
	// Evicts one specific URL or the entire cache from both memory and localStorage.
	// =========================================================================================================

	/**
	 * Evicts cache entries from both in-memory storage and localStorage.
	 *
	 * - When `url` is provided: removes only the entry for that specific URL.
	 * - When `url` is omitted: removes **all** cached entries (full cache flush).
	 *
	 * This should be called after write operations (POST / PUT / DELETE) that invalidate
	 * previously cached data, ensuring subsequent reads reflect the latest server state.
	 *
	 * @param {string} [url] - Optional URL to evict. Omit to flush the entire cache.
	 */
	clear(url) {
		if (url) {
			// Targeted eviction — removes only the specified URL from both layers.
			this.cache.delete(url);
			localStorage.removeItem(`${CACHE_PREFIX}${url}`);
		} else {
			// Full flush — clears the in-memory Map and every `cache:*` localStorage key.
			this.cache.clear();
			Object.keys(localStorage)
				.filter((k) => k.startsWith(CACHE_PREFIX))
				.forEach((k) => localStorage.removeItem(k));
		}
	},
};
