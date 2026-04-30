// =========================================================================================================
// VRCSTORAGE-SCANNER WORKER
// =========================================================================================================
// Cloudflare Worker entry point for the vrcstorage-scanner service.
//
// Responsibilities:
// - POST /api/scan       → VirusTotal-style cache check (D1) then forward to container
// - POST /api/sanitize    → Forward to container
// - POST /api/scan-batch  → Forward to container
// - GET  /api/health      → Forward to container
// - GET  /api/cache-stats → Read directly from D1
//
// All API routes live under /api/*.  The Worker strips the /api prefix
// before forwarding to the container (which exposes /scan, /sanitize, etc.).
// Non-API routes (/, /app.css, /app.js, …) are served by Cloudflare Static
// Assets configured in wrangler.jsonc.
//
// Cache flow (POST /api/scan):
//   1. If the request includes `expected_sha256`, build a cache key from
//      sha256 + query params (format, min_severity, verbose).
//   2. Query D1: cache HIT  → return cached JSON immediately (no container).
//                cache MISS → forward request to the Rust container.
//   3. After the container responds (HTTP 200), store the result in D1
//      via ctx.waitUntil() so the next identical request is a HIT.
//
// The container runs the full scan pipeline (axum server on port 8080) and
// requires outbound internet access (`enableInternet: true`) to download
// packages from R2 pre-signed URLs.
// =========================================================================================================

// =========================================================================================================
// Imports
// =========================================================================================================

import { Hono } from 'hono';
import { Container, getContainer } from '@cloudflare/containers';
import { buildCacheKey, getCachedScan, getCacheStats, putCachedScan } from './cache';

// =========================================================================================================
// Container class
// =========================================================================================================

/**
 * Cloudflare Container subclass that wraps the vrcstorage-scanner Rust binary.
 *
 * - `defaultPort` matches the axum server inside the Docker image.
 * - `sleepAfter` gracefully shuts down the container after 10 minutes of idle time.
 * - `enableInternet` is required so the container can download files from R2.
 */
export class ScannerContainer extends Container {
	defaultPort = 8080;
	sleepAfter = '10m';
	enableInternet = true;
}

// =========================================================================================================
// Helpers
// =========================================================================================================

/**
 * Strips the /api prefix from the request path and forwards it to the
 * container.  Used as a generic proxy for all non-cached endpoints.
 */
async function proxyToContainer(c: HonoContext): Promise<Response> {
	const container = getContainer(c.env.SCANNER, 'singleton');

	const url = new URL(c.req.url);
	url.pathname = url.pathname.replace('/api', '');

	const req = new Request(url, c.req.raw);
	return container.fetch(req);
}

/**
 * Extracts the relevant query parameters from the request URL for cache-key
 * construction.
 */
function extractQueryParams(url: URL) {
	return {
		format: url.searchParams.get('format') || 'json',
		minSeverity: url.searchParams.get('min_severity') || '',
		verbose: url.searchParams.get('verbose') || 'false',
	};
}

// =========================================================================================================
// App
// =========================================================================================================

const app = new Hono<{ Bindings: Env }>();

// ── POST /api/scan ───────────────────────────────────────────────────────────
// VirusTotal-style caching: check D1 before forwarding to the container.

app.post('/api/scan', async (c) => {
	const params = extractQueryParams(new URL(c.req.url));

	// Clone the raw request before reading the body so the original
	// can still be forwarded to the container on a cache miss.
	const raw = c.req.raw;
	const cloned = raw.clone();

	let expectedSha256: string | undefined;
	try {
		const body: any = await cloned.json();
		expectedSha256 = body.expected_sha256;
	} catch {
		return proxyToContainer(c);
	}

	// Cache HIT path — return the stored result immediately without
	// spinning up the container.
	if (expectedSha256) {
		const cacheKey = buildCacheKey(
			expectedSha256,
			params.format,
			params.minSeverity,
			params.verbose,
		);

		const cached = await getCachedScan(c.env.SCAN_CACHE_DB, cacheKey);

		if (cached) {
			c.header('X-Cache', 'HIT');
			c.header('X-Cache-Access-Count', String(cached.access_count));
			return c.body(cached.result, {
				status: 200,
				headers: { 'Content-Type': 'application/json' },
			});
		}
	}

	// Cache MISS path — forward the original request to the Rust container.
	// The body is still intact because we parsed from a clone above.
	const container = getContainer(c.env.SCANNER, 'singleton');

	const url = new URL(c.req.url);
	url.pathname = '/scan';

	const req = new Request(url, raw);
	const res = await container.fetch(req);

	// After a successful scan, store the result in D1 asynchronously
	// via ctx.waitUntil so the response is not delayed.
	if (res.ok && expectedSha256) {
		const resClone = res.clone();
		c.executionCtx.waitUntil(
			(async () => {
				try {
					const resultJson = await resClone.text();
					const parsed = JSON.parse(resultJson);
					const sha256 = parsed?.scan_result?.file?.sha256;
					const riskLevel = parsed?.scan_result?.risk?.level || 'UNKNOWN';

					if (sha256) {
						const cacheKey = buildCacheKey(
							sha256,
							params.format,
							params.minSeverity,
							params.verbose,
						);

						await putCachedScan(
							c.env.SCAN_CACHE_DB,
							cacheKey,
							sha256,
							resultJson,
							parsed.file_id || '',
							riskLevel,
						);
					}
				} catch {
					// Silently skip caching on parse errors — the scan
					// result is still returned to the client.
				}
			})(),
		);
	}

	// Forward the container response back to the client, annotating
	// that this was a cache miss.  Container headers are preserved.
	const responseHeaders = new Headers(res.headers);
	responseHeaders.set('X-Cache', 'MISS');

	return new Response(res.body, {
		status: res.status,
		headers: responseHeaders,
	});
});

// ── POST /api/sanitize ──────────────────────────────────────────────────────
// Proxy to container — no caching for sanitize.

app.post('/api/sanitize', proxyToContainer);

// ── POST /api/scan-batch ────────────────────────────────────────────────────
// Proxy to container — no caching for batch scans.

app.post('/api/scan-batch', proxyToContainer);

// ── GET /api/health ─────────────────────────────────────────────────────────
// Proxy to container.

app.get('/api/health', proxyToContainer);

// ── GET /api/cache-stats ────────────────────────────────────────────────────
// Queries D1 directly — no container needed.

app.get('/api/cache-stats', async (c) => {
	const stats = await getCacheStats(c.env.SCAN_CACHE_DB);
	return c.json(stats);
});

// =========================================================================================================
// Export
// =========================================================================================================

export default app;

// =========================================================================================================
// Bindings
// =========================================================================================================

interface Env {
	SCANNER: DurableObjectNamespace<ScannerContainer>;
	SCAN_CACHE_DB: D1Database;
}

/**
 * Shorthand for the Hono context with our bindings.
 */
type HonoContext = import('hono').Context<{ Bindings: Env }>;
