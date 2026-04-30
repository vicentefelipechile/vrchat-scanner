// =========================================================================================================
// VRCSTORAGE-SCANNER WORKER
// =========================================================================================================
// Cloudflare Worker entry point for the vrcstorage-scanner service.
//
// Responsibilities:
// - POST /api/upload       → Multipart file upload → R2 → return URL for scanning
// - GET  /api/download/:hash → Serve uploaded file from R2 (for container download)
// - POST /api/scan          → VirusTotal-style cache check (D1) then forward to container
// - POST /api/sanitize      → Forward to container
// - POST /api/scan-batch    → Forward to container
// - GET  /api/health        → Forward to container
// - GET  /api/cache-stats   → Read directly from D1
// - GET  /api/history       → Paginated scan history from D1
// - GET  /api/history/:hash → Full scan detail by SHA-256
// - GET  /api/search?q=     → Search by hash or filename
// - GET  /api/stats         → Global platform statistics
//
// All API routes live under /api/*.  The Worker strips the /api prefix
// before forwarding to the container (which exposes /scan, /sanitize, etc.).
// Non-API routes (/, /app.css, /app.js, ...) are served by Cloudflare Static
// Assets configured in wrangler.jsonc.
//
// Cache flow (POST /api/scan):
//   1. If the request includes `expected_sha256`, build a cache key from
//      sha256 + query params (format, min_severity, verbose).
//   2. Query D1: cache HIT  → return cached JSON immediately (no container).
//                cache MISS → forward request to the Rust container.
//   3. After the container responds (HTTP 200), store the result in D1
//      via ctx.waitUntil() so the next identical request is a HIT.
//   4. Also store in permanent `scans` table for history/search.
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
import { getScanHistory, getScanByHash, searchScans, putScanResult, getStats } from './history';
import { handleUpload, serveDownload, cleanupUpload } from './upload';

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

/**
 * Extracts counts by severity and overall finding count from a parsed
 * ScanReport JSON object.  Used to populate the scans table with summary
 * columns so the history list can show them without parsing full JSON.
 */
function countFindingsBySeverity(scanResult: any) {
	let critical = 0, high = 0, medium = 0, low = 0;
	const findings = scanResult?.findings ?? [];
	for (const f of findings) {
		const s = String(f.severity || '').toLowerCase();
		if (s === 'critical') critical++;
		else if (s === 'high') high++;
		else if (s === 'medium') medium++;
		else if (s === 'low') low++;
	}
	return { total: findings.length, critical, high, medium, low };
}

// =========================================================================================================
// App
// =========================================================================================================

const app = new Hono<{ Bindings: Env }>();

// ── POST /api/upload ─────────────────────────────────────────────────────────
// Receives a file via multipart/form-data, stores it in R2 temporarily,
// and returns a download URL + metadata for scanning.

app.post('/api/upload', async (c) => {
	const result = await handleUpload(c.req.raw, c.env.UPLOAD_BUCKET);

	if (result.error) {
		return c.json({ error: result.error, ok: false }, 400);
	}

	return c.json({
		url: result.url,
		sha256: result.sha256,
		file_id: result.sha256,
		filename: result.filename,
		file_size: result.file_size,
		ok: true,
	});
});

// ── GET /api/download/:hash ──────────────────────────────────────────────────
// Serves an uploaded file from R2 so the container can download it via reqwest.
// The container calls this URL when scanning an uploaded file.

app.get('/api/download/:hash', async (c) => {
	const hash = c.req.param('hash');
	return serveDownload(c.env.UPLOAD_BUCKET, hash);
});

// ── POST /api/scan ───────────────────────────────────────────────────────────
// VirusTotal-style caching: check D1 before forwarding to the container.
// Also stores results in the permanent `scans` table for history.

app.post('/api/scan', async (c) => {
	const params = extractQueryParams(new URL(c.req.url));

	// Clone the raw request before reading the body so the original
	// can still be forwarded to the container on a cache miss.
	const raw = c.req.raw;
	const cloned = raw.clone();

	let body: any;
	let expectedSha256: string | undefined;
	try {
		body = await cloned.json();
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
					const score = parsed?.scan_result?.risk?.score ?? 0;
					const durationMs = parsed?.scan_result?.scan_duration_ms ?? 0;

					if (sha256) {
						// Store in scan_cache (D1, 30-day TTL)
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

						// Store in permanent scans history table
						const counts = countFindingsBySeverity(parsed.scan_result);
						const fileTreeJson = parsed.scan_result?.file_tree
							? JSON.stringify(parsed.scan_result.file_tree)
							: undefined;

						// Extract filename and size from the scan report
						const filename = parsed.scan_result?.file?.path || sha256;
						const fileSize = parsed.scan_result?.file?.size ?? 0;

						// Build a result JSON that includes the full scan result
						// with finding counts at the top level for easy display
						const historyResult = JSON.stringify({
							...parsed.scan_result,
							_counts: counts,
						});

						await putScanResult(
							c.env.SCAN_CACHE_DB,
							sha256,
							filename,
							fileSize,
							historyResult,
							riskLevel,
							score,
							durationMs,
							fileTreeJson,
						);

						// Clean up the temporary R2 upload if it came from /api/upload
						await cleanupUpload(c.env.UPLOAD_BUCKET, sha256);
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

// ── GET /api/history ────────────────────────────────────────────────────────
// Paginated list of past scans.  Query params: page, limit, risk.

app.get('/api/history', async (c) => {
	const page = parseInt(c.req.query('page') || '1', 10);
	const limit = parseInt(c.req.query('limit') || '25', 10);
	const risk = c.req.query('risk');

	const result = await getScanHistory(c.env.SCAN_CACHE_DB, page, limit, risk || undefined);
	return c.json({ ...result, ok: true });
});

// ── GET /api/history/:sha256 ────────────────────────────────────────────────
// Full scan detail by SHA-256 hash.

app.get('/api/history/:sha256', async (c) => {
	const sha256 = c.req.param('sha256').toLowerCase();
	const detail = await getScanByHash(c.env.SCAN_CACHE_DB, sha256);

	if (!detail) {
		return c.json({ error: 'Scan not found', ok: false }, 404);
	}

	return c.json({ ...detail, ok: true });
});

// ── GET /api/search ─────────────────────────────────────────────────────────
// Search by hash prefix or filename substring.  Query param: q.

app.get('/api/search', async (c) => {
	const query = c.req.query('q') || '';

	if (!query.trim()) {
		return c.json({ results: [], ok: true });
	}

	const results = await searchScans(c.env.SCAN_CACHE_DB, query);
	return c.json({ results, ok: true });
});

// ── GET /api/stats ──────────────────────────────────────────────────────────
// Global platform statistics.

app.get('/api/stats', async (c) => {
	const stats = await getStats(c.env.SCAN_CACHE_DB);
	return c.json({ ...stats, ok: true });
});

// =========================================================================================================
// Export
// =========================================================================================================

export default app;

/**
 * Shorthand for the Hono context with our bindings.
 */
type HonoContext = import('hono').Context<{ Bindings: Env }>;
