// =========================================================================================================
// EMBED — Open Graph / Twitter Card SSR
// =========================================================================================================
// Generates a server-side HTML response for /file/:hash URLs so that
// Discord, Twitter/X, and forum crawlers receive rich link previews.
//
// How it works:
//   1. Fetch the scan detail from D1 / KV (same path as GET /api/history/:sha256).
//   2. Build <meta> OG + Twitter Card tags from the scan fields.
//   3. Return a full HTML document that is also a valid SPA shell —
//      real browsers load the JS bundle, which re-routes to the detail panel.
//
// Crawler detection note:
//   We do NOT try to detect bots. We always return the enriched HTML for
//   /file/:hash. Real browsers get the same document; the SPA takes over
//   via DOMContentLoaded → routePath(). This is the simplest, most robust
//   approach (no UA sniffing, no redirect chain).
// =========================================================================================================

import type { ScanDetail } from './history';

// ── Risk colours (CSS hex — safe for og:image text) ─────────────────────────

const RISK_COLOR: Record<string, string> = {
	CLEAN:    '#22c55e',
	LOW:      '#84cc16',
	MEDIUM:   '#f59e0b',
	HIGH:     '#f97316',
	CRITICAL: '#ef4444',
};

const RISK_EMOJI: Record<string, string> = {
	CLEAN:    '✅',
	LOW:      '🟡',
	MEDIUM:   '🟠',
	HIGH:     '🔴',
	CRITICAL: '☠️',
};

// ── Helpers ──────────────────────────────────────────────────────────────────

function esc(s: string): string {
	return s
		.replace(/&/g, '&amp;')
		.replace(/"/g, '&quot;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;');
}

function shortHash(sha256: string): string {
	return sha256.slice(0, 16) + '…';
}

function formatBytes(bytes: number): string {
	if (bytes === 0) return '0 B';
	const units = ['B', 'KB', 'MB', 'GB'];
	const i = Math.floor(Math.log(bytes) / Math.log(1024));
	return (bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1) + ' ' + units[i];
}

// ── OG description builder ───────────────────────────────────────────────────

function buildDescription(d: ScanDetail): string {
	const risk = d.risk_level || 'UNKNOWN';
	const emoji = RISK_EMOJI[risk] || '❓';
	const parts: string[] = [
		`${emoji} Risk: ${risk}  •  Score: ${d.total_score} pts`,
		`📄 ${d.filename}  •  ${formatBytes(d.file_size)}`,
	];

	const counts: string[] = [];
	if (d.critical_count > 0) counts.push(`${d.critical_count} Critical`);
	if (d.high_count     > 0) counts.push(`${d.high_count} High`);
	if (d.medium_count   > 0) counts.push(`${d.medium_count} Medium`);
	if (d.low_count      > 0) counts.push(`${d.low_count} Low`);

	if (counts.length > 0) {
		parts.push(`🔍 Findings: ${counts.join(', ')}`);
	} else {
		parts.push('🔍 No findings — package appears clean.');
	}

	parts.push(`🔑 SHA-256: ${d.sha256.slice(0, 32)}…`);
	return parts.join('\n');
}

// ── Image URL for OG (optional — uses a Cloudflare-hosted static banner) ─────
// We use a simple query-string approach so Cloudflare can serve a dynamic
// OG image via a Worker route in the future. For now we use a static banner.

function ogImageUrl(baseUrl: string, _d: ScanDetail): string {
	return `${baseUrl}/og-banner.png`;
}

// ── HTML template ─────────────────────────────────────────────────────────────

/**
 * Builds a complete HTML document for /file/:sha256 with OG + Twitter Card
 * meta tags pre-populated from the scan detail.
 *
 * The document also includes the full SPA shell (same CSS/JS as index.html)
 * so real browsers hydrate normally and the SPA router takes over.
 *
 * @param detail    Scan detail from D1 (null if not found)
 * @param sha256    Raw SHA-256 from the URL
 * @param baseUrl   Origin (e.g. "https://scanner.vrcstorage.lat")
 * @param indexHtml Raw index.html content from static assets
 */
export function buildEmbedHtml(
	detail: ScanDetail | null,
	sha256: string,
	baseUrl: string,
	indexHtml: string,
): string {
	// ── Not found — inject minimal meta and return the SPA ──────────────────
	if (!detail) {
		const notFoundMeta = [
			`<meta property="og:title" content="Scan not found — vrcstorage-scanner">`,
			`<meta property="og:description" content="No scan result found for hash ${sha256.slice(0, 16)}…">`,
			`<meta property="og:url" content="${baseUrl}/file/${sha256}">`,
			`<meta property="og:site_name" content="vrcstorage-scanner">`,
			`<meta property="og:type" content="website">`,
			`<meta name="twitter:card" content="summary">`,
			`<meta name="twitter:title" content="Scan not found — vrcstorage-scanner">`,
			`<meta name="twitter:description" content="No scan result found for hash ${sha256.slice(0, 16)}…">`,
		].join('\n  ');

		return indexHtml.replace('</head>', `  ${notFoundMeta}\n</head>`);
	}

	// ── Build rich meta tags ─────────────────────────────────────────────────
	const risk        = detail.risk_level || 'UNKNOWN';
	const color       = RISK_COLOR[risk]  || '#6b7280';
	const emoji       = RISK_EMOJI[risk]  || '❓';
	const title       = `${emoji} ${esc(detail.filename)} — vrcstorage-scanner`;
	const description = esc(buildDescription(detail));
	const url         = `${baseUrl}/file/${sha256}`;
	const imageUrl    = ogImageUrl(baseUrl, detail);

	const ogMeta = [
		// ── Open Graph ────────────────────────────────────────────────────────
		`<meta property="og:type"        content="website">`,
		`<meta property="og:site_name"   content="vrcstorage-scanner">`,
		`<meta property="og:url"         content="${url}">`,
		`<meta property="og:title"       content="${title}">`,
		`<meta property="og:description" content="${description}">`,
		`<meta property="og:image"       content="${imageUrl}">`,
		`<meta property="og:image:width" content="1200">`,
		`<meta property="og:image:height" content="630">`,
		`<meta property="og:image:alt"   content="vrcstorage-scanner result for ${esc(detail.filename)}">`,
		// Theme colour — picked up by Discord for the embed side-bar colour
		`<meta name="theme-color"        content="${color}">`,

		// ── Twitter / X Card ─────────────────────────────────────────────────
		`<meta name="twitter:card"        content="summary_large_image">`,
		`<meta name="twitter:site"        content="@vrcstorage">`,
		`<meta name="twitter:title"       content="${title}">`,
		`<meta name="twitter:description" content="${description}">`,
		`<meta name="twitter:image"       content="${imageUrl}">`,
		`<meta name="twitter:image:alt"   content="vrcstorage-scanner result for ${esc(detail.filename)}">`,

		// ── Canonical ─────────────────────────────────────────────────────────
		`<link rel="canonical" href="${url}">`,
	].join('\n  ');

	// Inject before </head>
	return indexHtml.replace('</head>', `  ${ogMeta}\n</head>`);
}
