// =========================================================================================================
// SCAN HISTORY — D1 Helpers
// =========================================================================================================
// Permanent scan history queries. Stores full scan results in the `scans`
// table for persistent history, search, and detail views.
//
// Tables are created via ./migrations/0002_create_scans.sql
// applied with: npx wrangler d1 migrations apply vrcstorage-scanner
// =========================================================================================================

// =========================================================================================================
// Types
// =========================================================================================================

/** Paginated list of past scans (summary — no full result JSON). */
export interface ScanEntry {
	sha256: string;
	filename: string;
	file_size: number;
	upload_date: number;
	risk_level: string;
	total_score: number;
	duration_ms: number;
	finding_count: number;
	access_count: number;
}

/** Pagination info returned with every list query. */
export interface HistoryPage {
	entries: ScanEntry[];
	total: number;
	page: number;
	limit: number;
}

/** Full scan detail (result_json parsed on server side or returned raw). */
export interface ScanDetail {
	sha256: string;
	filename: string;
	file_size: number;
	upload_date: number;
	risk_level: string;
	total_score: number;
	duration_ms: number;
	result: unknown;          // raw parsed ScanReport
	file_tree: unknown | null; // raw parsed FlatEntry[]
	finding_count: number;
	critical_count: number;
	high_count: number;
	medium_count: number;
	low_count: number;
	access_count: number;
	last_accessed: number;
}

/** Global statistics returned by /api/stats. */
export interface GlobalStats {
	total_scans: number;
	dangerous: number;       // High + Critical
	safe: number;             // Clean + Low + Medium
	by_risk: Record<string, number>;
	last_24h: number;
}

// =========================================================================================================
// Queries
// =========================================================================================================

/**
 * Returns a paginated list of scan history entries, newest first.
 *
 * @param db     D1 database binding
 * @param page   1-indexed page number
 * @param limit  Number of entries per page (default 25, max 100)
 * @param risk   Optional risk-level filter (clean, low, medium, high, critical)
 */
export async function getScanHistory(
	db: D1Database,
	page: number = 1,
	limit: number = 25,
	risk?: string,
): Promise<HistoryPage> {
	limit = Math.min(limit, 100);

	let where = '';
	const params: unknown[] = [];
	if (risk && risk !== 'all') {
		where = 'WHERE risk_level = ?';
		params.push(risk.toUpperCase());
	}

	// Count total for pagination
	const countRow = await db
		.prepare(`SELECT COUNT(*) as cnt FROM scans ${where}`)
		.bind(...params)
		.first<{ cnt: number }>();
	const total = countRow?.cnt ?? 0;

	const offset = (page - 1) * limit;

	const rows = await db
		.prepare(
			`SELECT sha256, filename, file_size, upload_date, risk_level,
			        total_score, duration_ms, finding_count, access_count
			 FROM scans ${where}
			 ORDER BY upload_date DESC
			 LIMIT ? OFFSET ?`,
		)
		.bind(...params, limit, offset)
		.all<ScanEntry>();

	return {
		entries: rows.results ?? [],
		total,
		page,
		limit,
	};
}

/**
 * Returns the full scan detail for a given SHA-256 hash.
 * Bumps the access count atomically.
 *
 * Returns `null` if no scan with that hash exists.
 */
export async function getScanByHash(
	db: D1Database,
	sha256: string,
): Promise<ScanDetail | null> {
	const row = await db
		.prepare(
			`SELECT sha256, filename, file_size, upload_date, risk_level,
			        total_score, duration_ms, result_json, file_tree_json,
			        finding_count, critical_count, high_count, medium_count,
			        low_count, access_count, last_accessed
			 FROM scans WHERE sha256 = ?`,
		)
		.bind(sha256)
		.first<{
			sha256: string;
			filename: string;
			file_size: number;
			upload_date: number;
			risk_level: string;
			total_score: number;
			duration_ms: number;
			result_json: string;
			file_tree_json: string | null;
			finding_count: number;
			critical_count: number;
			high_count: number;
			medium_count: number;
			low_count: number;
			access_count: number;
			last_accessed: number;
		}>();

	if (!row) return null;

	return {
		sha256: row.sha256,
		filename: row.filename,
		file_size: row.file_size,
		upload_date: row.upload_date,
		risk_level: row.risk_level,
		total_score: row.total_score,
		duration_ms: row.duration_ms,
		result: JSON.parse(row.result_json),
		file_tree: row.file_tree_json ? JSON.parse(row.file_tree_json) : null,
		finding_count: row.finding_count,
		critical_count: row.critical_count,
		high_count: row.high_count,
		medium_count: row.medium_count,
		low_count: row.low_count,
		access_count: row.access_count,
		last_accessed: row.last_accessed,
	};
}

/**
 * Searches scans by SHA-256 prefix or filename substring.
 *
 * - If the query looks like a hex hash (all hex chars, no spaces),
 *   searches by sha256 LIKE 'prefix%'.
 * - Otherwise, searches by filename LIKE '%query%'.
 *
 * Returns up to 50 matching entries, newest first.
 */
export async function searchScans(
	db: D1Database,
	query: string,
): Promise<ScanEntry[]> {
	const clean = query.trim().toLowerCase();

	if (!clean) return [];

	let rows: D1Result<ScanEntry>;
	if (/^[0-9a-f]+$/.test(clean)) {
		// Looks like a hash — prefix search
		rows = await db
			.prepare(
				`SELECT sha256, filename, file_size, upload_date, risk_level,
				        total_score, duration_ms, finding_count, access_count
				 FROM scans WHERE sha256 LIKE ?
				 ORDER BY upload_date DESC
				 LIMIT 50`,
			)
			.bind(`${clean}%`)
			.all<ScanEntry>();
	} else {
		// Filename search
		rows = await db
			.prepare(
				`SELECT sha256, filename, file_size, upload_date, risk_level,
				        total_score, duration_ms, finding_count, access_count
				 FROM scans WHERE lower(filename) LIKE ?
				 ORDER BY upload_date DESC
				 LIMIT 50`,
			)
			.bind(`%${clean}%`)
			.all<ScanEntry>();
	}

	return rows.results ?? [];
}

/**
 * Stores a completed scan result in the permanent history table.
 *
 * Uses INSERT OR REPLACE so re-scanning the same file updates the record.
 *
 * @param db         D1 database binding
 * @param sha256     SHA-256 hash of the scanned file
 * @param filename   Original filename
 * @param fileSize   File size in bytes
 * @param resultJson Full ScanReport JSON string
 * @param riskLevel  CLEAN / LOW / MEDIUM / HIGH / CRITICAL
 * @param score      Total risk score
 * @param durationMs Scan duration in milliseconds
 * @param fileTreeJson Optional file_tree JSON string
 */
export async function putScanResult(
	db: D1Database,
	sha256: string,
	filename: string,
	fileSize: number,
	resultJson: string,
	riskLevel: string,
	score: number,
	durationMs: number,
	fileTreeJson?: string,
): Promise<boolean> {
	// Count findings by severity from the JSON
	let critical = 0, high = 0, medium = 0, low = 0, findingCount = 0;
	try {
		const parsed = JSON.parse(resultJson);
		const findings = parsed?.findings ?? [];
		findingCount = findings.length;
		for (const f of findings) {
			const s = String(f.severity || '').toLowerCase();
			if (s === 'critical') critical++;
			else if (s === 'high') high++;
			else if (s === 'medium') medium++;
			else if (s === 'low') low++;
		}
	} catch { /* best effort */ }

	const now = Date.now();

	try {
		const result = await db
			.prepare(
				`INSERT OR REPLACE INTO scans (
					sha256, filename, file_size, upload_date,
					risk_level, total_score, duration_ms,
					result_json, file_tree_json,
					finding_count, critical_count, high_count,
					medium_count, low_count,
					access_count, last_accessed
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`,
			)
			.bind(
				sha256, filename, fileSize, now,
				riskLevel, score, durationMs,
				resultJson, fileTreeJson ?? null,
				findingCount, critical, high, medium, low,
				now,
			)
			.run();

		return result.success;
	} catch (e) {
		console.error('Failed to store scan result in history', e);
		return false;
	}
}

/**
 * Returns global platform statistics.
 */
export async function getStats(db: D1Database): Promise<GlobalStats> {
	const totalRow = await db
		.prepare('SELECT COUNT(*) as cnt FROM scans')
		.first<{ cnt: number }>();
	const total = totalRow?.cnt ?? 0;

	const riskRows = await db
		.prepare(
			'SELECT risk_level, COUNT(*) as cnt FROM scans GROUP BY risk_level',
		)
		.all<{ risk_level: string; cnt: number }>();

	const byRisk: Record<string, number> = {};
	let dangerous = 0;
	let safe = 0;

	for (const r of riskRows.results ?? []) {
		byRisk[r.risk_level] = Number(r.cnt);
		if (r.risk_level === 'HIGH' || r.risk_level === 'CRITICAL') {
			dangerous += Number(r.cnt);
		} else {
			safe += Number(r.cnt);
		}
	}

	const last24hRow = await db
		.prepare(
			'SELECT COUNT(*) as cnt FROM scans WHERE upload_date >= ?',
		)
		.bind(Date.now() - 24 * 60 * 60 * 1000)
		.first<{ cnt: number }>();

	return {
		total_scans: total,
		dangerous,
		safe,
		by_risk: byRisk,
		last_24h: last24hRow?.cnt ?? 0,
	};
}
