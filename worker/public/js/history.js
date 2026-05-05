// =============================================================================
// history.js — Scan history panel
// =============================================================================

let historyPage = 1;
let historyRisk = 'all';

$('history-risk-filter').addEventListener('change', function () {
	historyRisk = this.value;
	historyPage = 1;
	loadHistory();
});

// On manual refresh, bust the cache so the user gets the latest data from the server.
$('history-refresh-btn').addEventListener('click', function () {
	DataCache.clear();
	historyPage = 1;
	loadHistory();
});

// =============================================================================
// loadHistory — fetch + render
// =============================================================================

async function loadHistory() {
	setPending($('history-status'));
	$('history-tbody').innerHTML = '<tr><td colspan="7" class="table-empty">Loading...</td></tr>';

	try {
		const p = new URLSearchParams();
		p.set('page',  historyPage);
		p.set('limit', 25);
		if (historyRisk !== 'all') p.set('risk', historyRisk);
		const url  = '/api/history?' + p;

		// 30 s cache — fast on paginated navigation, fresh enough for live use.
		const json = await DataCache.fetch(url, { ttl: 30_000, type: 'json' });

		if (!json.ok) {
			setStatus($('history-status'), false, 'ERROR');
			$('history-tbody').innerHTML =
				'<tr><td colspan="7" class="table-empty">Failed to load: ' + (json.error || 'Unknown error') + '</td></tr>';
			return;
		}

		setStatus($('history-status'), true, json.total.toLocaleString() + ' scans');

		if (json.entries.length === 0) {
			$('history-tbody').innerHTML =
				'<tr><td colspan="7" class="table-empty">No scans yet. Upload a file to get started.</td></tr>';
			$('history-pagination').style.display = 'none';
			return;
		}

		// Render rows
		$('history-tbody').innerHTML = '';
		json.entries.forEach(function (e) {
			const tr = document.createElement('tr');
			tr.innerHTML =
				'<td>' + formatDate(e.upload_date)           + '</td>' +
				'<td class="col-filename" title="' + escapeHtml(e.filename) + '">' + escapeHtml(e.filename) + '</td>' +
				'<td><code>' + shortHash(e.sha256)           + '</code></td>' +
				'<td></td>' +
				'<td>' + e.total_score                       + '</td>' +
				'<td>' + e.finding_count                     + '</td>' +
				'<td>' + formatDuration(e.duration_ms)       + '</td>';
			tr.children[3].appendChild(riskBadge(e.risk_level));
			tr.addEventListener('click', function () { navigate('/file/' + e.sha256); });
			$('history-tbody').appendChild(tr);
		});

		renderPagination(json.total, json.limit);

	} catch (e) {
		setStatus($('history-status'), false, 'NETWORK ERROR');
		$('history-tbody').innerHTML =
			'<tr><td colspan="7" class="table-empty">Error: ' + e.message + '</td></tr>';
	}
}

// =============================================================================
// renderPagination — numbered pages with ellipsis
// =============================================================================

/**
 * Renders a VirusTotal-style paginator:
 *
 *   « 1  …  4  [5]  6  …  12  »
 *
 * Rules:
 *   - Always show the first and last page.
 *   - Always show up to WING pages on each side of the current page.
 *   - Fill gaps > 1 with a "…" button that jumps midway.
 *   - "«" / "»" jump to the previous / next page (disabled at boundaries).
 *
 * @param {number} total  Total number of entries.
 * @param {number} limit  Entries per page.
 */
function renderPagination(total, limit) {
	const totalPages = Math.ceil(total / limit);
	const pag        = $('history-pagination');

	if (totalPages <= 1) {
		pag.style.display = 'none';
		return;
	}

	pag.style.display = 'flex';
	pag.innerHTML     = '';

	// ── Helper: create one page button ───────────────────────────────────────
	function makeBtn(label, page, isCurrent, isDisabled) {
		const btn = document.createElement('button');
		btn.textContent = label;
		btn.className   = 'page-btn' + (isCurrent ? ' page-btn-active' : '');
		btn.disabled    = isDisabled || isCurrent;
		if (!isDisabled && !isCurrent) {
			btn.addEventListener('click', function () {
				historyPage = page;
				DataCache.clear('/api/history?' + buildParams(page));
				loadHistory();
			});
		}
		return btn;
	}

	// ── Helper: "…" gap button that jumps to a midpoint ──────────────────────
	function makeEllipsis(jumpTo) {
		const btn = document.createElement('button');
		btn.textContent = '…';
		btn.className   = 'page-btn page-btn-ellipsis';
		btn.addEventListener('click', function () {
			historyPage = jumpTo;
			DataCache.clear('/api/history?' + buildParams(jumpTo));
			loadHistory();
		});
		return btn;
	}

	// ── Helper: rebuild URLSearchParams for a given page ─────────────────────
	function buildParams(page) {
		const p = new URLSearchParams();
		p.set('page',  page);
		p.set('limit', limit);
		if (historyRisk !== 'all') p.set('risk', historyRisk);
		return p.toString();
	}

	// ── Build the page-number sequence ────────────────────────────────────────
	//    Always include: first, last, current ± WING
	const WING = 2; // pages to show on each side of current

	const shown = new Set();
	shown.add(1);
	shown.add(totalPages);
	for (let i = Math.max(1, historyPage - WING); i <= Math.min(totalPages, historyPage + WING); i++) {
		shown.add(i);
	}

	const sequence = Array.from(shown).sort(function (a, b) { return a - b; });

	// ── Previous arrow ────────────────────────────────────────────────────────
	pag.appendChild(makeBtn('«', historyPage - 1, false, historyPage <= 1));

	// ── Page buttons + ellipsis ───────────────────────────────────────────────
	for (let i = 0; i < sequence.length; i++) {
		const pg = sequence[i];

		// Gap before this page?
		if (i > 0) {
			const prev = sequence[i - 1];
			if (pg - prev === 2) {
				// Gap of exactly one — just show the missing page (no ellipsis needed)
				pag.appendChild(makeBtn(String(prev + 1), prev + 1, historyPage === prev + 1, false));
			} else if (pg - prev > 2) {
				// Larger gap — show "…" that jumps to the midpoint
				pag.appendChild(makeEllipsis(Math.round((prev + pg) / 2)));
			}
		}

		pag.appendChild(makeBtn(String(pg), pg, historyPage === pg, false));
	}

	// ── Next arrow ────────────────────────────────────────────────────────────
	pag.appendChild(makeBtn('»', historyPage + 1, false, historyPage >= totalPages));

	// ── Page counter label ────────────────────────────────────────────────────
	const label = document.createElement('span');
	label.className   = 'page-label';
	label.textContent = 'Page ' + historyPage + ' of ' + totalPages;
	pag.appendChild(label);
}
