// =============================================================================
// detail.js — Scan detail panel (VirusTotal-style)
// =============================================================================

let allFindings = [];
let currentDetailHash = null;

async function showDetail(sha256) {
	currentDetailHash = sha256;
	showPanel('detail');
	// Reset filters
	document.querySelectorAll('.sev-filter').forEach(function (b) { b.classList.toggle('active', b.getAttribute('data-sev') === 'all'); });

	$('detail-meta').innerHTML = '<div class="skeleton-line"></div><div class="skeleton-line"></div><div class="skeleton-line"></div>';
	$('detail-findings').innerHTML = '<div class="skeleton-line"></div><div class="skeleton-line"></div><div class="skeleton-line"></div>';
	$('detail-file-tree').innerHTML = '<div class="skeleton-line"></div>';
	$('detail-raw-content').textContent = '';

	const detailUrl = '/api/history/' + sha256;

	// Retry loop — the scan result may not yet be committed to D1/KV
	// immediately after navigation (race condition). Retry up to MAX_RETRIES
	// times with exponential backoff before giving up.
	const MAX_RETRIES = 5;
	const RETRY_DELAY = 600; // ms, doubles each attempt

	for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
		try {
			// 5-minute persistent cache — detail pages are immutable once written.
			// Bust the cache on every retry so we don't serve a stale 404.
			if (attempt > 0) DataCache.clear(detailUrl);
			const json = await DataCache.fetch(detailUrl, { ttl: 5 * 60_000, persistent: true, type: 'json' });

			if (json.ok) {
				renderDetail(json);
				return;
			}

			// Not found yet — wait and retry if attempts remain.
			if (attempt < MAX_RETRIES) {
				const waitMs = RETRY_DELAY * Math.pow(2, attempt);
				$('detail-meta').innerHTML =
					'<div class="skeleton-line"></div>' +
					'<p style="color:var(--text-dim);font-family:var(--font-mono);font-size:11px;margin-top:8px">' +
					'Waiting for result… (retry ' + (attempt + 1) + '/' + MAX_RETRIES + ')' +
					'</p>';
				await new Promise(function (r) { setTimeout(r, waitMs); });
			} else {
				$('detail-meta').innerHTML = '<p style="color:var(--danger)">Scan not found or failed to load.</p>';
			}
		} catch (e) {
			// On network error, bust the cache so the retry always goes to the network.
			DataCache.clear(detailUrl);
			if (attempt >= MAX_RETRIES) {
				$('detail-meta').innerHTML = '<p style="color:var(--danger)">Error: ' + e.message + '</p>';
			} else {
				await new Promise(function (r) { setTimeout(r, RETRY_DELAY * Math.pow(2, attempt)); });
			}
		}
	}
}

function renderDetail(d) {
	// Title
	$('detail-title').textContent = d.filename || d.sha256;

	// Meta grid
	$('detail-meta').innerHTML =
		'<div class="meta-row"><span class="meta-label">SHA-256</span><span style="display:flex;align-items:center;gap:4px"><code>' + d.sha256 + '</code><button class="hash-copy" onclick="copyHash(\'' + d.sha256 + '\',this)" title="Copy">&copy;</button></span></div>' +
		'<div class="meta-row"><span class="meta-label">File Name</span><span class="meta-value">' + d.filename + '</span></div>' +
		'<div class="meta-row"><span class="meta-label">File Size</span><span class="meta-value">' + formatBytes(d.file_size) + '</span></div>' +
		'<div class="meta-row"><span class="meta-label">Scanned</span><span class="meta-value">' + new Date(d.upload_date).toLocaleString() + '</span></div>' +
		'<div class="meta-row"><span class="meta-label">Duration</span><span class="meta-value">' + formatDuration(d.duration_ms) + '</span></div>' +
		'<div class="meta-row"><span class="meta-label">Views</span><span class="meta-value">' + d.access_count + '</span></div>';

	// Score
	const level = d.risk_level;
	const scoreColor = RISK_COLORS[level] || 'var(--text)';
	$('detail-score').innerHTML = '<div class="score-big" style="color:' + scoreColor + '">' + d.total_score + '</div>' + riskBadge(level).outerHTML;

	// Severity
	const sevs = [
		{ l: 'Critical', c: d.critical_count || 0, k: 'badge-critical' },
		{ l: 'High',     c: d.high_count     || 0, k: 'badge-high'     },
		{ l: 'Medium',   c: d.medium_count   || 0, k: 'badge-medium'   },
		{ l: 'Low',      c: d.low_count      || 0, k: 'badge-low'      },
	];
	$('detail-severity').innerHTML = sevs.map(function (s) {
		return '<div class="sev-count"><span class="count">' + s.c + '</span><span class="badge ' + s.k + '">' + s.l + '</span></div>';
	}).join('');

	// Findings
	allFindings = d.result?.findings || [];
	$('detail-finding-count').textContent = allFindings.length;
	if (allFindings.length === 0) {
		$('detail-findings').innerHTML = '<p style="color:var(--muted);padding:12px 0">No findings detected. This package is clean.</p>';
	} else {
		renderFindings('all');
	}

	// File tree — hierarchical collapsible
	if (d.file_tree && d.file_tree.length > 0) {
		// 1. Build a nested object tree
		const root = {};
		d.file_tree.forEach(function (e) {
			const parts = e.path.replace(/\\/g, '/').split('/');
			let node = root;
			parts.forEach(function (part, idx) {
				if (!node[part]) {
					node[part] = { __files: [], __children: {} };
				}
				if (idx === parts.length - 1) {
					node[part].__leaf = { asset_type: e.asset_type, size_bytes: e.size_bytes };
				}
				node = node[part].__children;
			});
		});

		// 2. Recursively render the node tree as HTML
		function renderNode(node, name, depth) {
			const entry = node;
			const isLeaf = !!entry.__leaf;
			const children = entry.__children;
			const hasChildren = Object.keys(children).length > 0;

			if (isLeaf && !hasChildren) {
				// Plain file
				const leaf = entry.__leaf;
				const icon = leaf.asset_type === 'Meta' ? 'M' : leaf.asset_type === 'Script' ? 'S' : 'F';
				const cls  = leaf.asset_type === 'Meta' ? 'ft-meta' : 'ft-file';
				const sz   = leaf.size_bytes > 0 ? '<span class="ft-size">' + formatBytes(leaf.size_bytes) + '</span>' : '';
				return '<div class="ft-row ' + cls + '" style="--depth:' + depth + '">' +
					'<span class="ft-icon">' + icon + '</span>' +
					'<span class="ft-name">' + escapeHtml(name) + '</span>' +
					sz +
					'</div>';
			} else {
				// Folder (possibly also a leaf with children — treat as dir)
				const open = depth < 2 ? ' open' : '';
				const keys = Object.keys(children).sort(function (a, b) {
					// dirs (have children) before files (leaves)
					const aDir = Object.keys(children[a].__children).length > 0;
					const bDir = Object.keys(children[b].__children).length > 0;
					if (aDir !== bDir) return aDir ? -1 : 1;
					return a.localeCompare(b);
				});
				const inner = keys.map(function (k) {
					return renderNode(children[k], k, depth + 1);
				}).join('');
				return '<details class="ft-dir-node"' + open + ' style="--depth:' + depth + '">' +
					'<summary class="ft-row ft-dir" style="--depth:' + depth + '">' +
					'<span class="ft-icon">▸</span>' +
					'<span class="ft-name">' + escapeHtml(name) + '</span>' +
					'</summary>' +
					inner +
					'</details>';
			}
		}

		const rootKeys = Object.keys(root).sort(function (a, b) {
			const aDir = Object.keys(root[a].__children).length > 0;
			const bDir = Object.keys(root[b].__children).length > 0;
			if (aDir !== bDir) return aDir ? -1 : 1;
			return a.localeCompare(b);
		});
		let treeHTML = '<div class="file-tree">';
		rootKeys.forEach(function (k) {
			treeHTML += renderNode(root[k], k, 0);
		});
		treeHTML += '</div>';
		$('detail-file-tree').innerHTML = treeHTML;
	} else {
		$('detail-file-tree').innerHTML = '<p style="color:var(--muted)">No file tree available.</p>';
	}

	// Raw
	$('detail-raw-content').textContent = JSON.stringify(d.result || d, null, 2);
	$('detail-raw-content').style.display = 'none';
	document.querySelector('.collapsible[data-target="detail-raw-content"]').classList.remove('open');
}

function renderFindings(filter) {
	let findingsHTML = '';
	allFindings.forEach(function (f) {
		const sev     = (f.severity || 'low').toLowerCase();
		const hidden   = (filter !== 'all' && filter !== sev) ? ' hidden' : '';
		const sevClass = sev;

		let linesText = '';
		if (f.line_numbers && f.line_numbers.length > 0) {
			const first = f.line_numbers.slice(0, 8).join(', ');
			const more  = f.line_numbers.length > 8 ? ' &hellip;(+' + (f.line_numbers.length - 8) + ')' : '';
			linesText = '<span>Lines: ' + first + more + '</span>';
		} else {
			linesText = '<span class="finding-lines-none">No line numbers</span>';
		}

		findingsHTML +=
			'<div class="finding-card' + hidden + '" data-finding-sev="' + sev + '">' +
			'<div class="finding-card-header">' +
			'<span class="severity-badge ' + sevClass + '">' + (f.severity || '') + '</span>' +
			'<span class="finding-card-detail">' + (f.detail || f.id || 'Unknown') + '</span>' +
			'<span class="finding-card-points">' + (f.points || 0) + ' pts</span>' +
			'</div>' +
			(f.location ? '<div class="finding-card-file">' + f.location + '</div>' : '') +
			'<div class="finding-card-footer">' +
			'<span>ID: ' + (f.id || '') + '</span>' +
			linesText +
			'</div>' +
			'</div>';
	});
	$('detail-findings').innerHTML = findingsHTML || '<p style="color:var(--muted)">No findings match the selected filter.</p>';
}

// Finding filters
document.querySelectorAll('.sev-filter').forEach(function (btn) {
	btn.addEventListener('click', function () {
		document.querySelectorAll('.sev-filter').forEach(function (b) { b.classList.remove('active'); });
		this.classList.add('active');
		const filter = this.getAttribute('data-sev');
		const cards  = $('detail-findings').querySelectorAll('.finding-card');
		cards.forEach(function (c) {
			if (filter === 'all' || c.getAttribute('data-finding-sev') === filter) c.classList.remove('hidden');
			else c.classList.add('hidden');
		});
	});
});

// Hash copy
function copyHash(hash, btn) {
	navigator.clipboard.writeText(hash).then(function () {
		btn.textContent = '✓';
		btn.classList.add('copied');
		setTimeout(function () { btn.textContent = '©'; btn.classList.remove('copied'); }, 2000);
	}).catch(function () {
		btn.textContent = '!';
		setTimeout(function () { btn.textContent = '©'; }, 1500);
	});
}

// Back button
$('detail-back-btn').addEventListener('click', function () {
	navigate('/history');
});
