// =============================================================================
// vrcstorage-scanner SPA — VirusTotal-style platform
// =============================================================================

// =============================================================================
// Helpers
// =============================================================================

function $(id) { return document.getElementById(id); }

function setStatus(el, ok, text) {
	el.textContent = text || (ok ? '200 OK' : 'ERROR');
	el.className = 'status ' + (ok ? 'ok' : 'err');
}

function setPending(el) {
	el.textContent = 'scanning...';
	el.className = 'status pending';
}

function setResult(el, text) { el.textContent = text; }

function formatBytes(bytes) {
	if (!bytes || bytes === 0) return '0 B';
	var u = ['B', 'KB', 'MB', 'GB'];
	var i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), u.length - 1);
	return (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0) + ' ' + u[i];
}

function formatDuration(ms) {
	if (!ms || ms < 1000) return (ms || 0) + 'ms';
	return (ms / 1000).toFixed(2) + 's';
}

function formatDate(ts) {
	var d = new Date(ts), now = new Date(), diff = now - d;
	if (diff < 60000) return 'Just now';
	if (diff < 3600000) return Math.floor(diff / 60000) + 'm ago';
	if (diff < 86400000) return Math.floor(diff / 3600000) + 'h ago';
	if (diff < 604800000) return Math.floor(diff / 86400000) + 'd ago';
	return d.toISOString().split('T')[0];
}

function riskBadge(level) {
	var s = document.createElement('span');
	var cls = 'badge badge-' + (level || 'clean').toLowerCase();
	s.className = cls;
	s.textContent = level || 'CLEAN';
	return s;
}

function shortHash(hash) { return hash ? hash.substring(0, 8) + '...' : ''; }

var RISK_COLORS = {
	'CRITICAL': 'var(--critical)',
	'HIGH': 'var(--high)',
	'MEDIUM': 'var(--medium)',
	'LOW': 'var(--low)',
	'CLEAN': 'var(--clean)',
};

// =============================================================================
// Panel navigation
// =============================================================================

var currentPanel = 'upload';

function showPanel(name) {
	currentPanel = name;
	document.querySelectorAll('.sidebar a').forEach(function (a) {
		a.classList.remove('active');
		if (a.getAttribute('data-panel') === name) a.classList.add('active');
	});
	document.querySelectorAll('.panel').forEach(function (p) { p.classList.remove('active'); });
	var t = $('panel-' + name);
	if (t) t.classList.add('active');
}

document.querySelectorAll('.sidebar a').forEach(function (link) {
	link.addEventListener('click', function () {
		showPanel(this.getAttribute('data-panel'));
	});
});

// =============================================================================
// Collapsible sections
// =============================================================================

document.addEventListener('click', function (e) {
	var el = e.target.closest('.collapsible');
	if (!el) return;
	var targetId = el.getAttribute('data-target');
	var target = document.getElementById(targetId);
	if (!target) return;
	var isOpen = target.style.display !== 'none';
	target.style.display = isOpen ? 'none' : 'block';
	el.classList.toggle('open', !isOpen);
});

// =============================================================================
// File upload panel
// =============================================================================

var uploadFile = null;
var uploadHash = null;

var dropzone = $('upload-dropzone');
var fileInput = $('upload-file-input');

dropzone.addEventListener('dragover', function (e) { e.preventDefault(); dropzone.classList.add('drag-over'); });
dropzone.addEventListener('dragleave', function () { dropzone.classList.remove('drag-over'); });
dropzone.addEventListener('drop', function (e) {
	e.preventDefault();
	dropzone.classList.remove('drag-over');
	if (e.dataTransfer.files.length > 0) processUploadFile(e.dataTransfer.files[0]);
});
dropzone.addEventListener('click', function () { fileInput.click(); });
fileInput.addEventListener('change', function () { if (this.files.length > 0) processUploadFile(this.files[0]); });

async function computeSHA256(file) {
	var buf = await file.arrayBuffer();
	var hashBuf = await crypto.subtle.digest('SHA-256', buf);
	return Array.from(new Uint8Array(hashBuf)).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
}

async function processUploadFile(file) {
	if (file.size > 500 * 1024 * 1024) { alert('File too large. Maximum size is 500 MB.'); return; }
	uploadFile = file;
	$('upload-filename').textContent = file.name;
	$('upload-filesize').textContent = formatBytes(file.size);
	$('upload-sha256').textContent = 'Computing SHA-256...';
	dropzone.style.display = 'none';
	$('upload-info').style.display = 'block';
	$('upload-result').style.display = 'none';
	try {
		uploadHash = await computeSHA256(file);
		$('upload-sha256').textContent = uploadHash;
	} catch (e) {
		$('upload-sha256').textContent = 'Failed: ' + e.message;
		uploadHash = null;
	}
}

function resetUpload() {
	uploadFile = null; uploadHash = null;
	dropzone.style.display = 'block';
	$('upload-info').style.display = 'none';
	$('upload-progress').style.display = 'none';
	$('upload-result').style.display = 'none';
	$('upload-status').textContent = '';
	$('upload-status').className = 'status';
	fileInput.value = '';
}

$('upload-reset-btn').addEventListener('click', resetUpload);
$('upload-scan-btn').addEventListener('click', function () { if (uploadFile && uploadHash) uploadAndScan(false); else alert('Please select a file first.'); });
$('upload-sanitize-btn').addEventListener('click', function () { if (uploadFile && uploadHash) uploadAndScan(true); else alert('Please select a file first.'); });

async function uploadAndScan(sanitize) {
	setStatus($('upload-status'), null, '');
	$('upload-result').style.display = 'block';
	setResult($('upload-result'), 'Uploading file...');
	$('upload-progress').style.display = 'block';
	$('upload-progress-fill').style.width = '5%';
	$('upload-progress-text').textContent = 'Uploading...';

	var fd = new FormData();
	fd.append('file', uploadFile);
	fd.append('sha256', uploadHash);

	try {
		var upRes = await fetch('/api/upload', { method: 'POST', body: fd });
		$('upload-progress-fill').style.width = '50%';
		$('upload-progress-text').textContent = 'Scanning...';
		var upJson = await upRes.json();

		if (!upJson.ok) {
			$('upload-progress').style.display = 'none';
			setStatus($('upload-status'), false, 'UPLOAD ERROR');
			setResult($('upload-result'), JSON.stringify(upJson, null, 2));
			return;
		}

		$('upload-progress-fill').style.width = '75%';

		var endpoint = sanitize ? '/api/sanitize' : '/api/scan';
		var params = new URLSearchParams();
		if (sanitize) params.set('min_severity', 'high');
		else params.set('format', 'json');

		var scanRes = await fetch(endpoint + '?' + params, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ url: upJson.url, file_id: upJson.file_id, expected_sha256: upJson.sha256 }),
		});

		$('upload-progress-fill').style.width = '100%';
		$('upload-progress-text').textContent = 'Done!';

		var text = await scanRes.text();
		setStatus($('upload-status'), scanRes.ok, scanRes.ok ? '200 OK' : scanRes.status);

		try {
			setResult($('upload-result'), JSON.stringify(JSON.parse(text), null, 2));
		} catch (_) {
			setResult($('upload-result'), text);
		}

		if (sanitize && scanRes.ok && (scanRes.headers.get('content-type') || '').includes('octet-stream')) {
			var blob = await scanRes.blob();
			var a = document.createElement('a');
			a.href = URL.createObjectURL(blob);
			a.download = uploadFile.name.replace(/\.unitypackage$/i, '') + '-sanitized.unitypackage';
			a.click();
		}

	} catch (e) {
		setStatus($('upload-status'), false, 'NETWORK ERROR');
		setResult($('upload-result'), 'Error: ' + e.message);
	} finally {
		setTimeout(function () { $('upload-progress').style.display = 'none'; }, 1200);
	}
}

// =============================================================================
// POST /api/scan (URL-based)
// =============================================================================

$('scan-btn').addEventListener('click', async function () {
	var url = $('scan-url').value.trim(), fid = $('scan-fileid').value.trim();
	if (!url || !fid) { alert('R2 URL and File ID are required'); return; }
	var sha = $('scan-sha').value.trim(), fmt = $('scan-fmt').value, sev = $('scan-minsev').value, v = $('scan-verbose').checked;
	var params = new URLSearchParams(); params.set('format', fmt);
	if (v) params.set('verbose', 'true'); if (sev) params.set('min_severity', sev);
	var body = { url: url, file_id: fid }; if (sha) body.expected_sha256 = sha;
	setResult($('scan-result'), 'Scanning...'); setPending($('scan-status'));
	try {
		var res = await fetch('/api/scan?' + params, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
		var text = await res.text(), cache = res.headers.get('X-Cache') || '';
		setStatus($('scan-status'), res.ok, res.status + ' ' + res.statusText + (cache ? ' [' + cache + ']' : ''));
		try { setResult($('scan-result'), JSON.stringify(JSON.parse(text), null, 2)); } catch (_) { setResult($('scan-result'), text); }
	} catch (e) { setStatus($('scan-status'), false, 'NETWORK ERROR'); setResult($('scan-result'), 'Error: ' + e.message); }
});

// =============================================================================
// POST /api/sanitize
// =============================================================================

$('san-btn').addEventListener('click', async function () {
	var url = $('san-url').value.trim(), fid = $('san-fileid').value.trim();
	if (!url || !fid) { alert('R2 URL and File ID are required'); return; }
	var sha = $('san-sha').value.trim(), sev = $('san-minsev').value;
	var params = new URLSearchParams(); if (sev) params.set('min_severity', sev);
	var body = { url: url, file_id: fid }; if (sha) body.expected_sha256 = sha;
	setResult($('san-result'), 'Sanitizing...'); setPending($('san-status'));
	try {
		var res = await fetch('/api/sanitize?' + params, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
		var rep = res.headers.get('x-sanitize-report'), orig = res.headers.get('x-original-score'), resid = res.headers.get('x-residual-score');
		var info = res.status + ' ' + res.statusText + '\n\nX-Original-Score: ' + orig + '\nX-Residual-Score: ' + resid + '\n\n';
		if (rep) { try { info += JSON.stringify(JSON.parse(rep), null, 2); } catch (_) { info += rep; } }
		setStatus($('san-status'), res.ok, res.ok ? '200 OK' : res.status); setResult($('san-result'), info);
		if (res.ok && (res.headers.get('content-type') || '').includes('octet-stream')) {
			var blob = await res.blob(), a = document.createElement('a');
			a.href = URL.createObjectURL(blob); a.download = fid + '-sanitized.unitypackage'; a.click();
		}
	} catch (e) { setStatus($('san-status'), false, 'NETWORK ERROR'); setResult($('san-result'), 'Error: ' + e.message); }
});

// =============================================================================
// History panel
// =============================================================================

var historyPage = 1, historyRisk = 'all';

$('history-risk-filter').addEventListener('change', function () { historyRisk = this.value; historyPage = 1; loadHistory(); });
$('history-refresh-btn').addEventListener('click', function () { historyPage = 1; loadHistory(); });

async function loadHistory() {
	setPending($('history-status'));
	$('history-tbody').innerHTML = '<tr><td colspan="7" class="table-empty">Loading...</td></tr>';
	try {
		var p = new URLSearchParams(); p.set('page', historyPage); p.set('limit', 25);
		if (historyRisk !== 'all') p.set('risk', historyRisk);
		var res = await fetch('/api/history?' + p), json = await res.json();
		if (!json.ok) { setStatus($('history-status'), false, 'ERROR'); $('history-tbody').innerHTML = '<tr><td colspan="7" class="table-empty">Failed to load.</td></tr>'; return; }
		setStatus($('history-status'), true, json.total + ' scans');
		if (json.entries.length === 0) {
			$('history-tbody').innerHTML = '<tr><td colspan="7" class="table-empty">No scans yet. Upload a file to get started.</td></tr>';
			$('history-pagination').style.display = 'none'; return;
		}
		$('history-tbody').innerHTML = '';
		json.entries.forEach(function (e) {
			var tr = document.createElement('tr');
			tr.innerHTML = '<td>' + formatDate(e.upload_date) + '</td><td>' + e.filename + '</td><td><code>' + shortHash(e.sha256) + '</code></td><td></td><td>' + e.total_score + '</td><td>' + e.finding_count + '</td><td>' + formatDuration(e.duration_ms) + '</td>';
			tr.children[3].appendChild(riskBadge(e.risk_level));
			tr.addEventListener('click', function () { showDetail(e.sha256); });
			$('history-tbody').appendChild(tr);
		});
		renderPagination(json);
	} catch (e) { setStatus($('history-status'), false, 'NETWORK ERROR'); $('history-tbody').innerHTML = '<tr><td colspan="7" class="table-empty">Error: ' + e.message + '</td></tr>'; }
}

function renderPagination(json) {
	var tp = Math.ceil(json.total / json.limit), pag = $('history-pagination');
	if (tp <= 1) { pag.style.display = 'none'; return; }
	pag.style.display = 'flex'; pag.innerHTML = '';
	var prev = document.createElement('button'); prev.textContent = '\u2190 Previous'; prev.disabled = historyPage <= 1;
	prev.addEventListener('click', function () { if (historyPage > 1) { historyPage--; loadHistory(); } }); pag.appendChild(prev);
	var s = document.createElement('span'); s.textContent = 'Page ' + historyPage + ' of ' + tp; pag.appendChild(s);
	var next = document.createElement('button'); next.textContent = 'Next \u2192'; next.disabled = historyPage >= tp;
	next.addEventListener('click', function () { historyPage++; loadHistory(); }); pag.appendChild(next);
}

// =============================================================================
// Detail panel
// =============================================================================

var allFindings = [];
var currentDetailHash = null;

async function showDetail(sha256) {
	currentDetailHash = sha256;
	showPanel('detail');
	// Reset filters
	document.querySelectorAll('.sev-filter').forEach(function (b) { b.classList.toggle('active', b.getAttribute('data-sev') === 'all'); });

	$('detail-meta').innerHTML = '<div class="skeleton-line"></div><div class="skeleton-line"></div><div class="skeleton-line"></div>';
	$('detail-findings').innerHTML = '<div class="skeleton-line"></div><div class="skeleton-line"></div><div class="skeleton-line"></div>';
	$('detail-file-tree').innerHTML = '<div class="skeleton-line"></div>';
	$('detail-raw-content').textContent = '';

	try {
		var res = await fetch('/api/history/' + sha256), json = await res.json();
		if (!json.ok) { $('detail-meta').innerHTML = '<p style="color:var(--danger)">Scan not found.</p>'; return; }
		renderDetail(json);
	} catch (e) { $('detail-meta').innerHTML = '<p style="color:var(--danger)">Error: ' + e.message + '</p>'; }
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
	var level = d.risk_level;
	var scoreColor = RISK_COLORS[level] || 'var(--text)';
	$('detail-score').innerHTML = '<div class="score-big" style="color:' + scoreColor + '">' + d.total_score + '</div>' + riskBadge(level).outerHTML;

	// Severity
	var sevs = [
		{ l: 'Critical', c: d.critical_count || 0, k: 'badge-critical' },
		{ l: 'High', c: d.high_count || 0, k: 'badge-high' },
		{ l: 'Medium', c: d.medium_count || 0, k: 'badge-medium' },
		{ l: 'Low', c: d.low_count || 0, k: 'badge-low' },
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

	// File tree
	if (d.file_tree && d.file_tree.length > 0) {
		var treeHTML = '<div class="file-tree">';
		d.file_tree.forEach(function (e) {
			var icon = e.asset_type === 'Meta' ? 'M' : e.asset_type === 'Script' ? 'S' : 'F';
			var cls = e.asset_type === 'Meta' ? 'ft-meta' : (e.asset_type === 'Script' ? 'ft-file' : 'ft-file');
			var sz = e.size_bytes > 0 ? '<span class="ft-size">' + formatBytes(e.size_bytes) + '</span>' : '';
			treeHTML += '<div class="' + cls + '">  ' + icon + '  ' + e.path + sz + '</div>';
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
	var findingsHTML = '';
	allFindings.forEach(function (f, i) {
		var sev = (f.severity || 'low').toLowerCase();
		var hidden = (filter !== 'all' && filter !== sev) ? ' hidden' : '';
		var sevClass = sev;

		var linesText = '';
		if (f.line_numbers && f.line_numbers.length > 0) {
			var first = f.line_numbers.slice(0, 8).join(', ');
			var more = f.line_numbers.length > 8 ? ' &hellip;(+' + (f.line_numbers.length - 8) + ')' : '';
			linesText = '<span>Lines: ' + first + more + '</span>';
		} else {
			linesText = '<span class="finding-lines-none">No line numbers</span>';
		}

		findingsHTML +=
			'<div class="finding-card' + hidden + '" data-finding-sev="' + sev + '">' +
			'<div class="finding-card-header">' +
			'<span class="severity-badge ' + sevClass + '"><span class="sev-dot"></span>' + (f.severity || '') + '</span>' +
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
		var filter = this.getAttribute('data-sev');
		var cards = $('detail-findings').querySelectorAll('.finding-card');
		cards.forEach(function (c) {
			if (filter === 'all' || c.getAttribute('data-finding-sev') === filter) c.classList.remove('hidden');
			else c.classList.add('hidden');
		});
	});
});

// Hash copy
function copyHash(hash, btn) {
	navigator.clipboard.writeText(hash).then(function () {
		btn.textContent = '\u2713';
		btn.classList.add('copied');
		setTimeout(function () { btn.textContent = '\xa9'; btn.classList.remove('copied'); }, 2000);
	}).catch(function () {
		btn.textContent = '!';
		setTimeout(function () { btn.textContent = '\xa9'; }, 1500);
	});
}

// Back button
$('detail-back-btn').addEventListener('click', function () {
	showPanel('history');
	loadHistory();
});

// =============================================================================
// Platform Stats
// =============================================================================

$('platform-stats-btn').addEventListener('click', loadPlatformStats);

async function loadPlatformStats() {
	setPending($('platform-stats-status'));
	try {
		var res = await fetch('/api/stats'), json = await res.json();
		if (!json.ok) { setStatus($('platform-stats-status'), false, 'ERROR'); return; }
		setStatus($('platform-stats-status'), true, 'Loaded');
		$('stat-total').textContent = json.total_scans;
		$('stat-last24').textContent = json.last_24h;
		$('stat-safe').textContent = json.safe;
		$('stat-dangerous').textContent = json.dangerous;

		// Animate stats
		document.querySelectorAll('.stat-card .stat-value').forEach(function (el) { el.classList.remove('skeleton-line'); });

		// Risk bars
		var total = json.total_scans || 1;
		var order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'CLEAN'];
		var barsHTML = '';
		order.forEach(function (r) {
			var count = json.by_risk[r] || 0;
			var pct = (total > 0 ? count / total * 100 : 0).toFixed(1);
			barsHTML +=
				'<div class="risk-bar-row">' +
				'<span class="risk-bar-label" style="color:' + (RISK_COLORS[r] || 'var(--text)') + '">' + r + '</span>' +
				'<div class="risk-bar-track"><div class="risk-bar-fill" style="width:' + pct + '%;background:' + (RISK_COLORS[r] || 'var(--muted)') + '"></div></div>' +
				'<span class="risk-bar-count">' + count + '</span>' +
				'</div>';
		});
		$('risk-bars').innerHTML = barsHTML;
		$('risk-distribution').style.display = 'block';

		$('platform-stats-raw').style.display = 'block';
		$('platform-stats-raw').textContent = JSON.stringify(json, null, 2);
	} catch (e) { setStatus($('platform-stats-status'), false, 'NETWORK ERROR'); }
}

// Load stats automatically when panel shown (first time)
var statsLoaded = false;
document.querySelector('[data-panel="platform-stats"]').addEventListener('click', function () {
	if (!statsLoaded) { statsLoaded = true; loadPlatformStats(); }
});

// =============================================================================
// Global search
// =============================================================================

$('global-search-btn').addEventListener('click', doSearch);
$('global-search').addEventListener('keydown', function (e) { if (e.key === 'Enter') doSearch(); });

async function doSearch() {
	var q = $('global-search').value.trim();
	if (!q) return;
	if (/^[0-9a-fA-F]{64}$/.test(q)) { showDetail(q.toLowerCase()); return; }
	try {
		var res = await fetch('/api/search?q=' + encodeURIComponent(q)), json = await res.json();
		if (json.results && json.results.length > 0) {
			showPanel('history');
			$('history-pagination').style.display = 'none';
			setStatus($('history-status'), true, json.results.length + ' results');
			$('history-tbody').innerHTML = '';
			json.results.forEach(function (e) {
				var tr = document.createElement('tr');
				tr.innerHTML = '<td>' + formatDate(e.upload_date) + '</td><td>' + e.filename + '</td><td><code>' + shortHash(e.sha256) + '</code></td><td></td><td>' + e.total_score + '</td><td>' + e.finding_count + '</td><td>' + formatDuration(e.duration_ms) + '</td>';
				tr.children[3].appendChild(riskBadge(e.risk_level));
				tr.addEventListener('click', function () { showDetail(e.sha256); });
				$('history-tbody').appendChild(tr);
			});
		} else {
			showPanel('history');
			setStatus($('history-status'), true, 'No results');
			$('history-tbody').innerHTML = '<tr><td colspan="7" class="table-empty">No results for "' + q + '".</td></tr>';
			$('history-pagination').style.display = 'none';
		}
	} catch (e) { /* silent */ }
}

// =============================================================================
// Batch scan
// =============================================================================

$('batch-btn').addEventListener('click', async function () {
	var raw = $('batch-json').value.trim(), sev = $('batch-minsev').value, v = $('batch-verbose').checked;
	var files; try { files = JSON.parse(raw); } catch (_) { alert('Invalid JSON'); return; }
	if (!Array.isArray(files) || !files.length) { alert('Files array is required'); return; }
	var params = new URLSearchParams(); if (v) params.set('verbose', 'true'); if (sev) params.set('min_severity', sev);
	setResult($('batch-result'), 'Scanning ' + files.length + ' files...'); setPending($('batch-status'));
	try {
		var res = await fetch('/api/scan-batch?' + params, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ files: files }) });
		var text = await res.text(); setStatus($('batch-status'), res.ok, res.status + ' ' + res.statusText);
		try { setResult($('batch-result'), JSON.stringify(JSON.parse(text), null, 2)); } catch (_) { setResult($('batch-result'), text); }
	} catch (e) { setStatus($('batch-status'), false, 'NETWORK ERROR'); setResult($('batch-result'), 'Error: ' + e.message); }
});

// =============================================================================
// Cache Stats
// =============================================================================

$('stats-btn').addEventListener('click', async function () {
	setResult($('stats-result'), 'Loading...'); setPending($('stats-status'));
	try {
		var res = await fetch('/api/cache-stats'), text = await res.text();
		setStatus($('stats-status'), res.ok, res.status + ' ' + res.statusText);
		try { setResult($('stats-result'), JSON.stringify(JSON.parse(text), null, 2)); } catch (_) { setResult($('stats-result'), text); }
	} catch (e) { setStatus($('stats-status'), false, 'NETWORK ERROR'); setResult($('stats-result'), 'Error: ' + e.message); }
});

// =============================================================================
// Health
// =============================================================================

$('health-btn').addEventListener('click', async function () {
	setResult($('health-result'), 'Checking...'); setPending($('health-status'));
	try {
		var res = await fetch('/api/health'), text = await res.text();
		setStatus($('health-status'), res.ok, res.ok ? '200 UP' : res.status); setResult($('health-result'), text);
	} catch (e) { setStatus($('health-status'), false, 'DOWN'); setResult($('health-result'), 'Error: ' + e.message); }
});
