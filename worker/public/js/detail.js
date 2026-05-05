// =============================================================================
// detail.js — Scan detail panel (VirusTotal-style)
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
	navigate('/history');
});
