// =============================================================================
// history.js — Scan history panel
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
		var res = await fetch('/api/history?' + p);
		var json = {};
		try { json = await res.json(); } catch(e) {}
		
		if (!res.ok || !json.ok) { 
			setStatus($('history-status'), false, 'ERROR'); 
			$('history-tbody').innerHTML = '<tr><td colspan="7" class="table-empty">Failed to load: ' + (json.error || res.statusText) + '</td></tr>'; 
			return; 
		}
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
			tr.addEventListener('click', function () { navigate('/file/' + e.sha256); });
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
