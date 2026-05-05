// =============================================================================
// search.js — Global search bar
// =============================================================================

$('global-search-btn').addEventListener('click', doSearch);
$('global-search').addEventListener('keydown', function (e) { if (e.key === 'Enter') doSearch(); });

async function doSearch() {
	const q = $('global-search').value.trim();
	if (!q) return;
	if (/^[0-9a-fA-F]{64}$/.test(q)) { navigate('/file/' + q.toLowerCase()); return; }
	try {
		// Cache search results for 30 s — same query typed again within the session is instant.
		const url  = '/api/search?q=' + encodeURIComponent(q);
		const json = await DataCache.fetch(url, { ttl: 30_000, type: 'json' });
		if (json.results && json.results.length > 0) {
			showPanel('history');
			$('history-pagination').style.display = 'none';
			setStatus($('history-status'), true, json.results.length + ' results');
			$('history-tbody').innerHTML = '';
			json.results.forEach(function (e) {
				const tr = document.createElement('tr');
				tr.innerHTML = '<td>' + formatDate(e.upload_date) + '</td><td>' + e.filename + '</td><td><code>' + shortHash(e.sha256) + '</code></td><td></td><td>' + e.total_score + '</td><td>' + e.finding_count + '</td><td>' + formatDuration(e.duration_ms) + '</td>';
				tr.children[3].appendChild(riskBadge(e.risk_level));
				tr.addEventListener('click', function () { navigate('/file/' + e.sha256); });
				$('history-tbody').appendChild(tr);
			});
		} else {
			navigate('/history');
			setStatus($('history-status'), true, 'No results');
			$('history-tbody').innerHTML = '<tr><td colspan="7" class="table-empty">No results for "' + q + '".</td></tr>';
			$('history-pagination').style.display = 'none';
		}
	} catch (e) { /* silent */ }
}
