// =============================================================================
// stats.js — Platform statistics panel
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
