// =============================================================================
// stats.js — Platform statistics panel
// =============================================================================

// Refresh button busts the cache first so the user always gets live data on demand.
$('platform-stats-btn').addEventListener('click', function () { DataCache.clear('/api/stats'); loadPlatformStats(); });

async function loadPlatformStats() {
	setPending($('platform-stats-status'));
	try {
		// Cache stats for 30 s — avoids a round-trip when the user reopens the panel.
		const json = await DataCache.fetch('/api/stats', { ttl: 30_000, type: 'json' });
		if (!json.ok) { setStatus($('platform-stats-status'), false, 'ERROR'); return; }
		setStatus($('platform-stats-status'), true, 'Loaded');
		$('stat-total').textContent   = json.total_scans;
		$('stat-last24').textContent  = json.last_24h;
		$('stat-safe').textContent    = json.safe;
		$('stat-dangerous').textContent = json.dangerous;

		// Animate stats
		document.querySelectorAll('.stat-card .stat-value').forEach(function (el) { el.classList.remove('skeleton-line'); });

		// Risk bars
		const total = json.total_scans || 1;
		const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'CLEAN'];
		let barsHTML = '';
		order.forEach(function (r) {
			const count = json.by_risk[r] || 0;
			const pct   = (total > 0 ? count / total * 100 : 0).toFixed(1);
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

// Load stats automatically when panel shown (first time only).
let statsLoaded = false;
document.querySelector('[data-panel="platform-stats"]').addEventListener('click', function () {
	if (!statsLoaded) { statsLoaded = true; loadPlatformStats(); }
});
