// =============================================================================
// misc.js — Batch scan, Cache Stats, and Health panels
// =============================================================================

// Batch scan
$('batch-btn').addEventListener('click', async function () {
	var raw = $('batch-json').value.trim(), sev = $('batch-minsev').value, v = $('batch-verbose').checked;
	var files; try { files = JSON.parse(raw); } catch (_) { alert('Invalid JSON'); return; }
	if (!Array.isArray(files) || !files.length) { alert('Files array is required'); return; }
	var params = new URLSearchParams(); if (v) params.set('verbose', 'true'); if (sev) params.set('min_severity', sev);
	setResult($('batch-result'), 'Verifying...'); setPending($('batch-status'));
	var turnstileToken;
	try { turnstileToken = await getTurnstileToken(); } catch (e) { setStatus($('batch-status'), false, 'VERIFICATION FAILED'); setResult($('batch-result'), 'Human verification failed: ' + e.message); return; }
	setResult($('batch-result'), 'Scanning ' + files.length + ' files...');
	try {
		var res = await fetch('/api/scan-batch?' + params, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ files: files, cf_turnstile_response: turnstileToken }) });
		var text = await res.text(); setStatus($('batch-status'), res.ok, res.status + ' ' + res.statusText);
		try { setResult($('batch-result'), JSON.stringify(JSON.parse(text), null, 2)); } catch (_) { setResult($('batch-result'), text); }
	} catch (e) { setStatus($('batch-status'), false, 'NETWORK ERROR'); setResult($('batch-result'), 'Error: ' + e.message); }
});

// Cache Stats
$('stats-btn').addEventListener('click', async function () {
	setResult($('stats-result'), 'Loading...'); setPending($('stats-status'));
	try {
		var res = await fetch('/api/cache-stats'), text = await res.text();
		setStatus($('stats-status'), res.ok, res.status + ' ' + res.statusText);
		try { setResult($('stats-result'), JSON.stringify(JSON.parse(text), null, 2)); } catch (_) { setResult($('stats-result'), text); }
	} catch (e) { setStatus($('stats-status'), false, 'NETWORK ERROR'); setResult($('stats-result'), 'Error: ' + e.message); }
});

// Health
$('health-btn').addEventListener('click', async function () {
	setResult($('health-result'), 'Checking...'); setPending($('health-status'));
	try {
		var res = await fetch('/api/health'), text = await res.text();
		setStatus($('health-status'), res.ok, res.ok ? '200 UP' : res.status); setResult($('health-result'), text);
	} catch (e) { setStatus($('health-status'), false, 'DOWN'); setResult($('health-result'), 'Error: ' + e.message); }
});
