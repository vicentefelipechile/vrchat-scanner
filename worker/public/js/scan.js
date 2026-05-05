// =============================================================================
// scan.js — POST /api/scan (URL-based) and POST /api/sanitize panels
// =============================================================================

// POST /api/scan
$('scan-btn').addEventListener('click', async function () {
	var url = $('scan-url').value.trim(), fid = $('scan-fileid').value.trim();
	if (!url || !fid) { alert('R2 URL and File ID are required'); return; }
	var sha = $('scan-sha').value.trim(), fmt = $('scan-fmt').value, sev = $('scan-minsev').value, v = $('scan-verbose').checked;
	var params = new URLSearchParams(); params.set('format', fmt);
	if (v) params.set('verbose', 'true'); if (sev) params.set('min_severity', sev);
	var body = { url: url, file_id: fid }; if (sha) body.expected_sha256 = sha;
	setResult($('scan-result'), 'Verifying...'); setPending($('scan-status'));
	var turnstileToken;
	try { turnstileToken = await getTurnstileToken(); } catch (e) { setStatus($('scan-status'), false, 'VERIFICATION FAILED'); setResult($('scan-result'), 'Human verification failed: ' + e.message); return; }
	body.cf_turnstile_response = turnstileToken;
	setResult($('scan-result'), 'Scanning...');
	try {
		var res = await fetch('/api/scan?' + params, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
		var text = await res.text(), cache = res.headers.get('X-Cache') || '';
		setStatus($('scan-status'), res.ok, res.status + ' ' + res.statusText + (cache ? ' [' + cache + ']' : ''));
		try { setResult($('scan-result'), JSON.stringify(JSON.parse(text), null, 2)); } catch (_) { setResult($('scan-result'), text); }
	} catch (e) { setStatus($('scan-status'), false, 'NETWORK ERROR'); setResult($('scan-result'), 'Error: ' + e.message); }
});

// POST /api/sanitize
$('san-btn').addEventListener('click', async function () {
	var url = $('san-url').value.trim(), fid = $('san-fileid').value.trim();
	if (!url || !fid) { alert('R2 URL and File ID are required'); return; }
	var sha = $('san-sha').value.trim(), sev = $('san-minsev').value;
	var params = new URLSearchParams(); if (sev) params.set('min_severity', sev);
	var body = { url: url, file_id: fid }; if (sha) body.expected_sha256 = sha;
	setResult($('san-result'), 'Verifying...'); setPending($('san-status'));
	var turnstileToken;
	try { turnstileToken = await getTurnstileToken(); } catch (e) { setStatus($('san-status'), false, 'VERIFICATION FAILED'); setResult($('san-result'), 'Human verification failed: ' + e.message); return; }
	body.cf_turnstile_response = turnstileToken;
	setResult($('san-result'), 'Sanitizing...');
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
