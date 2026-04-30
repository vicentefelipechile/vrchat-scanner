// =============================================================================
// vrcstorage-scanner SPA
// =============================================================================
// Single Page Application for the vrcstorage-scanner service.
// Communicates with the Worker API at /api/* endpoints.
//
// Panels: Scan, Sanitize, Batch, Cache Stats, Health
// =============================================================================

// =============================================================================
// Helpers
// =============================================================================

/** Shorthand for document.getElementById */
function $(id) {
	return document.getElementById(id);
}

/** Sets the status indicator text and color class */
function setStatus(el, ok, text) {
	el.textContent = text || (ok ? '200 OK' : 'ERROR');
	el.className = 'status ' + (ok ? 'ok' : 'err');
}

/** Sets pending status */
function setPending(el) {
	el.textContent = 'pending';
	el.className = 'status pending';
}

/** Formats the result area with a header line followed by the body */
function setResult(el, text) {
	el.textContent = text;
}

// =============================================================================
// Panel navigation
// =============================================================================

document.querySelectorAll('.sidebar a').forEach(function (link) {
	link.addEventListener('click', function () {
		var name = this.getAttribute('data-panel');

		document.querySelectorAll('.sidebar a').forEach(function (a) { a.classList.remove('active'); });
		this.classList.add('active');

		document.querySelectorAll('.panel').forEach(function (p) { p.classList.remove('active'); });
		$('panel-' + name).classList.add('active');
	});
});

// =============================================================================
// POST /api/scan
// =============================================================================

$('scan-btn').addEventListener('click', async function () {
	var url = $('scan-url').value.trim();
	var fid = $('scan-fileid').value.trim();

	if (!url || !fid) { alert('R2 URL and File ID are required'); return; }

	var sha = $('scan-sha').value.trim();
	var fmt = $('scan-fmt').value;
	var sev = $('scan-minsev').value;
	var v = $('scan-verbose').checked;

	var params = new URLSearchParams();
	params.set('format', fmt);
	if (v) params.set('verbose', 'true');
	if (sev) params.set('min_severity', sev);

	var body = { url: url, file_id: fid };
	if (sha) body.expected_sha256 = sha;

	setResult($('scan-result'), 'Scanning…');
	setPending($('scan-status'));

	try {
		var res = await fetch('/api/scan?' + params, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(body),
		});

		var text = await res.text();
		var cacheHeader = res.headers.get('X-Cache') || '';

		setStatus($('scan-status'), res.ok, res.status + ' ' + res.statusText + (cacheHeader ? ' [' + cacheHeader + ']' : ''));

		// Pretty-print JSON if possible
		try {
			var json = JSON.parse(text);
			setResult($('scan-result'), JSON.stringify(json, null, 2));
		} catch (_) {
			setResult($('scan-result'), text);
		}
	} catch (e) {
		setStatus($('scan-status'), false, 'NETWORK ERROR');
		setResult($('scan-result'), 'Error: ' + e.message);
	}
});

// =============================================================================
// POST /api/sanitize
// =============================================================================

$('san-btn').addEventListener('click', async function () {
	var url = $('san-url').value.trim();
	var fid = $('san-fileid').value.trim();

	if (!url || !fid) { alert('R2 URL and File ID are required'); return; }

	var sha = $('san-sha').value.trim();
	var sev = $('san-minsev').value;

	var params = new URLSearchParams();
	if (sev) params.set('min_severity', sev);

	var body = { url: url, file_id: fid };
	if (sha) body.expected_sha256 = sha;

	setResult($('san-result'), 'Sanitizing…');
	setPending($('san-status'));

	try {
		var res = await fetch('/api/sanitize?' + params, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(body),
		});

		var rep = res.headers.get('x-sanitize-report');
		var orig = res.headers.get('x-original-score');
		var resid = res.headers.get('x-residual-score');

		var info = res.status + ' ' + res.statusText + '\n\n';
		info += 'X-Original-Score: ' + orig + '\n';
		info += 'X-Residual-Score: ' + resid + '\n\n';

		if (rep) {
			try { info += JSON.stringify(JSON.parse(rep), null, 2); }
			catch (_) { info += rep; }
		}

		setStatus($('san-status'), res.ok, res.ok ? '200 OK' : res.status);
		setResult($('san-result'), info);

		// Auto-download cleaned .unitypackage
		if (res.ok && (res.headers.get('content-type') || '').includes('octet-stream')) {
			var blob = await res.blob();
			var a = document.createElement('a');
			a.href = URL.createObjectURL(blob);
			a.download = fid + '-sanitized.unitypackage';
			a.click();
		}
	} catch (e) {
		setStatus($('san-status'), false, 'NETWORK ERROR');
		setResult($('san-result'), 'Error: ' + e.message);
	}
});

// =============================================================================
// POST /api/scan-batch
// =============================================================================

$('batch-btn').addEventListener('click', async function () {
	var raw = $('batch-json').value.trim();
	var sev = $('batch-minsev').value;
	var v = $('batch-verbose').checked;

	var files;
	try { files = JSON.parse(raw); } catch (_) { alert('Invalid JSON'); return; }
	if (!Array.isArray(files) || !files.length) { alert('Files array is required'); return; }

	var params = new URLSearchParams();
	if (v) params.set('verbose', 'true');
	if (sev) params.set('min_severity', sev);

	setResult($('batch-result'), 'Scanning ' + files.length + ' files…');
	setPending($('batch-status'));

	try {
		var res = await fetch('/api/scan-batch?' + params, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ files: files }),
		});

		var text = await res.text();
		setStatus($('batch-status'), res.ok, res.status + ' ' + res.statusText);

		try {
			var json = JSON.parse(text);
			setResult($('batch-result'), JSON.stringify(json, null, 2));
		} catch (_) {
			setResult($('batch-result'), text);
		}
	} catch (e) {
		setStatus($('batch-status'), false, 'NETWORK ERROR');
		setResult($('batch-result'), 'Error: ' + e.message);
	}
});

// =============================================================================
// GET /api/cache-stats
// =============================================================================

$('stats-btn').addEventListener('click', async function () {
	setResult($('stats-result'), 'Loading…');
	setPending($('stats-status'));

	try {
		var res = await fetch('/api/cache-stats');
		var text = await res.text();
		setStatus($('stats-status'), res.ok, res.status + ' ' + res.statusText);

		try {
			var json = JSON.parse(text);
			setResult($('stats-result'), JSON.stringify(json, null, 2));
		} catch (_) {
			setResult($('stats-result'), text);
		}
	} catch (e) {
		setStatus($('stats-status'), false, 'NETWORK ERROR');
		setResult($('stats-result'), 'Error: ' + e.message);
	}
});

// =============================================================================
// GET /api/health
// =============================================================================

$('health-btn').addEventListener('click', async function () {
	setResult($('health-result'), 'Checking…');
	setPending($('health-status'));

	try {
		var res = await fetch('/api/health');
		var text = await res.text();
		setStatus($('health-status'), res.ok, res.ok ? '200 UP' : res.status);
		setResult($('health-result'), text);
	} catch (e) {
		setStatus($('health-status'), false, 'DOWN');
		setResult($('health-result'), 'Error: ' + e.message);
	}
});
