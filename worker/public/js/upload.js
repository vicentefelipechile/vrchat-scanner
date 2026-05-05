// =============================================================================
// upload.js — Multipart file upload panel
// =============================================================================
// Flow:
//   1. User selects/drops a file → SHA-256 computed in-browser
//   2. "Scan Now" click → POST /api/upload/start (Turnstile here)
//   3. File split into 10 MB chunks → PUT /api/upload/part × N (progress bar)
//   4. POST /api/upload/end → returns { url, sha256, file_id }
//   5. Second Turnstile → POST /api/scan → render structured result
// =============================================================================

let uploadFile = null;
let uploadHash = null;

/** R2 multipart minimum: 5 MB. We use 10 MB for comfortable headroom. */
const CHUNK_SIZE = 10 * 1024 * 1024;

const dropzone  = $('upload-dropzone');
const fileInput = $('upload-file-input');

// ── Drag & drop ───────────────────────────────────────────────────────────────

dropzone.addEventListener('dragover',  function (e) { e.preventDefault(); dropzone.classList.add('drag-over'); });
dropzone.addEventListener('dragleave', function ()  { dropzone.classList.remove('drag-over'); });
dropzone.addEventListener('drop', function (e) {
	e.preventDefault();
	dropzone.classList.remove('drag-over');
	if (e.dataTransfer.files.length > 0) processUploadFile(e.dataTransfer.files[0]);
});
// Guard against the file input's click bubbling back up to the dropzone
dropzone.addEventListener('click',   function (e) { if (e.target === fileInput) return; fileInput.click(); });
fileInput.addEventListener('click',  function (e) { e.stopPropagation(); });
fileInput.addEventListener('change', function ()  { if (this.files.length > 0) processUploadFile(this.files[0]); });

// ── SHA-256 (browser-side) ────────────────────────────────────────────────────

async function computeSHA256(file) {
	const buf     = await file.arrayBuffer();
	const hashBuf = await crypto.subtle.digest('SHA-256', buf);
	return Array.from(new Uint8Array(hashBuf))
		.map(function (b) { return b.toString(16).padStart(2, '0'); })
		.join('');
}

// ── File selection ────────────────────────────────────────────────────────────

async function processUploadFile(file) {
	if (file.size > 500 * 1024 * 1024) { alert('File too large. Maximum size is 500 MB.'); return; }
	uploadFile = file;
	$('upload-filename').textContent = file.name;
	$('upload-filesize').textContent = formatBytes(file.size);
	$('upload-sha256').textContent   = 'Computing SHA-256...';
	dropzone.style.display           = 'none';
	$('upload-info').style.display   = 'block';
	hideResult();
	hideStatusBar();
	try {
		uploadHash = await computeSHA256(file);
		$('upload-sha256').textContent = uploadHash;
		// Speculatively pre-fetch a Turnstile token while the user reads the info
		if (window.turnstileWidgetId && !window.turnstileToken) {
			getTurnstileToken().catch(function () {});
		}
	} catch (e) {
		$('upload-sha256').textContent = 'Failed: ' + e.message;
		uploadHash = null;
	}
}

// ── UI helpers ────────────────────────────────────────────────────────────────

function setProgress(pct, label) {
	$('upload-progress-fill').style.width = Math.min(100, pct) + '%';
	$('upload-progress-text').textContent = label || '';
}

function showProgress(label) {
	$('upload-progress').style.display = 'block';
	setProgress(0, label);
}

function hideProgress() {
	setTimeout(function () { $('upload-progress').style.display = 'none'; }, 900);
}

function setUploadStatus(ok, text) {
	const bar  = $('upload-status-bar');
	const icon = $('upload-status-icon');
	const txt  = $('upload-status-text');
	if (!bar) return;
	bar.style.display = 'flex';
	if (ok === null) {
		icon.textContent = '↻'; icon.className = 'status-icon pending';
	} else if (ok) {
		icon.textContent = '✓'; icon.className = 'status-icon ok';
	} else {
		icon.textContent = '✗'; icon.className = 'status-icon err';
	}
	txt.textContent = text || '';
}

function hideStatusBar() {
	const bar = $('upload-status-bar');
	if (bar) bar.style.display = 'none';
}

function hideResult() {
	const s = $('upload-result-structured');
	if (s) s.style.display = 'none';
}

function abortUpload(message) {
	hideProgress();
	setUploadStatus(false, message);
}

// ── Reset ─────────────────────────────────────────────────────────────────────

function resetUpload() {
	uploadFile = null;
	uploadHash = null;
	dropzone.style.display         = 'block';
	$('upload-info').style.display = 'none';
	$('upload-progress').style.display = 'none';
	hideStatusBar();
	hideResult();
	fileInput.value = '';
	resetTurnstile();
}

// ── Buttons ───────────────────────────────────────────────────────────────────

$('upload-reset-btn').addEventListener('click', resetUpload);
$('upload-scan-btn').addEventListener('click', function () {
	if (uploadFile && uploadHash) uploadAndScan();
	else alert('Please select a file first.');
});
// "Scan & Sanitize" is disabled in HTML — no listener needed.

// ── Main upload + scan flow ───────────────────────────────────────────────────

async function uploadAndScan() {
	window.uploadInProgress = true; // block navigation while uploading
	hideStatusBar();
	hideResult();
	showProgress('Checking scan cache...');

	// ── Step 0: Cache pre-check ───────────────────────────────────────────────
	// If this SHA-256 was already scanned, skip the upload entirely and
	// navigate directly to the existing result.
	try {
		const cacheRes  = await fetch('/api/history/' + uploadHash);
		if (cacheRes.ok) {
			const cacheJson = await cacheRes.json().catch(function () { return {}; });
			if (cacheJson.ok) {
				window.uploadInProgress = false;
				hideProgress();
				navigate('/detail/' + uploadHash);
				return;
			}
		}
	} catch (_) { /* network error on pre-check — continue with full upload */ }

	// ── Step 1: Turnstile ────────────────────────────────────────────────────
	setProgress(3, 'Verifying you are human...');
	let token;
	try { token = await getTurnstileToken(); }
	catch (e) { abortUpload('Verification failed: ' + e.message); return; }

	// ── Step 2: Start multipart upload ───────────────────────────────────────
	setProgress(3, 'Initializing upload...');
	let startJson;
	try {
		const startRes = await fetch('/api/upload/start', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				filename:              uploadFile.name,
				sha256:                uploadHash,
				file_size:             uploadFile.size,
				cf_turnstile_response: token,
			}),
		});
		startJson = await startRes.json();
		if (!startJson.ok) { abortUpload(startJson.error || 'Upload init failed'); return; }
	} catch (e) { abortUpload('Network error: ' + e.message); return; }

	const uploadId = startJson.upload_id;
	const r2Key    = startJson.r2_key;

	// ── Step 3: Upload parts (semaphore — always CONCURRENCY parts in-flight) ─
	const totalChunks = Math.max(1, Math.ceil(uploadFile.size / CHUNK_SIZE));
	const parts       = new Array(totalChunks); // pre-allocated by index
	let completedChunks = 0;
	let nextIdx         = 0;   // shared counter (safe: JS is single-threaded)
	const CONCURRENCY   = 2;   // simultaneous in-flight uploads

	/** Upload a single part by index; updates progress when done. */
	async function uploadPart(idx) {
		const chunkStart = idx * CHUNK_SIZE;
		const chunkEnd   = Math.min(chunkStart + CHUNK_SIZE, uploadFile.size);
		const chunk      = uploadFile.slice(chunkStart, chunkEnd);

		const partRes  = await fetch('/api/upload/part', {
			method:  'PUT',
			headers: {
				'Content-Type':  'application/octet-stream',
				'X-Upload-Id':   uploadId,
				'X-R2-Key':      r2Key,
				'X-Part-Number': String(idx + 1),
			},
			body: chunk,
		});
		const partJson = await partRes.json();
		if (!partJson.ok) throw new Error(partJson.error || 'Part upload failed');

		completedChunks++;
		const pct = Math.round(5 + (completedChunks / totalChunks) * 75);
		setProgress(pct, totalChunks === 1
			? 'Uploading...'
			: 'Uploading... ' + completedChunks + ' / ' + totalChunks + ' parts done'
		);

		parts[idx] = { etag: partJson.etag, part_number: partJson.part_number };
	}

	/**
	 * Each worker greedily picks the next available chunk and uploads it.
	 * As soon as it finishes, it grabs the next one — no waiting for siblings.
	 * CONCURRENCY workers running in parallel = always CONCURRENCY parts in-flight.
	 */
	async function worker() {
		while (nextIdx < totalChunks) {
			const idx = nextIdx++;   // atomically claim the next index
			await uploadPart(idx);
		}
	}

	try {
		const numWorkers = Math.min(CONCURRENCY, totalChunks);
		await Promise.all(Array.from({ length: numWorkers }, worker));
	} catch (e) { abortUpload('Network error: ' + e.message); return; }

	// ── Step 4: Complete upload ───────────────────────────────────────────────
	setProgress(83, 'Finalizing upload...');
	let endJson;
	try {
		const endRes = await fetch('/api/upload/end', {
			method:  'POST',
			headers: { 'Content-Type': 'application/json' },
			body:    JSON.stringify({
				upload_id: uploadId,
				r2_key:    r2Key,
				sha256:    uploadHash,
				filename:  uploadFile.name,
				file_size: uploadFile.size,
				parts:     parts,
			}),
		});
		endJson = await endRes.json();
		if (!endJson.ok) { abortUpload(endJson.error || 'Upload finalize failed'); return; }
	} catch (e) { abortUpload('Network error: ' + e.message); return; }

	// ── Step 5: Scan ─────────────────────────────────────────────────────────
	setProgress(88, 'Scanning...');
	let scanToken;
	try {
		resetTurnstile();
		scanToken = await getTurnstileToken();
	} catch (e) { abortUpload('Verification failed: ' + e.message); return; }

	setProgress(92, 'Analyzing package...');
	try {
		const scanRes = await fetch('/api/scan?format=json', {
			method:  'POST',
			headers: { 'Content-Type': 'application/json' },
			body:    JSON.stringify({
				url:                   endJson.url,
				file_id:               endJson.file_id,
				expected_sha256:       endJson.sha256,
				filename:              uploadFile.name,
				file_size:             uploadFile.size,
				cf_turnstile_response: scanToken,
			}),
		});

		setProgress(100, 'Done!');
		const cache = scanRes.headers.get('X-Cache') || '';
		setUploadStatus(scanRes.ok, scanRes.ok
			? '200 OK' + (cache ? ' [' + cache + ']' : '')
			: scanRes.status + ' ' + scanRes.statusText
		);

		const text   = await scanRes.text();
		let   parsed = null;
		try { parsed = JSON.parse(text); } catch (_) {}

		// Navigate to the detail page so the user sees the full VirusTotal-style view.
		// The detail panel fetches from /api/history/:sha256 (KV-cached).
		const resultSha = (parsed && (parsed.sha256 || (parsed.scan_result && parsed.scan_result.file && parsed.scan_result.file.sha256))) || endJson.sha256;
		// ── Clear the navigation guard BEFORE navigate() so the router's
		//    uploadInProgress check never sees it as true on a successful scan.
		window.uploadInProgress = false;
		if (scanRes.ok && resultSha) {
			navigate('/detail/' + resultSha);
		} else {
			// Fallback: show raw JSON inline if navigation target is unavailable
			const raw = $('upload-result-raw');
			if (raw) {
				raw.textContent = parsed ? JSON.stringify(parsed, null, 2) : text;
				raw.style.display = 'block';
				const structured = $('upload-result-structured');
				if (structured) structured.style.display = 'block';
			}
		}
	} catch (e) {
		abortUpload('Scan error: ' + e.message);
		return;
	} finally {
		window.uploadInProgress = false; // safety net for all other paths (errors, etc.)
		hideProgress();
	}
}

// ── Structured result renderer ────────────────────────────────────────────────

function renderScanResult(sr) {
	const structured = $('upload-result-structured');
	if (!structured) return;
	structured.style.display = 'block';
	$('upload-result-raw').textContent = JSON.stringify(sr, null, 2);

	const level = (sr.risk && sr.risk.level) || 'UNKNOWN';
	const score = (sr.risk && sr.risk.score) || 0;
	$('result-verdict-block').innerHTML =
		riskBadge(level).outerHTML +
		'<span style="font-family:var(--font-mono);font-size:24px;font-weight:600;margin-left:12px;color:var(--text)">' + score + '</span>';

	$('result-meta-block').innerHTML =
		'<div>' + ((sr.file && sr.file.path) || 'File') + '</div>' +
		'<div style="font-family:var(--font-mono);color:var(--text-dim);margin-top:4px">' + formatDuration(sr.scan_duration_ms) + '</div>';

	const findings = sr.findings || [];
	let crit = 0, high = 0, med = 0, low = 0;
	findings.forEach(function (f) {
		const s = (f.severity || '').toLowerCase();
		if      (s === 'critical') crit++;
		else if (s === 'high')     high++;
		else if (s === 'medium')   med++;
		else                       low++;
	});

	$('result-severity-bar').innerHTML =
		'<div class="sev-count"><span class="badge badge-critical">CRIT</span> <span class="count">' + crit + '</span></div>' +
		'<div class="sev-count"><span class="badge badge-high">HIGH</span> <span class="count">'     + high + '</span></div>' +
		'<div class="sev-count"><span class="badge badge-medium">MED</span> <span class="count">'   + med  + '</span></div>' +
		'<div class="sev-count"><span class="badge badge-low">LOW</span> <span class="count">'      + low  + '</span></div>';

	let html = '';
	if (findings.length === 0) {
		html = '<p style="color:var(--text-muted);font-family:var(--font-mono);padding:16px">No findings. Package is clean.</p>';
	} else {
		findings.forEach(function (f) {
			const sev = (f.severity || 'low').toLowerCase();
			html +=
				'<div class="finding-card" data-finding-sev="' + sev + '">' +
				'<div class="finding-card-header">' +
				'<span class="severity-badge ' + sev + '">' + (f.severity || 'low') + '</span>' +
				'<span class="finding-card-detail">' + (f.detail || f.id) + '</span>' +
				'<span class="finding-card-points">' + (f.points || 0) + ' pts</span>' +
				'</div>' +
				(f.location ? '<div class="finding-card-file">' + f.location + '</div>' : '') +
				'<div class="finding-card-footer"><span>ID: ' + f.id + '</span></div>' +
				'</div>';
		});
	}
	$('result-findings-list').innerHTML = html;
}
