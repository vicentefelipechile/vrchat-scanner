// =============================================================================
// upload.js — File upload panel logic
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
	resetTurnstile();
}

$('upload-reset-btn').addEventListener('click', resetUpload);
$('upload-scan-btn').addEventListener('click', function () { if (uploadFile && uploadHash) uploadAndScan(false); else alert('Please select a file first.'); });
$('upload-sanitize-btn').addEventListener('click', function () { if (uploadFile && uploadHash) uploadAndScan(true); else alert('Please select a file first.'); });

async function uploadAndScan(sanitize) {
	setStatus($('upload-status'), null, '');
	$('upload-result').style.display = 'block';
	setResult($('upload-result'), 'Verifying...');
	$('upload-progress').style.display = 'block';
	$('upload-progress-fill').style.width = '5%';
	$('upload-progress-text').textContent = 'Verifying you are human...';

	var token;
	try { token = await getTurnstileToken(); }
	catch (e) {
		$('upload-progress').style.display = 'none';
		setStatus($('upload-status'), false, 'VERIFICATION FAILED');
		setResult($('upload-result'), 'Human verification failed: ' + e.message);
		return;
	}

	$('upload-progress-text').textContent = 'Uploading...';

	var fd = new FormData();
	fd.append('file', uploadFile);
	fd.append('sha256', uploadHash);
	fd.append('cf-turnstile-response', token);

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

		var scanToken;
		try { scanToken = await getTurnstileToken(); }
		catch (e) {
			$('upload-progress').style.display = 'none';
			setStatus($('upload-status'), false, 'VERIFICATION FAILED');
			setResult($('upload-result'), 'Human verification failed: ' + e.message);
			return;
		}

		$('upload-progress-text').textContent = sanitize ? 'Sanitizing...' : 'Scanning...';

		var endpoint = sanitize ? '/api/sanitize' : '/api/scan';
		var params = new URLSearchParams();
		if (sanitize) params.set('min_severity', 'high');
		else params.set('format', 'json');

		var scanRes = await fetch(endpoint + '?' + params, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ url: upJson.url, file_id: upJson.file_id, expected_sha256: upJson.sha256, cf_turnstile_response: scanToken }),
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
