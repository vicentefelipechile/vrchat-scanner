// =========================================================================================================
// FILE UPLOAD — R2 upload + D1 logging
// =========================================================================================================
// Handles multipart file upload from the SPA via three-step protocol:
//   POST /api/upload/start  — initiates an R2 multipart upload, returns upload_id + r2_key
//   PUT  /api/upload/part   — uploads one chunk (≥5 MB except last), returns etag + part_number
//   POST /api/upload/end    — completes the multipart upload, returns download URL for scanning
//
// Turnstile is verified only on /start.  /part and /end are authenticated implicitly
// by the upload_id (opaque token issued by R2 createMultipartUpload).
//
// The R2 bucket must have a lifecycle rule to expire objects under
// uploads/* after 1 hour (or the Worker deletes them post-scan via cleanupUpload).
// =========================================================================================================

// =========================================================================================================
// Constants
// =========================================================================================================

/** Maximum file size accepted for upload: 500 MB */
const MAX_UPLOAD_SIZE = 500 * 1024 * 1024;

/** R2 key prefix for temporary uploads */
const UPLOAD_PREFIX = 'uploads';

/** Pre-signed URL lifetime in seconds (2 hours, container may take time) */
const PRESIGNED_TTL = 7200;

// =========================================================================================================
// Upload result
// =========================================================================================================

export interface UploadResult {
	/** R2 pre-signed download URL for the container */
	url: string;
	/** SHA-256 hex hash of the uploaded file */
	sha256: string;
	/** Original filename */
	filename: string;
	/** File size in bytes */
	file_size: number;
	/** Unique file ID (SHA-256) */
	file_id: string;
	/** Error message if upload failed */
	error?: string;
}

// =========================================================================================================
// SHA-256 helper
// =========================================================================================================

/**
 * Computes the SHA-256 hex digest of a Uint8Array using the Web Crypto API.
 * Workers runtime provides crypto.subtle natively.
 */
async function sha256Hex(data: Uint8Array): Promise<string> {
	const hashBuffer = await crypto.subtle.digest('SHA-256', data);
	const hashArray = Array.from(new Uint8Array(hashBuffer));
	return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

// =========================================================================================================
// Upload handler
// =========================================================================================================

/**
 * Handles a multipart file upload and stores it in R2.
 *
 * Expects the SPA to send FormData with the file in the "file" field.
 * Optionally accepts a "sha256" field with a pre-computed hash from the client.
 *
 * Returns an UploadResult with the pre-signed R2 URL for scanning.
 */
export async function handleUpload(
	request: Request,
	bucket: R2Bucket,
): Promise<UploadResult> {
	const contentType = request.headers.get('content-type') || '';

	if (!contentType.includes('multipart/form-data')) {
		return {
			url: '', sha256: '', filename: '', file_size: 0, file_id: '',
			error: 'Content-Type must be multipart/form-data',
		};
	}

	// Check content-length before reading the body
	const contentLength = parseInt(request.headers.get('content-length') || '0', 10);
	if (contentLength > MAX_UPLOAD_SIZE) {
		return {
			url: '', sha256: '', filename: '', file_size: 0, file_id: '',
			error: `File too large. Maximum size is ${MAX_UPLOAD_SIZE / 1024 / 1024} MB`,
		};
	}

	let formData: FormData;
	try {
		formData = await request.formData();
	} catch (e) {
		return {
			url: '', sha256: '', filename: '', file_size: 0, file_id: '',
			error: 'Failed to parse form data',
		};
	}

	const file = formData.get('file');
	if (!file || !(file instanceof File)) {
		return {
			url: '', sha256: '', filename: '', file_size: 0, file_id: '',
			error: 'No file found in request. Send as FormData field "file"',
		};
	}

	// Check file size
	if (file.size > MAX_UPLOAD_SIZE) {
		return {
			url: '', sha256: '', filename: '', file_size: 0, file_id: '',
			error: `File too large. Maximum size is ${MAX_UPLOAD_SIZE / 1024 / 1024} MB`,
		};
	}

	// Read file bytes
	const fileData = new Uint8Array(await file.arrayBuffer());

	// Compute SHA-256 (validate if client sent one)
	const clientHash = (formData.get('sha256') as string || '').trim().toLowerCase();
	const computedHash = await sha256Hex(fileData);

	if (clientHash && clientHash !== computedHash) {
		return {
			url: '', sha256: '', filename: file.name, file_size: file.size, file_id: '',
			error: `SHA-256 mismatch. Client sent ${clientHash}, computed ${computedHash}`,
		};
	}

	const hash = computedHash;

	// Store in R2: uploads/{hash[0:2]}/{hash}/{original_name}
	const r2Key = `${UPLOAD_PREFIX}/${hash.substring(0, 2)}/${hash}/${encodeURIComponent(file.name)}`;

	try {
		await bucket.put(r2Key, fileData, {
			httpMetadata: {
				contentType: file.type || 'application/octet-stream',
			},
			customMetadata: {
				'sha256': hash,
				'original-name': file.name,
				'upload-timestamp': String(Date.now()),
			},
		});
	} catch (e) {
		console.error('R2 put failed', e);
		return {
			url: '', sha256: '', filename: file.name, file_size: file.size, file_id: '',
			error: 'Failed to store file in R2',
		};
	}

	// Generate a pre-signed URL for the container to download
	// The container uses reqwest with an absolute URL
	let downloadUrl: string;
	try {
		// R2 objects can be accessed via the S3-compatible API pre-signed URLs
		// or via the custom domain if configured. For Cloudflare Containers,
		// we can use the R2 dev token URL or a Worker subdomain.
		//
		// The container needs a publicly accessible URL. Since the Worker runs
		// in the same Cloudflare account, we construct a URL that the container's
		// reqwest can fetch.
		//
		// Strategy: Return a URL through the Worker itself:
		//   https://{worker-host}/api/download/{hash}
		// The Worker serves the file from R2 when the container requests it.
		//
		// This avoids pre-signed URL complexity and R2 public access.
		const workerUrl = new URL(request.url);
		downloadUrl = `${workerUrl.origin}/api/download/${hash}`;
	} catch {
		const host = new URL(request.url).host;
		downloadUrl = `https://${host}/api/download/${hash}`;
	}

	return {
		url: downloadUrl,
		sha256: hash,
		filename: file.name,
		file_size: file.size,
		file_id: hash,
	};
}

/**
 * Serves an uploaded file from R2 for download by the container.
 *
 * Looks up the file by SHA-256 hash. Since the original filename is embedded
 * in the R2 key metadata, this requires listing objects with the hash prefix.
 */
export async function serveDownload(
	bucket: R2Bucket,
	hash: string,
): Promise<Response> {
	const prefix = `${UPLOAD_PREFIX}/${hash.substring(0, 2)}/${hash}/`;

	const objects = await bucket.list({ prefix, limit: 1 });
	const first = objects.objects[0];

	if (!first) {
		return new Response('File not found or expired', { status: 404 });
	}

	const obj = await bucket.get(first.key);
	if (!obj) {
		return new Response('File not found or expired', { status: 404 });
	}

	const headers = new Headers();
	obj.writeHttpMetadata(headers);
	headers.set('Content-Disposition', `attachment; filename="${first.key.split('/').pop() || 'file'}"`);

	return new Response(obj.body, {
		headers,
		status: 200,
	});
}

/**
 * Cleans up temporary uploads from R2 after a scan completes.
 * Called via ctx.waitUntil() after the scan finishes.
 *
 * Deletes all objects under uploads/{hash[0:2]}/{hash}/ for the given hash.
 */
export async function cleanupUpload(
	bucket: R2Bucket,
	hash: string,
): Promise<void> {
	const prefix = `${UPLOAD_PREFIX}/${hash.substring(0, 2)}/${hash}/`;

	try {
		const objects = await bucket.list({ prefix });
		const keys = objects.objects.map((o) => o.key);

		if (keys.length > 0) {
			await bucket.delete(keys);
		}
	} catch (e) {
		console.error('Failed to cleanup upload', e);
	}
}

// =========================================================================================================
// Multipart upload — three-step protocol
// =========================================================================================================

export interface MultipartStartResult {
	upload_id: string;
	r2_key: string;
	error?: string;
}

export interface MultipartPartResult {
	etag: string;
	part_number: number;
	error?: string;
}

export interface MultipartEndResult {
	url: string;
	sha256: string;
	filename: string;
	file_size: number;
	file_id: string;
	error?: string;
}

/**
 * Step 1 — Initiate an R2 multipart upload.
 *
 * Expects a JSON body: { filename, sha256, file_size, cf_turnstile_response }
 * Turnstile must be validated by the route before calling this function.
 * Returns an opaque upload_id and the R2 key that subsequent /part calls must supply.
 */
export async function startMultipartUpload(
	request: Request,
	bucket: R2Bucket,
): Promise<MultipartStartResult> {
	let body: any;
	try { body = await request.json(); } catch {
		return { upload_id: '', r2_key: '', error: 'Invalid JSON body' };
	}

	const filename = String(body.filename || '').trim();
	const sha256   = String(body.sha256   || '').trim().toLowerCase();
	const fileSize = Number(body.file_size || 0);

	if (!filename || !sha256) {
		return { upload_id: '', r2_key: '', error: 'filename and sha256 are required' };
	}
	if (!/^[0-9a-f]{64}$/.test(sha256)) {
		return { upload_id: '', r2_key: '', error: 'sha256 must be a 64-character lowercase hex string' };
	}
	if (fileSize > MAX_UPLOAD_SIZE) {
		return { upload_id: '', r2_key: '', error: `File too large. Maximum is ${MAX_UPLOAD_SIZE / 1024 / 1024} MB` };
	}

	const r2Key = `${UPLOAD_PREFIX}/${sha256.substring(0, 2)}/${sha256}/${encodeURIComponent(filename)}`;

	try {
		const mp = await bucket.createMultipartUpload(r2Key, {
			httpMetadata: { contentType: 'application/octet-stream' },
			customMetadata: {
				sha256,
				'original-name': filename,
				'upload-timestamp': String(Date.now()),
			},
		});
		return { upload_id: mp.uploadId, r2_key: r2Key };
	} catch (e) {
		console.error('createMultipartUpload failed', e);
		return { upload_id: '', r2_key: '', error: 'Failed to initiate upload' };
	}
}

/**
 * Step 2 — Upload one chunk of the file.
 *
 * Expects headers: X-Upload-Id, X-R2-Key, X-Part-Number (1-indexed).
 * Body must be raw binary (application/octet-stream).
 * All parts except the last must be ≥ 5 MB (R2 requirement).
 * Returns the part's etag which must be collected for the /end call.
 */
export async function uploadPart(
	request: Request,
	bucket: R2Bucket,
): Promise<MultipartPartResult> {
	const uploadId  = request.headers.get('X-Upload-Id')   || '';
	const r2Key     = request.headers.get('X-R2-Key')      || '';
	const partNumber = parseInt(request.headers.get('X-Part-Number') || '0', 10);

	if (!uploadId || !r2Key || !partNumber) {
		return { etag: '', part_number: 0, error: 'X-Upload-Id, X-R2-Key, and X-Part-Number headers are required' };
	}

	try {
		const mp   = bucket.resumeMultipartUpload(r2Key, uploadId);
		const part = await mp.uploadPart(partNumber, request.body!);
		return { etag: part.etag, part_number: part.partNumber };
	} catch (e) {
		console.error('uploadPart failed', e);
		return { etag: '', part_number: 0, error: 'Failed to upload part' };
	}
}

/**
 * Step 3 — Complete the multipart upload and return a download URL.
 *
 * Expects JSON: { upload_id, r2_key, sha256, filename, file_size, parts: [{etag, part_number}] }
 * After completion the file is available via GET /api/download/:sha256.
 */
export async function completeMultipartUpload(
	request: Request,
	bucket: R2Bucket,
): Promise<MultipartEndResult> {
	let body: any;
	try { body = await request.json(); } catch {
		return { url: '', sha256: '', filename: '', file_size: 0, file_id: '', error: 'Invalid JSON body' };
	}

	const uploadId = String(body.upload_id || '');
	const r2Key    = String(body.r2_key    || '');
	const sha256   = String(body.sha256    || '');
	const filename = String(body.filename  || '');
	const fileSize = Number(body.file_size || 0);
	const parts    = Array.isArray(body.parts) ? body.parts as { etag: string; part_number: number }[] : [];

	if (!uploadId || !r2Key || !sha256 || parts.length === 0) {
		return { url: '', sha256: '', filename: '', file_size: 0, file_id: '', error: 'upload_id, r2_key, sha256, and parts are required' };
	}
	if (!/^[0-9a-f]{64}$/.test(sha256)) {
		return { url: '', sha256: '', filename: '', file_size: 0, file_id: '', error: 'sha256 must be a 64-character lowercase hex string' };
	}

	try {
		const mp = bucket.resumeMultipartUpload(r2Key, uploadId);
		await mp.complete(parts.map((p) => ({ etag: p.etag, partNumber: p.part_number })));

		const origin = new URL(request.url).origin;
		const downloadUrl = `${origin}/api/download/${sha256}`;
		return { url: downloadUrl, sha256, filename, file_size: fileSize, file_id: sha256 };
	} catch (e) {
		console.error('completeMultipartUpload failed', e);
		return { url: '', sha256: '', filename: '', file_size: 0, file_id: '', error: 'Failed to complete upload' };
	}
}
