// =========================================================================================================
// FILE UPLOAD — R2 upload + D1 logging
// =========================================================================================================
// Handles multipart file upload from the SPA:
//   1. Receives the file via multipart/form-data
//   2. Computes SHA-256
//   3. Stores in R2 bucket temporarily (1-hour TTL via lifecycle)
//   4. Generates a pre-signed download URL for the container
//   5. Returns URL + metadata to the SPA for scanning
//
// The R2 bucket must have a lifecycle rule to expire objects under
// uploads/* after 1 hour (or the Worker deletes them post-scan).
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
