use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

use crate::pipeline::run_scan_bytes;

/// Request body for POST /scan
#[derive(Debug, Deserialize)]
pub struct ScanRequest {
    /// Pre-signed URL or direct URL to the file in R2
    pub r2_url: String,
    pub file_id: String,
    #[serde(default)]
    pub expected_sha256: Option<String>,
}

/// Response for POST /scan
#[derive(Debug, Serialize)]
pub struct ScanResponse {
    pub file_id: String,
    pub scan_result: Value,
    pub ok: bool,
}

/// Shared application state
#[derive(Clone)]
struct AppState {
    http: Arc<reqwest::Client>,
}

/// Start the HTTP server on the given address.
pub async fn serve(addr: SocketAddr) -> anyhow::Result<()> {
    let state = AppState {
        http: Arc::new(reqwest::Client::new()),
    };

    let app = Router::new()
        .route("/scan", post(handle_scan))
        .route("/health", axum::routing::get(|| async { Json(json!({"ok": true})) }))
        .with_state(state);

    println!("vrcstorage-scanner server listening on {addr}");
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn handle_scan(
    State(state): State<AppState>,
    Json(req): Json<ScanRequest>,
) -> Result<Json<ScanResponse>, (StatusCode, String)> {
    // Download the file from R2
    let resp = state
        .http
        .get(&req.r2_url)
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Download failed: {e}")))?;

    if !resp.status().is_success() {
        return Err((
            StatusCode::BAD_GATEWAY,
            format!("R2 returned HTTP {}", resp.status()),
        ));
    }

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Reading body failed: {e}")))?;

    // Validate SHA-256 if provided
    if let Some(expected) = &req.expected_sha256 {
        use sha2::{Digest, Sha256};
        let actual = hex::encode(Sha256::digest(&bytes));
        if &actual != expected {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("SHA-256 mismatch: expected={expected} actual={actual}"),
            ));
        }
    }

    // Run the scanner pipeline
    let scan_report = run_scan_bytes(&bytes, &req.file_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Scan error: {e}")))?;

    let scan_json = serde_json::to_value(&scan_report)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Serialize error: {e}")))?;

    Ok(Json(ScanResponse {
        file_id: req.file_id,
        scan_result: scan_json,
        ok: true,
    }))
}
