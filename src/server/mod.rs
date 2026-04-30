use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;

use crate::pipeline::run_scan_bytes_full;
use crate::report::finding::Severity;
use crate::report::txt_reporter::render_single_txt;
use crate::report::ScanReport;
use crate::sanitize::run_sanitize_bytes;
use crate::scoring::context::AnalysisContext;
use crate::scoring::RiskLevel;

// ─── Constants ───────────────────────────────────────────────────────────────

const DEFAULT_MAX_DOWNLOAD_BYTES: u64 = 500 * 1024 * 1024; // 500 MB

// ─── Request / response types ─────────────────────────────────────────────────

/// Body for `POST /scan` and `POST /sanitize`.
#[derive(Debug, Deserialize)]
pub struct ScanRequest {
    pub r2_url: String,
    pub file_id: String,
    #[serde(default)]
    pub expected_sha256: Option<String>,
}

/// Body for `POST /scan-batch`.
#[derive(Debug, Deserialize)]
pub struct BatchScanRequest {
    pub files: Vec<ScanRequest>,
}

/// Query parameters for `/scan`.
#[derive(Debug, Deserialize, Default)]
pub struct ScanOptions {
    /// Output format: `"json"` (default) or `"txt"`.
    #[serde(default)]
    pub format: Option<String>,
    /// Include human-readable explanation for each finding.
    #[serde(default)]
    pub verbose: Option<bool>,
    /// Minimum severity to include: `"low"`, `"medium"`, `"high"`, `"critical"`.
    #[serde(default)]
    pub min_severity: Option<String>,
}

/// Success response for `POST /scan`.
#[derive(Debug, Serialize)]
pub struct ScanResponse {
    pub file_id: String,
    pub scan_result: ScanReport,
    pub analysis_context: AnalysisContext,
    pub ok: bool,
}

/// Success response for `POST /scan-batch`.
#[derive(Debug, Serialize)]
pub struct BatchScanResponse {
    pub results: Vec<ScanResponse>,
    pub ok: bool,
}

/// JSON error response (used for all error codes).
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: u16,
}

// ─── App state ────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    http: Arc<reqwest::Client>,
    max_download_bytes: u64,
}

// ─── Server entry point ───────────────────────────────────────────────────────

pub async fn serve(addr: SocketAddr) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .build()?;

    let state = AppState {
        http: Arc::new(client),
        max_download_bytes: DEFAULT_MAX_DOWNLOAD_BYTES,
    };

    let app = Router::new()
        .route("/scan", post(handle_scan))
        .route("/scan-batch", post(handle_scan_batch))
        .route("/sanitize", post(handle_sanitize))
        .route("/health", get(|| async { Json(json!({"ok": true})) }))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    println!("vrcstorage-scanner server listening on {addr}");
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    println!("\nShutting down...");
}

// ─── Shared helpers ───────────────────────────────────────────────────────────

/// Helper to produce a JSON error response.
fn json_err(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    let code = status.as_u16();
    (
        status,
        Json(ErrorResponse {
            error: msg.into(),
            code,
        }),
    )
}

/// Parse a severity string from the query parameter.
fn parse_min_severity(s: &str) -> Option<Severity> {
    match s.to_lowercase().as_str() {
        "low" => Some(Severity::Low),
        "medium" | "med" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" | "crit" => Some(Severity::Critical),
        _ => None,
    }
}

/// Map a RiskLevel string from the report back to the enum for TXT output.
fn risk_level_from_str(s: &str) -> RiskLevel {
    match s {
        "LOW" => RiskLevel::Low,
        "MEDIUM" => RiskLevel::Medium,
        "HIGH" => RiskLevel::High,
        "CRITICAL" => RiskLevel::Critical,
        _ => RiskLevel::Clean,
    }
}

/// Human explanation for a finding — mirrors `cli_reporter::human_explanation()`.
fn human_explanation(id: &crate::report::FindingId) -> &'static str {
    use crate::report::FindingId as F;
    match id {
        F::ForbiddenExtension => "This file type should never appear in a Unity package.",
        F::PathTraversal => "Path traversal can overwrite files outside the Unity project.",
        F::DoubleExtension => "May deceive users about the actual file type.",
        F::DllOutsidePlugins => "DLLs outside Plugins/ are unusual and may indicate stealth.",
        F::ExcessiveDlls => "A high DLL count is atypical for VRChat avatars.",
        F::DllManyDependents => "This DLL is referenced by many assets, suggesting broad reach.",
        F::CsProcessStart => "Can launch arbitrary processes (cmd.exe, malware, etc.).",
        F::CsAssemblyLoadBytes => "Can load and execute arbitrary .NET bytecode at runtime.",
        F::CsFileWrite => "Can create, overwrite, or delete files — potential persistence.",
        F::CsBinaryFormatter => "Insecure deserializer — known RCE vector in .NET.",
        F::CsDllimportUnknown => "Calls into a native DLL; behaviour depends on the DLL contents.",
        F::CsShellStrings => "Shell command strings may indicate a dropper or reverse shell.",
        F::CsUrlUnknownDomain => "Downloads data from a non-whitelisted internet host.",
        F::CsIpHardcoded => "Hardcoded IP can be used to bypass DNS-based blocking.",
        F::CsUnicodeEscapes => "Obfuscation technique to hide strings from visual inspection.",
        F::CsReflectionEmit => "Generates code at runtime — very rare in legitimate VRChat assets.",
        F::CsHttpClient => "Contacting external servers is uncommon for most avatars.",
        F::CsUnsafeBlock => "Unsafe blocks can bypass .NET memory safety. Rare in VRChat content.",
        F::CsRegistryAccess => "Reading or writing the Windows Registry is suspicious.",
        F::CsEnvironmentAccess => "Reading environment variables can fingerprint the machine.",
        F::CsMarshalOps => "Marshal operations can interact with unmanaged memory.",
        F::CsBase64HighRatio => "Large base64 blocks often hide encoded executables.",
        F::CsXorDecryption => "Simple XOR decryption is a common malware deobfuscation pattern.",
        F::CsObfuscatedIdentifiers => "Short/single-char identifiers suggest automated obfuscation.",
        F::CsNoMeta => "C# script without a .meta file — may be injected.",
        F::PeInvalidHeader => "The PE header is malformed. Possibly a crafted binary.",
        F::PeParseError => "The PE/DLL file could not be parsed properly.",
        F::PeHighEntropySection => "High-entropy sections often contain packed or encrypted code.",
        F::PeUnnamedSection => "Unnamed sections may hide data from casual inspection.",
        F::PeWriteExecuteSection => "Writable+executable sections are dangerous.",
        F::PeInflatedSection => "Inflated sections may indicate packers or hidden payloads.",
        F::DllImportCreateprocess => "Can spawn child processes (process hollowing).",
        F::DllImportCreateremotethread => "Can inject code into another process.",
        F::DllImportSockets => "Socket API — network communication capability.",
        F::DllImportInternet => "WinInet/WinHTTP — HTTP communication from native code.",
        F::DllImportWriteProcessMem => "Can modify memory of another process.",
        F::DllImportVirtualAlloc => "Can allocate executable memory — shellcode staging.",
        F::DllImportLoadlibrary => "Can load arbitrary DLLs at runtime.",
        F::DllImportGetprocaddress => "Can resolve any function address dynamically.",
        F::DllImportFileOps => "File system operations from native code.",
        F::DllImportRegistry => "Registry access from native code.",
        F::DllImportCrypto => "Cryptographic APIs — may be used for ransomware or obfuscation.",
        F::DllImportSysinfo => "Gathers system information (hostname, etc.).",
        F::DllStringsSuspiciousPath => "Embedded suspicious file system path.",
        F::MagicMismatch => "File extension does not match its binary format — deliberate disguise.",
        F::MagicMismatchImage => "Image extension mismatch — likely an export mistake.",
        F::TextureHighEntropy => "Uncompressed texture with high entropy may hide embedded data.",
        F::AudioUnusualEntropy => "Audio file entropy outside expected range.",
        F::PolyglotFile => "File contains an embedded PE executable (polyglot attack).",
        F::MetaExternalRef => ".meta file references an external GUID outside this package.",
        F::MetaFutureTimestamp => ".meta timestamp in the future — possible tampering.",
        F::PrefabExcessiveGuids => "Excessive GUID references in a prefab.",
        F::PrefabInlineB64 => "Base64 content embedded in a prefab or ScriptableObject.",
        F::PrefabManyScripts => "Unusually high number of script references in a prefab.",
    }
}

// ─── Download helper ─────────────────────────────────────────────────────────

async fn download_and_verify(
    state: &AppState,
    req: &ScanRequest,
) -> Result<Vec<u8>, (StatusCode, Json<ErrorResponse>)> {
    let resp = state
        .http
        .get(&req.r2_url)
        .send()
        .await
        .map_err(|e| json_err(StatusCode::BAD_GATEWAY, format!("Download failed: {e}")))?;

    if !resp.status().is_success() {
        return Err(json_err(
            StatusCode::BAD_GATEWAY,
            format!("R2 returned HTTP {}", resp.status()),
        ));
    }

    // Check content length before downloading
    if let Some(len) = resp.content_length() {
        if len > state.max_download_bytes {
            return Err(json_err(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!(
                    "File too large: {} bytes exceeds limit of {} bytes",
                    len, state.max_download_bytes
                ),
            ));
        }
    }

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| json_err(StatusCode::BAD_GATEWAY, format!("Reading body failed: {e}")))?
        .to_vec();

    // Enforce size limit on downloaded bytes too (belt and suspenders)
    if bytes.len() as u64 > state.max_download_bytes {
        return Err(json_err(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "Downloaded file too large: {} bytes exceeds limit of {} bytes",
                bytes.len(),
                state.max_download_bytes
            ),
        ));
    }

    // Validate SHA-256 if provided
    if let Some(expected) = &req.expected_sha256 {
        use sha2::{Digest, Sha256};
        let actual = hex::encode(Sha256::digest(&bytes));
        if &actual != expected {
            return Err(json_err(
                StatusCode::BAD_REQUEST,
                format!("SHA-256 mismatch: expected={expected} actual={actual}"),
            ));
        }
    }

    Ok(bytes)
}

// ─── Filter findings by minimum severity ─────────────────────────────────────

fn filter_by_severity(findings: &mut Vec<crate::report::Finding>, min_severity: Severity) {
    findings.retain(|f| f.severity >= min_severity);
}

// ─── POST /scan ──────────────────────────────────────────────────────────────

async fn handle_scan(
    State(state): State<AppState>,
    Query(options): Query<ScanOptions>,
    Json(req): Json<ScanRequest>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let bytes = download_and_verify(&state, &req).await?;

    let format = options.format.as_deref().unwrap_or("json").to_lowercase();
    let verbose = options.verbose.unwrap_or(false);

    let min_severity: Option<Severity> = options
        .min_severity
        .as_deref()
        .and_then(parse_min_severity);

    // Run full pipeline to get context
    let (mut scan_report, analysis_context, _pkg_tree) =
        run_scan_bytes_full(&bytes, &req.file_id)
            .map_err(|e| json_err(StatusCode::INTERNAL_SERVER_ERROR, format!("Scan error: {e}")))?;

    // Filter by severity if requested
    if let Some(sev) = min_severity {
        filter_by_severity(&mut scan_report.findings, sev);
    }

    // Add verbose explanations if requested
    if verbose {
        for finding in &mut scan_report.findings {
            let explanation = human_explanation(&finding.id);
            if finding.context.is_none() {
                finding.context = Some(explanation.to_string());
            }
        }
    }

    // Dispatch by format
    if format == "txt" {
        let level = risk_level_from_str(&scan_report.risk.level);
        let txt = render_single_txt(&scan_report, level, false);
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(txt.into())
            .unwrap())
    } else {
        Ok(Json(ScanResponse {
            file_id: req.file_id,
            scan_result: scan_report,
            analysis_context,
            ok: true,
        })
        .into_response())
    }
}

// ─── POST /sanitize ──────────────────────────────────────────────────────────

async fn handle_sanitize(
    State(state): State<AppState>,
    Query(options): Query<ScanOptions>,
    Json(req): Json<ScanRequest>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let bytes = download_and_verify(&state, &req).await?;

    let min_severity: Severity = options
        .min_severity
        .as_deref()
        .and_then(parse_min_severity)
        .unwrap_or(Severity::High);

    let (cleaned_bytes, sanitize_report) =
        run_sanitize_bytes(&bytes, &req.file_id, min_severity)
            .map_err(|e| {
                json_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Sanitize error: {e}"),
                )
            })?;

    let report_json =
        serde_json::to_string(&sanitize_report).map_err(|e| {
            json_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Serialize error: {e}"),
            )
        })?;

    let filename = format!("{}-sanitized.unitypackage", req.file_id);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", filename),
        )
        .header("x-sanitize-report", report_json)
        .header("x-original-score", sanitize_report.original_score.to_string())
        .header(
            "x-residual-score",
            sanitize_report.residual_score.to_string(),
        )
        .body(cleaned_bytes.into())
        .unwrap())
}

// ─── POST /scan-batch ────────────────────────────────────────────────────────

async fn handle_scan_batch(
    State(state): State<AppState>,
    Query(options): Query<ScanOptions>,
    Json(req): Json<BatchScanRequest>,
) -> Result<Json<BatchScanResponse>, (StatusCode, Json<ErrorResponse>)> {
    if req.files.is_empty() {
        return Err(json_err(
            StatusCode::BAD_REQUEST,
            "No files provided in batch request",
        ));
    }

    let verbose = options.verbose.unwrap_or(false);
    let min_severity: Option<Severity> = options
        .min_severity
        .as_deref()
        .and_then(parse_min_severity);

    let mut results = Vec::with_capacity(req.files.len());

    for file_req in &req.files {
        let bytes = match download_and_verify(&state, file_req).await {
            Ok(b) => b,
            Err((_status, err)) => {
                // Return a synthetic error result for this file
                results.push(ScanResponse {
                    file_id: file_req.file_id.clone(),
                    scan_result: ScanReport::error_report(
                        &file_req.file_id,
                        &err.error,
                    ),
                    analysis_context: AnalysisContext::default(),
                    ok: false,
                });
                // Continue with remaining files
                continue;
            }
        };

        let (mut scan_report, analysis_context, _pkg_tree) =
            match run_scan_bytes_full(&bytes, &file_req.file_id) {
                Ok(r) => r,
                Err(e) => {
                    results.push(ScanResponse {
                        file_id: file_req.file_id.clone(),
                        scan_result: ScanReport::error_report(
                            &file_req.file_id,
                            &e.to_string(),
                        ),
                        analysis_context: AnalysisContext::default(),
                        ok: false,
                    });
                    continue;
                }
            };

        if let Some(ref sev) = min_severity {
            filter_by_severity(&mut scan_report.findings, *sev);
        }

        if verbose {
            for finding in &mut scan_report.findings {
                let explanation = human_explanation(&finding.id);
                if finding.context.is_none() {
                    finding.context = Some(explanation.to_string());
                }
            }
        }

        results.push(ScanResponse {
            file_id: file_req.file_id.clone(),
            scan_result: scan_report,
            analysis_context,
            ok: true,
        });
    }

    Ok(Json(BatchScanResponse {
        results,
        ok: true,
    }))
}
