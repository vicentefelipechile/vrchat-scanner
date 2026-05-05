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
    pub url: String,
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
        .route("/gui", get(handle_gui))
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
        F::AudioTrailingData => "Extra bytes found after all valid audio chunks — possible hidden payload.",
        F::AudioSuspiciousChunk => "Unknown RIFF chunk with substantial payload — possible steganography.",
        F::AudioMalformedHeader => "WAV/AIFF header is structurally invalid — may be crafted to bypass parsers.",
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
        .get(&req.url)
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

// ─── GET /gui ─────────────────────────────────────────────────────────────────

async fn handle_gui() -> Html<&'static str> {
    Html(GUI_HTML)
}

const GUI_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>vrcstorage-scanner · Console</title>
<style>
  body { font-family: monospace; margin: 0 }
  .layout { display: flex; height: 100vh }
  .sidebar { width: 200px; border-right: 1px solid #ccc; padding: 12px; overflow-y: auto }
  .sidebar a { display: block; padding: 4px 0; cursor: pointer; text-decoration: none }
  .sidebar a:hover { text-decoration: underline }
  .main { flex: 1; padding: 16px; overflow-y: auto; display: flex; flex-direction: column }
  .panel { display: none; flex: 1; flex-direction: column }
  .panel.active { display: flex }
  .field { margin-bottom: 10px }
  .field label { display: block; font-weight: bold; margin-bottom: 2px }
  .field input, .field select, .field textarea { width: 100%; max-width: 500px; padding: 4px; font-family: monospace }
  .field textarea { height: 120px }
  .row { margin-bottom: 12px }
  input[type=submit], button { padding: 6px 16px; font-family: monospace; cursor: pointer }
  h2 { margin-top: 0 }
  pre { border: 1px solid #ccc; padding: 12px; flex: 1; overflow: auto; white-space: pre-wrap; word-break: break-all; margin: 0; background: #fafafa }
  .status { font-weight: bold }
</style>
</head>
<body>
<div class="layout">
<div class="sidebar">
  <b>Endpoints</b><br><br>
  <a onclick="showPanel('scan')" id="nav-scan">POST /scan</a>
  <a onclick="showPanel('sanitize')" id="nav-sanitize">POST /sanitize</a>
  <a onclick="showPanel('batch')" id="nav-batch">POST /scan-batch</a>
  <a onclick="checkHealth()" id="nav-health">GET /health</a>
</div>
<div class="main">

  <!-- ── /scan ── -->
  <div id="panel-scan" class="panel active">
    <h2>POST /scan</h2>
    <form onsubmit="return false">
      <div class="field"><label>R2 URL</label><input id="scan-url"></div>
      <div class="field"><label>File ID</label><input id="scan-fileid"></div>
      <div class="field"><label>Expected SHA-256</label><input id="scan-sha"></div>
      <div class="field"><label>Format</label>
        <select id="scan-fmt"><option value="json">json</option><option value="txt">txt</option></select>
      </div>
      <div class="field"><label>Min Severity</label>
        <select id="scan-minsev">
          <option value="">(all)</option><option value="low">low</option><option value="medium">medium</option><option value="high" selected>high</option><option value="critical">critical</option>
        </select>
      </div>
      <div class="field"><label><input type="checkbox" id="scan-verbose"> Verbose</label></div>
      <div class="row"><button onclick="doScan()">Scan</button></div>
    </form>
    <span class="status" id="scan-status"></span>
    <pre id="scan-result">Click Scan to send request.</pre>
  </div>

  <!-- ── /sanitize ── -->
  <div id="panel-sanitize" class="panel">
    <h2>POST /sanitize</h2>
    <form onsubmit="return false">
      <div class="field"><label>R2 URL</label><input id="san-url"></div>
      <div class="field"><label>File ID</label><input id="san-fileid"></div>
      <div class="field"><label>Expected SHA-256</label><input id="san-sha"></div>
      <div class="field"><label>Min Severity</label>
        <select id="san-minsev">
          <option value="low">low</option><option value="medium">medium</option><option value="high" selected>high</option><option value="critical">critical</option>
        </select>
      </div>
      <div class="row"><button onclick="doSanitize()">Sanitize</button></div>
    </form>
    <span class="status" id="san-status"></span>
    <pre id="san-result">Click Sanitize. Cleaned .unitypackage will download automatically.</pre>
  </div>

  <!-- ── /scan-batch ── -->
  <div id="panel-batch" class="panel">
    <h2>POST /scan-batch</h2>
    <form onsubmit="return false">
      <div class="field"><label>Files (JSON array)</label>
        <textarea id="batch-json">[
  {"url": "https://...", "file_id": "file-1"},
  {"url": "https://...", "file_id": "file-2"}
]</textarea>
      </div>
      <div class="field"><label>Min Severity</label>
        <select id="batch-minsev">
          <option value="">(all)</option><option value="low">low</option><option value="medium">medium</option><option value="high">high</option><option value="critical">critical</option>
        </select>
      </div>
      <div class="field"><label><input type="checkbox" id="batch-verbose"> Verbose</label></div>
      <div class="row"><button onclick="doBatch()">Scan Batch</button></div>
    </form>
    <span class="status" id="batch-status"></span>
    <pre id="batch-result">Click Scan Batch to send request.</pre>
  </div>

</div>
</div>

<script>
function _(id){ return document.getElementById(id) }

function showPanel(name) {
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  _('panel-'+name).classList.add('active');
}

function setStatus(id, ok, text) {
  var el = _(id);
  el.textContent = text||(ok?'200 OK':'ERROR');
  el.style.color = ok?'green':'red';
}

function setResult(id, text) { var el = _(id); el.textContent = text }

async function doScan() {
  var url = _('scan-url').value.trim();
  var fid = _('scan-fileid').value.trim();
  if(!url||!fid){ alert('R2 URL and File ID required'); return }
  var sha = _('scan-sha').value.trim();
  var fmt = _('scan-fmt').value;
  var sev = _('scan-minsev').value;
  var v = _('scan-verbose').checked;
  var p = new URLSearchParams(); p.set('format',fmt); if(v)p.set('verbose','true'); if(sev)p.set('min_severity',sev);
  var b = {url:url,file_id:fid}; if(sha)b.expected_sha256=sha;
  setResult('scan-result','Scanning...'); setStatus('scan-status',0,'pending');
  try {
    var r = await fetch('/scan?'+p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});
    var t = await r.text();
    setStatus('scan-status',r.ok,r.status+' '+r.statusText);
    setResult('scan-result',t);
  } catch(e) { setStatus('scan-status',0,'NETWORK ERROR'); setResult('scan-result','Error: '+e.message) }
}

async function doSanitize() {
  var url = _('san-url').value.trim();
  var fid = _('san-fileid').value.trim();
  if(!url||!fid){ alert('R2 URL and File ID required'); return }
  var sha = _('san-sha').value.trim();
  var sev = _('san-minsev').value;
  var p = new URLSearchParams(); if(sev)p.set('min_severity',sev);
  var b = {url:url,file_id:fid}; if(sha)b.expected_sha256=sha;
  setResult('san-result','Sanitizing...'); setStatus('san-status',0,'pending');
  try {
    var r = await fetch('/sanitize?'+p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});
    var rep = r.headers.get('x-sanitize-report');
    var orig = r.headers.get('x-original-score');
    var resid = r.headers.get('x-residual-score');
    var info = r.status+' '+r.statusText+'\n\n';
    info += 'X-Original-Score: '+orig+'\nX-Residual-Score: '+resid+'\n\n';
    if(rep){ try{info += JSON.stringify(JSON.parse(rep),null,2)}catch(e2){info+=rep} }
    setStatus('san-status',r.ok,r.ok?'200 OK':r.status);
    setResult('san-result',info);
    if(r.ok && (r.headers.get('content-type')||'').includes('octet-stream')){
      var blob = await r.blob();
      var a = document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=fid+'-sanitized.unitypackage'; a.click();
    }
  } catch(e) { setStatus('san-status',0,'NETWORK ERROR'); setResult('san-result','Error: '+e.message) }
}

async function doBatch() {
  var raw = _('batch-json').value.trim();
  var sev = _('batch-minsev').value;
  var v = _('batch-verbose').checked;
  var files; try{files=JSON.parse(raw)}catch(e){alert('Invalid JSON');return}
  if(!Array.isArray(files)||!files.length){alert('Files array required');return}
  var p = new URLSearchParams(); if(v)p.set('verbose','true'); if(sev)p.set('min_severity',sev);
  setResult('batch-result','Scanning '+files.length+' files...'); setStatus('batch-status',0,'pending');
  try {
    var r = await fetch('/scan-batch?'+p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({files:files})});
    var t = await r.text();
    setStatus('batch-status',r.ok,r.status+' '+r.statusText);
    setResult('batch-result',t);
  } catch(e) { setStatus('batch-status',0,'NETWORK ERROR'); setResult('batch-result','Error: '+e.message) }
}

async function checkHealth() {
  showPanel('scan');
  setResult('scan-result','Checking /health ...'); setStatus('scan-status',0,'pending');
  try {
    var r = await fetch('/health');
    setResult('scan-result',await r.text());
    setStatus('scan-status',r.ok,r.ok?'200 UP':r.status);
  } catch(e) { setResult('scan-result','Error: '+e.message); setStatus('scan-status',0,'DOWN') }
}
</script>
</body>
</html>"##;
