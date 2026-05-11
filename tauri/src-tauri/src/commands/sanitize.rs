use serde::{Deserialize, Serialize};
use vrcstorage_scanner::report::finding::Severity;
use vrcstorage_scanner::sanitize::run_sanitize;

/// Serializable summary returned to the frontend after sanitize.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizeResult {
    pub neutralized_count: usize,
    pub removed_count: usize,
    pub skipped_count: usize,
    pub kept_count: usize,
    pub original_score: u32,
    pub residual_score: u32,
    pub output_path: Option<String>,
    pub dry_run: bool,
    pub threshold: String,
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high"     => Severity::High,
        "low"      => Severity::Low,
        _          => Severity::Medium,
    }
}

/// Sanitize a `.unitypackage` file.
///
/// `min_severity`: "low" | "medium" | "high" | "critical"
/// `dry_run`: if true, no file is written
#[tauri::command]
pub async fn sanitize_file(
    path: String,
    output_path: String,
    min_severity: String,
    dry_run: bool,
) -> Result<SanitizeResult, String> {
    tokio::task::spawn_blocking(move || {
        let sev = parse_severity(&min_severity);
        let report = run_sanitize(
            std::path::Path::new(&path),
            std::path::Path::new(&output_path),
            sev,
            dry_run,
        )
        .map_err(|e| e.to_string())?;

        Ok(SanitizeResult {
            neutralized_count: report.neutralized_scripts.len(),
            removed_count: report.removed_entries.len(),
            skipped_count: report.skipped_assets.len(),
            kept_count: report.kept_entries,
            original_score: report.original_score,
            residual_score: report.residual_score,
            output_path: report.output_path.map(|p| p.to_string_lossy().to_string()),
            dry_run: report.dry_run,
            threshold: format!("{:?}", report.threshold),
        })
    })
    .await
    .map_err(|e| e.to_string())?
}
