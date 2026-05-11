use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use tauri::ipc::Channel;
use vrcstorage_scanner::report::json_reporter::ScanReport;


// ─── Progress / result types ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub path: String,
    pub status: String, // "scanning" | "done" | "error"
    pub result: Option<ScanReport>,
    pub error: Option<String>,
    pub index: usize,
    pub total: usize,
}

// ─── Commands ─────────────────────────────────────────────────────────────────

/// Scan a single file and stream progress via a Channel.
#[tauri::command]
pub async fn scan_file(
    path: String,
    index: usize,
    total: usize,
    on_progress: Channel<ScanProgress>,
) -> Result<ScanReport, String> {
    let path_clone = path.clone();
    on_progress
        .send(ScanProgress {
            path: path.clone(),
            status: "scanning".into(),
            result: None,
            error: None,
            index,
            total,
        })
        .ok();

    let report = tokio::task::spawn_blocking(move || {
        vrcstorage_scanner::pipeline::run_scan(std::path::Path::new(&path_clone))
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;

    on_progress
        .send(ScanProgress {
            path: path.clone(),
            status: "done".into(),
            result: Some(report.clone()),
            error: None,
            index,
            total,
        })
        .ok();

    Ok(report)
}

/// Resolve a list of dropped paths (files and/or folders) into a deduplicated
/// flat list of scannable file paths.  Folders are walked recursively for
/// `.unitypackage` files; individual files are included as-is.
#[tauri::command]
pub async fn collect_packages(paths: Vec<String>) -> Result<Vec<String>, String> {
    tokio::task::spawn_blocking(move || {
        let mut results: Vec<String> = Vec::new();
        let mut seen: HashSet<PathBuf> = HashSet::new();

        for raw in &paths {
            let p = Path::new(raw);
            if !p.exists() {
                continue;
            }
            if p.is_file() {
                let canonical = canonicalize_clean(p);
                if seen.insert(canonical.clone()) {
                    results.push(canonical.to_string_lossy().to_string());
                }
            } else if p.is_dir() {
                collect_from_dir(p, &mut results, &mut seen);
            }
        }
        results
    })
    .await
    .map_err(|e| e.to_string())
}

/// Write a report (TXT or JSON string) to a file on disk.
#[tauri::command]
pub async fn save_report(content: String, path: String) -> Result<(), String> {
    tokio::task::spawn_blocking(move || std::fs::write(&path, content))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn generate_txt_report(report: ScanReport) -> Result<String, String> {
    let level = match report.risk.level.as_str() {
        "CLEAN" => vrcstorage_scanner::scoring::RiskLevel::Clean,
        "LOW" => vrcstorage_scanner::scoring::RiskLevel::Low,
        "MEDIUM" => vrcstorage_scanner::scoring::RiskLevel::Medium,
        "HIGH" => vrcstorage_scanner::scoring::RiskLevel::High,
        "CRITICAL" => vrcstorage_scanner::scoring::RiskLevel::Critical,
        _ => vrcstorage_scanner::scoring::RiskLevel::Clean,
    };
    Ok(vrcstorage_scanner::report::txt_reporter::render_single_txt(&report, level, false))
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn canonicalize_clean(path: &Path) -> PathBuf {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    #[cfg(target_os = "windows")]
    {
        let s = canonical.to_string_lossy();
        if let Some(stripped) = s.strip_prefix(r"\\?\") {
            return PathBuf::from(stripped);
        }
    }
    canonical
}

fn collect_from_dir(dir: &Path, results: &mut Vec<String>, seen: &mut HashSet<PathBuf>) {
    let read_dir = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return,
    };
    let mut entries: Vec<_> = read_dir.flatten().collect();
    entries.sort_by_key(|e| e.path());
    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            collect_from_dir(&path, results, seen);
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("unitypackage"))
            .unwrap_or(false)
        {
            let canonical = canonicalize_clean(&path);
            if seen.insert(canonical.clone()) {
                results.push(canonical.to_string_lossy().to_string());
            }
        }
    }
}
