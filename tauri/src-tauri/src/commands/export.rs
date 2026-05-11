use serde::{Deserialize, Serialize};
use vrcstorage_scanner::export::run_export;

/// Serializable export result for the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportResult {
    pub output_path: String,
    pub output_type: String,
    pub skip_meta: bool,
    pub total_entries: usize,
    pub exported_assets: usize,
    pub exported_meta: usize,
    pub skipped_empty: usize,
    pub skipped_unsafe: usize,
    pub warnings: Vec<String>,
}

/// Export a `.unitypackage` to a folder or ZIP file.
///
/// `output_type`: "folder" | "zip"
/// `out_dir`: target path (folder path or zip path)
/// `skip_meta`: if true, `.meta` files are omitted
#[tauri::command]
pub async fn export_file(
    path: String,
    output_type: String,
    out_dir: String,
    skip_meta: bool,
) -> Result<ExportResult, String> {
    tokio::task::spawn_blocking(move || {
        let report = run_export(
            std::path::Path::new(&path),
            &output_type,
            Some(std::path::Path::new(&out_dir)),
            skip_meta,
        )
        .map_err(|e| e.to_string())?;

        Ok(ExportResult {
            output_path: report.output_path.to_string_lossy().to_string(),
            output_type: match report.output_type {
                vrcstorage_scanner::export::ExportType::Folder => "folder".to_string(),
                vrcstorage_scanner::export::ExportType::Zip => "zip".to_string(),
            },
            skip_meta: report.skip_meta,
            total_entries: report.total_entries,
            exported_assets: report.exported_assets,
            exported_meta: report.exported_meta,
            skipped_empty: report.skipped_empty,
            skipped_unsafe: report.skipped_unsafe,
            warnings: report.warnings,
        })
    })
    .await
    .map_err(|e| e.to_string())?
}
