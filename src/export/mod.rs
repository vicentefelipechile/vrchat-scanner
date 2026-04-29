//! Export module: extracts a `.unitypackage` to a folder or ZIP file,
//! preserving Unity's original asset paths (e.g. `Assets/Scripts/MyScript.cs`).
//!
//! # Usage
//! ```text
//! vrcstorage-scanner export <FILE> [--output folder|zip] [--out-dir <DIR>]
//! ```

use std::path::{Path, PathBuf};

use crate::ingestion::extractor;
use crate::ingestion::type_detection::detect_type;
use crate::ingestion::file_record::FileType;

// ─── Public types ────────────────────────────────────────────────────────────

/// Output format for the exported content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportType {
    Folder,
    Zip,
}

/// Summary of a completed export.
#[derive(Debug)]
pub struct ExportReport {
    pub input_path: PathBuf,
    pub output_path: PathBuf,
    pub output_type: ExportType,
    pub skip_meta: bool,
    pub total_entries: usize,
    pub exported_assets: usize,
    pub exported_meta: usize,
    pub skipped_empty: usize,
    pub skipped_unsafe: usize,
    pub warnings: Vec<String>,
}

// ─── Public entry point ──────────────────────────────────────────────────────

/// Export a `.unitypackage` file to a folder or ZIP.
///
/// # Arguments
///
/// * `input_path` — Path to the `.unitypackage` file.
/// * `output_type` — `"folder"` or `"zip"`.
/// * `out_dir` — Optional output directory. Defaults to `<input-stem>-exported/`
///   next to the input file. When `output_type` is `"zip"`, a `.zip` extension is
///   appended to this path.
pub fn run_export(
    input_path: &Path,
    output_type: &str,
    out_dir: Option<&Path>,
    skip_meta: bool,
) -> crate::utils::Result<ExportReport> {
    let data = std::fs::read(input_path)?;
    let file_type = detect_type(&data, input_path);

    if file_type != FileType::UnityPackage && file_type != FileType::ZipArchive {
        return Err(crate::utils::ScannerError::ExportError(format!(
            "File is not a UnityPackage or ZIP archive (detected: {:?})",
            file_type
        )));
    }

    let tree = extractor::extract(&data, &file_type)?;

    let export_type = match output_type {
        "zip" => ExportType::Zip,
        _ => ExportType::Folder,
    };

    let total_entries = tree.entries.len();

    let output_path = if let Some(dir) = out_dir {
        match export_type {
            ExportType::Folder => dir.to_path_buf(),
            ExportType::Zip => {
                if dir.extension().map(|e| e.eq_ignore_ascii_case("zip")).unwrap_or(false) {
                    dir.to_path_buf()
                } else {
                    dir.with_extension("zip")
                }
            }
        }
    } else {
        let stem = input_path.file_stem().unwrap_or_default().to_string_lossy();
        match export_type {
            ExportType::Folder => input_path.with_file_name(format!("{stem}-exported")),
            ExportType::Zip => input_path.with_file_name(format!("{stem}-exported.zip")),
        }
    };

    let (exported_assets, exported_meta, skipped_empty, skipped_unsafe, warnings) = match export_type {
        ExportType::Folder => export_to_folder(&tree, &output_path, skip_meta)?,
        ExportType::Zip => export_to_zip(&tree, &output_path, skip_meta)?,
    };

    Ok(ExportReport {
        input_path: input_path.to_path_buf(),
        output_path,
        output_type: export_type,
        skip_meta,
        total_entries,
        exported_assets,
        exported_meta,
        skipped_empty,
        skipped_unsafe,
        warnings,
    })
}

// ─── Folder export ───────────────────────────────────────────────────────────

fn export_to_folder(
    tree: &extractor::PackageTree,
    out_dir: &Path,
    skip_meta: bool,
) -> crate::utils::Result<(usize, usize, usize, usize, Vec<String>)> {
    std::fs::create_dir_all(out_dir)?;

    let mut assets = 0usize;
    let mut metas = 0usize;
    let mut skipped_empty = 0usize;
    let mut skipped_unsafe = 0usize;
    let mut warnings = Vec::new();

    for entry in tree.all_entries() {
        if entry.bytes.is_empty() {
            skipped_empty += 1;
            continue;
        }

        let safe_path = match sanitize_export_path(&entry.original_path) {
            Some(p) => p,
            None => {
                warnings.push(format!(
                    "Skipped entry with unsafe path: {}",
                    entry.original_path
                ));
                skipped_unsafe += 1;
                continue;
            }
        };

        let full_path = out_dir.join(&safe_path);
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&full_path, &entry.bytes)?;
        assets += 1;

        if !skip_meta {
            if let Some(ref meta) = entry.meta_content {
                let meta_ext = format!(
                    "{}.meta",
                    full_path
                        .extension()
                        .unwrap_or_default()
                        .to_string_lossy()
                );
                let meta_path = full_path.with_extension(meta_ext);
                std::fs::write(&meta_path, meta.as_bytes())?;
                metas += 1;
            }
        }
    }

    Ok((assets, metas, skipped_empty, skipped_unsafe, warnings))
}

// ─── ZIP export ──────────────────────────────────────────────────────────────

fn export_to_zip(
    tree: &extractor::PackageTree,
    zip_path: &Path,
    skip_meta: bool,
) -> crate::utils::Result<(usize, usize, usize, usize, Vec<String>)> {
    use std::io::Write;
    use zip::write::FileOptions;
    use zip::CompressionMethod;
    use zip::ZipWriter;

    if let Some(parent) = zip_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let file = std::fs::File::create(zip_path)?;
    let mut zip = ZipWriter::new(file);

    let options = FileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o644);

    let mut assets = 0usize;
    let mut metas = 0usize;
    let mut skipped_empty = 0usize;
    let mut skipped_unsafe = 0usize;
    let mut warnings = Vec::new();

    for entry in tree.all_entries() {
        if entry.bytes.is_empty() {
            skipped_empty += 1;
            continue;
        }

        // ZIP paths must use forward slashes
        let safe_path = match sanitize_export_path_zip(&entry.original_path) {
            Some(p) => p,
            None => {
                warnings.push(format!(
                    "Skipped entry with unsafe path: {}",
                    entry.original_path
                ));
                skipped_unsafe += 1;
                continue;
            }
        };

        zip.start_file(&safe_path, options)?;
        zip.write_all(&entry.bytes)?;
        assets += 1;

        if !skip_meta {
            if let Some(ref meta) = entry.meta_content {
                let meta_path = format!("{safe_path}.meta");
                zip.start_file(&meta_path, options)?;
                zip.write_all(meta.as_bytes())?;
                metas += 1;
            }
        }
    }

    zip.finish()?;
    Ok((assets, metas, skipped_empty, skipped_unsafe, warnings))
}

// ─── Path sanitization ───────────────────────────────────────────────────────

/// Sanitize a path from inside a package for export to the filesystem.
///
/// Rejects paths containing `..` segments (path traversal) and returns a
/// platform-native path.
fn sanitize_export_path(raw: &str) -> Option<PathBuf> {
    // Strip leading slashes / backslashes
    let trimmed = raw.trim_start_matches('/').trim_start_matches('\\');

    if trimmed.is_empty() {
        return None;
    }

    let mut out = PathBuf::new();
    for segment in trimmed.split(&['/', '\\']) {
        let seg = segment.trim();
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            return None;
        }
        out.push(seg);
    }

    Some(out)
}

/// Sanitize a path from inside a package for inclusion in a ZIP archive.
///
/// Same semantics as [`sanitize_export_path`] but returns a forward-slash
/// string (ZIP standard).
fn sanitize_export_path_zip(raw: &str) -> Option<String> {
    let trimmed = raw.trim_start_matches('/').trim_start_matches('\\');

    if trimmed.is_empty() {
        return None;
    }

    let mut parts = Vec::new();
    for segment in trimmed.split(&['/', '\\']) {
        let seg = segment.trim();
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            return None;
        }
        parts.push(seg);
    }

    if parts.is_empty() {
        return None;
    }

    Some(parts.join("/"))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_normal_path() {
        let result = sanitize_export_path("Assets/Scripts/MyScript.cs");
        assert_eq!(
            result,
            Some(PathBuf::from("Assets").join("Scripts").join("MyScript.cs"))
        );
    }

    #[test]
    fn sanitize_leading_slash() {
        let result = sanitize_export_path("/Assets/Scripts/MyScript.cs");
        assert_eq!(
            result,
            Some(PathBuf::from("Assets").join("Scripts").join("MyScript.cs"))
        );
    }

    #[test]
    fn sanitize_rejects_dot_dot() {
        assert_eq!(sanitize_export_path("../etc/passwd"), None);
        assert_eq!(sanitize_export_path("Assets/../../etc/passwd"), None);
        assert_eq!(sanitize_export_path("Assets/Subdir/../passwd"), None);
    }

    #[test]
    fn sanitize_allows_single_dot() {
        let result = sanitize_export_path("Assets/./Scripts/MyScript.cs");
        assert_eq!(
            result,
            Some(PathBuf::from("Assets").join("Scripts").join("MyScript.cs"))
        );
    }

    #[test]
    fn sanitize_empty() {
        assert_eq!(sanitize_export_path(""), None);
        assert_eq!(sanitize_export_path("/"), None);
    }

    #[test]
    fn sanitize_zip_normal_path() {
        let result = sanitize_export_path_zip("Assets/Scripts/MyScript.cs");
        assert_eq!(result, Some("Assets/Scripts/MyScript.cs".to_string()));
    }

    #[test]
    fn sanitize_zip_rejects_dot_dot() {
        assert_eq!(sanitize_export_path_zip("../etc/passwd"), None);
        assert_eq!(sanitize_export_path_zip("Assets/../../etc/passwd"), None);
    }

    #[test]
    fn sanitize_zip_leading_slash() {
        let result = sanitize_export_path_zip("/Assets/Scripts/MyScript.cs");
        assert_eq!(result, Some("Assets/Scripts/MyScript.cs".to_string()));
    }

    #[test]
    fn sanitize_zip_backslash_to_forward() {
        let result = sanitize_export_path_zip("Assets\\Plugins\\MyLib.dll");
        assert_eq!(result, Some("Assets/Plugins/MyLib.dll".to_string()));
    }
}
