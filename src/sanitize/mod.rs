//! Sanitize module: neutralises malicious entries in a `.unitypackage`.
//!
//! # Decision matrix
//! | Asset type              | Condition                                        | Action                    |
//! |-------------------------|--------------------------------------------------|---------------------------|
//! | `.cs` Script            | any finding >= `min_severity`                    | Comment out matched lines |
//! | `.dll` binary           | any finding >= `min_severity`                    | Remove GUID from TAR      |
//! | Texture / Audio         | `POLYGLOT_FILE` or `MAGIC_MISMATCH` + loader     | Remove GUID from TAR      |
//! | Texture / Audio         | `POLYGLOT_FILE` or `MAGIC_MISMATCH` (no loader)  | Skip (inert)              |
//! | Texture / Audio         | only entropy finding                             | Always keep               |
//! | Prefab with `PREFAB_INLINE_B64` >= `min_severity` | —                   | Remove GUID from TAR      |
//! | Package-level findings  | `EXCESSIVE_DLLS`, `CS_NO_META`, etc.             | Ignore (no specific file) |

pub mod rebuilder;
pub mod script_neutralizer;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::ingestion::extractor::AssetType;
use crate::pipeline::run_scan_full;
use crate::pipeline::run_scan_bytes_full;
use crate::report::finding::{FindingId, Severity};
use crate::sanitize::rebuilder::rebuild_unitypackage;
use crate::sanitize::script_neutralizer::neutralize_script;
use serde::Serialize;

// ─── Public report structs ────────────────────────────────────────────────────

/// A C# script whose dangerous lines were commented out (not deleted).
#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)]
pub struct NeutralizedScript {
    pub guid: String,
    pub original_path: String,
    /// 1-indexed line numbers that were commented out.
    pub commented_lines: Vec<u64>,
    pub finding_ids: Vec<FindingId>,
}

/// A package entry (DLL, asset, prefab) that was fully removed from the TAR.
#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)]
pub struct RemovedEntry {
    pub guid: String,
    pub original_path: String,
    pub finding_ids: Vec<FindingId>,
}

/// A suspicious asset that was intentionally kept (no loader script present).
#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)]
pub struct SkippedAsset {
    pub guid: String,
    pub original_path: String,
    /// Human-readable reason for keeping the asset.
    pub reason: &'static str,
}

/// Full result of a sanitization run.
#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub struct SanitizeReport {
    pub neutralized_scripts: Vec<NeutralizedScript>,
    pub removed_entries: Vec<RemovedEntry>,
    /// Suspicious assets that were kept because no loader script was detected.
    pub skipped_assets: Vec<SkippedAsset>,
    /// Number of entries that had no actionable findings.
    pub kept_entries: usize,
    pub original_score: u32,
    pub residual_score: u32,
    /// `None` in dry-run mode.
    pub output_path: Option<PathBuf>,
    pub dry_run: bool,
    /// Severity threshold used during this run.
    pub threshold: Severity,
}


// ─── Package-level finding IDs (no specific file to act on) ──────────────────

fn is_package_level(id: FindingId) -> bool {
    matches!(
        id,
        FindingId::ExcessiveDlls | FindingId::CsNoMeta | FindingId::DllManyDependents
    )
}

// ─── Main public function ─────────────────────────────────────────────────────

/// Sanitize a `.unitypackage` file.
///
/// - Parses and scans the package exactly once via [`run_scan_full`].
/// - Decides per-GUID what to do based on the decision matrix above.
/// - Writes the cleaned package to `output_path` unless `dry_run` is true.
///
/// The original file is **never modified**.
pub fn run_sanitize(
    input_path: &Path,
    output_path: &Path,
    min_severity: Severity,
    dry_run: bool,
) -> crate::utils::Result<SanitizeReport> {
    // ── Step 1: scan (single pass) ────────────────────────────────────────
    let (report, context, tree) = run_scan_full(input_path)?;
    let original_score = report.risk.score;

    // ── Step 2: group findings by location (original_path) ────────────────
    // location == original_path of the entry inside the package
    let mut findings_by_path: HashMap<String, Vec<&crate::report::finding::Finding>> =
        HashMap::new();
    for f in &report.findings {
        if !is_package_level(f.id) {
            findings_by_path
                .entry(f.location.clone())
                .or_default()
                .push(f);
        }
    }

    // ── Step 3: decision loop ─────────────────────────────────────────────
    let mut guids_to_remove: HashSet<String> = HashSet::new();
    let mut guid_script_patches: HashMap<String, Vec<u8>> = HashMap::new();

    let mut neutralized_scripts: Vec<NeutralizedScript> = Vec::new();
    let mut removed_entries: Vec<RemovedEntry> = Vec::new();
    let mut skipped_assets: Vec<SkippedAsset> = Vec::new();
    let mut kept_entries: usize = 0;

    for (guid, entry) in &tree.entries {
        let path = &entry.original_path;
        let relevant_findings: Vec<&crate::report::finding::Finding> = findings_by_path
            .get(path.as_str())
            .map(|v| {
                v.iter()
                    .copied()
                    .filter(|f| f.severity >= min_severity)
                    .collect()
            })
            .unwrap_or_default();

        if relevant_findings.is_empty() {
            kept_entries += 1;
            continue;
        }

        match &entry.asset_type {
            // ── C# scripts: comment out dangerous lines ───────────────────
            AssetType::Script => {
                let source = String::from_utf8_lossy(&entry.bytes).to_string();
                let all_lines: Vec<u64> = relevant_findings
                    .iter()
                    .flat_map(|f| f.line_numbers.iter().copied())
                    .collect();

                // Deduplicate and sort
                let mut unique_lines = all_lines.clone();
                unique_lines.sort_unstable();
                unique_lines.dedup();

                if !unique_lines.is_empty() {
                    let patched = neutralize_script(&source, &unique_lines);
                    guid_script_patches.insert(guid.clone(), patched.into_bytes());

                    neutralized_scripts.push(NeutralizedScript {
                        guid: guid.clone(),
                        original_path: path.clone(),
                        commented_lines: unique_lines,
                        finding_ids: relevant_findings.iter().map(|f| f.id).collect(),
                    });
                } else {
                    // No line numbers provided — remove the entire script entry
                    guids_to_remove.insert(guid.clone());
                    removed_entries.push(RemovedEntry {
                        guid: guid.clone(),
                        original_path: path.clone(),
                        finding_ids: relevant_findings.iter().map(|f| f.id).collect(),
                    });
                }
            }

            // ── DLL binaries: always remove if flagged ────────────────────
            AssetType::Dll => {
                guids_to_remove.insert(guid.clone());
                removed_entries.push(RemovedEntry {
                    guid: guid.clone(),
                    original_path: path.clone(),
                    finding_ids: relevant_findings.iter().map(|f| f.id).collect(),
                });
            }

            // ── Textures / Audio: only remove if polyglot + loader ────────
            AssetType::Texture | AssetType::Audio => {
                let has_polyglot_or_magic = relevant_findings.iter().any(|f| {
                    matches!(f.id, FindingId::PolyglotFile | FindingId::MagicMismatch)
                });

                if has_polyglot_or_magic && context.has_loader_script {
                    guids_to_remove.insert(guid.clone());
                    removed_entries.push(RemovedEntry {
                        guid: guid.clone(),
                        original_path: path.clone(),
                        finding_ids: relevant_findings.iter().map(|f| f.id).collect(),
                    });
                } else {
                    skipped_assets.push(SkippedAsset {
                        guid: guid.clone(),
                        original_path: path.clone(),
                        reason: "no loader script in package — payload is inert without a trigger",
                    });
                }
            }

            // ── Prefab / ScriptableObject: remove if PREFAB_INLINE_B64 ────
            AssetType::Prefab | AssetType::ScriptableObject => {
                let has_inline_b64 = relevant_findings
                    .iter()
                    .any(|f| f.id == FindingId::PrefabInlineB64);

                if has_inline_b64 {
                    guids_to_remove.insert(guid.clone());
                    removed_entries.push(RemovedEntry {
                        guid: guid.clone(),
                        original_path: path.clone(),
                        finding_ids: relevant_findings.iter().map(|f| f.id).collect(),
                    });
                } else {
                    kept_entries += 1;
                }
            }

            // ── Everything else: keep ─────────────────────────────────────
            AssetType::Other(ext) => {
                let ext_lower = ext.to_lowercase();
                let is_forbidden = crate::config::FORBIDDEN_EXTENSIONS
                    .contains(&ext_lower.as_str());

                if is_forbidden && !relevant_findings.is_empty() {
                    guids_to_remove.insert(guid.clone());
                    removed_entries.push(RemovedEntry {
                        guid: guid.clone(),
                        original_path: path.clone(),
                        finding_ids: relevant_findings.iter().map(|f| f.id).collect(),
                    });
                } else {
                    kept_entries += 1;
                }
            }

            // ── Everything else: keep ─────────────────────────────────────
            #[allow(unreachable_patterns)]
            _ => {
                kept_entries += 1;
            }
        }
    }

    // ── Step 4: compute residual score ─────────────────────────────────────
    let removed_paths: HashSet<&str> = removed_entries
        .iter()
        .map(|e| e.original_path.as_str())
        .collect();
    let neutralized_paths: HashSet<&str> = neutralized_scripts
        .iter()
        .map(|e| e.original_path.as_str())
        .collect();

    let residual_score: u32 = report
        .findings
        .iter()
        .filter(|f| {
            !removed_paths.contains(f.location.as_str())
                && !neutralized_paths.contains(f.location.as_str())
        })
        .map(|f| f.points)
        .sum();

    // ── Step 5: rebuild package (unless dry_run) ───────────────────────────
    let actual_output_path = if !dry_run {
        let original_bytes = std::fs::read(input_path)?;
        let cleaned = rebuild_unitypackage(&original_bytes, &guids_to_remove, &guid_script_patches)?;
        std::fs::write(output_path, &cleaned)?;
        Some(output_path.to_path_buf())
    } else {
        None
    };

    Ok(SanitizeReport {
        neutralized_scripts,
        removed_entries,
        skipped_assets,
        kept_entries,
        original_score,
        residual_score,
        output_path: actual_output_path,
        dry_run,
        threshold: min_severity,
    })
}

/// In-memory version of [`run_sanitize`] — no filesystem I/O.
///
/// Accepts raw bytes of a `.unitypackage`, scans and sanitizes entirely in memory,
/// and returns the cleaned package bytes along with a full [`SanitizeReport`].
pub fn run_sanitize_bytes(
    data: &[u8],
    file_id: &str,
    min_severity: Severity,
) -> crate::utils::Result<(Vec<u8>, SanitizeReport)> {
    // ── Step 1: scan (single pass, in-memory) ────────────────────────────
    let (report, context, tree) = run_scan_bytes_full(data, file_id)?;
    let original_score = report.risk.score;

    // ── Step 2: group findings by location ────────────────────────────────
    let mut findings_by_path: HashMap<String, Vec<&crate::report::finding::Finding>> =
        HashMap::new();
    for f in &report.findings {
        if !is_package_level(f.id) {
            findings_by_path
                .entry(f.location.clone())
                .or_default()
                .push(f);
        }
    }

    // ── Step 3: decision loop ─────────────────────────────────────────────
    let mut guids_to_remove: HashSet<String> = HashSet::new();
    let mut guid_script_patches: HashMap<String, Vec<u8>> = HashMap::new();

    let mut neutralized_scripts: Vec<NeutralizedScript> = Vec::new();
    let mut removed_entries: Vec<RemovedEntry> = Vec::new();
    let mut skipped_assets: Vec<SkippedAsset> = Vec::new();
    let mut kept_entries: usize = 0;

    for (guid, entry) in &tree.entries {
        let path = &entry.original_path;
        let relevant_findings: Vec<&crate::report::finding::Finding> = findings_by_path
            .get(path.as_str())
            .map(|v| {
                v.iter()
                    .copied()
                    .filter(|f| f.severity >= min_severity)
                    .collect()
            })
            .unwrap_or_default();

        if relevant_findings.is_empty() {
            kept_entries += 1;
            continue;
        }

        match &entry.asset_type {
            AssetType::Script => {
                let source = String::from_utf8_lossy(&entry.bytes).to_string();
                let all_lines: Vec<u64> = relevant_findings
                    .iter()
                    .flat_map(|f| f.line_numbers.iter().copied())
                    .collect();

                let mut unique_lines = all_lines.clone();
                unique_lines.sort_unstable();
                unique_lines.dedup();

                if !unique_lines.is_empty() {
                    let patched = neutralize_script(&source, &unique_lines);
                    guid_script_patches.insert(guid.clone(), patched.into_bytes());

                    neutralized_scripts.push(NeutralizedScript {
                        guid: guid.clone(),
                        original_path: path.clone(),
                        commented_lines: unique_lines,
                        finding_ids: relevant_findings.iter().map(|f| f.id).collect(),
                    });
                } else {
                    guids_to_remove.insert(guid.clone());
                    removed_entries.push(RemovedEntry {
                        guid: guid.clone(),
                        original_path: path.clone(),
                        finding_ids: relevant_findings.iter().map(|f| f.id).collect(),
                    });
                }
            }

            AssetType::Dll => {
                guids_to_remove.insert(guid.clone());
                removed_entries.push(RemovedEntry {
                    guid: guid.clone(),
                    original_path: path.clone(),
                    finding_ids: relevant_findings.iter().map(|f| f.id).collect(),
                });
            }

            AssetType::Texture | AssetType::Audio => {
                let has_polyglot_or_magic = relevant_findings.iter().any(|f| {
                    matches!(f.id, FindingId::PolyglotFile | FindingId::MagicMismatch)
                });

                if has_polyglot_or_magic && context.has_loader_script {
                    guids_to_remove.insert(guid.clone());
                    removed_entries.push(RemovedEntry {
                        guid: guid.clone(),
                        original_path: path.clone(),
                        finding_ids: relevant_findings.iter().map(|f| f.id).collect(),
                    });
                } else {
                    skipped_assets.push(SkippedAsset {
                        guid: guid.clone(),
                        original_path: path.clone(),
                        reason: "no loader script in package — payload is inert without a trigger",
                    });
                }
            }

            AssetType::Prefab | AssetType::ScriptableObject => {
                let has_inline_b64 = relevant_findings
                    .iter()
                    .any(|f| f.id == FindingId::PrefabInlineB64);

                if has_inline_b64 {
                    guids_to_remove.insert(guid.clone());
                    removed_entries.push(RemovedEntry {
                        guid: guid.clone(),
                        original_path: path.clone(),
                        finding_ids: relevant_findings.iter().map(|f| f.id).collect(),
                    });
                } else {
                    kept_entries += 1;
                }
            }

            AssetType::Other(ext) => {
                let ext_lower = ext.to_lowercase();
                let is_forbidden = crate::config::FORBIDDEN_EXTENSIONS
                    .contains(&ext_lower.as_str());

                if is_forbidden && !relevant_findings.is_empty() {
                    guids_to_remove.insert(guid.clone());
                    removed_entries.push(RemovedEntry {
                        guid: guid.clone(),
                        original_path: path.clone(),
                        finding_ids: relevant_findings.iter().map(|f| f.id).collect(),
                    });
                } else {
                    kept_entries += 1;
                }
            }

            #[allow(unreachable_patterns)]
            _ => {
                kept_entries += 1;
            }
        }
    }

    // ── Step 4: compute residual score ─────────────────────────────────────
    let removed_paths: HashSet<&str> = removed_entries
        .iter()
        .map(|e| e.original_path.as_str())
        .collect();
    let neutralized_paths: HashSet<&str> = neutralized_scripts
        .iter()
        .map(|e| e.original_path.as_str())
        .collect();

    let residual_score: u32 = report
        .findings
        .iter()
        .filter(|f| {
            !removed_paths.contains(f.location.as_str())
                && !neutralized_paths.contains(f.location.as_str())
        })
        .map(|f| f.points)
        .sum();

    // ── Step 5: rebuild package in-memory ──────────────────────────────────
    let cleaned = rebuild_unitypackage(data, &guids_to_remove, &guid_script_patches)?;

    Ok((
        cleaned,
        SanitizeReport {
            neutralized_scripts,
            removed_entries,
            skipped_assets,
            kept_entries,
            original_score,
            residual_score,
            output_path: None,
            dry_run: false,
            threshold: min_severity,
        },
    ))
}
