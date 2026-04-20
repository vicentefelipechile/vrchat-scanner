pub mod assets;
pub mod dll;
pub mod metadata;
pub mod scripts;

use rayon::prelude::*;

use crate::ingestion::{AssetType, PackageTree};
use crate::report::{AssetCounts, Finding, FindingId, Severity};
use crate::scoring::context::AnalysisContext;
use crate::utils::patterns::PATH_TRAVERSAL;
use crate::config::*;

/// Run all analysis stages in parallel over the extracted package tree.
/// Returns a flat list of all findings and an asset count summary.
pub fn run_all_analyses(tree: &PackageTree) -> (Vec<Finding>, AssetCounts, AnalysisContext) {
    let entries: Vec<_> = tree.all_entries().collect();

    // Count DLL entries for "excessive DLLs" check
    let dll_count = entries.iter().filter(|e| e.asset_type == AssetType::Dll).count();
    let script_count = entries.iter().filter(|e| e.asset_type == AssetType::Script).count();
    let texture_count = entries.iter().filter(|e| e.asset_type == AssetType::Texture).count();
    let prefab_count = entries.iter().filter(|e| e.asset_type == AssetType::Prefab).count();
    let audio_count  = entries.iter().filter(|e| e.asset_type == AssetType::Audio).count();

    let counts = AssetCounts {
        total: entries.len(),
        dlls: dll_count,
        scripts: script_count,
        textures: texture_count,
        prefabs: prefab_count,
        audio: audio_count,
        other: entries.len() - dll_count - script_count - texture_count - prefab_count - audio_count,
    };

    // Run analysis in parallel across all entries using rayon
    let all_findings: Vec<Vec<Finding>> = entries
        .par_iter()
        .map(|entry| {
            let mut findings = Vec::new();
            let loc = &entry.original_path;

            // Stage 1 structural checks
            if PATH_TRAVERSAL.is_match(loc) {
                findings.push(Finding::new(
                    FindingId::PathTraversal,
                    Severity::Critical,
                    PTS_PATH_TRAVERSAL,
                    loc,
                    "Path traversal (../ or ..\\) detected in asset path",
                ));
            }

            // Check for forbidden extensions
            let ext_lower = std::path::Path::new(loc)
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.to_lowercase())
                .unwrap_or_default();

            if FORBIDDEN_EXTENSIONS.contains(&ext_lower.as_str()) {
                findings.push(Finding::new(
                    FindingId::ForbiddenExtension,
                    Severity::Critical,
                    PTS_FORBIDDEN_EXTENSION,
                    loc,
                    format!("Forbidden file type (.{}) inside the package", ext_lower),
                ));
            }

            // Double extension check (e.g. "texture.png.dll")
            let filename = std::path::Path::new(loc)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            let dot_count = filename.matches('.').count();
            if dot_count >= 2 && (filename.ends_with(".dll") || filename.ends_with(".exe")) {
                findings.push(Finding::new(
                    FindingId::DoubleExtension,
                    Severity::High,
                    PTS_DOUBLE_EXTENSION,
                    loc,
                    "Double extension detected (e.g. file.png.dll)",
                ));
            }

            // DLL outside Plugins folder
            if entry.asset_type == AssetType::Dll && !loc.to_lowercase().contains("plugins") {
                findings.push(Finding::new(
                    FindingId::DllOutsidePlugins,
                    Severity::Medium,
                    PTS_DLL_OUTSIDE_PLUGINS,
                    loc,
                    "DLL found outside Assets/Plugins/ directory",
                ));
            }

            // Stage-specific analysis
            match &entry.asset_type {
                AssetType::Dll => {
                    findings.extend(dll::analyze_dll(&entry.bytes, loc));
                }
                AssetType::Script => {
                    let source = String::from_utf8_lossy(&entry.bytes);
                    findings.extend(scripts::analyze_script(&source, loc));
                }
                AssetType::Texture => {
                    findings.extend(assets::analyze_asset(&entry.bytes, &entry.asset_type, loc));
                }
                AssetType::Audio => {
                    findings.extend(assets::analyze_asset(&entry.bytes, &entry.asset_type, loc));
                }
                AssetType::Prefab | AssetType::ScriptableObject => {
                    findings.extend(assets::analyze_asset(&entry.bytes, &entry.asset_type, loc));
                }
                _ => {}
            }

            // Metadata analysis for this entry
            if entry.meta_content.is_some() {
                let slice = std::slice::from_ref(entry);
                findings.extend(metadata::analyze_metadata(slice));
            }

            findings
        })
        .collect();

    let mut findings: Vec<Finding> = all_findings.into_iter().flatten().collect();

    // Check for scripts missing .meta
    let scripts_with_meta: std::collections::HashSet<_> = entries
        .iter()
        .filter(|e| e.asset_type == AssetType::Script && e.meta_content.is_some())
        .map(|e| e.original_path.clone())
        .collect();

    for entry in &entries {
        if entry.asset_type == AssetType::Script && !scripts_with_meta.contains(&entry.original_path) && entry.meta_content.is_none() {
            findings.push(Finding::new(
                FindingId::CsNoMeta,
                Severity::Low,
                PTS_CS_NO_META,
                &entry.original_path,
                "C# script without an associated .meta file",
            ));
        }
    }

    // Excessive DLLs
    if dll_count > THRESHOLD_EXCESSIVE_DLLS {
        findings.push(
            Finding::new(
                FindingId::ExcessiveDlls,
                Severity::Low,
                PTS_EXCESSIVE_DLLS,
                "package",
                format!("Package contains an excessive number of DLLs: {} (threshold: {})", dll_count, THRESHOLD_EXCESSIVE_DLLS),
            )
            .with_context(format!("count={}", dll_count)),
        );
    }

    // Dependency graph: detect DLLs referenced by many other assets
    {
        use std::collections::HashMap;

        // Map GUID → path for every DLL entry in the package
        let guid_to_path: HashMap<String, String> = tree
            .entries
            .iter()
            .filter(|(_, e)| e.asset_type == AssetType::Dll)
            .map(|(guid, e)| (guid.clone(), e.original_path.clone()))
            .collect();

        // Count how many .meta files reference each DLL GUID
        // Unity .meta files embed "guid: <hex>" lines for dependencies
        let mut dll_guid_count: HashMap<String, usize> = HashMap::new();
        for entry in &entries {
            if let Some(meta) = &entry.meta_content {
                for line in meta.lines() {
                    let trimmed = line.trim();
                    // Lines like: "  guid: <32-hex-chars>" inside externalObjects or references
                    if let Some(guid_part) = trimmed.strip_prefix("guid:") {
                        let referenced_guid = guid_part.trim().to_string();
                        if guid_to_path.contains_key(&referenced_guid) {
                            *dll_guid_count.entry(referenced_guid).or_insert(0) += 1;
                        }
                    }
                }
            }
        }

        findings.extend(metadata::dependency_graph::analyze(
            &guid_to_path,
            &dll_guid_count,
            "package",
        ));
    }

    // Build context for score reductions
    let has_vrchat_sdk = entries.iter().any(|e| {
        if e.asset_type == AssetType::Script {
            let source = String::from_utf8_lossy(&e.bytes);
            crate::utils::patterns::VRCHAT_SDK.is_match(&source)
        } else {
            false
        }
    });

    // A package has a "loader" if any script finding signals byte-array execution:
    //   CsAssemblyLoadBytes — Assembly.Load(byte[])
    //   CsProcessStart      — Process.Start()
    //   CsFileWrite         — File.WriteAllBytes / File.Delete etc.
    // Without at least one of these, any POLYGLOT_FILE embedded payload cannot
    // be triggered and its score is reduced in apply_context_reductions().
    let has_loader_script = findings.iter().any(|f| matches!(
        f.id,
        FindingId::CsAssemblyLoadBytes | FindingId::CsProcessStart | FindingId::CsFileWrite
    ));

    let context = AnalysisContext {
        has_vrchat_sdk,
        is_managed_dotnet: false, // set per DLL, aggregated as "any"
        in_editor_folder: false,  // per-entry context applied in scorer
        has_loader_script,
    };

    (findings, counts, context)
}
