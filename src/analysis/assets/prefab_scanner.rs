use crate::report::{Finding, FindingId, Severity};
use crate::utils::patterns::BASE64_LONG;
use crate::config::*;

/// Scan a Unity .prefab or .asset file (YAML or binary) for anomalies.
pub fn analyze(data: &[u8], location: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let content = String::from_utf8_lossy(data);
    let is_yaml = content.starts_with("%YAML");

    if is_yaml {
        findings.append(&mut analyze_yaml(&content, location));
    } else {
        // Binary serialized — limited analysis
        let text = String::from_utf8_lossy(data);
        // Look for GUID-like strings referencing external assets
        let guid_refs: Vec<_> = text.match_indices("guid: ").collect();
        if guid_refs.len() > THRESHOLD_PREFAB_EXCESSIVE_GUIDS {
            findings.push(Finding::new(
                FindingId::PrefabExcessiveGuids,
                Severity::Low,
                PTS_PREFAB_EXCESSIVE_GUIDS,
                location,
                "Binary prefab has an unusually large number of GUID references",
            ).with_context(format!("count={}", guid_refs.len())));
        }
    }

    findings
}

fn analyze_yaml(content: &str, location: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check for external references (externalVersions / externalObjects)
    if content.contains("externalObjects:") && !content.contains("externalObjects: {}") {
        findings.push(Finding::new(
            FindingId::MetaExternalRef,
            Severity::Medium,
            PTS_META_EXTERNAL_REF,
            location,
            "Prefab/asset references external objects not included in the package",
        ));
    }

    // Scan for long Base64 fields
    for m in BASE64_LONG.find_iter(content) {
        if m.len() > OBFUSC_BASE64_LONG_LEN {
            findings.push(Finding::new(
                FindingId::PrefabInlineB64,
                Severity::Low,
                PTS_PREFAB_INLINE_B64,
                location,
                "Long Base64-encoded field in YAML prefab/asset (may be inline texture or payload)",
            ).with_context(format!("length={}", m.len())));
            break; // report once per file
        }
    }

    // Check for script GUIDs without match (can't resolve here — mark for metadata stage)
    // Look for unknown component types
    if content.contains("m_Script:") {
        let script_count = content.matches("m_Script:").count();
        if script_count > THRESHOLD_PREFAB_MANY_SCRIPTS {
            findings.push(Finding::new(
                FindingId::PrefabManyScripts,
                Severity::Medium,
                PTS_PREFAB_MANY_SCRIPTS,
                location,
                "Prefab references an unusually large number of scripts",
            ).with_context(format!("count={script_count}")));
        }
    }

    findings
}
