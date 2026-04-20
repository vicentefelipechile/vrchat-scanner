use std::collections::HashMap;

use crate::config::{THRESHOLD_DLL_MANY_DEPENDENTS, PTS_DLL_MANY_DEPENDENTS};
use crate::report::{Finding, FindingId, Severity};

/// Analyze the dependency graph built from `.meta` file cross-references.
///
/// # Parameters
/// - `guid_to_path`: maps each GUID to the asset's internal path in the package.
/// - `dll_guid_count`: maps each DLL GUID to the number of `.meta` files that reference it.
/// - `location`: label used in findings (typically `"package"` or the package file name).
///
/// # Returns
/// A list of findings for DLLs with an abnormally high number of dependents.
/// Threshold: `config::THRESHOLD_DLL_MANY_DEPENDENTS`.
pub fn analyze(
    guid_to_path: &HashMap<String, String>,
    dll_guid_count: &HashMap<String, usize>,
    location: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (guid, &count) in dll_guid_count {
        if count > THRESHOLD_DLL_MANY_DEPENDENTS {
            let path = guid_to_path
                .get(guid)
                .map(String::as_str)
                .unwrap_or("<unknown>");

            findings.push(
                Finding::new(
                    FindingId::DllManyDependents,
                    Severity::Low,
                    PTS_DLL_MANY_DEPENDENTS,
                    location,
                    format!(
                        "DLL '{}' is referenced by {} assets (threshold: {})",
                        path, count, THRESHOLD_DLL_MANY_DEPENDENTS
                    ),
                )
                .with_context(format!("guid={guid} dependents={count}")),
            );
        }
    }

    findings
}
