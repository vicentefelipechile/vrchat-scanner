use std::collections::HashMap;

use crate::report::{Finding, Severity};

/// Threshold: a DLL referenced by more than this many assets is considered suspicious.
const DEPENDENCY_THRESHOLD: usize = 5;

/// Analyze the dependency graph built from `.meta` file cross-references.
///
/// # Parameters
/// - `guid_to_path`: maps each GUID to the asset's internal path in the package.
/// - `dll_guid_count`: maps each DLL GUID to the number of `.meta` files that reference it.
/// - `location`: label used in findings (typically `"package"` or the package file name).
///
/// # Returns
/// A list of findings for DLLs with an abnormally high number of dependents.
pub fn analyze(
    guid_to_path: &HashMap<String, String>,
    dll_guid_count: &HashMap<String, usize>,
    location: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (guid, &count) in dll_guid_count {
        if count > DEPENDENCY_THRESHOLD {
            let path = guid_to_path
                .get(guid)
                .map(String::as_str)
                .unwrap_or("<unknown>");

            findings.push(
                Finding::new(
                    "DLL_MANY_DEPENDENTS",
                    Severity::Low,
                    15,
                    location,
                    format!(
                        "DLL '{}' is referenced by {} assets (threshold: {})",
                        path, count, DEPENDENCY_THRESHOLD
                    ),
                )
                .with_context(format!("guid={guid} dependents={count}")),
            );
        }
    }

    findings
}
