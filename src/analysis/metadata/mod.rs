pub mod dependency_graph;
pub mod meta_parser;


use crate::report::Finding;
use crate::ingestion::PackageEntry;

/// Run metadata analysis over all entries in the package.
pub fn analyze_metadata(entries: &[&PackageEntry]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for entry in entries {
        if let Some(meta_content) = &entry.meta_content {
            let (_info, mut f) = meta_parser::analyze(meta_content, &entry.original_path);
            findings.append(&mut f);
        }
    }

    findings
}
