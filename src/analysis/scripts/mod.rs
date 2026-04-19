pub mod obfuscation;
pub mod pattern_matcher;
pub mod url_extractor;

use crate::report::Finding;

/// Run all C# script analysis stages.
pub fn analyze_script(source: &str, location: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    findings.append(&mut pattern_matcher::analyze(source, location));
    findings.append(&mut url_extractor::analyze(source, location));
    findings.append(&mut obfuscation::analyze(source, location));

    findings
}
