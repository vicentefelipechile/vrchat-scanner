pub mod obfuscation;
pub mod pattern_matcher;
pub mod preprocessor;
pub mod url_extractor;

use crate::report::Finding;
use crate::whitelist::{self, WhitelistVerdict};

/// Run all C# script analysis stages.
///
/// `data` is the raw file bytes — needed to compute SHA-256 for the whitelist check.
/// `source` is the decoded UTF-8 content used by every pattern-based analyser.
pub fn analyze_script(data: &[u8], source: &str, location: &str) -> Vec<Finding> {
    // Whitelist check first — trusted files skip everything.
    match whitelist::check(location, data, source) {
        WhitelistVerdict::FullyTrusted { .. } => {
            return vec![];
        }
        WhitelistVerdict::Modified { name, line_count_ok } => {
            // Modified known files: obfuscation-only on the raw source (no
            // preprocessing — we want to catch obfuscation even in comments).
            let mut findings = obfuscation::analyze(source, location);
            for f in &mut findings {
                f.context = Some(format!(
                    "whitelisted={name}, sha256_mismatch=true, line_count_ok={line_count_ok}"
                ));
            }
            return findings;
        }
        WhitelistVerdict::NotWhitelisted => {}
    }

    // Preprocess: blank comments and inactive #if blocks so pattern matchers
    // do not flag dead / sanitized code.
    let preprocessed = preprocessor::preprocess(source, &[]);
    let active = &preprocessed.active_source;

    let mut findings = Vec::new();

    findings.append(&mut pattern_matcher::analyze(active, location));
    findings.append(&mut url_extractor::analyze(active, location));
    // Obfuscation runs on the original source — obfuscated identifiers and
    // base64 blobs inside comments are still worth flagging (low severity).
    findings.append(&mut obfuscation::analyze(source, location));

    findings
}