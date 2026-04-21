pub mod obfuscation;
pub mod pattern_matcher;
pub mod url_extractor;

use crate::report::Finding;
use crate::whitelist::{self, WhitelistVerdict};

/// Run all C# script analysis stages.
///
/// `data` is the raw file bytes — needed to compute SHA-256 for the whitelist check.
/// `source` is the decoded UTF-8 content used by every pattern-based analyser.
pub fn analyze_script(data: &[u8], source: &str, location: &str) -> Vec<Finding> {
    // Whitelist check: trusted files are skipped entirely; modified known files
    // only go through obfuscation checks with extra context attached.
    match whitelist::check(location, data, source) {
        WhitelistVerdict::FullyTrusted { .. } => {
            return vec![];
        }
        WhitelistVerdict::Modified { name, line_count_ok } => {
            let mut findings = obfuscation::analyze(source, location);
            for f in &mut findings {
                f.context = Some(format!(
                    "whitelisted={name}, sha256_mismatch=true, line_count_ok={line_count_ok}"
                ));
            }
            return findings;
        }
        WhitelistVerdict::NotWhitelisted => { /* fall through to full analysis */ }
    }

    let mut findings = Vec::new();

    findings.append(&mut pattern_matcher::analyze(source, location));
    findings.append(&mut url_extractor::analyze(source, location));
    findings.append(&mut obfuscation::analyze(source, location));

    findings
}
