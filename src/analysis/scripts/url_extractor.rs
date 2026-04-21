use crate::report::{Finding, FindingId, Severity};
use crate::utils::patterns::{URL_PATTERN, IP_PATTERN, is_safe_domain};
use crate::config::*;

/// Extract and validate all URLs found in C# source code.
pub fn analyze(source: &str, location: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen_urls = std::collections::HashSet::new();

    for m in URL_PATTERN.find_iter(source) {
        let url = m.as_str().trim_end_matches(|c: char| !c.is_alphanumeric());
        if seen_urls.contains(url) {
            continue;
        }
        seen_urls.insert(url.to_string());

        if is_safe_domain(url) {
            // Trusted domain — low risk, don't add finding
            continue;
        }

        // Compute 1-indexed line number from byte offset
        let line_num = source[..m.start()].bytes().filter(|&b| b == b'\n').count() as u64 + 1;

        // IP address used as URL host
        if IP_PATTERN.is_match(url) {
            findings.push(
                Finding::new(
                    FindingId::CsIpHardcoded,
                    Severity::High,
                    PTS_CS_IP_HARDCODED,
                    location,
                    "Hardcoded IP address used as URL in C# script",
                )
                .with_context(url.chars().take(120).collect::<String>())
                .with_line_numbers(vec![line_num]),
            );
        } else {
            findings.push(
                Finding::new(
                    FindingId::CsUrlUnknownDomain,
                    Severity::High,
                    PTS_CS_URL_UNKNOWN_DOMAIN,
                    location,
                    "URL to unrecognized domain in C# script",
                )
                .with_context(url.chars().take(120).collect::<String>())
                .with_line_numbers(vec![line_num]),
            );
        }
    }

    findings
}
