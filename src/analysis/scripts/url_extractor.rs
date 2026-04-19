use crate::report::{Finding, Severity};
use crate::utils::patterns::{URL_PATTERN, IP_PATTERN, is_safe_domain};

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

        // IP address used as URL host
        if IP_PATTERN.is_match(url) {
            findings.push(
                Finding::new(
                    "CS_IP_HARDCODED",
                    Severity::High,
                    50,
                    location,
                    "Hardcoded IP address used as URL in C# script",
                )
                .with_context(url.chars().take(120).collect::<String>()),
            );
        } else {
            findings.push(
                Finding::new(
                    "CS_URL_UNKNOWN_DOMAIN",
                    Severity::High,
                    50,
                    location,
                    "URL to unrecognized domain in C# script",
                )
                .with_context(url.chars().take(120).collect::<String>()),
            );
        }
    }

    findings
}
