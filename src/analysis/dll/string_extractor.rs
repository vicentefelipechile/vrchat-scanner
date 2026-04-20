use crate::config::{
    PTS_CS_SHELL_STRINGS, PTS_DLL_STRINGS_SUSPICIOUS_PATH, PTS_DLL_IMPORT_REGISTRY,
    PTS_DLL_URL_UNKNOWN_DOMAIN, PTS_DLL_IP_HARDCODED, PTS_POLYGLOT_FILE,
    PTS_CS_BASE64_HIGH_RATIO, DLL_MIN_STRING_LEN,
};
use crate::report::{Finding, FindingId, Severity};
use crate::utils::patterns::{URL_PATTERN, IP_PATTERN, REGISTRY_KEY, SYSTEM_PATH, SHELL_CMD, BASE64_LONG, is_safe_domain};

/// Extract ASCII strings of length >= 6 bytes from raw binary data
fn extract_ascii_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut results = Vec::new();
    let mut current = Vec::new();

    for &b in data {
        if (0x20..0x7F).contains(&b) {
            current.push(b);
        } else {
            if current.len() >= min_len {
                results.push(String::from_utf8_lossy(&current).into_owned());
            }
            current.clear();
        }
    }
    if current.len() >= min_len {
        results.push(String::from_utf8_lossy(&current).into_owned());
    }
    results
}

/// Classify strings found in a DLL and return findings
pub fn analyze(data: &[u8], location: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let strings = extract_ascii_strings(data, DLL_MIN_STRING_LEN);

    let mut found_shell_cmd = false;
    let mut found_sys_path = false;
    let mut found_embedded_hex_pe = false;

    for s in &strings {
        // Shell commands
        if !found_shell_cmd && SHELL_CMD.is_match(s) {
            findings.push(
                Finding::new(
                    FindingId::CsShellStrings,
                    Severity::High,
                    PTS_CS_SHELL_STRINGS,
                    location,
                    "Shell command string found in DLL",
                )
                .with_context(s.chars().take(80).collect::<String>()),
            );
            found_shell_cmd = true;
        }

        // System paths
        if !found_sys_path && SYSTEM_PATH.is_match(s) {
            findings.push(
                Finding::new(
                    FindingId::DllStringsSuspiciousPath,
                    Severity::Low,
                    PTS_DLL_STRINGS_SUSPICIOUS_PATH,
                    location,
                    "Suspicious system path embedded in DLL strings",
                )
                .with_context(s.chars().take(80).collect::<String>()),
            );
            found_sys_path = true;
        }

        // Registry
        if REGISTRY_KEY.is_match(s) {
            findings.push(
                Finding::new(
                    FindingId::DllImportRegistry,
                    Severity::Medium,
                    PTS_DLL_IMPORT_REGISTRY,
                    location,
                    "Windows registry path embedded in DLL strings",
                )
                .with_context(s.chars().take(80).collect::<String>()),
            );
        }

        // URLs
        for cap in URL_PATTERN.find_iter(s) {
            let url = cap.as_str();
            if !is_safe_domain(url) {
                findings.push(
                    Finding::new(FindingId::CsUrlUnknownDomain, Severity::High, PTS_DLL_URL_UNKNOWN_DOMAIN, location, "URL to unrecognized domain in DLL strings")
                        .with_context(url.chars().take(120).collect::<String>()),
                );
            }
        }

        // IP addresses
        if IP_PATTERN.is_match(s) && !s.starts_with("127.") && !s.starts_with("0.0.") {
            findings.push(
                Finding::new(FindingId::CsIpHardcoded, Severity::High, PTS_DLL_IP_HARDCODED, location, "Hardcoded IP address in DLL strings")
                    .with_context(s.chars().take(40).collect::<String>()),
            );
        }

        // Hex-encoded PE in strings
        if !found_embedded_hex_pe && s.len() >= 8 && s.to_uppercase().contains("4D5A") {
            findings.push(Finding::new(
                FindingId::PolyglotFile,
                Severity::High,
                PTS_POLYGLOT_FILE,
                location,
                "Hex-encoded PE header (4D5A) found in DLL strings — possible embedded executable",
            ));
            found_embedded_hex_pe = true;
        }

        // Long Base64
        if BASE64_LONG.is_match(s) {
            findings.push(
                Finding::new(FindingId::CsBase64HighRatio, Severity::Medium, PTS_CS_BASE64_HIGH_RATIO, location, "Long Base64 string in DLL")
                    .with_context(format!("length={}", s.len())),
            );
        }
    }

    findings
}
