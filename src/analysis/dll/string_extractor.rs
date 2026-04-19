use crate::report::{Finding, Severity};
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
    let strings = extract_ascii_strings(data, 6);

    let mut found_shell_cmd = false;
    let mut found_sys_path = false;
    let mut found_embedded_hex_pe = false;

    for s in &strings {
        // Shell commands
        if !found_shell_cmd && SHELL_CMD.is_match(s) {
            findings.push(
                Finding::new(
                    "CS_SHELL_STRINGS",
                    Severity::High,
                    45,
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
                    "DLL_STRINGS_SUSPICIOUS_PATH",
                    Severity::Low,
                    12,
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
                    "DLL_IMPORT_REGISTRY",
                    Severity::Medium,
                    25,
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
                    Finding::new("CS_URL_UNKNOWN_DOMAIN", Severity::High, 50, location, "URL to unrecognized domain in DLL strings")
                        .with_context(url.chars().take(120).collect::<String>()),
                );
            }
        }

        // IP addresses
        if IP_PATTERN.is_match(s) && !s.starts_with("127.") && !s.starts_with("0.0.") {
            findings.push(
                Finding::new("CS_IP_HARDCODED", Severity::High, 50, location, "Hardcoded IP address in DLL strings")
                    .with_context(s.chars().take(40).collect::<String>()),
            );
        }

        // Hex-encoded PE in strings
        if !found_embedded_hex_pe && s.len() >= 8 && s.to_uppercase().contains("4D5A") {
            findings.push(Finding::new(
                "POLYGLOT_FILE",
                Severity::High,
                70,
                location,
                "Hex-encoded PE header (4D5A) found in DLL strings — possible embedded executable",
            ));
            found_embedded_hex_pe = true;
        }

        // Long Base64
        if BASE64_LONG.is_match(s) {
            findings.push(
                Finding::new("CS_BASE64_HIGH_RATIO", Severity::Medium, 25, location, "Long Base64 string in DLL")
                    .with_context(format!("length={}", s.len())),
            );
        }
    }

    findings
}
