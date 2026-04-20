use crate::report::{Finding, FindingId, Severity};
use crate::utils::patterns::BASE64_LONG;

/// Detect obfuscation patterns in C# source code.
pub fn analyze(source: &str, location: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // 1. High ratio of Base64 strings
    let base64_matches: Vec<_> = BASE64_LONG.find_iter(source).collect();
    let total_chars = source.len() as f64;
    let base64_chars: f64 = base64_matches.iter().map(|m| m.len() as f64).sum();

    if total_chars > 0.0 && (base64_chars / total_chars) > 0.15 {
        findings.push(
            Finding::new(
                FindingId::CsBase64HighRatio,
                Severity::Medium,
                25,
                location,
                "High ratio of Base64 strings in C# script (>15% of content)",
            )
            .with_context(format!(
                "ratio={:.1}%",
                (base64_chars / total_chars) * 100.0
            )),
        );
    } else if !base64_matches.is_empty() && base64_matches.iter().any(|m| m.len() > 200) {
        // Very long individual Base64 strings are also suspicious
        findings.push(Finding::new(
            FindingId::CsBase64HighRatio,
            Severity::Medium,
            15,
            location,
            "Long Base64 literal (>200 chars) in C# script",
        ));
    }

    // 2. Obfuscated identifiers — detect scripts with many very short identifiers
    // Simple heuristic: count word-like tokens of length 1 or 2
    let tokens: Vec<&str> = source
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|s| !s.is_empty())
        .collect();

    if !tokens.is_empty() {
        let short_count = tokens.iter().filter(|t| t.len() <= 2 && t.chars().all(|c| c.is_alphabetic())).count();
        let ratio = short_count as f64 / tokens.len() as f64;
        if ratio > 0.4 && tokens.len() > 50 {
            findings.push(
                Finding::new(
                    FindingId::CsObfuscatedIdentifiers,
                    Severity::Low,
                    15,
                    location,
                    "High density of very short identifiers (possible obfuscation)",
                )
                .with_context(format!(
                    "short_ratio={:.1}% ({}/{})",
                    ratio * 100.0,
                    short_count,
                    tokens.len()
                )),
            );
        }
    }

    // 3. XOR decryption pattern (byte array XOR loop)
    if source.contains("^ ") || source.contains("^=") {
        // Look for byte array + XOR combination
        if (source.contains("byte[]") || source.contains("byte [")) && (source.contains("^ ") || source.contains("^=")) {
            findings.push(Finding::new(
                FindingId::CsXorDecryption,
                Severity::Medium,
                20,
                location,
                "XOR operation on byte array detected (possible string/code decryption)",
            ));
        }
    }

    // 4. Unicode escape sequences forming keywords
    if source.contains("\\u0") {
        findings.push(Finding::new(
            FindingId::CsUnicodeEscapes,
            Severity::High,
            30,
            location,
            "Unicode escape sequences in C# source (possible obfuscation of keywords/APIs)",
        ));
    }

    findings
}
