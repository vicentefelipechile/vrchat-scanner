use crate::config::{
    PTS_CS_BASE64_HIGH_RATIO, PTS_CS_XOR_DECRYPTION, PTS_CS_OBFUSCATED_IDENTIFIERS,
    PTS_CS_UNICODE_ESCAPES, OBFUSC_BASE64_RATIO, OBFUSC_MIN_TOKENS, OBFUSC_SHORT_IDENT_RATIO,
};
use crate::report::{Finding, FindingId, Severity};
use crate::utils::patterns::BASE64_LONG;

/// Detect obfuscation patterns in C# source code.
pub fn analyze(source: &str, location: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // 1. High ratio of Base64 strings
    let base64_matches: Vec<_> = BASE64_LONG.find_iter(source).collect();
    let total_chars = source.len() as f64;
    let base64_chars: f64 = base64_matches.iter().map(|m| m.len() as f64).sum();

    if total_chars > 0.0 && (base64_chars / total_chars) > OBFUSC_BASE64_RATIO {
        let lines: Vec<u64> = base64_matches
            .iter()
            .map(|m| source[..m.start()].bytes().filter(|&b| b == b'\n').count() as u64 + 1)
            .collect();
        findings.push(
            Finding::new(
                FindingId::CsBase64HighRatio,
                Severity::Medium,
                PTS_CS_BASE64_HIGH_RATIO,
                location,
                "High ratio of Base64 strings in C# script (>15% of content)",
            )
            .with_context(format!(
                "ratio={:.1}%",
                (base64_chars / total_chars) * 100.0
            ))
            .with_line_numbers(lines),
        );
    } else if !base64_matches.is_empty() && base64_matches.iter().any(|m| m.len() > 200) {
        // Very long individual Base64 strings are also suspicious
        let lines: Vec<u64> = base64_matches
            .iter()
            .filter(|m| m.len() > 200)
            .map(|m| source[..m.start()].bytes().filter(|&b| b == b'\n').count() as u64 + 1)
            .collect();
        findings.push(
            Finding::new(
                FindingId::CsBase64HighRatio,
                Severity::Medium,
                PTS_CS_BASE64_HIGH_RATIO / 2, // half points for the single-string variant
                location,
                "Long Base64 literal (>200 chars) in C# script",
            )
            .with_line_numbers(lines),
        );
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
        if ratio > OBFUSC_SHORT_IDENT_RATIO && tokens.len() > OBFUSC_MIN_TOKENS {
            findings.push(
                Finding::new(
                    FindingId::CsObfuscatedIdentifiers,
                    Severity::Low,
                    PTS_CS_OBFUSCATED_IDENTIFIERS,
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
            let xor_lines: Vec<u64> = source
                .lines()
                .enumerate()
                .filter_map(|(i, line)| {
                    if (line.contains("^ ") || line.contains("^="))
                        && (line.contains("byte") || source.contains("byte[]"))
                    {
                        Some(i as u64 + 1)
                    } else {
                        None
                    }
                })
                .collect();
            findings.push(
                Finding::new(
                    FindingId::CsXorDecryption,
                    Severity::Medium,
                    PTS_CS_XOR_DECRYPTION,
                    location,
                    "XOR operation on byte array detected (possible string/code decryption)",
                )
                .with_line_numbers(xor_lines),
            );
        }
    }

    // 4. Unicode escape sequences forming keywords
    if source.contains("\\u0") {
        let uni_lines: Vec<u64> = source
            .lines()
            .enumerate()
            .filter_map(|(i, line)| {
                if line.contains("\\u0") {
                    Some(i as u64 + 1)
                } else {
                    None
                }
            })
            .collect();
        findings.push(
            Finding::new(
                FindingId::CsUnicodeEscapes,
                Severity::High,
                PTS_CS_UNICODE_ESCAPES,
                location,
                "Unicode escape sequences in C# source (possible obfuscation of keywords/APIs)",
            )
            .with_line_numbers(uni_lines),
        );
    }

    findings
}
