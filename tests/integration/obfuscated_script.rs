//! Integration tests — Obfuscated C# scripts
//! Expected: at least one obfuscation finding per test.

use vrcstorage_scanner::analysis::scripts::analyze_script;
use vrcstorage_scanner::report::FindingId;

// ─────────────────────────────────────────────
// Base64 ratio detection
// ─────────────────────────────────────────────

#[test]
fn obfuscated_script_detected() {
    // Script with many single-char identifiers and a long Base64 string
    let obfuscated_cs = format!(
        r#"public class A {{ void B() {{ var c = "{}"; var d = System.Convert.FromBase64String(c); }} }}"#,
        "SGVsbG8gV29ybGQhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEh"
    );

    let findings = analyze_script(obfuscated_cs.as_bytes(), &obfuscated_cs, "Assets/Scripts/Obfuscated.cs");

    let has_obfuscation = findings
        .iter()
        .any(|f| f.id == FindingId::CsBase64HighRatio || f.id == FindingId::CsObfuscatedIdentifiers);
    assert!(
        has_obfuscation,
        "Expected obfuscation findings, got: {:#?}",
        findings
    );
}

#[test]
fn long_base64_literal_flagged() {
    // A very long Base64 literal alone in a script — should trigger CS_BASE64_HIGH_RATIO
    let b64 = "A".repeat(80); // 80 chars of 'A' — valid looking Base64
    let source = format!(
        r#"public class Enc {{ string k = "{b64}"; }}"#,
        b64 = b64
    );

    let findings = analyze_script(source.as_bytes(), &source, "Assets/Scripts/Enc.cs");
    let has = findings.iter().any(|f| f.id == FindingId::CsBase64HighRatio);
    assert!(has, "Long Base64 literal not flagged; findings: {:#?}", findings);
}

#[test]
fn high_density_short_identifiers_flagged() {
    // A class where almost all identifiers are 1-2 chars
    let source = r#"
public class A {
    int a; int b; int c; int d; int e; int f; int g; int h;
    void B(int x, int y, int z) {
        int q = x + y; int r = q * z; int s = r - a;
        int t = s ^ b; int u = t | c; int v = u & d;
        int w = v + e; int p = w * f;
        if (p > 0) { a = b + c; } else { d = e - f; }
        for (int i = 0; i < g; i++) { h = i * a; }
    }
}
"#;

    let findings = analyze_script(source.as_bytes(), source, "Assets/Scripts/Obfuscated2.cs");
    let has = findings
        .iter()
        .any(|f| f.id == FindingId::CsObfuscatedIdentifiers);
    assert!(
        has,
        "Expected CS_OBFUSCATED_IDENTIFIERS for short-identifier script; got: {:#?}",
        findings
    );
}

#[test]
fn xor_decryption_pattern_flagged() {
    let source = r#"
public class Decrypt {
    byte[] Decode(byte[] input, byte key) {
        byte[] result = new byte[input.Length];
        for (int i = 0; i < input.Length; i++) {
            result[i] = (byte)(input[i] ^ key);
        }
        return result;
    }
}
"#;

    let findings = analyze_script(source.as_bytes(), source, "Assets/Scripts/Decrypt.cs");
    let has = findings.iter().any(|f| f.id == FindingId::CsXorDecryption);
    assert!(has, "CS_XOR_DECRYPTION not flagged; findings: {:#?}", findings);
}

#[test]
fn unicode_escape_obfuscation_flagged() {
    // \u0053 = 'S' — classic string obfuscation in C#
    let source = "public class A { string cmd = \"\\u0063\\u006D\\u0064\"; }";

    let findings = analyze_script(source.as_bytes(), source, "Assets/Scripts/UnicodeObf.cs");
    let has = findings.iter().any(|f| f.id == FindingId::CsUnicodeEscapes);
    assert!(
        has,
        "CS_UNICODE_ESCAPES not flagged for unicode-escaped string; got: {:#?}",
        findings
    );
}

#[test]
fn clean_short_script_not_flagged_as_obfuscated() {
    // A very short legitimate script should NOT trigger obfuscation detection
    let source = r#"
using UnityEngine;

public class UI : MonoBehaviour {
    void Start() { gameObject.SetActive(true); }
}
"#;

    let findings = analyze_script(source.as_bytes(), source, "Assets/Scripts/UI.cs");
    let has_obfuscation = findings
        .iter()
        .any(|f| f.id == FindingId::CsObfuscatedIdentifiers || f.id == FindingId::CsBase64HighRatio);
    assert!(
        !has_obfuscation,
        "Short clean script should not be flagged as obfuscated; got: {:#?}",
        findings
    );
}
