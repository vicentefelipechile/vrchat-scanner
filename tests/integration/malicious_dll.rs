//! Integration tests — Malicious DLL / dangerous C# scripts
//! Expected: score > 60 (MEDIUM or higher) for dangerous content.

use vrcstorage_scanner::analysis::scripts::analyze_script;
use vrcstorage_scanner::scoring::{compute_score, RiskLevel};

// ─────────────────────────────────────────────
// C# script tests (via script analyzer)
// ─────────────────────────────────────────────

#[test]
fn malicious_script_scores_high() {
    let source = r#"
using System;
using System.Diagnostics;
using System.Net.Http;
using System.Reflection;

public class Malicious {
    void Run() {
        Process.Start("cmd.exe", "/c calc.exe");
        var client = new HttpClient();
        Assembly.Load(new byte[] { 0x4D, 0x5A });
        var p = "C:\\Windows\\System32\\evil.exe";
    }
}
"#;

    let findings = analyze_script(source, "Assets/Scripts/Malicious.cs");
    let score: u32 = findings.iter().map(|f| f.points).sum();

    assert!(
        score > 60,
        "Expected score > 60 for malicious script, got {} (findings: {:#?})",
        score,
        findings
    );
    assert!(!findings.is_empty(), "Expected findings for malicious script");
}

#[test]
fn process_start_detected_as_critical() {
    let source = r#"
public class Dropper {
    void Run() { System.Diagnostics.Process.Start("cmd.exe"); }
}
"#;
    let findings = analyze_script(source, "Assets/Scripts/Dropper.cs");
    let has_process = findings.iter().any(|f| f.id == "CS_PROCESS_START");
    assert!(has_process, "CS_PROCESS_START not detected; findings: {:#?}", findings);

    let critical = findings
        .iter()
        .find(|f| f.id == "CS_PROCESS_START")
        .unwrap();
    assert_eq!(
        critical.severity,
        vrcstorage_scanner::report::Severity::Critical
    );
    assert!(critical.points >= 75);
}

#[test]
fn assembly_load_bytes_detected() {
    let source = r#"
using System.Reflection;

public class Loader {
    void Load(byte[] raw) {
        Assembly.Load(raw);
    }
}
"#;
    let findings = analyze_script(source, "Assets/Scripts/Loader.cs");
    let has = findings.iter().any(|f| f.id == "CS_ASSEMBLY_LOAD_BYTES");
    assert!(has, "CS_ASSEMBLY_LOAD_BYTES not found; got: {:#?}", findings);
}

#[test]
fn binary_formatter_flagged() {
    let source = r#"
using System.Runtime.Serialization.Formatters.Binary;
using System.IO;

public class SaveLoad {
    void Load(Stream s) {
        var bf = new BinaryFormatter();
        var obj = bf.Deserialize(s);
    }
}
"#;
    let findings = analyze_script(source, "Assets/Scripts/SaveLoad.cs");
    let has = findings.iter().any(|f| f.id == "CS_BINARY_FORMATTER");
    assert!(has, "CS_BINARY_FORMATTER not flagged; got: {:#?}", findings);
}

#[test]
fn dll_import_piinvoke_flagged() {
    let source = r#"
using System.Runtime.InteropServices;

public class NativeCall {
    [DllImport("MaliciousLib.dll")]
    private static extern void Execute();
}
"#;
    let findings = analyze_script(source, "Assets/Scripts/NativeCall.cs");
    let has = findings.iter().any(|f| f.id == "CS_DLLIMPORT_UNKNOWN");
    assert!(has, "CS_DLLIMPORT_UNKNOWN not detected; got: {:#?}", findings);
}

#[test]
fn unsafe_block_flagged() {
    let source = r#"
public class RawMemory {
    unsafe void Write(byte* ptr) {
        *ptr = 0xFF;
    }
}
"#;
    let findings = analyze_script(source, "Assets/Scripts/RawMemory.cs");
    let has = findings.iter().any(|f| f.id == "CS_UNSAFE_BLOCK");
    assert!(has, "CS_UNSAFE_BLOCK not found; got: {:#?}", findings);
}

#[test]
fn registry_access_flagged() {
    let source = r#"
using Microsoft.Win32;

public class AutoRun {
    void SetStartup() {
        Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", true);
    }
}
"#;
    let findings = analyze_script(source, "Assets/Scripts/AutoRun.cs");
    let has = findings.iter().any(|f| f.id == "CS_REGISTRY_ACCESS");
    assert!(has, "CS_REGISTRY_ACCESS not detected; got: {:#?}", findings);
}

#[test]
fn shell_command_strings_flagged() {
    let source = r#"
public class CmdRunner {
    string payload = "cmd.exe /c whoami";
    string ps = "powershell -EncodedCommand ZQBj";
}
"#;
    let findings = analyze_script(source, "Assets/Scripts/CmdRunner.cs");
    let has = findings.iter().any(|f| f.id == "CS_SHELL_STRINGS");
    assert!(has, "CS_SHELL_STRINGS not detected; got: {:#?}", findings);
}

#[test]
fn multiple_danger_signals_reach_high_risk() {
    let source = r#"
using System.Diagnostics;
using System.Net.Http;
using System.Reflection;
using Microsoft.Win32;
using System.Runtime.InteropServices;

public class Danger {
    [DllImport("evil.dll")]
    static extern void Run();

    void Execute() {
        Process.Start("cmd.exe");
        Assembly.Load(new byte[0]);
        Registry.LocalMachine.OpenSubKey("SOFTWARE");
        var h = new HttpClient();
    }
}
"#;

    let findings = analyze_script(source, "Assets/Scripts/Danger.cs");
    let (score, level) = compute_score(&findings);

    assert!(
        score > 150,
        "Expected score > 150 for heavily malicious script, got {}",
        score
    );
    assert_eq!(
        level,
        RiskLevel::Critical,
        "Expected Critical risk level, got {:?}",
        level
    );
}

// ─────────────────────────────────────────────
// PE / DLL analysis tests (via pe_parser)
// ─────────────────────────────────────────────

#[test]
fn non_pe_file_gets_invalid_header_finding() {
    // Random bytes that don't start with MZ
    let data = b"This is definitely not a PE file at all.";
    let findings = vrcstorage_scanner::analysis::dll::pe_parser::analyze(data, "fake.dll").1;

    let has = findings.iter().any(|f| f.id == "PE_INVALID_HEADER");
    assert!(has, "PE_INVALID_HEADER not detected for non-PE data; got: {:#?}", findings);
}

#[test]
fn high_entropy_bytes_detected_by_entropy_module() {
    use vrcstorage_scanner::utils::shannon_entropy;

    // All 256 byte values → maximum entropy
    let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
    let e = shannon_entropy(&data);
    assert!(e > 7.9, "Expected entropy > 7.9, got {}", e);

    // All-zero slice → near-zero entropy
    let zeros = vec![0u8; 512];
    let e0 = shannon_entropy(&zeros);
    assert!(e0 < 0.01, "Expected entropy ~0 for uniform bytes, got {}", e0);
}
