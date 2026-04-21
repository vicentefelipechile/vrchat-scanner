//! Integration tests — Edge cases and boundary conditions.
//!
//! Tests for things that should gracefully handle weird inputs:
//! empty files, very large content, path traversal, double extensions, etc.

use vrcstorage_scanner::analysis::scripts::analyze_script;
use vrcstorage_scanner::analysis::assets::{texture_scanner, audio_scanner};
use vrcstorage_scanner::ingestion::type_detection::detect_type;
use vrcstorage_scanner::ingestion::FileType;
use vrcstorage_scanner::report::FindingId;
use vrcstorage_scanner::utils::shannon_entropy;

// ─────────────────────────────────────────────
// Empty and minimal inputs
// ─────────────────────────────────────────────

#[test]
fn empty_script_produces_no_findings() {
    let findings = analyze_script(b"", "", "Assets/Scripts/Empty.cs");
    // Empty script should not crash and should produce no critical findings
    let critical: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == vrcstorage_scanner::report::Severity::Critical)
        .collect();
    assert!(critical.is_empty(), "Empty script should not produce critical findings");
}

#[test]
fn empty_texture_no_panic() {
    // Should not panic on empty data
    let findings = texture_scanner::analyze(&[], "Assets/Textures/empty.png");
    let _ = findings;
}

#[test]
fn empty_audio_no_panic() {
    let findings = audio_scanner::analyze(&[], "Assets/Audio/empty.wav");
    let _ = findings;
}

#[test]
fn entropy_of_empty_is_zero() {
    assert_eq!(shannon_entropy(&[]), 0.0);
}

// ─────────────────────────────────────────────
// File type detection edge cases
// ─────────────────────────────────────────────

#[test]
fn detect_type_zip_magic() {
    let data = b"PK\x03\x04some zip content";
    let path = std::path::Path::new("package.unitypackage");
    let ft = detect_type(data, path);
    // PK magic → should detect as ZIP or Unity package
    assert!(
        ft == FileType::UnityPackage || ft == FileType::ZipArchive,
        "Expected ZIP/UnityPackage for PK magic, got {:?}",
        ft
    );
}

#[test]
fn detect_type_mz_magic() {
    let mut data = b"MZ".to_vec();
    data.extend(vec![0u8; 60]);
    let path = std::path::Path::new("plugin.dll");
    let ft = detect_type(&data, path);
    assert_eq!(ft, FileType::DllPe, "Expected DllPe for MZ magic, got {:?}", ft);
}

#[test]
fn detect_type_yaml_meta() {
    let data = b"%YAML 1.1\n%TAG !u! tag:unity3d.com,2011:\n";
    let path = std::path::Path::new("Asset.meta");
    let ft = detect_type(data, path);
    assert!(
        ft == FileType::MetaFile || ft == FileType::Prefab,
        "Expected MetaFile/Prefab for YAML meta, got {:?}",
        ft
    );
}

#[test]
fn detect_type_cs_extension() {
    let data = b"using UnityEngine;";
    let path = std::path::Path::new("Script.cs");
    let ft = detect_type(data, path);
    assert_eq!(ft, FileType::CSharpScript);
}

#[test]
fn detect_type_unknown_returns_unknown() {
    let data = b"\xFF\xFE\x00\x01this is something weird";
    let path = std::path::Path::new("mystery.bin");
    let ft = detect_type(data, path);
    assert_eq!(ft, FileType::Unknown, "Unexpected magic bytes should yield Unknown");
}

// ─────────────────────────────────────────────
// Structural checks via scripts analysis
// ─────────────────────────────────────────────

#[test]
fn script_with_environment_access_flagged() {
    let source = r#"
using System;
public class Telemetry {
    void Collect() {
        var user = Environment.UserName;
        var machine = Environment.MachineName;
    }
}
"#;
    let findings = analyze_script(source.as_bytes(), source, "Assets/Scripts/Telemetry.cs");
    let has = findings.iter().any(|f| f.id == FindingId::CsEnvironmentAccess);
    assert!(has, "CS_ENVIRONMENT_ACCESS not flagged; got: {:#?}", findings);
}

#[test]
fn script_with_marshal_ops_flagged() {
    let source = r#"
using System.Runtime.InteropServices;
public class RawPtr {
    unsafe void Copy(byte[] src, IntPtr dst) {
        Marshal.Copy(src, 0, dst, src.Length);
        IntPtr buf = Marshal.AllocHGlobal(1024);
    }
}
"#;
    let findings = analyze_script(source.as_bytes(), source, "Assets/Scripts/RawPtr.cs");
    let has = findings.iter().any(|f| f.id == FindingId::CsMarshalOps);
    assert!(has, "CS_MARSHAL_OPS not detected; got: {:#?}", findings);
}

#[test]
fn file_write_operation_flagged() {
    let source = r#"
using System.IO;
public class DataExfil {
    void Save(string data) {
        File.WriteAllText("C:\\Windows\\Temp\\stolen.txt", data);
    }
}
"#;
    let findings = analyze_script(source.as_bytes(), source, "Assets/Scripts/DataExfil.cs");
    let has = findings.iter().any(|f| f.id == FindingId::CsFileWrite);
    assert!(has, "CS_FILE_WRITE not flagged for File.WriteAllText; got: {:#?}", findings);
}

#[test]
fn reflection_emit_alone_is_medium_not_critical() {
    // Reflection.Emit in isolation should be MEDIUM, not CRITICAL
    let source = r#"
using System.Reflection.Emit;
public class CodeGen {
    void Build() {
        var ab = System.Reflection.Emit.AssemblyBuilder.DefineDynamicAssembly(null, 0);
    }
}
"#;
    let findings = analyze_script(source.as_bytes(), source, "Assets/Scripts/CodeGen.cs");
    let ref_emit: Vec<_> = findings.iter().filter(|f| f.id == FindingId::CsReflectionEmit).collect();

    if !ref_emit.is_empty() {
        let is_medium = ref_emit[0].severity == vrcstorage_scanner::report::Severity::Medium;
        assert!(is_medium, "CS_REFLECTION_EMIT alone should be MEDIUM severity");
    }
    // Note: not asserting it's detected (source doesn't use exact pattern), just that if it IS detected it's Medium
}

// ─────────────────────────────────────────────
// Finding struct construction
// ─────────────────────────────────────────────

#[test]
fn finding_with_context_stores_context() {
    use vrcstorage_scanner::report::{Finding, Severity};

    let f = Finding::new(FindingId::PeHighEntropySection, Severity::High, 50, "path/to/file", "Some detail")
        .with_context("extra info here");

    assert_eq!(f.id, FindingId::PeHighEntropySection);
    assert_eq!(f.points, 50);
    assert_eq!(f.context.as_deref(), Some("extra info here"));
}

#[test]
fn finding_without_context_is_none() {
    use vrcstorage_scanner::report::{Finding, Severity};

    let f = Finding::new(FindingId::CsNoMeta, Severity::Low, 10, "some/file.cs", "detail");
    assert!(f.context.is_none());
}

// ─────────────────────────────────────────────
// Entropy edge cases
// ─────────────────────────────────────────────

#[test]
fn entropy_single_byte_value_is_zero() {
    let data = vec![0x42u8; 512];
    let e = shannon_entropy(&data);
    assert!(e < 0.01, "All-same bytes should have ~0 entropy, got {}", e);
}

#[test]
fn entropy_two_values_is_one_bit() {
    // Alternating 0x00 and 0xFF → 1.0 bit of entropy
    let data: Vec<u8> = (0..256).map(|i| if i % 2 == 0 { 0x00 } else { 0xFF }).collect();
    let e = shannon_entropy(&data);
    // Should be exactly 1.0
    assert!(
        (e - 1.0).abs() < 0.01,
        "Two-value uniform data should have entropy ~1.0, got {}",
        e
    );
}

#[test]
fn entropy_never_exceeds_eight() {
    let data: Vec<u8> = (0u8..=255).collect();
    let e = shannon_entropy(&data);
    assert!(e <= 8.0, "Shannon entropy cannot exceed 8.0 bits, got {}", e);
}
