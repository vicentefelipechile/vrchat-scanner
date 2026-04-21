//! Integration tests — Clean package (Stage 3: C# scripts)
//! Expected: score < 30 (CLEAN) for safe scripts.

use vrcstorage_scanner::analysis::scripts::analyze_script;
use vrcstorage_scanner::scoring::compute_score;

// ─────────────────────────────────────────────
// Happy-path: a minimal, clean Unity behaviour
// ─────────────────────────────────────────────

#[test]
fn clean_package_scores_low() {
    let clean_cs = include_str!("../fixtures/clean/clean_script.cs");

    let findings = analyze_script(clean_cs.as_bytes(), clean_cs, "Assets/Scripts/Clean.cs");
    let score: u32 = findings.iter().map(|f| f.points).sum();

    assert!(
        score < 30,
        "Expected score < 30 for clean script, got {} (findings: {:#?})",
        score,
        findings
    );
}

#[test]
fn clean_package_no_critical_findings() {
    let clean_cs = include_str!("../fixtures/clean/clean_script.cs");
    let findings = analyze_script(clean_cs.as_bytes(), clean_cs, "Assets/Scripts/Clean.cs");

    let has_critical = findings
        .iter()
        .any(|f| f.severity == vrcstorage_scanner::report::Severity::Critical);

    assert!(
        !has_critical,
        "Expected zero Critical findings for clean script, got: {:#?}",
        findings
    );
}

#[test]
fn debug_log_is_never_flagged() {
    let source = r#"
using UnityEngine;

public class SoundManager : MonoBehaviour {
    void Start() {
        Debug.Log("Sound system ready");
        Debug.LogWarning("Low memory");
    }
}
"#;
    let findings = analyze_script(source.as_bytes(), source, "Assets/Scripts/SoundManager.cs");
    assert!(
        findings.is_empty(),
        "Debug.Log should not produce findings, got: {:#?}",
        findings
    );
}

#[test]
fn vrchat_sdk_script_scores_low() {
    // A typical UdonSharp behaviour — HTTP score reduced by context
    let source = r#"
using UdonSharp;
using UnityEngine;
using VRC.SDK3.Components;
using VRC.Udon;

public class PickupItem : UdonSharpBehaviour {
    public VRCPickup pickup;

    public override void OnPickup() {
        Debug.Log("Picked up!");
    }
}
"#;
    let findings = analyze_script(source.as_bytes(), source, "Assets/UdonScripts/PickupItem.cs");
    let score: u32 = findings.iter().map(|f| f.points).sum();

    assert!(
        score < 35,
        "Expected low score for clean VRChat SDK script, got {} (findings: {:#?})",
        score,
        findings
    );
}

#[test]
fn compute_score_clean_range() {
    let findings = vec![];
    let (score, level) = compute_score(&findings);
    assert_eq!(score, 0);
    assert_eq!(level, vrcstorage_scanner::scoring::RiskLevel::Clean);
}

#[test]
fn ingestion_type_detection_cs() {
    use vrcstorage_scanner::ingestion::type_detection::detect_type;
    use vrcstorage_scanner::ingestion::FileType;

    let source = b"using UnityEngine;";
    let path = std::path::Path::new("MyScript.cs");
    let ft = detect_type(source, path);
    assert_eq!(ft, FileType::CSharpScript);
}
