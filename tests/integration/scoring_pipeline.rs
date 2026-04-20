//! Integration tests — End-to-end scoring pipeline.
//!
//! Tests the full `compute_score` + `apply_context_reductions` flow,
//! verifying score thresholds map to the correct RiskLevel.

use vrcstorage_scanner::report::{Finding, FindingId, Severity};
use vrcstorage_scanner::scoring::{
    apply_context_reductions, compute_score, context::AnalysisContext, RiskLevel,
};

// ─── Helpers ─────────────────────────────────

fn finding(id: FindingId, sev: Severity, points: u32) -> Finding {
    Finding::new(id, sev, points, "test/location", "test detail")
}

// ─── Score threshold tests ────────────────────

#[test]
fn score_zero_is_clean() {
    let (score, level) = compute_score(&[]);
    assert_eq!(score, 0);
    assert_eq!(level, RiskLevel::Clean);
}

#[test]
fn score_30_is_clean_boundary() {
    let findings = vec![finding(FindingId::CsNoMeta, Severity::Low, 30)];
    let (score, level) = compute_score(&findings);
    assert_eq!(score, 30);
    assert_eq!(level, RiskLevel::Clean);
}

#[test]
fn score_31_is_low() {
    let findings = vec![finding(FindingId::CsNoMeta, Severity::Low, 31)];
    let (_, level) = compute_score(&findings);
    assert_eq!(level, RiskLevel::Low);
}

#[test]
fn score_60_is_low_boundary() {
    let findings = vec![finding(FindingId::CsNoMeta, Severity::Low, 60)];
    let (_, level) = compute_score(&findings);
    assert_eq!(level, RiskLevel::Low);
}

#[test]
fn score_61_is_medium() {
    let findings = vec![finding(FindingId::CsUnsafeBlock, Severity::Medium, 61)];
    let (_, level) = compute_score(&findings);
    assert_eq!(level, RiskLevel::Medium);
}

#[test]
fn score_100_is_medium_boundary() {
    let findings = vec![finding(FindingId::CsUnsafeBlock, Severity::Medium, 100)];
    let (_, level) = compute_score(&findings);
    assert_eq!(level, RiskLevel::Medium);
}

#[test]
fn score_101_is_high() {
    let findings = vec![finding(FindingId::CsFileWrite, Severity::High, 101)];
    let (_, level) = compute_score(&findings);
    assert_eq!(level, RiskLevel::High);
}

#[test]
fn score_150_is_high_boundary() {
    let findings = vec![finding(FindingId::CsFileWrite, Severity::High, 150)];
    let (_, level) = compute_score(&findings);
    assert_eq!(level, RiskLevel::High);
}

#[test]
fn score_151_is_critical() {
    let findings = vec![finding(FindingId::CsProcessStart, Severity::Critical, 151)];
    let (_, level) = compute_score(&findings);
    assert_eq!(level, RiskLevel::Critical);
}

#[test]
fn score_accumulates_all_findings() {
    let findings = vec![
        finding(FindingId::CsNoMeta, Severity::Low, 10),
        finding(FindingId::CsUnsafeBlock, Severity::Medium, 25),
        finding(FindingId::PeHighEntropySection, Severity::High, 55),
    ];
    let (score, _) = compute_score(&findings);
    assert_eq!(score, 90);
}

// ─── Context reduction tests ──────────────────

#[test]
fn vrchat_sdk_reduces_http_client_finding() {
    let mut findings = vec![
        Finding::new(FindingId::CsHttpClient, Severity::Medium, 30, "Test.cs", "HTTP client"),
    ];
    let ctx = AnalysisContext {
        has_vrchat_sdk: true,
        is_managed_dotnet: false,
        in_editor_folder: false,
        has_loader_script: false,
    };
    apply_context_reductions(&mut findings, &ctx);

    assert!(
        findings[0].points <= 10,
        "HTTP client points should be reduced to ≤10 in VRChat context, got {}",
        findings[0].points
    );
}

#[test]
fn no_sdk_does_not_reduce_http_client() {
    let mut findings = vec![
        Finding::new(FindingId::CsHttpClient, Severity::Medium, 30, "Test.cs", "HTTP client"),
    ];
    let ctx = AnalysisContext {
        has_vrchat_sdk: false,
        is_managed_dotnet: false,
        in_editor_folder: false,
        has_loader_script: false,
    };
    apply_context_reductions(&mut findings, &ctx);

    assert_eq!(findings[0].points, 30, "Points should stay at 30 without SDK context");
}

#[test]
fn editor_folder_reduces_reflection_emit() {
    let mut findings = vec![
        Finding::new(FindingId::CsReflectionEmit, Severity::Medium, 40, "Editor/Tool.cs", "Reflect"),
    ];
    let ctx = AnalysisContext {
        has_vrchat_sdk: false,
        is_managed_dotnet: false,
        in_editor_folder: true,
        has_loader_script: false,
    };
    apply_context_reductions(&mut findings, &ctx);

    assert!(
        findings[0].points <= 15,
        "Reflection.Emit in Editor/ should be reduced to ≤15, got {}",
        findings[0].points
    );
}

#[test]
fn managed_dotnet_reduces_dll_outside_plugins() {
    let mut findings = vec![
        Finding::new(FindingId::DllOutsidePlugins, Severity::Medium, 35, "Assets/Lib.dll", "Outside"),
    ];
    let ctx = AnalysisContext {
        has_vrchat_sdk: false,
        is_managed_dotnet: true,
        in_editor_folder: false,
        has_loader_script: false,
    };
    apply_context_reductions(&mut findings, &ctx);

    assert_eq!(
        findings[0].points, 0,
        "DLL_OUTSIDE_PLUGINS should be zeroed for managed .NET DLL, got {}",
        findings[0].points
    );
}

#[test]
fn critical_findings_never_reduced_by_context() {
    // Process.Start is CRITICAL — context reductions should not apply to it
    let mut findings = vec![
        Finding::new(FindingId::CsProcessStart, Severity::Critical, 75, "Evil.cs", "Process"),
    ];
    let ctx = AnalysisContext {
        has_vrchat_sdk: true,
        is_managed_dotnet: true,
        in_editor_folder: true,
        has_loader_script: true,
    };
    apply_context_reductions(&mut findings, &ctx);

    assert_eq!(
        findings[0].points, 75,
        "CS_PROCESS_START points should not be reduced, got {}",
        findings[0].points
    );
}

// ─── Polyglot correlation tests ───────────────

#[test]
fn polyglot_without_loader_script_is_reduced() {
    // A polyglot texture/audio alone cannot execute — score should drop to 15.
    let mut findings = vec![
        Finding::new(FindingId::PolyglotFile, Severity::High, 70, "Assets/Textures/evil.png", "PE in PNG"),
    ];
    let ctx = AnalysisContext {
        has_vrchat_sdk: false,
        is_managed_dotnet: false,
        in_editor_folder: false,
        has_loader_script: false,
    };
    apply_context_reductions(&mut findings, &ctx);

    assert_eq!(
        findings[0].points, 15,
        "POLYGLOT_FILE without a loader should be reduced to 15 pts, got {}",
        findings[0].points
    );
    // Severity must not change (invariant from AGENTS.md)
    assert_eq!(findings[0].severity, Severity::High);
}

#[test]
fn polyglot_with_loader_script_keeps_full_score() {
    // When Assembly.Load / Process.Start is also present, the payload IS
    // potentially exploitable — keep the original 70 pts.
    let mut findings = vec![
        Finding::new(FindingId::PolyglotFile, Severity::High, 70, "Assets/Textures/evil.png", "PE in PNG"),
    ];
    let ctx = AnalysisContext {
        has_vrchat_sdk: false,
        is_managed_dotnet: false,
        in_editor_folder: false,
        has_loader_script: true,
    };
    apply_context_reductions(&mut findings, &ctx);

    assert_eq!(
        findings[0].points, 70,
        "POLYGLOT_FILE with a loader script should keep 70 pts, got {}",
        findings[0].points
    );
}

// ─── RiskLevel display ────────────────────────

#[test]
fn risk_level_display_strings() {
    assert_eq!(RiskLevel::Clean.to_string(), "CLEAN");
    assert_eq!(RiskLevel::Low.to_string(), "LOW");
    assert_eq!(RiskLevel::Medium.to_string(), "MEDIUM");
    assert_eq!(RiskLevel::High.to_string(), "HIGH");
    assert_eq!(RiskLevel::Critical.to_string(), "CRITICAL");
}
