use std::fmt::Write as FmtWrite;

use crate::report::finding::{Finding, Severity};
use crate::report::json_reporter::ScanReport;
use crate::scoring::RiskLevel;

/// One entry in a multi-file scan session.
pub struct BatchEntry<'a> {
    pub report: &'a ScanReport,
    pub level: RiskLevel,
    pub sanitized: bool,
}

/// Render a human-readable plain-text report for a batch of scanned files.
/// No ANSI escape codes — safe to write directly to a .txt file.
pub fn render_batch_txt(entries: &[BatchEntry<'_>]) -> String {
    let mut out = String::new();

    let divider = "=".repeat(70);
    let thin     = "-".repeat(70);

    // ── Header ────────────────────────────────────────────────────────────
    writeln!(out, "{divider}").unwrap();
    writeln!(out, "  vrcstorage-scanner — Batch Scan Report").unwrap();
    writeln!(out, "  Generated: {}", chrono::Utc::now().to_rfc2822()).unwrap();
    writeln!(out, "  Files scanned: {}", entries.len()).unwrap();
    writeln!(out, "{divider}").unwrap();
    writeln!(out).unwrap();

    // ── Summary table ─────────────────────────────────────────────────────
    writeln!(out, "SUMMARY").unwrap();
    writeln!(out, "{thin}").unwrap();
    writeln!(out, "  {:<6}  {:<12}  {:<8}  {}",
        "Score", "Risk Level", "Sanitize", "File").unwrap();
    writeln!(out, "  {:<6}  {:<12}  {:<8}  {}",
        "-----", "----------", "--------", "----").unwrap();

    for entry in entries {
        let sanitize_str = if entry.sanitized { "YES" } else { "no" };
        let filename = std::path::Path::new(&entry.report.file.path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(&entry.report.file.path);
        writeln!(out, "  {:<6}  {:<12}  {:<8}  {}",
            entry.report.risk.score,
            level_str(entry.level),
            sanitize_str,
            filename,
        ).unwrap();
    }
    writeln!(out).unwrap();

    // ── Per-file detail ───────────────────────────────────────────────────
    for (i, entry) in entries.iter().enumerate() {
        writeln!(out, "{divider}").unwrap();
        writeln!(out, "  FILE {}/{}: {}",
            i + 1, entries.len(), entry.report.file.path).unwrap();
        writeln!(out, "{divider}").unwrap();
        writeln!(out, "  SHA-256 : {}", entry.report.file.sha256).unwrap();
        writeln!(out, "  Size    : {}", format_bytes(entry.report.file.size_bytes)).unwrap();
        writeln!(out, "  Score   : {}  |  Risk: {}  |  Duration: {}  |  Action: {}",
            entry.report.risk.score,
            level_str(entry.level),
            format_duration(entry.report.scan_duration_ms),
            entry.report.risk.recommendation,
        ).unwrap();

        // Asset stats
        let c = &entry.report.assets_analyzed;
        writeln!(out,
            "  Assets  : total={} scripts={} dlls={} textures={} audio={} prefabs={}",
            c.total, c.scripts, c.dlls, c.textures, c.audio, c.prefabs,
        ).unwrap();

        if entry.sanitized {
            writeln!(out, "  [SANITIZED COPY CREATED]").unwrap();
        }
        writeln!(out).unwrap();

        // Findings
        if entry.report.findings.is_empty() {
            writeln!(out, "  No findings detected.").unwrap();
        } else {
            writeln!(out, "  FINDINGS ({}):", entry.report.findings.len()).unwrap();
            writeln!(out, "  {thin}").unwrap();
            for f in &entry.report.findings {
                render_finding(&mut out, f);
            }
        }

        // Verdict
        writeln!(out).unwrap();
        writeln!(out, "  VERDICT: {}", verdict_text(entry.level)).unwrap();
        writeln!(out).unwrap();
    }

    // ── Footer ────────────────────────────────────────────────────────────
    writeln!(out, "{divider}").unwrap();

    let clean_count    = entries.iter().filter(|e| e.level == RiskLevel::Clean).count();
    let low_count      = entries.iter().filter(|e| e.level == RiskLevel::Low).count();
    let medium_count   = entries.iter().filter(|e| e.level == RiskLevel::Medium).count();
    let high_count     = entries.iter().filter(|e| e.level == RiskLevel::High).count();
    let critical_count = entries.iter().filter(|e| e.level == RiskLevel::Critical).count();
    let sanitized_count = entries.iter().filter(|e| e.sanitized).count();

    writeln!(out, "  OVERALL RESULTS").unwrap();
    writeln!(out, "  {thin}").unwrap();
    writeln!(out, "  Clean    : {clean_count}").unwrap();
    writeln!(out, "  Low      : {low_count}").unwrap();
    writeln!(out, "  Medium   : {medium_count}").unwrap();
    writeln!(out, "  High     : {high_count}").unwrap();
    writeln!(out, "  Critical : {critical_count}").unwrap();
    writeln!(out, "  Sanitized: {sanitized_count}").unwrap();
    writeln!(out, "{divider}").unwrap();
    writeln!(out, "  vrcstorage-scanner by SummerTYT").unwrap();
    writeln!(out, "{divider}").unwrap();

    out
}

/// Render a single ScanReport to plain text (single-file mode).
pub fn render_single_txt(report: &ScanReport, level: RiskLevel, sanitized: bool) -> String {
    let entry = BatchEntry { report, level, sanitized };
    render_batch_txt(&[entry])
}

fn render_finding(out: &mut String, f: &Finding) {
    let sev = match f.severity {
        Severity::Critical => "CRITICAL",
        Severity::High     => "HIGH    ",
        Severity::Medium   => "MEDIUM  ",
        Severity::Low      => "LOW     ",
    };
    writeln!(out, "  [{sev} +{:>3}pt]  {}  ({})",
        f.points, f.detail, f.id).unwrap();
    writeln!(out, "             File: {}", f.location).unwrap();
    if let Some(ctx) = &f.context {
        writeln!(out, "             Context: {ctx}").unwrap();
    }
    if !f.line_numbers.is_empty() {
        let lines: Vec<String> = f.line_numbers.iter().map(|n| n.to_string()).collect();
        writeln!(out, "             Lines: {}", lines.join(", ")).unwrap();
    }
    writeln!(out).unwrap();
}

fn level_str(level: RiskLevel) -> &'static str {
    match level {
        RiskLevel::Clean    => "CLEAN",
        RiskLevel::Low      => "LOW",
        RiskLevel::Medium   => "MEDIUM",
        RiskLevel::High     => "HIGH",
        RiskLevel::Critical => "CRITICAL",
    }
}

fn verdict_text(level: RiskLevel) -> &'static str {
    match level {
        RiskLevel::Clean    => "SAFE TO USE — no significant concerns found.",
        RiskLevel::Low      => "LIKELY SAFE — minor concerns, review findings if unsure.",
        RiskLevel::Medium   => "REVIEW RECOMMENDED — moderate concerns, trust the source before installing.",
        RiskLevel::High     => "NOT RECOMMENDED — dangerous code detected, mandatory manual review.",
        RiskLevel::Critical => "DO NOT INSTALL — potentially malicious, may compromise your system.",
    }
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if bytes >= GB      { format!("{:.1} GB", bytes as f64 / GB as f64) }
    else if bytes >= MB { format!("{:.1} MB", bytes as f64 / MB as f64) }
    else if bytes >= KB { format!("{:.1} KB", bytes as f64 / KB as f64) }
    else                { format!("{} B", bytes) }
}

fn format_duration(ms: u128) -> String {
   if ms < 1_000 { format!("{ms}ms") } else { format!("{:.2}s", ms as f64 / 1_000.0) }
}