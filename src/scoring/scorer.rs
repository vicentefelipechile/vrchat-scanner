use crate::config::{SCORE_CLEAN_MAX, SCORE_LOW_MAX, SCORE_MEDIUM_MAX, SCORE_HIGH_MAX};
use crate::report::Finding;

/// Final risk level classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    Clean,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Clean    => write!(f, "CLEAN"),
            RiskLevel::Low      => write!(f, "LOW"),
            RiskLevel::Medium   => write!(f, "MEDIUM"),
            RiskLevel::High     => write!(f, "HIGH"),
            RiskLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Compute total score and risk level from a list of findings.
///
/// The final level is the **maximum** of:
///   1. The score-band classification (sum of all points).
///   2. A severity-based floor: any `Critical`-severity finding forces the
///      level to at least `High`; two or more escalate it to `Critical`.
///
/// This prevents a single FORBIDDEN_EXTENSION (90 pts, Critical severity)
/// from being reported as "Medium" when the total score happens to be low.
pub fn compute_score(findings: &[Finding]) -> (u32, RiskLevel) {
    let score: u32 = findings.iter().map(|f| f.points).sum();
    let score_level = classify(score);

    let critical_count = findings
        .iter()
        .filter(|f| f.severity == crate::report::Severity::Critical)
        .count();

    let severity_floor = match critical_count {
        0 => RiskLevel::Clean,
        1 => RiskLevel::High,     // un solo finding Critical → al menos High
        _ => RiskLevel::Critical, // dos o más → Critical directo
    };

    let level = level_max(score_level, severity_floor);
    (score, level)
}

fn level_max(a: RiskLevel, b: RiskLevel) -> RiskLevel {
    if level_ord(a) >= level_ord(b) { a } else { b }
}

fn level_ord(l: RiskLevel) -> u8 {
    match l {
        RiskLevel::Clean    => 0,
        RiskLevel::Low      => 1,
        RiskLevel::Medium   => 2,
        RiskLevel::High     => 3,
        RiskLevel::Critical => 4,
    }
}

fn classify(score: u32) -> RiskLevel {
    if score <= SCORE_CLEAN_MAX       { RiskLevel::Clean    }
    else if score <= SCORE_LOW_MAX    { RiskLevel::Low      }
    else if score <= SCORE_MEDIUM_MAX { RiskLevel::Medium   }
    else if score <= SCORE_HIGH_MAX   { RiskLevel::High     }
    else                              { RiskLevel::Critical }
}