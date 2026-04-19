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
pub fn compute_score(findings: &[Finding]) -> (u32, RiskLevel) {
    let score: u32 = findings.iter().map(|f| f.points).sum();
    let level = classify(score);
    (score, level)
}

fn classify(score: u32) -> RiskLevel {
    match score {
        0..=30  => RiskLevel::Clean,
        31..=60 => RiskLevel::Low,
        61..=100 => RiskLevel::Medium,
        101..=150 => RiskLevel::High,
        _ => RiskLevel::Critical,
    }
}
