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
pub fn compute_score(findings: &[Finding]) -> (u32, RiskLevel) {
    let score: u32 = findings.iter().map(|f| f.points).sum();
    let level = classify(score);
    (score, level)
}

fn classify(score: u32) -> RiskLevel {
    if score <= SCORE_CLEAN_MAX  { RiskLevel::Clean    }
    else if score <= SCORE_LOW_MAX    { RiskLevel::Low      }
    else if score <= SCORE_MEDIUM_MAX { RiskLevel::Medium   }
    else if score <= SCORE_HIGH_MAX   { RiskLevel::High     }
    else                              { RiskLevel::Critical }
}
