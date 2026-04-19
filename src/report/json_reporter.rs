use serde::{Deserialize, Serialize};

use crate::ingestion::FileRecord;
use crate::scoring::RiskLevel;
use super::finding::Finding;

/// Full scan result, suitable for serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub schema_version: String,
    pub scanner: String,
    pub file: FileRecord,
    pub risk: RiskSummary,
    pub findings: Vec<Finding>,
    pub assets_analyzed: AssetCounts,
    pub scan_duration_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskSummary {
    pub score: u32,
    pub level: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AssetCounts {
    pub total: usize,
    pub dlls: usize,
    pub scripts: usize,
    pub textures: usize,
    pub prefabs: usize,
    pub audio: usize,
    pub other: usize,
}

impl ScanReport {
    pub fn build(
        file: FileRecord,
        mut findings: Vec<Finding>,
        score: u32,
        level: RiskLevel,
        counts: AssetCounts,
        duration_ms: u128,
    ) -> Self {
        // Sort findings by severity desc, then points desc
        findings.sort_by(|a, b| {
            b.severity.cmp(&a.severity).then(b.points.cmp(&a.points))
        });

        let (level_str, recommendation) = match level {
            RiskLevel::Clean    => ("CLEAN",    "AutoPublish"),
            RiskLevel::Low      => ("LOW",      "PublishWithNote"),
            RiskLevel::Medium   => ("MEDIUM",   "ManualReviewRecommended"),
            RiskLevel::High     => ("HIGH",     "ManualReviewRequired"),
            RiskLevel::Critical => ("CRITICAL", "AutoReject"),
        };

        ScanReport {
            schema_version: "1.0".to_string(),
            scanner: "vrcstorage-scanner".to_string(),
            file,
            risk: RiskSummary {
                score,
                level: level_str.to_string(),
                recommendation: recommendation.to_string(),
            },
            findings,
            assets_analyzed: counts,
            scan_duration_ms: duration_ms,
        }
    }
}

/// Serialize the report to a pretty-printed JSON string
pub fn to_json(report: &ScanReport) -> crate::utils::Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}
