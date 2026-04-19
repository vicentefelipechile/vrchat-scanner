use serde::{Deserialize, Serialize};

/// Severity level of a finding
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low      => write!(f, "LOW"),
            Severity::Medium   => write!(f, "MEDIUM"),
            Severity::High     => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// A single detected finding from any analysis stage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique rule ID (e.g. "DLL_IMPORT_CREATEPROCESS")
    pub id: String,
    pub severity: Severity,
    /// Risk points contributed by this finding
    pub points: u32,
    /// File path inside the package (e.g. "Assets/Plugins/MyPlugin.dll")
    pub location: String,
    /// Human-readable description of the finding
    pub detail: String,
    /// Optional extra context (URL, function name, etc.)
    pub context: Option<String>,
}

impl Finding {
    pub fn new(
        id: impl Into<String>,
        severity: Severity,
        points: u32,
        location: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            severity,
            points,
            location: location.into(),
            detail: detail.into(),
            context: None,
        }
    }

    pub fn with_context(mut self, ctx: impl Into<String>) -> Self {
        self.context = Some(ctx.into());
        self
    }
}
