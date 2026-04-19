use chrono::{DateTime, Utc};
use crate::report::{Finding, Severity};

/// Parse a Unity .meta YAML file and extract relevant information.
pub struct MetaInfo {
    pub guid: Option<String>,
    pub time_created: Option<DateTime<Utc>>,
    pub has_external_objects: bool,
}

/// Analyze a .meta file's content for anomalies.
pub fn analyze(content: &str, location: &str) -> (MetaInfo, Vec<Finding>) {
    let mut findings = Vec::new();
    let mut info = MetaInfo {
        guid: None,
        time_created: None,
        has_external_objects: false,
    };

    for line in content.lines() {
        let line = line.trim();

        // Extract GUID
        if let Some(guid_part) = line.strip_prefix("guid:") {
            info.guid = Some(guid_part.trim().to_string());
        }

        // Extract timeCreated
        if let Some(ts_part) = line.strip_prefix("timeCreated:") {
            if let Ok(ts) = ts_part.trim().parse::<i64>() {
                use chrono::TimeZone;
                if let chrono::LocalResult::Single(dt) = Utc.timestamp_opt(ts, 0) {
                    // Timestamp in the future?
                    if dt > Utc::now() {
                        findings.push(
                            Finding::new(
                                "META_FUTURE_TIMESTAMP",
                                Severity::Medium,
                                20,
                                location,
                                "Meta file has a timestamp set in the future (possible manipulation)",
                            )
                            .with_context(format!("timestamp={}", dt.to_rfc3339())),
                        );
                    }
                    info.time_created = Some(dt);
                }
            }
        }

        // External objects
        if line.starts_with("externalObjects:") && !line.contains("{}") {
            info.has_external_objects = true;
            findings.push(Finding::new(
                "META_EXTERNAL_REF",
                Severity::Medium,
                25,
                location,
                "Meta file contains external object references (assets not included in package)",
            ));
        }
    }

    (info, findings)
}
