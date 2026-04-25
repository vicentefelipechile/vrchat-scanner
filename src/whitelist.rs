//! # Known-file whitelist
//!
//! Implements a three-step verification flow:
//!
//! 1. Does the asset path match any whitelist entry?  NO → full analysis.
//! 2. Does the SHA-256 match a known trusted hash?    YES → `FullyTrusted` (skip all findings).
//! 3. Hash mismatch (or no hashes registered yet)?   → `Modified`: obfuscation-only analysis
//!    with extra context attached to every finding.
//!
//! **Data** (entries, hashes, line ranges) live in `crate::config`.
//! **Logic** (structs, enum, `check` function) lives here.

use sha2::{Digest, Sha256};

use crate::config::WHITELIST;

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

/// Outcome of evaluating a C# asset against the known-file whitelist.
#[allow(dead_code)] // `name` fields are kept for future logging/context use
pub enum WhitelistVerdict {
    /// The asset path does not match any whitelist entry.
    /// Full analysis should proceed as normal.
    NotWhitelisted,

    /// The asset SHA-256 matches a known trusted hash.
    /// No findings should be emitted for this asset.
    FullyTrusted { name: &'static str },

    /// The asset matches a whitelist entry by path, but the SHA-256 does not
    /// match any known hash (modified or unknown version).
    /// Only obfuscation checks should run; findings must carry extra context.
    Modified {
        name: &'static str,
        /// `true` if the file's line count falls within `WhitelistEntry::expected_line_range`,
        /// or if no range is configured (no restriction). Informational only — does not block.
        line_count_ok: bool,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Check whether a C# asset is whitelisted and determine which analysis to run.
///
/// # Parameters
/// - `location` — internal asset path within the package (e.g. `"Assets/Poiyomi/PoiExternalToolRegistry.cs"`).
/// - `data`     — raw file bytes (used to compute SHA-256).
/// - `source`   — UTF-8 file content (used to count lines).
pub fn check(location: &str, data: &[u8], source: &str) -> WhitelistVerdict {
    // Find the first entry whose path_patterns all appear in the location (AND logic).
    let entry = WHITELIST.iter().find(|e| {
        e.path_patterns.iter().all(|pat| location.contains(pat))
    });

    let entry = match entry {
        None => return WhitelistVerdict::NotWhitelisted,
        Some(e) => e,
    };

    // If hashes are registered, compute SHA-256 and compare.
    if !entry.sha256_hashes.is_empty() {
        let hash = hex::encode(Sha256::digest(data));
        if entry.sha256_hashes.contains(&hash.as_str()) {
            return WhitelistVerdict::FullyTrusted { name: entry.name };
        }
    }

    // SHA-256 did not match (or no hashes registered yet) → Modified mode.
    let line_count_ok = match entry.expected_line_range {
        None => true, // no restriction configured
        Some((min, max)) => {
            let lines = source.lines().count();
            lines >= min && lines <= max
        }
    };

    WhitelistVerdict::Modified {
        name: entry.name,
        line_count_ok,
    }
}
