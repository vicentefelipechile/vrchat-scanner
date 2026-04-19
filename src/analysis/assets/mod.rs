pub mod audio_scanner;
pub mod prefab_scanner;
pub mod texture_scanner;

use crate::report::Finding;
use crate::ingestion::AssetType;

/// Dispatch asset to the appropriate scanner.
pub fn analyze_asset(data: &[u8], asset_type: &AssetType, location: &str) -> Vec<Finding> {
    match asset_type {
        AssetType::Texture => texture_scanner::analyze(data, location),
        AssetType::Audio   => audio_scanner::analyze(data, location),
        AssetType::Prefab | AssetType::ScriptableObject => prefab_scanner::analyze(data, location),
        _ => Vec::new(),
    }
}
