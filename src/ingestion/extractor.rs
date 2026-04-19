use std::collections::HashMap;
use std::io::{Cursor, Read};
use serde::{Deserialize, Serialize};

use super::file_record::FileType;

/// Unity asset type classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AssetType {
    Script,
    Dll,
    Shader,
    Prefab,
    ScriptableObject,
    Texture,
    Audio,
    AnimationClip,
    Meta,
    Other(String),
}

/// A single entry inside a Unity package
#[derive(Debug, Clone)]
pub struct PackageEntry {
    pub original_path: String,
    pub asset_type: AssetType,
    pub bytes: Vec<u8>,
    /// Parsed content of the .meta file for this entry, if available
    pub meta_content: Option<String>,
}

/// The full extracted tree of a package
#[derive(Debug, Default)]
pub struct PackageTree {
    pub entries: HashMap<String, PackageEntry>,
}

impl PackageTree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn all_entries(&self) -> impl Iterator<Item = &PackageEntry> {
        self.entries.values()
    }
}

/// Classify asset by path extension
fn asset_type_from_ext(original_path: &str) -> AssetType {
    let ext = std::path::Path::new(original_path)
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "cs"   => AssetType::Script,
        "dll"  => AssetType::Dll,
        "shader" | "cginc" | "hlsl" | "glsl" => AssetType::Shader,
        "prefab" => AssetType::Prefab,
        "asset"  => AssetType::ScriptableObject,
        "png" | "jpg" | "jpeg" | "tga" | "exr" | "bmp" | "tiff" => AssetType::Texture,
        "wav" | "mp3" | "ogg" | "aif" | "aiff" => AssetType::Audio,
        "anim" => AssetType::AnimationClip,
        "meta" => AssetType::Meta,
        other  => AssetType::Other(other.to_string()),
    }
}

/// Extract a .unitypackage or .zip into a PackageTree (in-memory)
pub fn extract(data: &[u8], file_type: &FileType) -> crate::utils::Result<PackageTree> {
    match file_type {
        FileType::UnityPackage => extract_unity_package(data),
        FileType::ZipArchive   => extract_zip(data),
        _                      => {
            // Single file — wrap as a single entry
            let mut tree = PackageTree::new();
            tree.entries.insert(
                "direct".to_string(),
                PackageEntry {
                    original_path: "unknown".to_string(),
                    asset_type: AssetType::Other("direct".to_string()),
                    bytes: data.to_vec(),
                    meta_content: None,
                },
            );
            Ok(tree)
        }
    }
}

fn extract_unity_package(data: &[u8]) -> crate::utils::Result<PackageTree> {
    // .unitypackage is a gzip-compressed TAR
    // Try gzip first, then plain TAR
    let decompressed: Vec<u8>;
    let tar_data: &[u8];

    if data.starts_with(&[0x1f, 0x8b]) {
        use flate2::read::GzDecoder;
        let mut decoder = GzDecoder::new(Cursor::new(data));
        let mut buf = Vec::new();
        decoder.read_to_end(&mut buf).map_err(|e| {
            crate::utils::ScannerError::ExtractionError(format!("gzip decompress: {e}"))
        })?;
        decompressed = buf;
        tar_data = &decompressed;
    } else {
        tar_data = data;
    }

    let mut archive = tar::Archive::new(Cursor::new(tar_data));

    // Intermediate storage before building entries:
    // guid -> (original_path, asset_bytes, meta_bytes)
    let mut paths: HashMap<String, String>    = HashMap::new();
    let mut assets: HashMap<String, Vec<u8>>  = HashMap::new();
    let mut metas: HashMap<String, Vec<u8>>   = HashMap::new();

    for entry in archive.entries().map_err(|e| {
        crate::utils::ScannerError::ExtractionError(format!("TAR read: {e}"))
    })? {
        let mut entry = entry.map_err(|e| {
            crate::utils::ScannerError::ExtractionError(format!("TAR entry: {e}"))
        })?;

        let header_path = entry.path().map_err(|e| {
            crate::utils::ScannerError::ExtractionError(format!("TAR path: {e}"))
        })?;
        let path_str = header_path.to_string_lossy().to_string();

        // Unity package structure: <guid>/<filename>
        let parts: Vec<&str> = path_str.splitn(3, '/').collect();
        if parts.len() < 2 {
            continue;
        }
        let guid = parts[0].to_string();
        let filename = parts[1];

        let mut buf = Vec::new();
        entry.read_to_end(&mut buf).unwrap_or(0);

        match filename {
            "pathname"   => { paths.insert(guid, String::from_utf8_lossy(&buf).trim().to_string()); }
            "asset"      => { assets.insert(guid, buf); }
            "asset.meta" => { metas.insert(guid, buf); }
            _ => {}
        }
    }

    // Merge
    let mut tree = PackageTree::new();
    for (guid, asset_bytes) in assets {
        let original_path = paths.get(&guid).cloned().unwrap_or_else(|| guid.clone());
        let asset_type = asset_type_from_ext(&original_path);
        let meta_content = metas.get(&guid)
            .map(|b| String::from_utf8_lossy(b).to_string());

        tree.entries.insert(guid.clone(), PackageEntry {
            original_path,
            asset_type,
            bytes: asset_bytes,
            meta_content,
        });
    }

    // Also add entries that only have pathname (no asset bytes) — helps detect orphan .cs without meta
    for (guid, original_path) in &paths {
        if !tree.entries.contains_key(guid) {
            let asset_type = asset_type_from_ext(original_path);
            let meta_content = metas.get(guid)
                .map(|b| String::from_utf8_lossy(b).to_string());
            tree.entries.insert(guid.clone(), PackageEntry {
                original_path: original_path.clone(),
                asset_type,
                bytes: Vec::new(),
                meta_content,
            });
        }
    }

    Ok(tree)
}

fn extract_zip(data: &[u8]) -> crate::utils::Result<PackageTree> {
    use zip::ZipArchive;

    let cursor = Cursor::new(data);
    let mut archive = ZipArchive::new(cursor).map_err(|e| {
        crate::utils::ScannerError::ExtractionError(format!("ZIP open: {e}"))
    })?;

    let mut tree = PackageTree::new();
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).map_err(|e| {
            crate::utils::ScannerError::ExtractionError(format!("ZIP entry {i}: {e}"))
        })?;

        if file.is_dir() {
            continue;
        }

        let name = file.name().to_string();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap_or(0);

        let asset_type = asset_type_from_ext(&name);
        let id = format!("zip_{i}");
        tree.entries.insert(id, PackageEntry {
            original_path: name,
            asset_type,
            bytes: buf,
            meta_content: None,
        });
    }

    Ok(tree)
}
