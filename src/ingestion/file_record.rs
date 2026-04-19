use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use md5::Md5;
use sha1::Sha1;
use std::path::Path;

/// Type of the scanned file, determined by magic bytes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FileType {
    UnityPackage,
    ZipArchive,
    DllPe,
    CSharpScript,
    Prefab,
    Asset,
    MetaFile,
    Shader,
    Unknown,
}

impl std::fmt::Display for FileType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileType::UnityPackage => write!(f, "UnityPackage"),
            FileType::ZipArchive   => write!(f, "ZipArchive"),
            FileType::DllPe        => write!(f, "DllPe"),
            FileType::CSharpScript => write!(f, "CSharpScript"),
            FileType::Prefab       => write!(f, "Prefab"),
            FileType::Asset        => write!(f, "Asset"),
            FileType::MetaFile     => write!(f, "MetaFile"),
            FileType::Shader       => write!(f, "Shader"),
            FileType::Unknown      => write!(f, "Unknown"),
        }
    }
}

/// Complete record of the input file identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRecord {
    pub path: String,
    pub size_bytes: u64,
    pub file_type: FileType,
    pub sha256: String,
    pub md5: String,
    pub sha1: String,
    pub timestamp: DateTime<Utc>,
}

impl FileRecord {
    /// Build a FileRecord for the given file path.
    /// Computes SHA-256, MD5, SHA-1 and detects file type.
    pub fn from_path(path: &Path) -> crate::utils::Result<Self> {
        use std::fs;

        if !path.exists() {
            return Err(crate::utils::ScannerError::FileNotFound(
                path.to_string_lossy().into_owned(),
            ));
        }

        let data = fs::read(path)?;
        let size_bytes = data.len() as u64;

        // Compute hashes
        let sha256 = hex::encode(Sha256::digest(&data));
        let md5    = hex::encode(Md5::digest(&data));
        let sha1   = hex::encode(Sha1::digest(&data));

        // Detect type
        let file_type = crate::ingestion::type_detection::detect_type(&data, path);

        Ok(FileRecord {
            path: path.to_string_lossy().into_owned(),
            size_bytes,
            file_type,
            sha256,
            md5,
            sha1,
            timestamp: Utc::now(),
        })
    }
}
