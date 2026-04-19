use std::path::Path;
use super::file_record::FileType;

/// Detect file type from magic bytes and file extension.
pub fn detect_type(data: &[u8], path: &Path) -> FileType {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_lowercase())
        .unwrap_or_default();

    // Check magic bytes first
    if data.starts_with(b"PK\x03\x04") {
        // ZIP magic — could be unitypackage or plain zip
        if ext == "unitypackage" {
            return FileType::UnityPackage;
        }
        return FileType::ZipArchive;
    }

    // TAR/gzip magic (used by legacy .unitypackage)
    if data.starts_with(&[0x1f, 0x8b]) {
        return FileType::UnityPackage;
    }
    // Plain TAR magic
    if data.len() >= 512 && &data[257..262] == b"ustar" {
        return FileType::UnityPackage;
    }

    // PE magic (MZ)
    if data.starts_with(b"MZ") {
        return FileType::DllPe;
    }

    // YAML/text detection by extension
    match ext.as_str() {
        "cs"          => FileType::CSharpScript,
        "prefab"      => FileType::Prefab,
        "asset"       => FileType::Asset,
        "meta"        => FileType::MetaFile,
        "shader" | "cginc" | "hlsl" | "glsl" => FileType::Shader,
        "dll"         => FileType::DllPe,
        "unitypackage" => FileType::UnityPackage,
        "zip"         => FileType::ZipArchive,
        _             => FileType::Unknown,
    }
}
