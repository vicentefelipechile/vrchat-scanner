use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Read};

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use tar::{Archive, Builder, Header};

/// Rebuild a `.unitypackage` (gzip-TAR) by:
///  - Skipping entries whose GUID is in `guids_to_remove`
///  - Replacing the `asset` file content for GUIDs in `guid_script_patches`
///  - Copying all other entries verbatim
///
/// Returns the new `.unitypackage` as an in-memory byte vector.
pub fn rebuild_unitypackage(
    original_data: &[u8],
    guids_to_remove: &HashSet<String>,
    guid_script_patches: &HashMap<String, Vec<u8>>,
) -> crate::utils::Result<Vec<u8>> {
    // ── Step 1: decompress gzip if needed ──────────────────────────────────
    let decompressed: Vec<u8>;
    let tar_data: &[u8];

    if original_data.starts_with(&[0x1f, 0x8b]) {
        let mut decoder = GzDecoder::new(Cursor::new(original_data));
        let mut buf = Vec::new();
        decoder.read_to_end(&mut buf).map_err(|e| {
            crate::utils::ScannerError::ExtractionError(format!("gzip decompress: {e}"))
        })?;
        decompressed = buf;
        tar_data = &decompressed;
    } else {
        tar_data = original_data;
    }

    // ── Step 2: iterate TAR, filter and/or patch entries ───────────────────
    let mut archive = Archive::new(Cursor::new(tar_data));

    // We write into a gzip-TAR in memory
    let out_buf: Vec<u8> = Vec::new();
    let gz_enc = GzEncoder::new(out_buf, Compression::new(6));
    let mut builder = Builder::new(gz_enc);

    for raw_entry in archive.entries().map_err(|e| {
        crate::utils::ScannerError::ExtractionError(format!("TAR read: {e}"))
    })? {
        let mut entry = raw_entry.map_err(|e| {
            crate::utils::ScannerError::ExtractionError(format!("TAR entry: {e}"))
        })?;

        let header_path = entry.path().map_err(|e| {
            crate::utils::ScannerError::ExtractionError(format!("TAR path: {e}"))
        })?;
        let path_str = header_path.to_string_lossy().to_string();

        // Unity structure: <guid>/<filename>
        let parts: Vec<&str> = path_str.splitn(2, '/').collect();
        let guid = parts[0];
        let filename = if parts.len() > 1 { parts[1] } else { "" };

        // ── Skip entire GUID ────────────────────────────────────────────────
        if guids_to_remove.contains(guid) {
            continue;
        }

        // ── Patch script asset bytes ────────────────────────────────────────
        if filename == "asset" {
            if let Some(patched_bytes) = guid_script_patches.get(guid) {
                let mut header = Header::new_gnu();
                header.set_size(patched_bytes.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();

                builder
                    .append_data(&mut header, &path_str, Cursor::new(patched_bytes))
                    .map_err(|e| {
                        crate::utils::ScannerError::ExtractionError(format!(
                            "TAR append patched: {e}"
                        ))
                    })?;
                continue; // processed, skip the verbatim copy below
            }
        }

        // ── Copy entry verbatim ─────────────────────────────────────────────
        let mut data = Vec::new();
        entry.read_to_end(&mut data).map_err(|e| {
            crate::utils::ScannerError::ExtractionError(format!("TAR read entry data: {e}"))
        })?;

        let orig_header = entry.header();
        let mut header = orig_header.clone();
        header.set_size(data.len() as u64);
        header.set_cksum();

        builder
            .append_data(&mut header, &path_str, Cursor::new(&data))
            .map_err(|e| {
                crate::utils::ScannerError::ExtractionError(format!("TAR append: {e}"))
            })?;
    }

    // ── Step 3: finalise TAR + gzip ────────────────────────────────────────
    let gz_enc = builder.into_inner().map_err(|e| {
        crate::utils::ScannerError::ExtractionError(format!("TAR finish: {e}"))
    })?;

    let result = gz_enc.finish().map_err(|e| {
        crate::utils::ScannerError::ExtractionError(format!("gzip finish: {e}"))
    })?;

    Ok(result)
}
