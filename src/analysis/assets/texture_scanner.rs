use crate::config::*;
use crate::report::{Finding, FindingId, Severity};
use crate::utils::shannon_entropy;

// Magic bytes for common image formats
const PNG_MAGIC:  &[u8] = &[0x89, 0x50, 0x4E, 0x47];
const JPG_MAGIC:  &[u8] = &[0xFF, 0xD8, 0xFF];
const EXR_MAGIC:  &[u8] = &[0x76, 0x2F, 0x31, 0x01];
const DDS_MAGIC:  &[u8] = b"DDS ";
const HDR_MAGIC:  &[u8] = b"#?RADIANCE";
const HDR_MAGIC_ALT: &[u8] = b"#?RGBE";
// BMP: "BM"
const BMP_MAGIC:  &[u8] = b"BM";
// TGA has no universal magic — identified by elimination / extension only
// PSD: "8BPS"
const PSD_MAGIC:  &[u8] = b"8BPS";

/// Returns true if `data` starts with the magic bytes of any known image format.
fn is_any_image(data: &[u8]) -> bool {
    data.starts_with(PNG_MAGIC)
        || data.starts_with(JPG_MAGIC)
        || data.starts_with(EXR_MAGIC)
        || data.starts_with(DDS_MAGIC)
        || data.starts_with(HDR_MAGIC)
        || data.starts_with(HDR_MAGIC_ALT)
        || data.starts_with(BMP_MAGIC)
        || data.starts_with(PSD_MAGIC)
        || (data.len() >= 12 && data.starts_with(b"RIFF") && &data[8..12] == b"WEBP")
}

/// Scan a texture file for anomalies.
pub fn analyze(data: &[u8], location: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let ext = std::path::Path::new(location)
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_lowercase())
        .unwrap_or_default();

    // 1. Magic bytes vs declared extension.
    //
    // Three possible outcomes:
    //   a) magic matches declared extension           → magic_ok = true
    //   b) magic doesn't match BUT is still an image  → MAGIC_MISMATCH_IMAGE (Low, 2pts)
    //   c) magic doesn't match AND is not any image   → MAGIC_MISMATCH (Medium, 25pts)
    //
    // is_natively_compressed is only true when the magic confirms the format,
    // so a mislabelled compressed image still goes through entropy.
    let (magic_ok, is_natively_compressed) = match ext.as_str() {
        "png"       => (data.starts_with(PNG_MAGIC), true),
        "jpg" | "jpeg" => (data.starts_with(JPG_MAGIC), true),
        "webp"      => (
            data.len() >= 12 && data.starts_with(b"RIFF") && &data[8..12] == b"WEBP",
            true,
        ),
        "exr"       => (data.starts_with(EXR_MAGIC), true),
        "dds"       => (data.starts_with(DDS_MAGIC), true),
        "hdr"       => (
            data.starts_with(HDR_MAGIC) || data.starts_with(HDR_MAGIC_ALT),
            true,
        ),
        "bmp"       => (data.starts_with(BMP_MAGIC), false),
        "psd"       => (data.starts_with(PSD_MAGIC), false),
        // TGA has no magic bytes — treat as matching to avoid false positives
        "tga"       => (true, false),
        // Unknown extension: can't verify magic, not a known compressed format
        _           => (true, false),
    };

    if !magic_ok {
        if is_any_image(data) {
            // The file is a valid image, just a different format than declared.
            // Low severity — mislabelled but not inherently malicious.
            findings.push(
                Finding::new(
                    FindingId::MagicMismatchImage,
                    Severity::Low,
                    PTS_MAGIC_MISMATCH_IMAGE,
                    location,
                    "File is a valid image but in a different format than its extension suggests",
                )
                .with_context(format!("declared_ext={ext}")),
            );
        } else {
            // The file is not any recognised image format — much more suspicious.
            findings.push(
                Finding::new(
                    FindingId::MagicMismatch,
                    Severity::Medium,
                    PTS_MAGIC_MISMATCH,
                    location,
                    "Magic bytes don't match the declared file extension and file is not a recognised image format",
                )
                .with_context(format!("declared_ext={ext}")),
            );
        }
    }

    // 2. Overall entropy.
    //
    // Skip only when the format is natively compressed AND magic confirmed it.
    // A mislabelled compressed image still goes through entropy.
    let skip_entropy = is_natively_compressed && magic_ok;
    if !skip_entropy {
        let entropy = shannon_entropy(data);
        if entropy > ENTROPY_TEXTURE_HIGH {
            findings.push(
                Finding::new(
                    FindingId::TextureHighEntropy,
                    Severity::Low,
                    PTS_TEXTURE_HIGH_ENTROPY,
                    location,
                    format!(
                        "Texture file has high entropy {:.2} (possible embedded payload)",
                        entropy
                    ),
                )
                .with_context(format!("entropy={:.4}", entropy)),
            );
        }
    }

    // 3. Polyglot scan — look for a *valid PE structure* or ZIP magic within
    //    the image data, starting after byte 16 (legitimate format header area).
    let skip = 16_usize;
    for offset in skip..data.len().saturating_sub(3) {
        let window = &data[offset..offset + 4];

        // --- PE / MZ ---
        if window.starts_with(b"MZ") {
            if is_valid_pe_header(data, offset) {
                findings.push(
                    Finding::new(
                        FindingId::PolyglotFile,
                        Severity::High,
                        PTS_POLYGLOT_FILE,
                        location,
                        "Valid PE header found inside texture file — polyglot payload detected",
                    )
                    .with_context(format!("offset=0x{:X}", offset)),
                );
                break;
            }
            continue;
        }

        // --- ZIP / PK ---
        if window == b"PK\x03\x04" {
            findings.push(
                Finding::new(
                    FindingId::PolyglotFile,
                    Severity::High,
                    PTS_POLYGLOT_FILE,
                    location,
                    "ZIP (PK) header found inside texture file — polyglot payload detected",
                )
                .with_context(format!("offset=0x{:X}", offset)),
            );
            break;
        }
    }

    findings
}

/// Returns `true` only when the bytes at `base` inside `data` look like a
/// genuine DOS/PE header — not just an accidental "MZ" sequence.
fn is_valid_pe_header(data: &[u8], base: usize) -> bool {
    let lfanew_off = base.wrapping_add(0x3C);
    if lfanew_off + 4 > data.len() {
        return false;
    }
    let e_lfanew = u32::from_le_bytes([
        data[lfanew_off],
        data[lfanew_off + 1],
        data[lfanew_off + 2],
        data[lfanew_off + 3],
    ]) as usize;
    let pe_sig_off = base.wrapping_add(e_lfanew);
    if e_lfanew < 0x40 || pe_sig_off + 4 > data.len() {
        return false;
    }
    &data[pe_sig_off..pe_sig_off + 4] == b"PE\0\0"
}