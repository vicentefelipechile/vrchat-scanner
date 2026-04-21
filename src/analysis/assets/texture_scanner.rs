use crate::config::*;
use crate::report::{Finding, FindingId, Severity};
use crate::utils::shannon_entropy;

// Magic bytes for common image formats
const PNG_MAGIC: &[u8] = &[0x89, 0x50, 0x4E, 0x47];
const JPG_MAGIC: &[u8] = &[0xFF, 0xD8, 0xFF];
const EXR_MAGIC: &[u8] = &[0x76, 0x2F, 0x31, 0x01];
const DDS_MAGIC: &[u8] = b"DDS ";
const HDR_MAGIC: &[u8] = b"#?RADIANCE";
const HDR_MAGIC_ALT: &[u8] = b"#?RGBE";

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
    // For natively-compressed formats we also use the magic check to decide
    // whether to skip entropy: if the bytes confirm the format is legitimate
    // we trust the high entropy is due to compression; if they don't match we
    // treat the file as suspicious and run entropy anyway.
    //
    // WebP: RIFF????WEBP — 4-byte RIFF header, 4-byte size, 4-byte "WEBP".
    // EXR:  76 2F 31 01
    // DDS:  "DDS " (4 ASCII bytes)
    // HDR:  "#?RADIANCE" or "#?RGBE" (Radiance RGBE format)
    let (magic_ok, is_natively_compressed) = match ext.as_str() {
        "png" => (data.starts_with(PNG_MAGIC), true),
        "jpg" | "jpeg" => (data.starts_with(JPG_MAGIC), true),
        "webp" => (
            data.len() >= 12 && data.starts_with(b"RIFF") && &data[8..12] == b"WEBP",
            true,
        ),
        "exr" => (data.starts_with(EXR_MAGIC), true),
        "dds" => (data.starts_with(DDS_MAGIC), true),
        "hdr" => (
            data.starts_with(HDR_MAGIC) || data.starts_with(HDR_MAGIC_ALT),
            true,
        ),
        // Unknown format: can't verify magic, not a known compressed format.
        _ => (true, false),
    };

    if !magic_ok {
        findings.push(
            Finding::new(
                FindingId::MagicMismatch,
                Severity::Medium,
                PTS_MAGIC_MISMATCH,
                location,
                "Magic bytes don't match the declared file extension",
            )
            .with_context(format!("declared_ext={ext}")),
        );
    }

    // 2. Overall entropy.
    //
    // Skip entropy only when the format is natively compressed AND the magic
    // bytes confirmed the file is genuine. If magic failed for a "compressed"
    // format we still run entropy — the file may be hiding a payload behind a
    // fake extension. For truly raw formats (BMP, TGA, PSD) always check.
    let skip_entropy = is_natively_compressed && magic_ok;
    if !skip_entropy {
        let entropy = shannon_entropy(data);
        if entropy > ENTROPY_TEXTURE_HIGH {
            findings.push(
                Finding::new(
                    FindingId::TextureHighEntropy,
                    Severity::Medium,
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
    //
    //    Checking only "MZ" (2 bytes) produces massive false positives because
    //    the byte sequence 0x4D 0x5A appears naturally in any compressed or
    //    encrypted binary stream.  We require:
    //
    //    PE polyglot:
    //      a) "MZ" at `offset`
    //      b) A plausible e_lfanew value at `offset + 0x3C` (must fit in data)
    //      c) The PE signature "PE\0\0" at the location e_lfanew points to
    //
    //    ZIP polyglot:
    //      Four bytes "PK\x03\x04" — much rarer to appear by chance.
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
            // bytes are "MZ" but no valid PE structure follows — skip quietly
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
///
/// Checks:
///   1. `base + 0x3F` fits inside `data` (minimum DOS stub size).
///   2. The little-endian u32 at `base + 0x3C` (`e_lfanew`) points to a
///      location that still fits inside `data`.
///   3. The four bytes at that location are exactly `PE\0\0`.
fn is_valid_pe_header(data: &[u8], base: usize) -> bool {
    // Need at least 64 bytes for the DOS header (0x40).
    let lfanew_off = base.wrapping_add(0x3C);
    if lfanew_off + 4 > data.len() {
        return false;
    }

    // Read e_lfanew as a little-endian u32.
    let e_lfanew = u32::from_le_bytes([
        data[lfanew_off],
        data[lfanew_off + 1],
        data[lfanew_off + 2],
        data[lfanew_off + 3],
    ]) as usize;

    // e_lfanew must be within a sane range and fit inside the buffer.
    let pe_sig_off = base.wrapping_add(e_lfanew);
    if e_lfanew < 0x40 || pe_sig_off + 4 > data.len() {
        return false;
    }

    // The PE signature must be "PE\0\0".
    &data[pe_sig_off..pe_sig_off + 4] == b"PE\0\0"
}
