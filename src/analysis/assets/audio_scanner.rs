use crate::report::{Finding, FindingId, Severity};
use crate::utils::shannon_entropy;

/// Scan an audio file for anomalies.
pub fn analyze(data: &[u8], location: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let ext = std::path::Path::new(location)
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_lowercase())
        .unwrap_or_default();

    // 1. Entropy check.
    //
    // MP3, OGG, FLAC, and AAC are all compressed audio formats and can easily
    // reach entropy >= 7.8.  Only flag when the value is clearly abnormal:
    //   – very low (< 4.0) → almost certainly not audio
    //   – extremely high (> 7.97) → essentially random, unusual even for
    //     compressed audio and worth noting
    //
    // Natively-compressed formats (ogg, mp3, aac, flac) are excluded from the
    // upper bound because DEFLATE/Vorbis compression naturally pushes entropy
    // towards 8.0.
    let is_compressed_audio = matches!(
        ext.as_str(),
        "mp3" | "ogg" | "aac" | "flac" | "opus" | "m4a"
    );

    let entropy = shannon_entropy(data);
    let unusual = if is_compressed_audio {
        // For compressed formats only flag when it is suspiciously *low* —
        // a compressed audio file with entropy < 4.0 is very odd.
        entropy < 4.0
    } else {
        // For uncompressed formats (wav, aiff, raw pcm) flag both extremes.
        !(5.0..=7.9).contains(&entropy)
    };

    if unusual {
        findings.push(
            Finding::new(
                FindingId::AudioUnusualEntropy,
                Severity::Low,
                8,
                location,
                format!("Audio file has unusual entropy {:.2}", entropy),
            )
            .with_context(format!("entropy={:.4}", entropy)),
        );
    }

    // 2. Polyglot scan — look for a *valid PE structure* or ZIP magic inside
    //    the audio data, starting after byte 16 (audio header area).
    //
    //    A bare "MZ" check produces too many false positives on compressed
    //    audio data.  We require the full DOS+PE header structure.
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
                        70,
                        location,
                        "Valid PE header found inside audio file — polyglot payload detected",
                    )
                    .with_context(format!("offset=0x{:X}", offset)),
                );
                break;
            }
            continue;
        }

        // --- ZIP / PK (4-byte signature, rare by coincidence) ---
        if window == b"PK\x03\x04" {
            findings.push(
                Finding::new(
                    FindingId::PolyglotFile,
                    Severity::High,
                    70,
                    location,
                    "ZIP (PK) header found inside audio file — polyglot payload detected",
                )
                .with_context(format!("offset=0x{:X}", offset)),
            );
            break;
        }
    }

    findings
}

/// Returns `true` only when the bytes at `base` inside `data` look like a
/// genuine DOS/PE header — not just an accidental "MZ" byte pair.
///
/// Checks:
///   1. At least 64 bytes remain after `base`.
///   2. The little-endian u32 at `base + 0x3C` (`e_lfanew`) is >= 0x40 and
///      points to a location that fits inside `data`.
///   3. The four bytes at `e_lfanew` are exactly `PE\0\0`.
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
