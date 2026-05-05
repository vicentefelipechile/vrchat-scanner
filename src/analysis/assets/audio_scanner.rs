use crate::config::*;
use crate::report::{Finding, FindingId, Severity};
use crate::utils::shannon_entropy;

// ─────────────────────────────────────────────────────────────────────────────
// Known RIFF chunk IDs that are standard / innocuous in WAV files.
// Anything not on this list and carrying ≥ AUDIO_SUSPICIOUS_CHUNK_MIN_BYTES
// bytes is flagged as AudioSuspiciousChunk.
//
// References:
//   – RIFF spec (Microsoft Multimedia Programming Reference)
//   – Broadcast Wave Format (EBU R 68-2000): adds "bext", "junk", "md5"
//   – iXML spec: adds "iXML"
//   – AIFF/AIFC spec: FORM, COMM, SSND, MARK, INST, MIDI, AESD, APPL
// ─────────────────────────────────────────────────────────────────────────────
const KNOWN_RIFF_CHUNKS: &[&[u8; 4]] = &[
    b"fmt ", // WAV audio format descriptor     (mandatory)
    b"data", // WAV PCM sample data             (mandatory)
    b"fact", // WAV compressed-format metadata  (optional)
    b"LIST", // Container for sub-chunks        (optional; holds INFO, adtl…)
    b"INFO", // Metadata (title, artist…)       (inside LIST)
    b"JUNK", // Alignment padding               (optional)
    b"junk", // Lowercase variant               (optional)
    b"PAD ", // Padding                         (optional)
    b"bext", // Broadcast Wave Extension        (EBU)
    b"iXML", // iXML metadata                   (post-production)
    b"id3 ", // ID3 tag embedded in WAV         (uncommon but valid)
    b"ID3 ", // Uppercase variant
    b"_PMX", // Adobe XMP metadata              (uncommon but valid)
    b"minf", // Apple/AIFF minimal info         (AIFF)
    b"elm1", // ELM1 chunk                      (AIFF extensions)
    b"cue ", // Cue point list                  (DAW markers)
    b"plst", // Playlist chunk
    b"ltxt", // Labeled text
    b"smpl", // Sampler/loop data               (e.g. VST plugins)
    b"inst", // Instrument data                 (e.g. VST plugins)
    b"labl", // Label inside adtl LIST
    b"note", // Note inside adtl LIST
    b"adtl", // Associated data list            (inside LIST)
    b"acid", // ACID loop info                  (Sony ACID / Magix)
    b"strc", // Structure chunk                 (some legacy editors)
    b"tlst", // Trigger list                    (uncommon)
    b"wavl", // Wave list                       (RIFF multi-block audio)
    b"slnt", // Silence chunk                   (RIFF multi-block audio)
    b"levl", // Peak-envelope chunk             (Broadcast Wave)
    b"MD5 ", // MD5 integrity chunk             (Broadcast Wave)
    b"axml", // axml metadata                   (Broadcast Wave AXMLv2)
    b"dbmd", // Dolby metadata                  (broadcast)
    b"r64m", // RF64 marker chunk
    b"ds64", // RF64 64-bit sizes chunk
    // AIFF / AIFC equivalents (wrapped in FORM…AIFF)
    b"COMM", // AIFF Common chunk
    b"SSND", // AIFF Sound Data chunk
    b"MARK", // AIFF Markers
    b"INST", // AIFF Instrument
    b"MIDI", // AIFF MIDI data
    b"AESD", // AIFF Audio Recording chunk
    b"APPL", // AIFF Application specific
    b"NAME", // AIFF Name
    b"AUTH", // AIFF Author
    b"(c) ", // AIFF Copyright
    b"ANNO", // AIFF Annotation
];

// ─────────────────────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Scan an audio file for anomalies.
pub fn analyze(data: &[u8], location: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let ext = std::path::Path::new(location)
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_lowercase())
        .unwrap_or_default();

    let is_compressed_audio = matches!(
        ext.as_str(),
        "mp3" | "ogg" | "aac" | "flac" | "opus" | "m4a"
    );

    // ── 1. Structural WAV/AIFF analysis (uncompressed formats only) ──────────
    if !is_compressed_audio {
        if is_riff_wav(data) {
            analyze_riff_wav(data, location, &mut findings);
        } else if is_aiff(data) {
            analyze_aiff(data, location, &mut findings);
        } else {
            // Not a recognized container — fall back to whole-file entropy.
            let entropy = shannon_entropy(data);
            if !(ENTROPY_AUDIO_MIN..=ENTROPY_AUDIO_MAX).contains(&entropy) {
                findings.push(
                    Finding::new(
                        FindingId::AudioUnusualEntropy,
                        Severity::Low,
                        PTS_AUDIO_UNUSUAL_ENTROPY,
                        location,
                        format!("Audio file has unusual entropy {:.2}", entropy),
                    )
                    .with_context(format!("entropy={:.4} source=whole_file", entropy)),
                );
            }
        }
    } else {
        // Compressed audio: only flag suspiciously LOW entropy (< 4.0).
        // High entropy is expected for compressed formats.
        let entropy = shannon_entropy(data);
        if entropy < 4.0 {
            findings.push(
                Finding::new(
                    FindingId::AudioUnusualEntropy,
                    Severity::Low,
                    PTS_AUDIO_UNUSUAL_ENTROPY,
                    location,
                    format!(
                        "Compressed audio file has unusually low entropy {:.2} \
                         (compressed audio is expected to be near 7.5–8.0)",
                        entropy
                    ),
                )
                .with_context(format!("entropy={:.4} format=compressed", entropy)),
            );
        }
    }

    // ── 2. Polyglot scan — look for a valid PE or ZIP structure ─────────────
    //
    // Run on all audio formats.  Skip the first 16 bytes (audio header area)
    // to avoid accidental matches on the container magic bytes themselves.
    // Require a full DOS+PE header, not just an "MZ" byte pair, to avoid the
    // high false-positive rate of bare MZ checks on compressed audio data.
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
                        "Valid PE header found inside audio file — polyglot payload detected",
                    )
                    .with_context(format!("offset=0x{:X}", offset)),
                );
                break;
            }
            continue;
        }

        // --- ZIP / PK (4-byte signature) ---
        if window == b"PK\x03\x04" {
            findings.push(
                Finding::new(
                    FindingId::PolyglotFile,
                    Severity::High,
                    PTS_POLYGLOT_FILE,
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

// ─────────────────────────────────────────────────────────────────────────────
// WAV / RIFF structural analysis
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` when `data` starts with a RIFF…WAVE header.
fn is_riff_wav(data: &[u8]) -> bool {
    data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WAVE"
}

/// Returns `true` when `data` starts with a FORM…AIFF or FORM…AIFC header.
fn is_aiff(data: &[u8]) -> bool {
    if data.len() < 12 {
        return false;
    }
    &data[0..4] == b"FORM" && (&data[8..12] == b"AIFF" || &data[8..12] == b"AIFC")
}

/// Full structural analysis for RIFF/WAV files.
///
/// Parses every chunk in the RIFF container and:
///   • Computes entropy on the `data` chunk only (not the whole file).
///   • Flags unknown chunk IDs with payloads ≥ AUDIO_SUSPICIOUS_CHUNK_MIN_BYTES.
///   • Flags trailing bytes that lie outside any declared chunk.
///   • Flags basic structural violations (truncated headers, impossible sizes).
fn analyze_riff_wav(data: &[u8], location: &str, findings: &mut Vec<Finding>) {
    // The RIFF header is: "RIFF" (4) + file_size_minus_8 (4 LE) + "WAVE" (4)
    // All chunks follow at offset 12.
    let file_len = data.len();

    // Sanity-check the declared RIFF size.
    let riff_declared_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    let riff_end = riff_declared_size + 8; // the "RIFF" + size field itself = 8 bytes

    if riff_end > file_len + 2 {
        // Allow ≤ 2 bytes of RIFF alignment slop.
        findings.push(
            Finding::new(
                FindingId::AudioMalformedHeader,
                Severity::Low,
                PTS_AUDIO_MALFORMED_HEADER,
                location,
                format!(
                    "RIFF declared size {} exceeds actual file size {} by more than 2 bytes",
                    riff_end, file_len
                ),
            )
            .with_context(format!(
                "riff_declared_end={} file_len={}",
                riff_end, file_len
            )),
        );
        // Continue parsing — we can still extract useful information.
    }

    // Walk the chunk list starting at offset 12.
    let mut cursor: usize = 12;
    let walk_end = riff_end.min(file_len); // never read past the real EOF

    let mut found_fmt = false;
    let mut found_data = false;
    let mut data_chunk_bytes: Option<&[u8]> = None;

    while cursor + 8 <= walk_end {
        let id = &data[cursor..cursor + 4];
        let chunk_size =
            u32::from_le_bytes([data[cursor + 4], data[cursor + 5], data[cursor + 6], data[cursor + 7]])
                as usize;
        let payload_start = cursor + 8;
        // RIFF pads chunks to even byte boundaries.
        let padded_size = chunk_size + (chunk_size & 1);
        let next_cursor = payload_start + padded_size;

        // Check for a chunk that would extend past file end.
        if payload_start + chunk_size > file_len {
            findings.push(
                Finding::new(
                    FindingId::AudioMalformedHeader,
                    Severity::Low,
                    PTS_AUDIO_MALFORMED_HEADER,
                    location,
                    format!(
                        "RIFF chunk '{}' at offset 0x{:X} declares size {} but only {} bytes remain",
                        chunk_id_str(id),
                        cursor,
                        chunk_size,
                        file_len.saturating_sub(payload_start),
                    ),
                )
                .with_context(format!(
                    "chunk={} offset=0x{:X} declared_size={} remaining={}",
                    chunk_id_str(id),
                    cursor,
                    chunk_size,
                    file_len.saturating_sub(payload_start),
                )),
            );
            break; // Cannot continue walking safely.
        }

        let payload = &data[payload_start..payload_start + chunk_size];

        match id {
            b"fmt " => {
                found_fmt = true;
                check_fmt_chunk(payload, location, findings);
            }
            b"data" => {
                found_data = true;
                data_chunk_bytes = Some(payload);
            }
            _ => {
                // Check against known-chunk list.
                let is_known = KNOWN_RIFF_CHUNKS
                    .iter()
                    .any(|known| *known == id);

                if !is_known && chunk_size >= AUDIO_SUSPICIOUS_CHUNK_MIN_BYTES {
                    findings.push(
                        Finding::new(
                            FindingId::AudioSuspiciousChunk,
                            Severity::Medium,
                            PTS_AUDIO_SUSPICIOUS_CHUNK,
                            location,
                            format!(
                                "Unknown RIFF chunk '{}' carries {} bytes — possible steganographic payload",
                                chunk_id_str(id),
                                chunk_size,
                            ),
                        )
                        .with_context(format!(
                            "chunk={} offset=0x{:X} size={}",
                            chunk_id_str(id),
                            cursor,
                            chunk_size,
                        )),
                    );
                }
            }
        }

        if next_cursor <= cursor {
            break; // Guard against zero-size infinite loop.
        }
        cursor = next_cursor;
    }

    // ── Mandatory chunk presence check ──────────────────────────────────────
    if !found_fmt {
        findings.push(
            Finding::new(
                FindingId::AudioMalformedHeader,
                Severity::Low,
                PTS_AUDIO_MALFORMED_HEADER,
                location,
                "WAV file is missing mandatory 'fmt ' chunk",
            )
            .with_context("missing_chunk=fmt"),
        );
    }
    if !found_data {
        findings.push(
            Finding::new(
                FindingId::AudioMalformedHeader,
                Severity::Low,
                PTS_AUDIO_MALFORMED_HEADER,
                location,
                "WAV file is missing mandatory 'data' chunk",
            )
            .with_context("missing_chunk=data"),
        );
    }

    // ── Trailing data check ──────────────────────────────────────────────────
    // `cursor` now points to the first byte beyond all parsed chunks.
    // Anything between `cursor` and `file_len` is outside the RIFF container.
    let trailing = file_len.saturating_sub(cursor.max(riff_end.min(file_len)));
    if trailing >= AUDIO_TRAILING_MIN_BYTES {
        findings.push(
            Finding::new(
                FindingId::AudioTrailingData,
                Severity::Low,
                PTS_AUDIO_TRAILING_DATA,
                location,
                format!(
                    "{} bytes of data found after the last RIFF chunk — possible hidden payload",
                    trailing
                ),
            )
            .with_context(format!(
                "trailing_bytes={} riff_end=0x{:X} file_len={}",
                trailing, riff_end, file_len
            )),
        );
    }

    // ── Data-chunk entropy check ─────────────────────────────────────────────
    // Measure entropy only on the PCM sample payload, not the RIFF headers.
    // Headers contain low-entropy ASCII (chunk IDs, fmt fields) which would
    // drag down the whole-file entropy and produce false positives on short clips.
    if let Some(pcm) = data_chunk_bytes {
        if pcm.len() >= 64 {
            // Skip entropy check on trivially small samples (< 64 bytes)
            // as they give unreliable readings.
            let entropy = shannon_entropy(pcm);
            if !(ENTROPY_AUDIO_MIN..=ENTROPY_AUDIO_MAX).contains(&entropy) {
                let description = if entropy < ENTROPY_AUDIO_MIN {
                    format!(
                        "WAV audio data has very low entropy {:.2} — file may be near-silence, \
                         zero-filled, or a non-audio carrier",
                        entropy
                    )
                } else {
                    format!(
                        "WAV audio data has very high entropy {:.2} — PCM samples appear \
                         near-random, consistent with encrypted or compressed payload",
                        entropy
                    )
                };
                findings.push(
                    Finding::new(
                        FindingId::AudioUnusualEntropy,
                        Severity::Low,
                        PTS_AUDIO_UNUSUAL_ENTROPY,
                        location,
                        description,
                    )
                    .with_context(format!(
                        "entropy={:.4} source=data_chunk pcm_bytes={}",
                        entropy,
                        pcm.len()
                    )),
                );
            }
        }
    }
}

/// Validate a `fmt ` chunk payload (must be ≥ 16 bytes for PCM).
/// Flags implausible channel counts or sample rates as AudioMalformedHeader.
fn check_fmt_chunk(payload: &[u8], location: &str, findings: &mut Vec<Finding>) {
    if payload.len() < 16 {
        findings.push(
            Finding::new(
                FindingId::AudioMalformedHeader,
                Severity::Low,
                PTS_AUDIO_MALFORMED_HEADER,
                location,
                format!(
                    "WAV 'fmt ' chunk is only {} bytes (minimum is 16)",
                    payload.len()
                ),
            )
            .with_context(format!("fmt_size={}", payload.len())),
        );
        return;
    }

    let audio_format = u16::from_le_bytes([payload[0], payload[1]]);
    let channels = u16::from_le_bytes([payload[2], payload[3]]);
    let sample_rate = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let bits_per_sample = u16::from_le_bytes([payload[14], payload[15]]);

    // Sanity ranges:
    //   channels       1–32  (mono to 32-channel surround; >32 is exotic)
    //   sample_rate    8 000–192 000 Hz (telephone to hi-res audio)
    //   bits_per_sample 8, 16, 24, 32, 64 (or 0 for extensible if fmt=0xFFFE)
    let format_extensible: u16 = 0xFFFE;
    let is_extensible = audio_format == format_extensible;

    let channels_ok = channels >= 1 && channels <= 32;
    let rate_ok = sample_rate >= 8_000 && sample_rate <= 384_000;
    let bits_ok = is_extensible
        || matches!(bits_per_sample, 8 | 16 | 24 | 32 | 64)
        || bits_per_sample == 0;

    if !channels_ok || !rate_ok || !bits_ok {
        findings.push(
            Finding::new(
                FindingId::AudioMalformedHeader,
                Severity::Low,
                PTS_AUDIO_MALFORMED_HEADER,
                location,
                format!(
                    "WAV 'fmt ' chunk contains implausible values: channels={} sample_rate={} bits={}",
                    channels, sample_rate, bits_per_sample,
                ),
            )
            .with_context(format!(
                "format=0x{:04X} channels={} sample_rate={} bits_per_sample={}",
                audio_format, channels, sample_rate, bits_per_sample,
            )),
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AIFF structural analysis
// ─────────────────────────────────────────────────────────────────────────────

/// Structural analysis for AIFF/AIFC containers (big-endian chunk IDs).
///
/// Performs the same trailing-data and suspicious-chunk checks as the WAV path.
fn analyze_aiff(data: &[u8], location: &str, findings: &mut Vec<Finding>) {
    let file_len = data.len();

    // FORM header: "FORM" (4) + size (4 BE) + "AIFF"/"AIFC" (4).
    let form_declared_size = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;
    let form_end = form_declared_size + 8;

    if form_end > file_len + 2 {
        findings.push(
            Finding::new(
                FindingId::AudioMalformedHeader,
                Severity::Low,
                PTS_AUDIO_MALFORMED_HEADER,
                location,
                format!(
                    "AIFF FORM declared size {} exceeds actual file size {}",
                    form_end, file_len
                ),
            )
            .with_context(format!(
                "form_declared_end={} file_len={}",
                form_end, file_len
            )),
        );
    }

    let mut cursor: usize = 12;
    let walk_end = form_end.min(file_len);
    let mut found_comm = false;
    let mut found_ssnd = false;
    let mut ssnd_bytes: Option<&[u8]> = None;

    while cursor + 8 <= walk_end {
        let id = &data[cursor..cursor + 4];
        // AIFF chunk sizes are big-endian.
        let chunk_size =
            u32::from_be_bytes([data[cursor + 4], data[cursor + 5], data[cursor + 6], data[cursor + 7]])
                as usize;
        let payload_start = cursor + 8;
        let padded_size = chunk_size + (chunk_size & 1);
        let next_cursor = payload_start + padded_size;

        if payload_start + chunk_size > file_len {
            findings.push(
                Finding::new(
                    FindingId::AudioMalformedHeader,
                    Severity::Low,
                    PTS_AUDIO_MALFORMED_HEADER,
                    location,
                    format!(
                        "AIFF chunk '{}' at 0x{:X} declares size {} but only {} bytes remain",
                        chunk_id_str(id),
                        cursor,
                        chunk_size,
                        file_len.saturating_sub(payload_start),
                    ),
                )
                .with_context(format!(
                    "chunk={} offset=0x{:X} size={}",
                    chunk_id_str(id),
                    cursor,
                    chunk_size
                )),
            );
            break;
        }

        let payload = &data[payload_start..payload_start + chunk_size];

        match id {
            b"COMM" => found_comm = true,
            b"SSND" => {
                found_ssnd = true;
                // SSND has an 8-byte header (offset + blockSize) before PCM data.
                if payload.len() > 8 {
                    ssnd_bytes = Some(&payload[8..]);
                }
            }
            _ => {
                let is_known = KNOWN_RIFF_CHUNKS.iter().any(|known| *known == id);
                if !is_known && chunk_size >= AUDIO_SUSPICIOUS_CHUNK_MIN_BYTES {
                    findings.push(
                        Finding::new(
                            FindingId::AudioSuspiciousChunk,
                            Severity::Medium,
                            PTS_AUDIO_SUSPICIOUS_CHUNK,
                            location,
                            format!(
                                "Unknown AIFF chunk '{}' carries {} bytes — possible steganographic payload",
                                chunk_id_str(id),
                                chunk_size,
                            ),
                        )
                        .with_context(format!(
                            "chunk={} offset=0x{:X} size={}",
                            chunk_id_str(id),
                            cursor,
                            chunk_size,
                        )),
                    );
                }
            }
        }

        if next_cursor <= cursor {
            break;
        }
        cursor = next_cursor;
    }

    if !found_comm {
        findings.push(
            Finding::new(
                FindingId::AudioMalformedHeader,
                Severity::Low,
                PTS_AUDIO_MALFORMED_HEADER,
                location,
                "AIFF file is missing mandatory 'COMM' chunk",
            )
            .with_context("missing_chunk=COMM"),
        );
    }
    if !found_ssnd {
        findings.push(
            Finding::new(
                FindingId::AudioMalformedHeader,
                Severity::Low,
                PTS_AUDIO_MALFORMED_HEADER,
                location,
                "AIFF file is missing mandatory 'SSND' chunk",
            )
            .with_context("missing_chunk=SSND"),
        );
    }

    // Trailing-data check.
    let trailing = file_len.saturating_sub(cursor.max(form_end.min(file_len)));
    if trailing >= AUDIO_TRAILING_MIN_BYTES {
        findings.push(
            Finding::new(
                FindingId::AudioTrailingData,
                Severity::Low,
                PTS_AUDIO_TRAILING_DATA,
                location,
                format!(
                    "{} bytes of data found after the last AIFF chunk — possible hidden payload",
                    trailing
                ),
            )
            .with_context(format!(
                "trailing_bytes={} form_end=0x{:X} file_len={}",
                trailing, form_end, file_len
            )),
        );
    }

    // Entropy on SSND PCM data only.
    if let Some(pcm) = ssnd_bytes {
        if pcm.len() >= 64 {
            let entropy = shannon_entropy(pcm);
            if !(ENTROPY_AUDIO_MIN..=ENTROPY_AUDIO_MAX).contains(&entropy) {
                findings.push(
                    Finding::new(
                        FindingId::AudioUnusualEntropy,
                        Severity::Low,
                        PTS_AUDIO_UNUSUAL_ENTROPY,
                        location,
                        format!("AIFF audio data has unusual entropy {:.2}", entropy),
                    )
                    .with_context(format!(
                        "entropy={:.4} source=ssnd_chunk pcm_bytes={}",
                        entropy,
                        pcm.len()
                    )),
                );
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PE header validation (unchanged from original)
// ─────────────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Convert a 4-byte chunk ID to a human-readable string, replacing non-ASCII
/// bytes with '?' to avoid garbled output.
fn chunk_id_str(id: &[u8]) -> String {
    id.iter()
        .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '?' })
        .collect()
}
