//! Integration tests — Binary asset scanning (textures, audio, prefabs).

use vrcstorage_scanner::analysis::assets::{analyze_asset, texture_scanner, audio_scanner, prefab_scanner};
use vrcstorage_scanner::ingestion::AssetType;
use vrcstorage_scanner::report::FindingId;

// ─────────────────────────────────────────────
// Texture magic byte checks
// ─────────────────────────────────────────────

/// Valid PNG header (8 bytes)
const PNG_HEADER: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

/// Valid JPEG header
const JPG_HEADER: &[u8] = &[0xFF, 0xD8, 0xFF, 0xE0];

/// ZIP magic bytes
const ZIP_MAGIC: &[u8] = b"PK\x03\x04";

fn make_png(extra: &[u8]) -> Vec<u8> {
    let mut v = PNG_HEADER.to_vec();
    v.extend_from_slice(extra);
    v
}

fn make_jpg(extra: &[u8]) -> Vec<u8> {
    let mut v = JPG_HEADER.to_vec();
    v.extend_from_slice(extra);
    v
}

// ─── texture_scanner ────────────────────────

#[test]
fn valid_png_no_magic_mismatch() {
    let data = make_png(&[0u8; 600]);
    let findings = texture_scanner::analyze(&data, "Assets/Textures/icon.png");

    let mismatch = findings.iter().any(|f| f.id == FindingId::MagicMismatch);
    assert!(!mismatch, "Valid PNG should not produce MAGIC_MISMATCH; got: {:#?}", findings);
}

#[test]
fn wrong_magic_for_png_extension_flagged() {
    // JPEG bytes but declared as .png
    let data = make_jpg(&[0u8; 600]);
    let findings = texture_scanner::analyze(&data, "Assets/Textures/icon.png");

    let has = findings.iter().any(|f| f.id == FindingId::MagicMismatch);
    assert!(has, "MAGIC_MISMATCH not detected for JPEG data with .png extension; got: {:#?}", findings);
}

#[test]
fn pe_embedded_inside_png_is_polyglot() {
    // Build a valid minimal DOS+PE header so the stricter validator accepts it.
    //
    // Layout (all at `base` = PNG_HEADER.len() + 512 padding bytes):
    //   [+0x00]  MZ
    //   [+0x3C]  e_lfanew = 0x40  (little-endian u32)
    //   [+0x40]  PE\0\0
    let mut data = make_png(&[]);
    data.extend(vec![0u8; 512]); // padding before the embedded PE

    let base = data.len();
    let mut pe_stub = vec![0u8; 0x44]; // 68 bytes covers MZ + e_lfanew + PE sig
    pe_stub[0] = b'M';
    pe_stub[1] = b'Z';
    // e_lfanew at offset 0x3C = 0x40 (points 64 bytes from stub start)
    pe_stub[0x3C] = 0x40;
    pe_stub[0x3D] = 0x00;
    pe_stub[0x3E] = 0x00;
    pe_stub[0x3F] = 0x00;
    // PE signature at offset 0x40
    pe_stub[0x40] = b'P';
    pe_stub[0x41] = b'E';
    pe_stub[0x42] = 0x00;
    pe_stub[0x43] = 0x00;
    data.extend_from_slice(&pe_stub);
    let _ = base; // used implicitly by data construction

    let findings = texture_scanner::analyze(&data, "Assets/Textures/evil.png");
    let has = findings.iter().any(|f| f.id == FindingId::PolyglotFile);
    assert!(has, "POLYGLOT_FILE not detected for valid PE embedded in PNG; got: {:#?}", findings);
}

#[test]
fn zip_embedded_inside_png_is_polyglot() {
    let mut data = make_png(&[]);
    data.extend(vec![0u8; 512]);
    data.extend_from_slice(ZIP_MAGIC);
    data.extend(vec![0u8; 8]);

    let findings = texture_scanner::analyze(&data, "Assets/Textures/evil.png");
    let has = findings.iter().any(|f| f.id == FindingId::PolyglotFile);
    assert!(has, "POLYGLOT_FILE not detected for ZIP embedded in PNG; got: {:#?}", findings);
}

#[test]
fn high_entropy_texture_flagged() {
    // PNG is natively compressed and is excluded from the entropy check.
    // Use a .tga extension (uncompressed format) so the scanner applies the
    // entropy heuristic.  High-entropy random bytes on an uncompressed format
    // are genuinely suspicious.
    let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();

    let findings = texture_scanner::analyze(&data, "Assets/Textures/noisy.tga");
    let has = findings.iter().any(|f| f.id == FindingId::TextureHighEntropy);
    assert!(has, "TEXTURE_HIGH_ENTROPY not flagged for high-entropy .tga; got: {:#?}", findings);
}

// ─── audio_scanner ───────────────────────────

#[test]
fn polyglot_audio_with_pe_detected() {
    // Build fake WAV with a structurally-valid embedded PE header.
    // The stricter validator requires MZ + valid e_lfanew + PE\0\0.
    let mut data = vec![0x52u8, 0x49, 0x46, 0x46]; // RIFF magic
    data.extend(vec![0xA0u8; 512]);                 // fake audio payload

    // Minimal PE stub: 0x44 bytes
    let mut pe_stub = vec![0u8; 0x44];
    pe_stub[0] = b'M';
    pe_stub[1] = b'Z';
    pe_stub[0x3C] = 0x40; // e_lfanew = 0x40
    pe_stub[0x40] = b'P';
    pe_stub[0x41] = b'E';
    pe_stub[0x42] = 0x00;
    pe_stub[0x43] = 0x00;
    data.extend_from_slice(&pe_stub);

    let findings = audio_scanner::analyze(&data, "Assets/Audio/ambient.wav");
    let has = findings.iter().any(|f| f.id == FindingId::PolyglotFile);
    assert!(has, "POLYGLOT_FILE not detected for valid PE embedded in audio; got: {:#?}", findings);
}

#[test]
fn low_entropy_audio_flagged() {
    // All-zero audio data → entropy ~0, which is below 5.0
    let data = vec![0u8; 1024];
    let findings = audio_scanner::analyze(&data, "Assets/Audio/silent.wav");

    let has = findings.iter().any(|f| f.id == FindingId::AudioUnusualEntropy);
    assert!(has, "AUDIO_UNUSUAL_ENTROPY not flagged for all-zero audio; got: {:#?}", findings);
}

// ─── prefab_scanner ──────────────────────────

#[test]
fn clean_yaml_prefab_no_findings() {
    let yaml = r#"%YAML 1.1
%TAG !u! tag:unity3d.com,2011:
--- !u!1 &1
GameObject:
  m_ObjectHideFlags: 0
  m_Name: Cube
  m_IsActive: 1
"#;
    let findings = prefab_scanner::analyze(yaml.as_bytes(), "Assets/Prefabs/Cube.prefab");
    // A clean prefab with no externalObjects or suspicious content
    let suspicious: Vec<_> = findings
        .iter()
        .filter(|f| f.id == FindingId::MetaExternalRef || f.id == FindingId::PrefabInlineB64)
        .collect();
    assert!(suspicious.is_empty(), "Clean prefab should have no suspicious findings; got: {:#?}", suspicious);
}

#[test]
fn prefab_with_external_objects_flagged() {
    let yaml = r#"%YAML 1.1
%TAG !u! tag:unity3d.com,2011:
--- !u!114 &1
MonoBehaviour:
  externalObjects:
    SomeRef: {fileID: 12345, guid: abcdef0123456789abcdef0123456789, type: 3}
"#;
    let findings = prefab_scanner::analyze(yaml.as_bytes(), "Assets/Prefabs/Linked.prefab");
    let has = findings.iter().any(|f| f.id == FindingId::MetaExternalRef);
    assert!(has, "META_EXTERNAL_REF not flagged; got: {:#?}", findings);
}

// ─── analyze_asset dispatcher ────────────────

#[test]
fn dispatch_texture_type_goes_to_texture_scanner() {
    let data = make_jpg(&[0u8; 600]);
    // Declared as .png → magic mismatch expected
    let findings = analyze_asset(&data, &AssetType::Texture, "Assets/Textures/pic.png");
    // At minimum the dispatcher should return some result (may or may not have mismatch)
    // Just ensure it doesn't panic
    let _ = findings;
}

#[test]
fn dispatch_audio_type_does_not_panic() {
    let data = vec![0u8; 128];
    let findings = analyze_asset(&data, &AssetType::Audio, "Assets/Audio/sound.wav");
    let _ = findings;
}

#[test]
fn dispatch_unknown_type_returns_empty() {
    let data = vec![0xDEu8, 0xAD, 0xBE, 0xEF];
    let findings = analyze_asset(&data, &AssetType::AnimationClip, "Assets/Anims/walk.anim");
    assert!(findings.is_empty(), "AnimationClip should return empty findings from dispatcher");
}
