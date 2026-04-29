//! Integration tests — Export subcommand
//!
//! Tests that exporting a .unitypackage to folder and ZIP works correctly,
//! including path sanitization and edge cases.

use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};

use vrcstorage_scanner::export::{run_export, ExportType};

static TMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn make_temp_dir() -> std::path::PathBuf {
    let id = TMP_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "vrcstorage_test_export_{}_{}",
        std::process::id(),
        id
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Build a minimal gzip+TAR buffer that mimics a .unitypackage file with the
/// following contents:
///
/// ```text
/// guid1/pathname   → "Assets/Scripts/MyScript.cs"
/// guid1/asset      → "// Hello World"
/// guid1/asset.meta → "guid: abc123\n"
/// ```
fn make_unitypackage_buffer() -> Vec<u8> {
    let tar_buf = {
        let mut tar_builder = tar::Builder::new(Vec::new());

        // pathname
        let mut header = tar::Header::new_gnu();
        header.set_path("a1b2c3d4/pathname").unwrap();
        header.set_size("Assets/Scripts/MyScript.cs".len() as u64);
        header.set_cksum();
        tar_builder
            .append(&header, "Assets/Scripts/MyScript.cs".as_bytes())
            .unwrap();

        // asset
        let mut header = tar::Header::new_gnu();
        header.set_path("a1b2c3d4/asset").unwrap();
        header.set_size("// Hello World\nusing UnityEngine;\n".len() as u64);
        header.set_cksum();
        tar_builder
            .append(
                &header,
                "// Hello World\nusing UnityEngine;\n".as_bytes(),
            )
            .unwrap();

        // asset.meta
        let mut header = tar::Header::new_gnu();
        header.set_path("a1b2c3d4/asset.meta").unwrap();
        header.set_size("guid: abc123\ntype: 115\n".len() as u64);
        header.set_cksum();
        tar_builder
            .append(&header, "guid: abc123\ntype: 115\n".as_bytes())
            .unwrap();

        tar_builder.into_inner().unwrap()
    };

    // Compress with gzip
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&tar_buf).unwrap();
    gz.finish().unwrap()
}

// ── Basic export tests ───────────────────────────────────────────────────────

#[test]
fn export_to_folder_creates_correct_structure() {
    let tmp = make_temp_dir();
    let pkg_path = tmp.join("test_package.unitypackage");
    std::fs::write(&pkg_path, make_unitypackage_buffer()).unwrap();

    let result = run_export(&pkg_path, "folder", None, false).unwrap();

    assert_eq!(result.output_type, ExportType::Folder);
    assert_eq!(result.exported_assets, 1);
    assert_eq!(result.exported_meta, 1);
    assert_eq!(result.skipped_empty, 0);
    assert_eq!(result.skipped_unsafe, 0);

    // Verify the output files exist
    let exported_dir = pkg_path.with_file_name("test_package-exported");
    assert!(exported_dir.exists(), "Export dir should exist at {exported_dir:?}");

    let script_path = exported_dir.join("Assets/Scripts/MyScript.cs");
    assert!(script_path.exists(), "Script should exist at {script_path:?}");
    let content = std::fs::read_to_string(&script_path).unwrap();
    assert!(content.contains("Hello World"));

    let meta_path = exported_dir.join("Assets/Scripts/MyScript.cs.meta");
    assert!(meta_path.exists(), "Meta file should exist at {meta_path:?}");

    // Cleanup
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn export_to_zip_creates_valid_archive() {
    let tmp = make_temp_dir();
    let pkg_path = tmp.join("test_package.unitypackage");
    std::fs::write(&pkg_path, make_unitypackage_buffer()).unwrap();

    let result = run_export(&pkg_path, "zip", None, false).unwrap();

    assert_eq!(result.output_type, ExportType::Zip);
    assert_eq!(result.exported_assets, 1);
    assert_eq!(result.exported_meta, 1);

    let zip_path = pkg_path.with_file_name("test_package-exported.zip");
    assert!(zip_path.exists(), "ZIP should exist at {zip_path:?}");

    // Verify ZIP contents
    let zip_data = std::fs::read(&zip_path).unwrap();
    let cursor = std::io::Cursor::new(zip_data);
    let mut archive = zip::ZipArchive::new(cursor).unwrap();

    let mut found_script = false;
    let mut found_meta = false;
    for i in 0..archive.len() {
        let file = archive.by_index(i).unwrap();
        match file.name() {
            "Assets/Scripts/MyScript.cs" => found_script = true,
            "Assets/Scripts/MyScript.cs.meta" => found_meta = true,
            _ => {}
        }
    }
    assert!(found_script, "ZIP should contain the script file");
    assert!(found_meta, "ZIP should contain the .meta file");

    // Cleanup
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn export_with_custom_output_dir() {
    let tmp = make_temp_dir();
    let pkg_path = tmp.join("test_package.unitypackage");
    std::fs::write(&pkg_path, make_unitypackage_buffer()).unwrap();

    let custom_out = tmp.join("custom_output");
    let result = run_export(&pkg_path, "folder", Some(&custom_out), false).unwrap();

    assert_eq!(result.output_path, custom_out);
    assert_eq!(result.exported_assets, 1);

    assert!(custom_out.join("Assets/Scripts/MyScript.cs").exists());

    // Cleanup
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn export_rejects_non_unitypackage() {
    let tmp = make_temp_dir();
    let txt_path = tmp.join("test.txt");
    std::fs::write(&txt_path, "hello world").unwrap();

    let result = run_export(&txt_path, "folder", None, false);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("Export error"), "Expected export error, got: {err}");

    // Cleanup
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn export_rejects_path_traversal_in_package() {
    // Build a TAR that has a pathname entry with ".." traversal
    let tar_buf = {
        let mut tar_builder = tar::Builder::new(Vec::new());

        // pathname with traversal
        let mut header = tar::Header::new_gnu();
        header.set_path("evil/pathname").unwrap();
        header.set_size("../../../etc/passwd".len() as u64);
        header.set_cksum();
        tar_builder
            .append(&header, "../../../etc/passwd".as_bytes())
            .unwrap();

        // asset
        let mut header = tar::Header::new_gnu();
        header.set_path("evil/asset").unwrap();
        header.set_size("evil content".len() as u64);
        header.set_cksum();
        tar_builder
            .append(&header, "evil content".as_bytes())
            .unwrap();

        tar_builder.into_inner().unwrap()
    };

    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&tar_buf).unwrap();
    let evil_data = gz.finish().unwrap();

    let tmp = make_temp_dir();
    let pkg_path = tmp.join("evil.unitypackage");
    std::fs::write(&pkg_path, evil_data).unwrap();

    let result = run_export(&pkg_path, "folder", None, false).unwrap();

    // The traversal entry should be skipped, not exported
    assert_eq!(result.skipped_unsafe, 1);
    assert_eq!(result.exported_assets, 0);
    assert_eq!(result.warnings.len(), 1);

    // Cleanup
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn export_zip_rejects_path_traversal() {
    // Same test as above but for ZIP output
    let tar_buf = {
        let mut tar_builder = tar::Builder::new(Vec::new());

        let mut header = tar::Header::new_gnu();
        header.set_path("evil/pathname").unwrap();
        header.set_size("../../../etc/passwd".len() as u64);
        header.set_cksum();
        tar_builder
            .append(&header, "../../../etc/passwd".as_bytes())
            .unwrap();

        let mut header = tar::Header::new_gnu();
        header.set_path("evil/asset").unwrap();
        header.set_size("evil content".len() as u64);
        header.set_cksum();
        tar_builder
            .append(&header, "evil content".as_bytes())
            .unwrap();

        tar_builder.into_inner().unwrap()
    };

    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&tar_buf).unwrap();
    let evil_data = gz.finish().unwrap();

    let tmp = make_temp_dir();
    let pkg_path = tmp.join("evil.unitypackage");
    std::fs::write(&pkg_path, evil_data).unwrap();

    let result = run_export(&pkg_path, "zip", None, false).unwrap();

    assert_eq!(result.skipped_unsafe, 1);
    assert_eq!(result.exported_assets, 0);

    // Cleanup
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn export_skips_empty_entries() {
    // Build a TAR with a pathname entry that has no corresponding asset
    let tar_buf = {
        let mut tar_builder = tar::Builder::new(Vec::new());

        // pathname without asset — this creates an orphan entry
        let mut header = tar::Header::new_gnu();
        header.set_path("orphan/pathname").unwrap();
        header.set_size("Assets/Orphan.cs".len() as u64);
        header.set_cksum();
        tar_builder
            .append(&header, "Assets/Orphan.cs".as_bytes())
            .unwrap();

        // Valid entry
        let mut header = tar::Header::new_gnu();
        header.set_path("valid/pathname").unwrap();
        header.set_size("Assets/Scripts/Valid.cs".len() as u64);
        header.set_cksum();
        tar_builder
            .append(&header, "Assets/Scripts/Valid.cs".as_bytes())
            .unwrap();

        let mut header = tar::Header::new_gnu();
        header.set_path("valid/asset").unwrap();
        header.set_size("// Valid script".len() as u64);
        header.set_cksum();
        tar_builder
            .append(&header, "// Valid script".as_bytes())
            .unwrap();

        tar_builder.into_inner().unwrap()
    };

    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&tar_buf).unwrap();
    let data = gz.finish().unwrap();

    let tmp = make_temp_dir();
    let pkg_path = tmp.join("package.unitypackage");
    std::fs::write(&pkg_path, data).unwrap();

    let result = run_export(&pkg_path, "folder", None, false).unwrap();

    assert_eq!(result.exported_assets, 1);
    assert_eq!(result.skipped_empty, 1);

    // Cleanup
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn export_handles_multiple_entries() {
    // Build a TAR with multiple assets in different paths
    let tar_buf = {
        let mut tar_builder = tar::Builder::new(Vec::new());

        // Script entry
        {
            let guid = "multi1";
            let path = "Assets/Scripts/A.cs";
            let content = "// Script A";
            let meta = "meta1";

            let mut h = tar::Header::new_gnu();
            h.set_path(format!("{guid}/pathname")).unwrap();
            h.set_size(path.len() as u64);
            h.set_cksum();
            tar_builder.append(&h, path.as_bytes()).unwrap();

            let mut h = tar::Header::new_gnu();
            h.set_path(format!("{guid}/asset")).unwrap();
            h.set_size(content.len() as u64);
            h.set_cksum();
            tar_builder.append(&h, content.as_bytes()).unwrap();

            let mut h = tar::Header::new_gnu();
            h.set_path(format!("{guid}/asset.meta")).unwrap();
            h.set_size(meta.len() as u64);
            h.set_cksum();
            tar_builder.append(&h, meta.as_bytes()).unwrap();
        }

        // DLL entry (binary)
        {
            let guid = "multi2";
            let path = "Assets/Plugins/B.dll";
            let content: &[u8] = &[0x4D, 0x5A, 0x90, 0x00];
            let meta = "meta2";

            let mut h = tar::Header::new_gnu();
            h.set_path(format!("{guid}/pathname")).unwrap();
            h.set_size(path.len() as u64);
            h.set_cksum();
            tar_builder.append(&h, path.as_bytes()).unwrap();

            let mut h = tar::Header::new_gnu();
            h.set_path(format!("{guid}/asset")).unwrap();
            h.set_size(content.len() as u64);
            h.set_cksum();
            tar_builder.append(&h, content).unwrap();

            let mut h = tar::Header::new_gnu();
            h.set_path(format!("{guid}/asset.meta")).unwrap();
            h.set_size(meta.len() as u64);
            h.set_cksum();
            tar_builder.append(&h, meta.as_bytes()).unwrap();
        }

        tar_builder.into_inner().unwrap()
    };

    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&tar_buf).unwrap();
    let data = gz.finish().unwrap();

    let tmp = make_temp_dir();
    let pkg_path = tmp.join("multi.unitypackage");
    std::fs::write(&pkg_path, data).unwrap();

    let result = run_export(&pkg_path, "folder", None, false).unwrap();

    assert_eq!(result.exported_assets, 2);
    assert_eq!(result.exported_meta, 2);
    assert_eq!(result.skipped_empty, 0);

    let exported_dir = pkg_path.with_file_name("multi-exported");
    assert!(exported_dir.join("Assets/Scripts/A.cs").exists());
    assert!(exported_dir.join("Assets/Scripts/A.cs.meta").exists());
    assert!(exported_dir.join("Assets/Plugins/B.dll").exists());
    assert!(exported_dir.join("Assets/Plugins/B.dll.meta").exists());

    // Cleanup
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn export_skip_meta_omits_meta_files() {
    let tmp = make_temp_dir();
    let pkg_path = tmp.join("test_package.unitypackage");
    std::fs::write(&pkg_path, make_unitypackage_buffer()).unwrap();

    let result = run_export(&pkg_path, "folder", None, true).unwrap();

    assert!(result.skip_meta);
    assert_eq!(result.exported_assets, 1);
    assert_eq!(result.exported_meta, 0);

    let exported_dir = pkg_path.with_file_name("test_package-exported");
    let script_path = exported_dir.join("Assets/Scripts/MyScript.cs");
    assert!(script_path.exists(), "Script should exist with skip-meta");

    let meta_path = exported_dir.join("Assets/Scripts/MyScript.cs.meta");
    assert!(!meta_path.exists(), "Meta should NOT exist with skip-meta");

    // Cleanup
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn export_skip_meta_zip_omits_meta_files() {
    let tmp = make_temp_dir();
    let pkg_path = tmp.join("test_package.unitypackage");
    std::fs::write(&pkg_path, make_unitypackage_buffer()).unwrap();

    let result = run_export(&pkg_path, "zip", None, true).unwrap();

    assert!(result.skip_meta);
    assert_eq!(result.exported_assets, 1);
    assert_eq!(result.exported_meta, 0);

    let zip_path = pkg_path.with_file_name("test_package-exported.zip");
    let zip_data = std::fs::read(&zip_path).unwrap();
    let cursor = std::io::Cursor::new(zip_data);
    let mut archive = zip::ZipArchive::new(cursor).unwrap();

    let mut found_script = false;
    let mut found_meta = false;
    for i in 0..archive.len() {
        let file = archive.by_index(i).unwrap();
        match file.name() {
            "Assets/Scripts/MyScript.cs" => found_script = true,
            "Assets/Scripts/MyScript.cs.meta" => found_meta = true,
            _ => {}
        }
    }
    assert!(found_script, "ZIP should contain the script file");
    assert!(!found_meta, "ZIP should NOT contain the .meta file with skip-meta");

    // Cleanup
    let _ = std::fs::remove_dir_all(&tmp);
}
