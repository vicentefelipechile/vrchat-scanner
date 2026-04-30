use vrcstorage_scanner::tree::{self, TreeFormat, TreeOptions};

// ─── Helper: build a minimal .unitypackage on disk ───────────────────────

fn build_unitypackage(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut tar_buf = Vec::new();
    {
        let mut tar = tar::Builder::new(&mut tar_buf);
        for (path, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_path(path).unwrap();
            header.set_size(data.len() as u64);
            header.set_cksum();
            tar.append(&header, &data[..]).unwrap();
        }
        tar.finish().unwrap();
    }
    let mut encoder =
        flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut encoder, &tar_buf).unwrap();
    encoder.finish().unwrap()
}

// ─── TXT output ──────────────────────────────────────────────────────────

#[test]
fn txt_pretty_uses_unicode_box_chars() {
    let dir = tempfile::tempdir().unwrap();
    let pkg = dir.path().join("test.unitypackage");
    let data = build_unitypackage(&[
        ("guid1/pathname", b"Assets/Scripts/Hello.cs".to_vec()),
        ("guid1/asset", b"using System;".to_vec()),
        ("guid1/asset.meta", b"guid: guid1".to_vec()),
        ("guid2/pathname", b"Assets/Plugins/Tool.dll".to_vec()),
        ("guid2/asset", vec![0u8; 2048]),
        ("guid2/asset.meta", b"guid: guid2".to_vec()),
    ]);
    std::fs::write(&pkg, &data).unwrap();

    let opts = TreeOptions { pretty: true };
    let result = tree::run_tree(&pkg, &TreeFormat::Txt, &opts);
    assert!(result.is_ok(), "run_tree failed: {:?}", result.err());
    let (_report, output) = result.unwrap();

    assert!(output.contains("test"));
    assert!(output.contains("Hello.cs"));
    assert!(output.contains("Tool.dll"));
    assert!(output.contains("entries"));
    assert!(
        output.contains('\u{251C}') || output.contains('\u{2514}'),
        "pretty output should have unicode box-drawing chars"
    );
}

#[test]
fn txt_ascii_uses_plain_chars() {
    let dir = tempfile::tempdir().unwrap();
    let pkg = dir.path().join("ascii.unitypackage");
    let data = build_unitypackage(&[
        ("guid1/pathname", b"Assets/Data/Config.json".to_vec()),
        ("guid1/asset", b"{}".to_vec()),
        ("guid1/asset.meta", b"guid: guid1".to_vec()),
    ]);
    std::fs::write(&pkg, &data).unwrap();

    let opts = TreeOptions { pretty: false };
    let result = tree::run_tree(&pkg, &TreeFormat::Txt, &opts);
    assert!(result.is_ok());
    let (_report, output) = result.unwrap();

    assert!(output.contains("|--") || output.contains("`--"));
    assert!(!output.contains('\u{251C}'));
    assert!(!output.contains('\u{2514}'));
    assert!(output.contains("Config.json"));
}

#[test]
fn txt_includes_formatted_sizes() {
    let dir = tempfile::tempdir().unwrap();
    let pkg = dir.path().join("sizes.unitypackage");
    // 2300 bytes → "2.2 KB", 160000 bytes → "156.3 KB"
    let data = build_unitypackage(&[
        ("guid1/pathname", b"Assets/BigScript.cs".to_vec()),
        ("guid1/asset", vec![0u8; 160_000]),
        ("guid1/asset.meta", b"guid: guid1".to_vec()),
    ]);
    std::fs::write(&pkg, &data).unwrap();

    let opts = TreeOptions { pretty: false };
    let result = tree::run_tree(&pkg, &TreeFormat::Txt, &opts);
    assert!(result.is_ok());
    let (_report, output) = result.unwrap();
    assert!(output.contains("KB"));
}

#[test]
fn txt_handles_empty_package() {
    let dir = tempfile::tempdir().unwrap();
    let pkg = dir.path().join("empty.unitypackage");
    let data = build_unitypackage(&[]);
    std::fs::write(&pkg, &data).unwrap();

    let opts = TreeOptions { pretty: false };
    let result = tree::run_tree(&pkg, &TreeFormat::Txt, &opts);
    assert!(result.is_ok());
    let (_report, output) = result.unwrap();
    assert!(output.contains("0 entries"));
}

// ─── JSON output ─────────────────────────────────────────────────────────

#[test]
fn json_output_is_valid_and_complete() {
    let dir = tempfile::tempdir().unwrap();
    let pkg = dir.path().join("json.unitypackage");
    let data = build_unitypackage(&[
        ("guid1/pathname", b"Assets/MyScript.cs".to_vec()),
        ("guid1/asset", b"void Start() {}".to_vec()),
        ("guid1/asset.meta", b"guid: guid1".to_vec()),
    ]);
    std::fs::write(&pkg, &data).unwrap();

    let opts = TreeOptions { pretty: false };
    let result = tree::run_tree(&pkg, &TreeFormat::Json, &opts);
    assert!(result.is_ok());
    let (_report, output) = result.unwrap();

    let parsed: serde_json::Value = serde_json::from_str(&output).expect("valid JSON");
    assert_eq!(parsed["file"], "json");
    assert_eq!(parsed["total_entries"], 1);
    let tree = &parsed["tree"];
    assert_eq!(tree["name"], "json");
    let children = tree["children"].as_array().unwrap();
    assert!(!children.is_empty());
    // First child should be a directory "Assets"
    let assets = &children[0];
    assert_eq!(assets["type"], "directory");
    assert_eq!(assets["name"], "Assets");
}

#[test]
fn json_pretty_flag_does_not_break_output() {
    let dir = tempfile::tempdir().unwrap();
    let pkg = dir.path().join("json_pretty.unitypackage");
    let data = build_unitypackage(&[
        ("guid1/pathname", b"Assets/A.cs".to_vec()),
        ("guid1/asset", b"class A {}".to_vec()),
        ("guid1/asset.meta", b"guid: guid1".to_vec()),
    ]);
    std::fs::write(&pkg, &data).unwrap();

    let opts = TreeOptions { pretty: true }; // ignored for JSON
    let result = tree::run_tree(&pkg, &TreeFormat::Json, &opts);
    assert!(result.is_ok());
    let (_report, output) = result.unwrap();
    serde_json::from_str::<serde_json::Value>(&output).expect("valid JSON with pretty=true");
}

// ─── XML output ──────────────────────────────────────────────────────────

#[test]
fn xml_output_is_well_formed() {
    let dir = tempfile::tempdir().unwrap();
    let pkg = dir.path().join("xml.unitypackage");
    let data = build_unitypackage(&[
        ("guid1/pathname", b"Assets/Shaders/MyShader.shader".to_vec()),
        ("guid1/asset", b"Shader { }".to_vec()),
        ("guid1/asset.meta", b"guid: guid1".to_vec()),
    ]);
    std::fs::write(&pkg, &data).unwrap();

    let opts = TreeOptions { pretty: false };
    let result = tree::run_tree(&pkg, &TreeFormat::Xml, &opts);
    assert!(result.is_ok());
    let (_report, output) = result.unwrap();

    assert!(output.starts_with("<?xml"));
    assert!(output.contains("<package name=\"xml\""));
    assert!(output.contains("</package>"));
    assert!(output.contains("<file"));
    assert!(output.contains("MyShader.shader"));
}

#[test]
fn xml_entry_without_meta_has_no_has_meta_attr() {
    let dir = tempfile::tempdir().unwrap();
    let pkg = dir.path().join("nometa.unitypackage");
    let data = build_unitypackage(&[
        ("guid1/pathname", b"Assets/NoMeta.cs".to_vec()),
        ("guid1/asset", b"class X {}".to_vec()),
        // no asset.meta
    ]);
    std::fs::write(&pkg, &data).unwrap();

    let opts = TreeOptions { pretty: false };
    let result = tree::run_tree(&pkg, &TreeFormat::Xml, &opts);
    assert!(result.is_ok());
    let (_report, output) = result.unwrap();
    assert!(!output.contains("has_meta=\"true\""));
}

#[test]
fn xml_entry_with_meta_shows_has_meta() {
    let dir = tempfile::tempdir().unwrap();
    let pkg = dir.path().join("withmeta.unitypackage");
    let data = build_unitypackage(&[
        ("guid1/pathname", b"Assets/WithMeta.cs".to_vec()),
        ("guid1/asset", b"class Y {}".to_vec()),
        ("guid1/asset.meta", b"guid: guid1".to_vec()),
    ]);
    std::fs::write(&pkg, &data).unwrap();

    let opts = TreeOptions { pretty: false };
    let result = tree::run_tree(&pkg, &TreeFormat::Xml, &opts);
    assert!(result.is_ok());
    let (_report, output) = result.unwrap();
    assert!(output.contains("has_meta=\"true\""));
}

#[test]
fn xml_escapes_special_chars_in_name() {
    let dir = tempfile::tempdir().unwrap();
    let pkg = dir.path().join("escape.unitypackage");
    let data = build_unitypackage(&[
        ("guid1/pathname", b"Assets/Foo & Bar.cs".to_vec()),
        ("guid1/asset", b"class Z {}".to_vec()),
        ("guid1/asset.meta", b"guid: guid1".to_vec()),
    ]);
    std::fs::write(&pkg, &data).unwrap();

    let opts = TreeOptions { pretty: false };
    let result = tree::run_tree(&pkg, &TreeFormat::Xml, &opts);
    assert!(result.is_ok());
    let (_report, output) = result.unwrap();
    assert!(output.contains("Foo &amp; Bar"));
}

// ─── Error cases ─────────────────────────────────────────────────────────

#[test]
fn rejects_non_package_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("not_pkg.txt");
    std::fs::write(&path, b"hello world").unwrap();

    let opts = TreeOptions { pretty: true };
    let result = tree::run_tree(&path, &TreeFormat::Txt, &opts);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("not a UnityPackage") || err.contains("ZIP archive"));
}

// ─── Sorting ─────────────────────────────────────────────────────────────

#[test]
fn directories_appear_before_files() {
    let dir = tempfile::tempdir().unwrap();
    let pkg = dir.path().join("sorted.unitypackage");
    let data = build_unitypackage(&[
        ("guid1/pathname", b"Assets/ZFile.cs".to_vec()),
        ("guid1/asset", b"class Z {}".to_vec()),
        ("guid1/asset.meta", b"guid: guid1".to_vec()),
        ("guid2/pathname", b"Assets/SubDir/XFile.cs".to_vec()),
        ("guid2/asset", b"class X {}".to_vec()),
        ("guid2/asset.meta", b"guid: guid2".to_vec()),
        ("guid3/pathname", b"Assets/BFile.cs".to_vec()),
        ("guid3/asset", b"class B {}".to_vec()),
        ("guid3/asset.meta", b"guid: guid3".to_vec()),
    ]);
    std::fs::write(&pkg, &data).unwrap();

    let opts = TreeOptions { pretty: false };
    let result = tree::run_tree(&pkg, &TreeFormat::Txt, &opts);
    assert!(result.is_ok());
    let (_report, output) = result.unwrap();

    let subdir_pos = output.find("SubDir/").unwrap();
    let bfile_pos = output.find("BFile.cs").unwrap();
    let zfile_pos = output.find("ZFile.cs").unwrap();
    assert!(
        subdir_pos < bfile_pos,
        "SubDir/ should appear before BFile.cs"
    );
    assert!(
        bfile_pos < zfile_pos,
        "BFile.cs should appear before ZFile.cs"
    );
}
