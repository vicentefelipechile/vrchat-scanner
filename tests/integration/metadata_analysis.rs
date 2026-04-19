//! Integration tests — Unity .meta parsing and dependency graph analysis.

use vrcstorage_scanner::analysis::metadata::{meta_parser, dependency_graph};

// ─── meta_parser ─────────────────────────────

#[test]
fn clean_meta_no_findings() {
    let meta = r#"fileFormatVersion: 2
guid: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4
timeCreated: 1672531200
MonoImporter:
  externalObjects: {}
  serializedVersion: 2
  defaultReferences: []
"#;
    let (info, findings) = meta_parser::analyze(meta, "Assets/Scripts/Foo.cs.meta");

    assert!(info.guid.is_some(), "GUID should be parsed");
    assert_eq!(info.guid.as_deref(), Some("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"));

    let suspicious: Vec<_> = findings
        .iter()
        .filter(|f| f.id != "META_FUTURE_TIMESTAMP")   // ignore timestamp issues
        .collect();
    assert!(suspicious.is_empty(), "Clean meta should have no findings; got: {:#?}", suspicious);
}

#[test]
fn meta_with_external_objects_flagged() {
    let meta = r#"fileFormatVersion: 2
guid: aaaabbbbccccddddeeeeffffaaaabbbb
externalObjects:
  SomeType: {fileID: 12345, guid: 11112222333344445555666677778888, type: 3}
"#;
    let (_info, findings) = meta_parser::analyze(meta, "Assets/Plugins/External.cs.meta");
    let has = findings.iter().any(|f| f.id == "META_EXTERNAL_REF");
    assert!(has, "META_EXTERNAL_REF not detected; got: {:#?}", findings);
}

#[test]
fn meta_future_timestamp_flagged() {
    // Year 2099 timestamp
    let future_ts: i64 = 4102444800; // 2100-01-01 UTC
    let meta = format!(
        "fileFormatVersion: 2\nguid: deadbeefdeadbeefdeadbeefdeadbeef\ntimeCreated: {}\n",
        future_ts
    );
    let (_info, findings) = meta_parser::analyze(&meta, "Assets/Scripts/Future.cs.meta");
    let has = findings.iter().any(|f| f.id == "META_FUTURE_TIMESTAMP");
    assert!(has, "META_FUTURE_TIMESTAMP not flagged; got: {:#?}", findings);
}

#[test]
fn meta_past_timestamp_not_flagged() {
    // Year 2022 — clearly in the past
    let past_ts: i64 = 1672531200; // 2023-01-01 UTC
    let meta = format!(
        "fileFormatVersion: 2\nguid: cafecafecafecafecafecafecafecafe\ntimeCreated: {}\n",
        past_ts
    );
    let (_info, findings) = meta_parser::analyze(&meta, "Assets/Scripts/Old.cs.meta");
    let timestamp_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.id == "META_FUTURE_TIMESTAMP")
        .collect();
    assert!(
        timestamp_findings.is_empty(),
        "Past timestamp should not be flagged; got: {:#?}",
        timestamp_findings
    );
}

#[test]
fn guid_extracted_correctly() {
    let guid_value = "0123456789abcdef0123456789abcdef";
    let meta = format!("fileFormatVersion: 2\nguid: {guid_value}\n");
    let (info, _) = meta_parser::analyze(&meta, "Asset.cs.meta");
    assert_eq!(info.guid.as_deref(), Some(guid_value));
}

// ─── dependency_graph ────────────────────────

#[test]
fn dll_with_many_dependents_flagged() {
    use std::collections::HashMap;

    let mut guid_to_path = HashMap::new();
    guid_to_path.insert("abc123".to_string(), "Assets/Plugins/Suspicious.dll".to_string());

    let mut dll_guid_count = HashMap::new();
    // 6 references — above the threshold of 5
    dll_guid_count.insert("abc123".to_string(), 6usize);

    let findings = dependency_graph::analyze(&guid_to_path, &dll_guid_count, "package");
    let has = findings.iter().any(|f| f.id == "DLL_MANY_DEPENDENTS");
    assert!(has, "DLL_MANY_DEPENDENTS not flagged; got: {:#?}", findings);
}

#[test]
fn dll_with_few_dependents_not_flagged() {
    use std::collections::HashMap;

    let mut guid_to_path = HashMap::new();
    guid_to_path.insert("abc123".to_string(), "Assets/Plugins/Normal.dll".to_string());

    let mut dll_guid_count = HashMap::new();
    // 3 references — below threshold
    dll_guid_count.insert("abc123".to_string(), 3usize);

    let findings = dependency_graph::analyze(&guid_to_path, &dll_guid_count, "package");
    assert!(findings.is_empty(), "Small dependency count should not be flagged; got: {:#?}", findings);
}

#[test]
fn empty_dependency_graph_no_findings() {
    use std::collections::HashMap;
    let findings = dependency_graph::analyze(&HashMap::new(), &HashMap::new(), "package");
    assert!(findings.is_empty());
}
