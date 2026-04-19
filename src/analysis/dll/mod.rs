pub mod dotnet_scanner;
pub mod import_scanner;
pub mod pe_parser;
pub mod string_extractor;

use crate::report::Finding;

/// Run all DLL analysis stages on the given raw bytes.
/// `location` is the asset path (e.g. "Assets/Plugins/MyPlugin.dll").
/// Returns a flat list of findings.
pub fn analyze_dll(data: &[u8], location: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // PE header + sections
    let (pe_info, mut pe_findings) = pe_parser::analyze(data, location);
    findings.append(&mut pe_findings);

    // Import table
    let mut import_findings = import_scanner::analyze(data, location);
    findings.append(&mut import_findings);

    // Strings
    let mut string_findings = string_extractor::analyze(data, location);
    findings.append(&mut string_findings);

    // .NET metadata (only if managed assembly)
    if pe_info.is_dotnet {
        let mut dotnet_findings = dotnet_scanner::analyze(data, location);
        findings.append(&mut dotnet_findings);
    }

    findings
}
