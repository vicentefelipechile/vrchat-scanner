use crate::report::{Finding, Severity};

/// Minimal .NET metadata analysis.
/// Looks for dangerous type/method references in the .NET metadata tables.
pub fn analyze(data: &[u8], location: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // We use a string-search approach over the PE bytes looking for
    // .NET metadata signatures. A full IL parser would require dotnetpe crate.
    let text = String::from_utf8_lossy(data);

    // Reflection.Emit
    if text.contains("System.Reflection.Emit") || text.contains("ILGenerator") {
        findings.push(Finding::new(
            "CS_REFLECTION_EMIT",
            Severity::Medium,
            40,
            location,
            "System.Reflection.Emit found in .NET metadata (runtime code generation)",
        ));
    }

    // P/Invoke interop
    if text.contains("System.Runtime.InteropServices") {
        findings.push(Finding::new(
            "CS_DLLIMPORT_UNKNOWN",
            Severity::High,
            60,
            location,
            "System.Runtime.InteropServices in .NET metadata (possible P/Invoke to native code)",
        ));
    }

    // Assembly.Load
    if text.contains("Assembly.Load") {
        findings.push(Finding::new(
            "CS_ASSEMBLY_LOAD_BYTES",
            Severity::Critical,
            80,
            location,
            "Assembly.Load reference in .NET metadata (dynamic assembly loading)",
        ));
    }

    // Process
    if text.contains("System.Diagnostics.Process") {
        findings.push(Finding::new(
            "CS_PROCESS_START",
            Severity::Critical,
            75,
            location,
            "System.Diagnostics.Process reference in .NET metadata",
        ));
    }

    findings
}
