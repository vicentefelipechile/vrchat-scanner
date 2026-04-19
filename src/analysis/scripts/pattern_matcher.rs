use crate::report::{Finding, Severity};
use crate::utils::patterns::*;

/// Scan C# source code for dangerous API patterns.
pub fn analyze(source: &str, location: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // CRITICAL — Process execution
    if CS_PROCESS_START.is_match(source) {
        findings.push(Finding::new(
            "CS_PROCESS_START",
            Severity::Critical,
            75,
            location,
            "Process.Start() detected in C# script — executes arbitrary process",
        ));
    }

    // CRITICAL — Assembly loading from bytes
    if CS_ASSEMBLY_LOAD.is_match(source) {
        // Check if loading from bytes (most dangerous variant)
        let points = if source.contains("Assembly.Load(") && source.contains("byte") {
            80
        } else {
            60
        };
        findings.push(Finding::new(
            "CS_ASSEMBLY_LOAD_BYTES",
            Severity::Critical,
            points,
            location,
            "Assembly.Load/LoadFile detected in C# script (dynamic assembly loading)",
        ));
    }

    // CRITICAL — Reflection.Emit
    if CS_REFLECTION_EMIT.is_match(source) {
        findings.push(Finding::new(
            "CS_REFLECTION_EMIT",
            Severity::Medium,
            40,
            location,
            "System.Reflection.Emit detected (runtime code generation)",
        ));
    }

    // ALTO — HTTP/WebClient
    if CS_WEBCLIENT.is_match(source) {
        findings.push(Finding::new(
            "CS_HTTP_CLIENT",
            Severity::Medium,
            30,
            location,
            "HTTP client (WebClient/HttpClient/UnityWebRequest) detected in C# script",
        ));
    }

    // ALTO — File system writes
    if CS_FILE_WRITE.is_match(source) {
        findings.push(Finding::new(
            "CS_FILE_WRITE",
            Severity::High,
            40,
            location,
            "File write/delete operations detected in C# script",
        ));
    }

    // ALTO — BinaryFormatter
    if CS_BINARY_FORMATTER.is_match(source) {
        findings.push(Finding::new(
            "CS_BINARY_FORMATTER",
            Severity::High,
            45,
            location,
            "BinaryFormatter detected (insecure deserialization — arbitrary object execution)",
        ));
    }

    // MEDIO — DllImport / P/Invoke
    for cap in CS_DLLIMPORT.captures_iter(source) {
        let dll_name = cap.get(1).map(|m| m.as_str()).unwrap_or("?");
        let known_dlls = ["kernel32", "user32", "advapi32", "ntdll", "ws2_32", "shell32"];
        let is_known = known_dlls.iter().any(|k| dll_name.to_lowercase().contains(k));
        let points = if is_known { 45 } else { 60 };
        let severity = if is_known { Severity::Medium } else { Severity::High };
        findings.push(
            Finding::new("CS_DLLIMPORT_UNKNOWN", severity, points, location,
                "P/Invoke ([DllImport]) detected in C# script")
                .with_context(format!("DLL: {dll_name}")),
        );
    }

    // MEDIO — Unsafe block
    if CS_UNSAFE.is_match(source) {
        findings.push(Finding::new(
            "CS_UNSAFE_BLOCK",
            Severity::Medium,
            30,
            location,
            "Unsafe block detected in C# script",
        ));
    }

    // MEDIO — Registry access
    if CS_REGISTRY.is_match(source) {
        findings.push(Finding::new(
            "CS_REGISTRY_ACCESS",
            Severity::Medium,
            35,
            location,
            "Windows Registry access detected in C# script",
        ));
    }

    // MEDIO — Environment variables / machine identity
    if CS_ENVIRONMENT.is_match(source) {
        findings.push(Finding::new(
            "CS_ENVIRONMENT_ACCESS",
            Severity::Medium,
            15,
            location,
            "System environment variable or machine identity access in C# script",
        ));
    }

    // MEDIO — Marshal
    if CS_MARSHAL.is_match(source) {
        findings.push(Finding::new(
            "CS_MARSHAL_OPS",
            Severity::Medium,
            25,
            location,
            "Marshal operations (unsafe memory access) detected in C# script",
        ));
    }

    // Shell commands (in string literals)
    if SHELL_CMD.is_match(source) {
        findings.push(Finding::new(
            "CS_SHELL_STRINGS",
            Severity::High,
            45,
            location,
            "Shell command strings found in C# script",
        ));
    }

    findings
}
