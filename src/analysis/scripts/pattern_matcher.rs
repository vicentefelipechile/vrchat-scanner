use crate::report::{Finding, FindingId, Severity};
use crate::utils::patterns::*;
use crate::config::*;

/// Returns 1-indexed line numbers where `pattern` matches within `source`.
fn matching_lines(pattern: &regex::Regex, source: &str) -> Vec<u64> {
    source
        .lines()
        .enumerate()
        .filter_map(|(i, line)| {
            if pattern.is_match(line) {
                Some(i as u64 + 1)
            } else {
                None
            }
        })
        .collect()
}

/// Scan C# source code for dangerous API patterns.
pub fn analyze(source: &str, location: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // CRITICAL — Process execution
    if CS_PROCESS_START.is_match(source) {
        findings.push(
            Finding::new(
                FindingId::CsProcessStart,
                Severity::Critical,
                PTS_CS_PROCESS_START,
                location,
                "Process.Start() detected in C# script — executes arbitrary process",
            )
            .with_line_numbers(matching_lines(&CS_PROCESS_START, source)),
        );
    }

    // CRITICAL — Assembly loading from bytes
    if CS_ASSEMBLY_LOAD.is_match(source) {
        // Check if loading from bytes (most dangerous variant)
        let points = if source.contains("Assembly.Load(") && source.contains("byte") {
            PTS_CS_ASSEMBLY_LOAD_BYTES
        } else {
            PTS_CS_ASSEMBLY_LOAD_FILE
        };
        findings.push(
            Finding::new(
                FindingId::CsAssemblyLoadBytes,
                Severity::Critical,
                points,
                location,
                "Assembly.Load/LoadFile detected in C# script (dynamic assembly loading)",
            )
            .with_line_numbers(matching_lines(&CS_ASSEMBLY_LOAD, source)),
        );
    }

    // MEDIUM — Reflection.Emit
    if CS_REFLECTION_EMIT.is_match(source) {
        findings.push(
            Finding::new(
                FindingId::CsReflectionEmit,
                Severity::Medium,
                PTS_CS_REFLECTION_EMIT,
                location,
                "System.Reflection.Emit detected (runtime code generation)",
            )
            .with_line_numbers(matching_lines(&CS_REFLECTION_EMIT, source)),
        );
    }

    // MEDIUM — HTTP/WebClient
    if CS_WEBCLIENT.is_match(source) {
        findings.push(
            Finding::new(
                FindingId::CsHttpClient,
                Severity::Medium,
                PTS_CS_HTTP_CLIENT,
                location,
                "HTTP client (WebClient/HttpClient/UnityWebRequest) detected in C# script",
            )
            .with_line_numbers(matching_lines(&CS_WEBCLIENT, source)),
        );
    }

    // HIGH — File system writes
    if CS_FILE_WRITE.is_match(source) {
        findings.push(
            Finding::new(
                FindingId::CsFileWrite,
                Severity::High,
                PTS_CS_FILE_WRITE,
                location,
                "File write/delete operations detected in C# script",
            )
            .with_line_numbers(matching_lines(&CS_FILE_WRITE, source)),
        );
    }

    // HIGH — BinaryFormatter
    if CS_BINARY_FORMATTER.is_match(source) {
        findings.push(
            Finding::new(
                FindingId::CsBinaryFormatter,
                Severity::High,
                PTS_CS_BINARY_FORMATTER,
                location,
                "BinaryFormatter detected (insecure deserialization — arbitrary object execution)",
            )
            .with_line_numbers(matching_lines(&CS_BINARY_FORMATTER, source)),
        );
    }

    // MEDIUM/HIGH — DllImport / P/Invoke
    for cap in CS_DLLIMPORT.captures_iter(source) {
        let dll_name = cap.get(1).map(|m| m.as_str()).unwrap_or("?");
        let known_dlls = ["kernel32", "user32", "advapi32", "ntdll", "ws2_32", "shell32"];
        let is_known = known_dlls.iter().any(|k| dll_name.to_lowercase().contains(k));
        let points = if is_known { PTS_CS_DLLIMPORT_KNOWN } else { PTS_CS_DLLIMPORT_UNKNOWN };
        let severity = if is_known { Severity::Medium } else { Severity::High };
        findings.push(
            Finding::new(FindingId::CsDllimportUnknown, severity, points, location,
                "P/Invoke ([DllImport]) detected in C# script")
                .with_context(format!("DLL: {dll_name}")),
        );
    }

    // MEDIUM — Unsafe block
    if CS_UNSAFE.is_match(source) {
        findings.push(
            Finding::new(
                FindingId::CsUnsafeBlock,
                Severity::Medium,
                PTS_CS_UNSAFE_BLOCK,
                location,
                "Unsafe block detected in C# script",
            )
            .with_line_numbers(matching_lines(&CS_UNSAFE, source)),
        );
    }

    // MEDIUM — Registry access
    if CS_REGISTRY.is_match(source) {
        findings.push(
            Finding::new(
                FindingId::CsRegistryAccess,
                Severity::Medium,
                PTS_CS_REGISTRY_ACCESS,
                location,
                "Windows Registry access detected in C# script",
            )
            .with_line_numbers(matching_lines(&CS_REGISTRY, source)),
        );
    }

    // MEDIUM — Environment variables / machine identity
    if CS_ENVIRONMENT.is_match(source) {
        findings.push(
            Finding::new(
                FindingId::CsEnvironmentAccess,
                Severity::Medium,
                PTS_CS_ENVIRONMENT_ACCESS,
                location,
                "System environment variable or machine identity access in C# script",
            )
            .with_line_numbers(matching_lines(&CS_ENVIRONMENT, source)),
        );
    }

    // MEDIUM — Marshal
    if CS_MARSHAL.is_match(source) {
        findings.push(
            Finding::new(
                FindingId::CsMarshalOps,
                Severity::Medium,
                PTS_CS_MARSHAL_OPS,
                location,
                "Marshal operations (unsafe memory access) detected in C# script",
            )
            .with_line_numbers(matching_lines(&CS_MARSHAL, source)),
        );
    }

    // Shell commands (in string literals)
    if SHELL_CMD.is_match(source) {
        findings.push(
            Finding::new(
                FindingId::CsShellStrings,
                Severity::High,
                PTS_CS_SHELL_STRINGS,
                location,
                "Shell command strings found in C# script",
            )
            .with_line_numbers(matching_lines(&SHELL_CMD, source)),
        );
    }

    findings
}
