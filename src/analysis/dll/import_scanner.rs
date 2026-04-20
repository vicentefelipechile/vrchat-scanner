use crate::report::{Finding, FindingId, Severity};
use crate::config::*;

/// Categories of dangerous imports
enum ImportRisk {
    Critical(u32, &'static str),
    High(u32, &'static str),
    Medium(u32, &'static str),
    Low(u32, &'static str),
}

struct ImportRule {
    dll: &'static str,
    func: &'static str,
    rule_id: FindingId,
    risk: ImportRisk,
}

const IMPORT_RULES: &[ImportRule] = &[
    // CRITICAL — Process execution
    ImportRule { dll: "kernel32.dll", func: "CreateProcessA",    rule_id: FindingId::DllImportCreateprocess,     risk: ImportRisk::Critical(PTS_DLL_IMPORT_CREATEPROCESS, "CreateProcess (execute arbitrary process)") },
    ImportRule { dll: "kernel32.dll", func: "CreateProcessW",    rule_id: FindingId::DllImportCreateprocess,     risk: ImportRisk::Critical(PTS_DLL_IMPORT_CREATEPROCESS, "CreateProcess (execute arbitrary process)") },
    ImportRule { dll: "shell32.dll",  func: "ShellExecuteA",     rule_id: FindingId::DllImportCreateprocess,     risk: ImportRisk::Critical(PTS_DLL_IMPORT_CREATEPROCESS, "ShellExecute (open/execute file)") },
    ImportRule { dll: "shell32.dll",  func: "ShellExecuteW",     rule_id: FindingId::DllImportCreateprocess,     risk: ImportRisk::Critical(PTS_DLL_IMPORT_CREATEPROCESS, "ShellExecute (open/execute file)") },
    ImportRule { dll: "kernel32.dll", func: "WinExec",           rule_id: FindingId::DllImportCreateprocess,     risk: ImportRisk::Critical(PTS_DLL_IMPORT_CREATEPROCESS, "WinExec (execute command)") },
    // CRITICAL — Code injection
    ImportRule { dll: "kernel32.dll", func: "CreateRemoteThread", rule_id: FindingId::DllImportCreateremotethread, risk: ImportRisk::Critical(PTS_DLL_IMPORT_CREATEREMOTETHREAD, "CreateRemoteThread (classic code injection)") },
    ImportRule { dll: "ntdll.dll",    func: "RtlCreateUserThread", rule_id: FindingId::DllImportCreateremotethread, risk: ImportRisk::Critical(PTS_DLL_IMPORT_CREATEREMOTETHREAD, "RtlCreateUserThread (code injection via NT API)") },
    // HIGH — Network
    ImportRule { dll: "ws2_32.dll",   func: "connect",           rule_id: FindingId::DllImportSockets,          risk: ImportRisk::High(PTS_DLL_IMPORT_SOCKETS, "Raw TCP socket connect") },
    ImportRule { dll: "ws2_32.dll",   func: "send",              rule_id: FindingId::DllImportSockets,          risk: ImportRisk::High(PTS_DLL_IMPORT_SOCKETS, "Raw socket send") },
    ImportRule { dll: "ws2_32.dll",   func: "recv",              rule_id: FindingId::DllImportSockets,          risk: ImportRisk::High(PTS_DLL_IMPORT_SOCKETS, "Raw socket recv") },
    ImportRule { dll: "wininet.dll",  func: "InternetOpenA",     rule_id: FindingId::DllImportInternet,         risk: ImportRisk::High(PTS_DLL_IMPORT_INTERNET, "WinInet InternetOpen") },
    ImportRule { dll: "winhttp.dll",  func: "WinHttpOpen",       rule_id: FindingId::DllImportInternet,         risk: ImportRisk::High(PTS_DLL_IMPORT_INTERNET, "WinHTTP client") },
    // HIGH — Memory manipulation
    ImportRule { dll: "kernel32.dll", func: "WriteProcessMemory", rule_id: FindingId::DllImportWriteProcessMem, risk: ImportRisk::High(PTS_DLL_IMPORT_WRITE_PROCESS_MEM, "WriteProcessMemory (process memory manipulation)") },
    ImportRule { dll: "kernel32.dll", func: "VirtualAlloc",      rule_id: FindingId::DllImportVirtualAlloc,     risk: ImportRisk::High(PTS_DLL_IMPORT_VIRTUAL_ALLOC, "VirtualAlloc (allocate executable memory)") },
    // MEDIUM — Dynamic loading
    ImportRule { dll: "kernel32.dll", func: "LoadLibraryA",      rule_id: FindingId::DllImportLoadlibrary,      risk: ImportRisk::Medium(PTS_DLL_IMPORT_LOADLIBRARY, "LoadLibrary (dynamic DLL loading)") },
    ImportRule { dll: "kernel32.dll", func: "LoadLibraryW",      rule_id: FindingId::DllImportLoadlibrary,      risk: ImportRisk::Medium(PTS_DLL_IMPORT_LOADLIBRARY, "LoadLibrary (dynamic DLL loading)") },
    ImportRule { dll: "kernel32.dll", func: "GetProcAddress",    rule_id: FindingId::DllImportGetprocaddress,   risk: ImportRisk::Medium(PTS_DLL_IMPORT_GETPROCADDRESS, "GetProcAddress (resolve function at runtime)") },
    // MEDIUM — File system
    ImportRule { dll: "kernel32.dll", func: "DeleteFileA",       rule_id: FindingId::DllImportFileOps,          risk: ImportRisk::Medium(PTS_DLL_IMPORT_FILE_OPS, "DeleteFile") },
    ImportRule { dll: "kernel32.dll", func: "DeleteFileW",       rule_id: FindingId::DllImportFileOps,          risk: ImportRisk::Medium(PTS_DLL_IMPORT_FILE_OPS, "DeleteFile") },
    // MEDIUM — Registry
    ImportRule { dll: "advapi32.dll", func: "RegOpenKeyA",       rule_id: FindingId::DllImportRegistry,         risk: ImportRisk::Medium(PTS_DLL_IMPORT_REGISTRY, "RegOpenKey (Windows registry access)") },
    ImportRule { dll: "advapi32.dll", func: "RegSetValueExA",    rule_id: FindingId::DllImportRegistry,         risk: ImportRisk::Medium(PTS_DLL_IMPORT_REGISTRY, "RegSetValue (registry write)") },
    ImportRule { dll: "advapi32.dll", func: "RegCreateKeyA",     rule_id: FindingId::DllImportRegistry,         risk: ImportRisk::Medium(PTS_DLL_IMPORT_REGISTRY, "RegCreateKey") },
    // MEDIUM — Cryptography
    ImportRule { dll: "advapi32.dll", func: "CryptEncrypt",      rule_id: FindingId::DllImportCrypto,           risk: ImportRisk::Medium(PTS_DLL_IMPORT_CRYPTO, "CryptEncrypt (may be ransomware or legitimate)") },
    ImportRule { dll: "bcrypt.dll",   func: "BCryptEncrypt",     rule_id: FindingId::DllImportCrypto,           risk: ImportRisk::Medium(PTS_DLL_IMPORT_CRYPTO, "BCryptEncrypt") },
    // LOW — System information
    ImportRule { dll: "kernel32.dll", func: "GetComputerNameA",  rule_id: FindingId::DllImportSysinfo,          risk: ImportRisk::Low(PTS_DLL_IMPORT_SYSINFO, "GetComputerName (system info, may be telemetry)") },
    ImportRule { dll: "kernel32.dll", func: "GetUserNameA",      rule_id: FindingId::DllImportSysinfo,          risk: ImportRisk::Low(PTS_DLL_IMPORT_SYSINFO, "GetUserName (system info, may be telemetry)") },
];

/// Scan the import table of a PE file and produce findings.
pub fn analyze(data: &[u8], location: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen_rules = std::collections::HashSet::new();

    let pe = match goblin::pe::PE::parse(data) {
        Ok(pe) => pe,
        Err(_) => return findings,
    };

    for import in &pe.imports {
        let dll_lower = import.dll.to_lowercase();
        let func_name = &import.name;

        for rule in IMPORT_RULES {
            if rule.dll == dll_lower
                && func_name.to_lowercase().starts_with(&rule.func.to_lowercase())
                && !seen_rules.contains(&rule.rule_id)
            {
                let (severity, points, detail) = match &rule.risk {
                    ImportRisk::Critical(p, d) => (Severity::Critical, *p, *d),
                    ImportRisk::High(p, d)     => (Severity::High, *p, *d),
                    ImportRisk::Medium(p, d)   => (Severity::Medium, *p, *d),
                    ImportRisk::Low(p, d)      => (Severity::Low, *p, *d),
                };

                findings.push(
                    Finding::new(rule.rule_id, severity, points, location, detail)
                        .with_context(format!("{}::{}", rule.dll, func_name)),
                );
                seen_rules.insert(rule.rule_id);
            }
        }
    }

    findings
}
