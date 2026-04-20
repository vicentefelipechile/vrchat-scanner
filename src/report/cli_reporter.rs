use colored::Colorize;
use crate::scoring::RiskLevel;
use crate::terminal::TermCaps;
use super::{finding::{Finding, FindingId, Severity}, json_reporter::ScanReport};

// ─────────────────────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Print a formatted CLI report with ANSI colors.
///
/// * `verbose = false` — compact technical output (programmer / CI).
/// * `verbose = true`  — adds a plain-English explanation under every finding
///   and a user-facing verdict at the end (drag-and-drop / end-user mode).
/// * `caps` — terminal capabilities; when `caps.unicode = false` box-drawing
///   characters are replaced with plain ASCII hyphens/equals.
pub fn print_report(report: &ScanReport, level: RiskLevel, verbose: bool, caps: TermCaps) {
    let (_sep, thin, thick) = if caps.unicode {
        ("─".repeat(52), "─".repeat(52), "━".repeat(52))
    } else {
        ("-".repeat(52), "-".repeat(52), "=".repeat(52))
    };

    // ── File header ───────────────────────────────────────────
    println!("{}", thick.dimmed());
    println!("{:12} {}", "File:".bold(),    report.file.path);
    println!("{:12} {}", "SHA-256:".bold(), report.file.sha256);
    println!("{:12} {}", "Size:".bold(),    format_bytes(report.file.size_bytes));
    println!("{:12} {}", "Type:".bold(),    report.file.file_type);
    println!("{}", thick.dimmed());

    // ── Asset statistics ──────────────────────────────────────
    let c = &report.assets_analyzed;
    println!(
        "\n{} {}  {} {}  {} {}  {} {}  {} {}  {} {}",
        "Assets:".bold(),
        format!("total={}", c.total),
        "|" .dimmed(),
        format!("scripts={}", c.scripts),
        "|" .dimmed(),
        format!("dlls={}", c.dlls),
        "|" .dimmed(),
        format!("textures={}", c.textures),
        "|" .dimmed(),
        format!("audio={}", c.audio),
        "|" .dimmed(),
        format!("prefabs={}", c.prefabs),
    );

    // ── Findings ──────────────────────────────────────────────
    let count = report.findings.len();
    if count == 0 {
        if caps.unicode {
            println!("\n{}", "  No findings detected. ✓".green().bold());
        } else {
            println!("\n{}", "  No findings detected.".green().bold());
        }
    } else {
        println!("\n{} ({} found)", "FINDINGS".bold(), count);
        println!("{}", thin.dimmed());

        for f in &report.findings {
            print_finding(f, verbose, caps);
        }
    }

    // ── Score summary ─────────────────────────────────────────
    println!("{}", thin.dimmed());
    println!("{:14} {}", "Total score:".bold(), report.risk.score);
    println!("{:14} {}", "Risk level:".bold(),  level_colored(level));
    println!("{:14} {}", "Action:".bold(),       &report.risk.recommendation);
    println!("{}", thin.dimmed());
    println!("{:14} {}ms", "Duration:".bold(), report.scan_duration_ms);

    // Always print a verdict — the key outcome in human-readable terms.
    print_verdict(level, &report.findings, caps);
}

// ─────────────────────────────────────────────────────────────────────────────
// Finding printer
// ─────────────────────────────────────────────────────────────────────────────

fn print_finding(f: &Finding, verbose: bool, caps: TermCaps) {
    let severity_label = match f.severity {
        Severity::Critical => format!("[CRITICAL +{}]", f.points).red().bold().to_string(),
        Severity::High     => format!("[HIGH     +{}]", f.points).yellow().bold().to_string(),
        Severity::Medium   => format!("[MEDIUM   +{}]", f.points).bright_yellow().to_string(),
        Severity::Low      => format!("[LOW      +{}]", f.points).white().to_string(),
    };

    println!("\n{} {}", severity_label, f.detail.bold());
    println!("  {:10} {}", "File:".dimmed(),    f.location);
    println!("  {:10} {}", "ID:".dimmed(),      f.id);
    if let Some(ctx) = &f.context {
        println!("  {:10} {}", "Context:".dimmed(), ctx);
    }

    if verbose {
        let explanation = human_explanation(f.id);
        // Word-wrap at ~60 chars and indent every line
        let wrapped = word_wrap(explanation, 60);
        for line in wrapped {
            println!("  {}", line.dimmed());
        }
    }
    let _ = caps; // used by callers for separator style
}

// ─────────────────────────────────────────────────────────────────────────────
// Verdict section (always shown)
// ─────────────────────────────────────────────────────────────────────────────

fn print_verdict(level: RiskLevel, findings: &[Finding], caps: TermCaps) {
    let double = if caps.unicode { "═".repeat(52) } else { "=".repeat(52) };
    let repo   = env!("CARGO_PKG_REPOSITORY");
    let critical_high = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Critical | Severity::High))
        .count();

    println!("\n{}", double.dimmed());
    println!("{}", " VERDICT".bold());
    println!("{}", double.dimmed());

    match level {
        RiskLevel::Clean => {
            println!("{}", " ✓  SAFE TO USE".green().bold());
            println!("    No significant security concerns were found.");
            println!("    This package appears to be legitimate Unity content.");
            println!("    You can install it normally.");
        }
        RiskLevel::Low => {
            println!("{}", " ✓  LIKELY SAFE — minor concerns".blue().bold());
            println!("    A few low-priority signals were detected, but nothing");
            println!("    alarming. Review the findings above. If you trust the");
            println!("    creator, this package is probably fine to use.");
        }
        RiskLevel::Medium => {
            println!("{}", " ⚠  REVIEW RECOMMENDED".bright_yellow().bold());
            println!("    This package has moderate security concerns.");
            println!("    Consider asking the creator to explain the flagged items.");
            println!("    Only install if you fully trust the source.");
        }
        RiskLevel::High => {
            println!("{}", " ✗  NOT RECOMMENDED".yellow().bold());
            println!("    This package has {} critical or high-severity finding(s).", critical_high);
            println!("    It may contain dangerous code. Avoid installing unless you");
            println!("    have manually reviewed every flagged item and fully trust");
            println!("    the creator.");
        }
        RiskLevel::Critical => {
            println!("{}", " ✗  DO NOT INSTALL".red().bold());
            println!("    This package has been flagged as potentially malicious.");
            println!("    Installing it could compromise your computer or account.");
            println!("    If you received it from someone you don't know,");
            println!("    do not use it and consider reporting it.");
        }
    }

    println!("{}", double.dimmed());
    println!(
        "  {} | {}",
        "vrcstorage-scanner by SummerTYT".dimmed(),
        repo.dimmed()
    );
    println!("{}\n", double.dimmed());
}

// ─────────────────────────────────────────────────────────────────────────────
// Plain-English explanations (verbose / drag-and-drop mode)
// ─────────────────────────────────────────────────────────────────────────────

/// Return a plain-English explanation for why a finding is suspicious
/// and what it means in practice for a non-technical user.
fn human_explanation(id: FindingId) -> &'static str {
    match id {
        FindingId::ForbiddenExtension =>
            "The package contains a standalone executable (.exe, .bat, .ps1, \
             etc.). Legitimate Unity packages should never ship runnable files. \
             This is a strong indicator of malicious intent.",

        FindingId::PathTraversal =>
            "A file path inside the package uses '../' sequences. These can \
             trick Unity into writing files outside your project folder — \
             a classic attack that can overwrite system files.",

        FindingId::CsAssemblyLoadBytes =>
            "A C# script loads a .NET library from raw bytes at runtime. \
             Malicious packages use this to hide their payload: the real \
             code only appears in memory, invisible to file-based scanners.",

        FindingId::CsProcessStart =>
            "A C# script launches an external program on your computer. \
             No legitimate VRChat or Unity content ever needs to start \
             external processes. This is almost always malicious.",

        FindingId::PolyglotFile =>
            "A file is structurally valid in two different formats at once \
             (e.g., a PNG that is also a Windows executable). Without a \
             companion loader script this payload is inert, but it is still \
             an unusual and suspicious artifact.",

        FindingId::CsDllimportUnknown =>
            "A C# script imports a function from an unknown native DLL via \
             P/Invoke. This bypasses .NET's safety sandbox and can run \
             arbitrary native machine code.",

        FindingId::DllImportSockets =>
            "A DLL imports Windows socket libraries (ws2_32.dll), which \
             enable raw network connections. Unity content rarely needs this; \
             it may be used to establish a covert communication channel.",

        FindingId::PeHighEntropySection =>
            "A DLL section has very high data randomness (entropy). \
             Legitimate compiled code has recognisable patterns. Very high \
             entropy usually means the section is packed or encrypted to \
             hide its real contents from scanners.",

        FindingId::CsUrlUnknownDomain =>
            "A script contains a URL pointing to an unknown external server. \
             This could be used to download additional malicious code or \
             silently send your data to a remote server.",

        FindingId::CsIpHardcoded =>
            "A hardcoded IP address was found in a script. This is a common \
             sign of a command-and-control (C2) setup, where the malware \
             phones home to receive instructions.",

        FindingId::MagicMismatch =>
            "The file's actual binary format does not match its extension. \
             For example, a file named '.png' that is actually a Windows \
             executable. This is a disguise technique.",

        FindingId::DoubleExtension =>
            "A file uses two extensions (e.g., file.png.dll) to make an \
             executable look like an innocent image or audio file.",

        FindingId::CsBinaryFormatter =>
            "A script uses BinaryFormatter, which has well-known \
             deserialization vulnerabilities. An attacker can craft a \
             malicious payload that executes arbitrary code when \
             deserialized.",

        FindingId::CsShellStrings =>
            "Strings referencing shell commands (cmd.exe, powershell, bash, \
             curl, etc.) were found. This suggests the package may attempt \
             to run system commands on your machine.",

        FindingId::CsFileWrite =>
            "A script writes, deletes, or moves files on your computer. \
             Legitimate VRChat content has no reason to access your \
             filesystem directly. This can be used to drop additional \
             files or destroy data.",

        FindingId::PeWriteExecuteSection =>
            "A DLL has memory regions that are simultaneously writable and \
             executable. This is a hallmark of code that modifies itself in \
             memory or injects shellcode — a serious red flag.",

        FindingId::CsReflectionEmit =>
            "A script compiles and executes brand-new .NET code at runtime. \
             This means the real malicious code may not exist in any file — \
             it is generated on the fly after installation.",

        FindingId::DllOutsidePlugins =>
            "A DLL is located outside the standard Assets/Plugins/ folder. \
             Unity expects managed libraries there. Unusual placement can \
             indicate that the file was added to avoid visibility.",

        FindingId::CsRegistryAccess =>
            "A script reads or writes Windows Registry keys. \
             Unity/VRChat content running inside the game engine has no \
             legitimate reason to touch the Windows Registry.",

        FindingId::CsHttpClient =>
            "A script makes HTTP/HTTPS requests. This is normal in VRChat \
             SDK tools (e.g., avatar uploads), but could also be used to \
             download additional payloads or exfiltrate data.",

        FindingId::CsUnsafeBlock =>
            "A script uses C# 'unsafe' code, which bypasses .NET's memory \
             safety guarantees and allows raw pointer operations. Legitimate \
             use exists (e.g., high-performance math), but it also opens \
             the door to memory corruption exploits.",

        FindingId::MetaExternalRef =>
            "A .meta file references assets that are not included in this \
             package. Those assets would be loaded from another source \
             whose contents are not being scanned.",

        FindingId::CsBase64HighRatio =>
            "There is a large concentrated block of Base64 data in the code. \
             Base64 is plain text, so tools encode malicious bytes in it \
             to avoid binary detection, then decode it at runtime.",

        FindingId::CsMarshalOps =>
            "A script uses raw memory operations (Marshal.Copy, \
             AllocHGlobal, GetFunctionPointerForDelegate). These are \
             advanced techniques that can be used to execute shellcode \
             directly in memory.",

        FindingId::PeUnnamedSection =>
            "A DLL section has no name. Legitimate compilers always name \
             sections (.text, .data, .rdata, etc.). A nameless section \
             is unusual and may indicate manual binary patching.",

        FindingId::PeInflatedSection =>
            "A DLL section is much larger in memory than it is on disk. \
             Code can be hidden in the gap — it only materialises in RAM \
             after the DLL is loaded, making it invisible in the file.",

        FindingId::DllManyDependents =>
            "A single DLL is imported by many different assets in the \
             package. If that DLL is malicious, it has a wide blast radius \
             across the entire project.",

        FindingId::ExcessiveDlls =>
            "The package ships an unusually large number of DLL files. \
             More DLLs means more attack surface and more code to review.",

        FindingId::CsObfuscatedIdentifiers =>
            "Script variables and methods use meaninglessly short names \
             (single letters). Obfuscation tools do this to hide a \
             script's true purpose and make manual review very difficult.",

        FindingId::DllStringsSuspiciousPath =>
            "A DLL contains strings that look like system file paths \
             (%APPDATA%, C:\\Windows\\, /etc/, etc.). This suggests the DLL \
             intends to access or modify system locations.",

        FindingId::DllImportRegistry =>
            "A DLL references Windows Registry paths. This suggests it may \
             read or modify system configuration outside of the game.",

        FindingId::CsEnvironmentAccess =>
            "A script reads environment variables such as your username or \
             machine name. This can be used to fingerprint or target \
             specific computers.",

        FindingId::CsNoMeta =>
            "A C# script has no accompanying .meta file. Unity generates \
             these automatically for every tracked asset. A missing .meta \
             suggests the script was injected outside Unity's normal \
             workflow.",

        FindingId::TextureHighEntropy =>
            "This texture has unusually random byte distribution for its \
             format. For uncompressed formats this can indicate hidden data \
             embedded inside the image.",

        FindingId::AudioUnusualEntropy =>
            "This audio file has an abnormal entropy level for its format, \
             which may indicate it is not a genuine audio file.",

        FindingId::CsXorDecryption =>
            "A XOR operation on a byte array was detected. This is a common \
             technique used to obfuscate strings or embedded payloads that \
             are decoded at runtime.",

        FindingId::CsUnicodeEscapes =>
            "Unicode escape sequences were found in C# source code. \
             Obfuscators use these to disguise keywords and API calls as \
             innocent character sequences.",

        FindingId::PeInvalidHeader =>
            "The file does not start with the expected PE magic bytes (MZ). \
             This DLL may be corrupted or intentionally malformed.",

        FindingId::PeParseError =>
            "The PE header could not be fully parsed. The binary may be \
             intentionally malformed to evade analysis tools.",

        FindingId::DllImportCreateprocess =>
            "A DLL imports process-creation APIs (CreateProcess, \
             ShellExecute, WinExec) capable of launching arbitrary \
             executables on the host system.",

        FindingId::DllImportCreateremotethread =>
            "A DLL imports thread-injection APIs (CreateRemoteThread, \
             RtlCreateUserThread) classically used for code injection into \
             other processes.",

        FindingId::DllImportInternet =>
            "A DLL imports WinInet or WinHTTP APIs used to make network \
             requests, potentially to download payloads or exfiltrate data.",

        FindingId::DllImportWriteProcessMem =>
            "A DLL imports WriteProcessMemory, which is the core API for \
             injecting code or data into another running process.",

        FindingId::DllImportVirtualAlloc =>
            "A DLL imports VirtualAlloc, used to allocate executable memory \
             regions — a key step in shellcode injection.",

        FindingId::DllImportLoadlibrary =>
            "A DLL imports LoadLibrary, enabling it to dynamically load \
             additional DLLs at runtime that are not visible at import time.",

        FindingId::DllImportGetprocaddress =>
            "A DLL imports GetProcAddress to resolve function pointers at \
             runtime, hiding what APIs it actually calls from static analysis.",

        FindingId::DllImportFileOps =>
            "A DLL imports file-deletion APIs (DeleteFile), which could be \
             used to remove evidence or destroy user data.",

        FindingId::DllImportCrypto =>
            "A DLL imports cryptographic APIs. While common in legitimate \
             software, these are also used by ransomware to encrypt files.",

        FindingId::DllImportSysinfo =>
            "A DLL queries system identity information (computer name, \
             username). This is often used for fingerprinting or victim \
             targeting.",

        FindingId::MetaFutureTimestamp =>
            "A .meta file contains a creation timestamp set in the future. \
             This is unusual and may indicate the file was tampered with \
             or crafted outside Unity.",

        FindingId::PrefabExcessiveGuids =>
            "A binary prefab contains an abnormally large number of GUID \
             references, which may indicate hidden dependencies.",

        FindingId::PrefabInlineB64 =>
            "A YAML prefab or asset file contains a long Base64-encoded \
             field. This could be an inline texture or an embedded payload.",

        FindingId::PrefabManyScripts =>
            "A prefab references an unusually large number of scripts. \
             This increases the attack surface if any of those scripts \
             contain malicious code.",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn level_colored(level: RiskLevel) -> String {
    match level {
        RiskLevel::Clean    => "■ CLEAN".green().bold().to_string(),
        RiskLevel::Low      => "■ LOW".blue().bold().to_string(),
        RiskLevel::Medium   => "■ MEDIUM".bright_yellow().bold().to_string(),
        RiskLevel::High     => "■ HIGH".yellow().bold().to_string(),
        RiskLevel::Critical => "■ CRITICAL".red().bold().to_string(),
    }
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Split `text` into lines of at most `max_len` characters, breaking on spaces.
fn word_wrap(text: &str, max_len: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if !current.is_empty() && current.len() + 1 + word.len() > max_len {
            lines.push(current.clone());
            current.clear();
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}
