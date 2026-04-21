mod analysis;
mod config;
mod ingestion;
mod pipeline;
mod report;
mod sanitize;
mod scoring;
mod server;
mod terminal;
mod utils;
mod whitelist;

use clap::{Parser, Subcommand};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use terminal::TermCaps;

// ─────────────────────────────────────────────────────────────────────────────
// CLI definition
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "vrcstorage-scanner",
    version = env!("CARGO_PKG_VERSION"),
    author = "SummerTYT (vicentefelipechile)",
    about = "Static analysis scanner for Unity/VRChat packages\n\
             Detects malicious scripts, dangerous DLLs, and suspicious assets.\n\n\
             TIP: You can drag-and-drop a file onto this executable to scan it directly.",
    disable_version_flag = false,
)]
struct Cli {
    /// File to scan directly — no subcommand needed.
    /// Equivalent to: vrcstorage-scanner scan <FILE>
    #[arg(value_name = "FILE")]
    file: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a Unity package or DLL file (CLI mode)
    Scan {
        /// Path to the file to scan (.unitypackage, .dll, .cs, .zip, …)
        #[arg(value_name = "FILE")]
        path: PathBuf,

        /// Output format: "cli" (default) or "json"
        #[arg(short, long, default_value = "cli")]
        output: String,

        /// Write output to a file instead of stdout
        #[arg(short = 'f', long)]
        output_file: Option<PathBuf>,
    },

    /// Remove or neutralize malicious entries from a Unity package
    Sanitize {
        /// Path to the .unitypackage to sanitize
        #[arg(value_name = "FILE")]
        path: PathBuf,

        /// Output path [default: <input>-sanitized.unitypackage]
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Minimum severity to act on: low|medium|high|critical [default: high]
        #[arg(short = 's', long, default_value = "high")]
        min_severity: String,

        /// Show what would happen without writing any output file
        #[arg(short = 'd', long)]
        dry_run: bool,

        /// Emit JSON scan report of the sanitized package
        #[arg(long)]
        json: bool,
    },

    /// Start HTTP server mode (for Cloudflare Containers)
    Serve {
        /// Port to listen on
        #[arg(short, long, default_value = "8080")]
        port: u16,
    },

    /// Show credits and project information
    Credits,
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    // Detect terminal capabilities FIRST — before any output.
    // On Win10 legacy consoles this will try to enable VTP; if it fails
    // colored will output raw escape codes, so we disable it.
    let caps = TermCaps::detect();
    if !caps.ansi {
        colored::control::set_override(false);
    }

    let cli = Cli::parse();

    match (cli.command, cli.file) {
        // vrcstorage-scanner scan <FILE> [OPTIONS]
        (Some(Command::Scan { path, output, output_file }), _) => {
            print_banner(caps);
            let (level, _) = run_scan_command(&path, &output, output_file.as_deref(), false, caps);
            // Exit code 2 for CRITICAL — lets CI pipelines auto-block.
            use scoring::RiskLevel;
            if level == RiskLevel::Critical {
                std::process::exit(2);
            }
        }
        // vrcstorage-scanner sanitize <FILE> [OPTIONS]
        (Some(Command::Sanitize { path, output, min_severity, dry_run, json }), _) => {
            print_banner(caps);
            let out = output.unwrap_or_else(|| default_sanitize_output(&path));
            run_sanitize_command(&path, &out, &min_severity, dry_run, json, caps);
        }
        // vrcstorage-scanner serve [--port N]
        (Some(Command::Serve { port }), _) => {
            let addr = SocketAddr::from(([0, 0, 0, 0], port));
            if let Err(e) = server::serve(addr).await {
                eprintln!("Server error: {e}");
                std::process::exit(1);
            }
        }
        // vrcstorage-scanner credits
        (Some(Command::Credits), _) => {
            print_credits(caps);
            // No pause — user ran this explicitly from a terminal
        }
        // Drag-and-drop: vrcstorage-scanner <FILE>
        (None, Some(file)) => {
            print_banner(caps);
            let (level, findings) = run_scan_command(&file, "cli", None, true, caps);

            // After scanning: offer sanitize prompt if the file is a .unitypackage
            // and at least one High/Critical finding was detected.
            let is_unitypackage = file
                .extension()
                .map(|e| e.eq_ignore_ascii_case("unitypackage"))
                .unwrap_or(false);

            if is_unitypackage {
                use scoring::RiskLevel;
                let has_high = matches!(level, RiskLevel::High | RiskLevel::Critical);
                if has_high && prompt_sanitize(&file, &findings, caps) {
                    let out = default_sanitize_output(&file);
                    run_sanitize_command(&file, &out, "high", false, false, caps);
                }
            }

            // Pause only here: the window was opened by double-click / drag-and-drop
            // and would close immediately otherwise.
            wait_for_keypress(caps);

            // Exit code 2 for CRITICAL — after all interactive prompts are done.
            use scoring::RiskLevel;
            if level == RiskLevel::Critical {
                std::process::exit(2);
            }
        }
        // No arguments: print help
        (None, None) => {
            print_banner(caps);
            use clap::CommandFactory;
            Cli::command().print_help().unwrap();
            println!();
            // No pause — user ran this from a terminal intentionally
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Banner & credits
// ─────────────────────────────────────────────────────────────────────────────

fn print_banner(caps: TermCaps) {
    let version = env!("CARGO_PKG_VERSION");
    let repo    = env!("CARGO_PKG_REPOSITORY");

    if caps.unicode {
        // Inner width = chars between the ║ borders.
        // Longest line: "  " + repo URL (52 chars) + 2 margin = 56.
        const W: usize = 56;

        // Helper: build a ║ border + padded content + ║ border row, each
        // element colored independently (no {} {} {} spacing bug).
        let border = || "║".bright_cyan().to_string();
        let row = |content: String, bold: bool| {
            let padded = format!("{content:<W$}");
            let colored = if bold {
                padded.bold().white().to_string()
            } else {
                padded.cyan().to_string()
            };
            format!("{}{}{}", border(), colored, border())
        };

        println!();
        println!("{}", format!("╔{}╗", "═".repeat(W)).bright_cyan());
        println!("{}", row(format!("  vrcstorage-scanner v{version}"), true));
        println!("{}", row("  by SummerTYT (vicentefelipechile)".to_string(), false));
        println!("{}", row(format!("  {repo}"), false));
        println!("{}", format!("╚{}╝", "═".repeat(W)).bright_cyan());
        println!();
    } else {
        // ASCII fallback for legacy consoles
        println!();
        println!("==========================================================");
        println!("  vrcstorage-scanner v{version}");
        println!("  by SummerTYT (vicentefelipechile)");
        println!("  {repo}");
        println!("==========================================================");
        println!();
    }
}


fn print_credits(caps: TermCaps) {
    let version = env!("CARGO_PKG_VERSION");
    let repo    = env!("CARGO_PKG_REPOSITORY");

    print_banner(caps);

    if caps.unicode {
        let sep = "─".repeat(52);
        println!("{}", sep.dimmed());
        println!("{}", "  PROJECT".bold().cyan());
        println!("{}", sep.dimmed());
        println!("  Name       : vrcstorage-scanner");
        println!("  Version    : v{version}");
        println!("  Repository : {repo}");
        println!("  License    : MIT");
        println!();
        println!("{}", sep.dimmed());
        println!("{}", "  AUTHOR".bold().cyan());
        println!("{}", sep.dimmed());
        println!("  SummerTYT");
        println!("  GitHub     : https://github.com/vicentefelipechile");
        println!();
        println!("{}", sep.dimmed());
        println!("{}", "  DESCRIPTION".bold().cyan());
        println!("{}", sep.dimmed());
        println!("  Static analysis tool for Unity/VRChat packages.");
        println!("  Detects malicious scripts, suspicious DLLs, dangerous");
        println!("  imports, and hidden payloads without executing any code.");
        println!("{}", sep.dimmed());
    } else {
        let sep = "-".repeat(52);
        println!("{sep}");
        println!("  PROJECT");
        println!("{sep}");
        println!("  Name       : vrcstorage-scanner");
        println!("  Version    : v{version}");
        println!("  Repository : {repo}");
        println!("  License    : MIT");
        println!();
        println!("{sep}");
        println!("  AUTHOR");
        println!("{sep}");
        println!("  SummerTYT");
        println!("  GitHub     : https://github.com/vicentefelipechile");
        println!();
        println!("{sep}");
        println!("  DESCRIPTION");
        println!("{sep}");
        println!("  Static analysis tool for Unity/VRChat packages.");
        println!("  Detects malicious scripts, suspicious DLLs, dangerous");
        println!("  imports, and hidden payloads without executing any code.");
        println!("{sep}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Scan command
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `(RiskLevel, findings)` so the caller can decide when to exit
/// and show context-aware prompts (e.g. the sanitize dialog).
/// In drag-and-drop mode the caller must show prompts and pause BEFORE
/// calling `process::exit`, otherwise the window closes immediately.
fn run_scan_command(
    path: &std::path::Path,
    output: &str,
    output_file: Option<&std::path::Path>,
    verbose: bool,
    caps: TermCaps,
) -> (scoring::RiskLevel, Vec<report::Finding>) {
    if !path.exists() {
        eprintln!("{} File not found: {}", "ERROR:".red().bold(), path.display());
        std::process::exit(1);
    }

    // Progress spinner — shown while the scan is running.
    // Suppressed in JSON mode (stdout would corrupt the JSON output).
    let spinner = if output != "json" {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::with_template(if caps.unicode {
                "  {spinner:.cyan} {msg}"
            } else {
                "  {msg}..."
            })
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
        );
        pb.enable_steady_tick(Duration::from_millis(80));
        pb.set_message(format!("Scanning {}", path.display()));
        Some(pb)
    } else {
        None
    };

    let report = match pipeline::run_scan(path) {
        Ok(r) => r,
        Err(e) => {
            if let Some(pb) = spinner { pb.finish_and_clear(); }
            eprintln!("{} {}", "ERROR:".red().bold(), e);
            std::process::exit(1);
        }
    };

    if let Some(pb) = spinner { pb.finish_and_clear(); }

    let (_, level) = scoring::compute_score(&report.findings);

    match output {
        "json" => {
            let json_str = match report::json_reporter::to_json(&report) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("JSON serialization error: {e}");
                    std::process::exit(1);
                }
            };
            if let Some(out_path) = output_file {
                std::fs::write(out_path, &json_str).expect("Failed to write output file");
                println!("Report written to {}", out_path.display());
            } else {
                println!("{}", json_str);
            }
        }
        _ => {
            report::cli_reporter::print_report(&report, level, verbose, caps);
            if let Some(out_path) = output_file {
                let json_str = report::json_reporter::to_json(&report).unwrap_or_default();
                std::fs::write(out_path, json_str).expect("Failed to write output file");
                println!("JSON report written to {}", out_path.display());
            }
        }
    }

    let findings = report.findings.clone();
    (level, findings)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Waits for the user to press Enter before returning.
/// Called after drag-and-drop scans so the terminal window does not close
/// immediately and the user has time to read the results.
fn wait_for_keypress(caps: TermCaps) {
    use std::io::{self, BufRead, Write};
    if caps.unicode {
        print!("\n\n  Press ENTER to exit…");
    } else {
        print!("\n\n  Press ENTER to exit...");
    }
    let _ = io::stdout().flush();
    let stdin = io::stdin();
    let _ = stdin.lock().lines().next();
}

// ─────────────────────────────────────────────────────────────────────────────
// Sanitize command
// ─────────────────────────────────────────────────────────────────────────────

fn run_sanitize_command(
    path: &std::path::Path,
    output: &std::path::Path,
    min_severity_str: &str,
    dry_run: bool,
    _json: bool,
    caps: TermCaps,
) {
    use report::Severity;

    if !path.exists() {
        eprintln!("{} File not found: {}", "ERROR:".red().bold(), path.display());
        std::process::exit(1);
    }

    let min_severity = match min_severity_str.to_lowercase().as_str() {
        "low"      => Severity::Low,
        "medium"   => Severity::Medium,
        "high"     => Severity::High,
        "critical" => Severity::Critical,
        other => {
            eprintln!(
                "{} Unknown severity level '{}'. Use: low|medium|high|critical",
                "ERROR:".red().bold(),
                other
            );
            std::process::exit(1);
        }
    };

    // Progress spinner
    let spinner = {
        let pb = indicatif::ProgressBar::new_spinner();
        pb.set_style(
            indicatif::ProgressStyle::with_template(if caps.unicode {
                "  {spinner:.cyan} {msg}"
            } else {
                "  {msg}..."
            })
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
        );
        pb.enable_steady_tick(std::time::Duration::from_millis(80));
        pb.set_message(format!("Sanitizing {}", path.display()));
        pb
    };

    let result = sanitize::run_sanitize(path, output, min_severity, dry_run);
    spinner.finish_and_clear();

    match result {
        Ok(report) => {
            report::sanitize_reporter::print_sanitize_report(&report, caps);
        }
        Err(e) => {
            eprintln!("{} {}", "ERROR:".red().bold(), e);
            std::process::exit(1);
        }
    }
}

/// Default output path: `<stem>-sanitized.unitypackage` in the same directory.
fn default_sanitize_output(path: &std::path::Path) -> PathBuf {
    let stem = path.file_stem().unwrap_or_default().to_string_lossy();
    path.with_file_name(format!("{stem}-sanitized.unitypackage"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Sanitize prompt helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Maps a `FindingId` to a short human-readable API name for script findings.
fn finding_api_label(id: report::FindingId) -> &'static str {
    use report::FindingId as F;
    match id {
        F::CsProcessStart          => "Process.Start()",
        F::CsAssemblyLoadBytes     => "Assembly.Load(bytes)",
        F::CsFileWrite             => "File.Write/Delete",
        F::CsBinaryFormatter       => "BinaryFormatter",
        F::CsDllimportUnknown      => "[DllImport] unknown",
        F::CsShellStrings          => "shell command strings",
        F::CsUrlUnknownDomain      => "unknown domain URL",
        F::CsIpHardcoded           => "hardcoded IP address",
        F::CsUnicodeEscapes        => "unicode escape obfuscation",
        F::CsReflectionEmit        => "System.Reflection.Emit",
        F::CsHttpClient            => "HttpClient / WebClient",
        F::CsUnsafeBlock           => "unsafe block",
        F::CsRegistryAccess        => "Registry access",
        F::CsEnvironmentAccess     => "Environment access",
        F::CsMarshalOps            => "Marshal ops",
        F::CsBase64HighRatio       => "high Base64 ratio",
        F::CsXorDecryption         => "XOR decryption",
        F::CsObfuscatedIdentifiers => "obfuscated identifiers",
        F::PolyglotFile            => "embedded binary payload",
        F::MagicMismatch           => "magic bytes mismatch",
        _                          => "",
    }
}

/// Build a sorted, deduplicated list of action lines from High/Critical findings.
/// Each line describes exactly what the sanitizer will do to one asset.
fn build_action_list(findings: &[report::Finding]) -> Vec<String> {
    use std::collections::{BTreeMap, BTreeSet};

    // location → set of API labels / reasons
    let mut script_apis:  BTreeMap<&str, BTreeSet<&'static str>> = BTreeMap::new();
    let mut remove_files: BTreeSet<&str>                         = BTreeSet::new();

    for f in findings.iter().filter(|f| f.severity >= report::Severity::High) {
        let loc = f.location.as_str();
        let lower = loc.to_lowercase();

        if lower.ends_with(".cs") {
            let label = finding_api_label(f.id);
            if !label.is_empty() {
                script_apis.entry(loc).or_default().insert(label);
            } else {
                // ensure the file appears even if we have no specific label
                script_apis.entry(loc).or_default();
            }
        } else if lower.ends_with(".dll") || lower.ends_with(".so") {
            remove_files.insert(loc);
        } else {
            // texture, audio, prefab, etc.
            remove_files.insert(loc);
        }
    }

    let mut actions = Vec::new();

    for (loc, apis) in &script_apis {
        if apis.is_empty() {
            actions.push(format!("  · {loc} : dangerous lines will be commented out"));
        } else {
            let api_list = apis.iter().copied().collect::<Vec<_>>().join(", ");
            actions.push(format!("  · {loc} : comment out {api_list}"));
        }
    }
    for loc in &remove_files {
        actions.push(format!("  · {loc} : will be removed from the package"));
    }

    actions
}

/// Show an interactive prompt asking whether to create a sanitized copy.
/// Returns `true` if the user answers Y/y.
fn prompt_sanitize(
    file: &std::path::Path,
    findings: &[report::Finding],
    caps: TermCaps,
) -> bool {
    use std::io::{self, Write};

    let out_name = {
        let stem = file.file_stem().unwrap_or_default().to_string_lossy();
        format!("{stem}-sanitized.unitypackage")
    };

    let actions = build_action_list(findings);

    let sep = if caps.unicode {
        "  ════════════════════════════════════════════════════"
    } else {
        "  ===================================================="
    };

    println!();
    println!("{sep}");
    println!("    Sanitize");
    println!("{sep}");
    println!();
    println!("  Threats (High/Critical) were detected in this package.");
    println!("  Would you like to create a sanitized copy?");
    println!();

    if actions.is_empty() {
        println!("  · All dangerous assets will be neutralized");
    } else {
        for action in &actions {
            println!("{action}");
        }
    }

    println!();
    println!("  · Threshold  : HIGH");
    println!("  · Output     : {out_name}");
    println!();
    println!("  [Y] Yes");
    println!("  [N] No (or Enter)");

    print!("\n  > ");
    let _ = io::stdout().flush();

    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return false;
    }

    matches!(input.trim().to_lowercase().as_str(), "y")
}
