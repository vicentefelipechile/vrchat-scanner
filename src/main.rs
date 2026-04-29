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
mod export;
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
             TIP: Drag-and-drop one or more files/folders onto this executable to scan them.\n\
             Folders are scanned recursively for .unitypackage files.",
    disable_version_flag = false,
)]
struct Cli {
    /// Files or folders to scan directly — no subcommand needed.
    /// Accepts multiple paths; folders are searched recursively for .unitypackage files.
    #[arg(value_name = "PATH")]
    files: Vec<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Scan one or more Unity packages, DLL files, or folders
    Scan {
        /// Paths to scan (.unitypackage, .dll, .cs, .zip, folder, …)
        /// Folders are searched recursively for .unitypackage files.
        #[arg(value_name = "PATH", required = true, num_args = 1..)]
        paths: Vec<PathBuf>,

        /// Output format: "cli" (default), "json", or "txt"
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

    /// Export a .unitypackage to a readable folder or ZIP file
    Export {
        /// Path to the .unitypackage to export
        #[arg(value_name = "FILE")]
        path: PathBuf,

        /// Output format: "folder" (default) or "zip"
        #[arg(short, long, default_value = "folder")]
        output: String,

        /// Output directory or file [default: <input>-exported/ next to input]
        #[arg(short = 'd', long)]
        out_dir: Option<PathBuf>,

        /// Omit .meta files from the export
        #[arg(short = 'm', long)]
        skip_meta: bool,
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
    let caps = TermCaps::detect();
    if !caps.ansi {
        colored::control::set_override(false);
    }

    let cli = Cli::parse();

    match (cli.command, cli.files.is_empty(), cli.files) {
        // vrcstorage-scanner scan <PATH...> [OPTIONS]
        (Some(Command::Scan { paths, output, output_file }), _, _) => {
            print_banner(caps);
            let targets = collect_unitypackages(&paths, caps);
            if targets.is_empty() {
                eprintln!("{} No scannable files found.", "ERROR:".red().bold());
                std::process::exit(1);
            }

            let mut any_critical = false;
            let mut batch: Vec<BatchResult> = Vec::new();

            for path in &targets {
                let (level, _findings) = run_scan_command(path, &output, None, false, caps, false);
                if level == scoring::RiskLevel::Critical {
                    any_critical = true;
                }
                batch.push(BatchResult {
                    path: path.clone(),
                    level,
                    findings: _findings,
                    sanitized: false,
                });
            }

            // Write combined output file if requested
            if let Some(out_path) = output_file {
                if output == "txt" {
                    // Re-scan to get reports for txt output
                    let txt = build_txt_for_paths(&targets, &batch, caps);
                    std::fs::write(&out_path, txt).expect("Failed to write txt report");
                    println!("Report written to {}", out_path.display());
                }
                // JSON for multi-file: already handled per-file above or could be extended
            }

            if any_critical {
                std::process::exit(2);
            }
        }

        // vrcstorage-scanner sanitize <FILE> [OPTIONS]
        (Some(Command::Sanitize { path, output, min_severity, dry_run, json }), _, _) => {
            print_banner(caps);
            let out = output.unwrap_or_else(|| default_sanitize_output(&path));
            run_sanitize_command(&path, &out, &min_severity, dry_run, json, caps);
        }

        // vrcstorage-scanner export <FILE> [--output folder|zip] [--out-dir <DIR>] [--skip-meta]
        (Some(Command::Export { path, output, out_dir, skip_meta }), _, _) => {
            print_banner(caps);
            let out_lower = output.to_lowercase();
            if out_lower != "folder" && out_lower != "zip" {
                eprintln!(
                    "{} Invalid output type '{}'. Use 'folder' or 'zip'.",
                    "ERROR:".red().bold(),
                    output
                );
                std::process::exit(1);
            }
            run_export_command(&path, &out_lower, out_dir.as_deref(), skip_meta, caps);
        }

        // vrcstorage-scanner serve [--port N]
        (Some(Command::Serve { port }), _, _) => {
            let addr = SocketAddr::from(([0, 0, 0, 0], port));
            if let Err(e) = server::serve(addr).await {
                eprintln!("Server error: {e}");
                std::process::exit(1);
            }
        }

        // vrcstorage-scanner credits
        (Some(Command::Credits), _, _) => {
            print_credits(caps);
        }

        // Drag-and-drop / positional: one or more files or folders
        (None, false, files) => {
            print_banner(caps);

            // Collect all .unitypackage targets (recursive in folders)
            let targets = collect_unitypackages(&files, caps);
            if targets.is_empty() {
                eprintln!(
                    "{} No .unitypackage files found in the provided paths.",
                    "ERROR:".red().bold()
                );
                wait_for_keypress(caps);
                std::process::exit(1);
            }

            // Large-batch guard: ask confirmation if > 6 files
            if targets.len() > 6 && !prompt_continue_large_batch(targets.len(), caps) {
                println!("  Scan cancelled.");
                wait_for_keypress(caps);
                return;
            }

            // ── Scan each file ────────────────────────────────────────────
            let mut batch: Vec<BatchResult> = Vec::new();
            let mut any_critical = false;

            let batch_start = std::time::Instant::now();
            for (idx, path) in targets.iter().enumerate() {
                print_file_header(idx + 1, targets.len(), path, caps);
                let (level, findings) = run_scan_command(path, "cli", None, true, caps, true);

                if level == scoring::RiskLevel::Critical {
                    any_critical = true;
                }

                batch.push(BatchResult {
                    path: path.clone(),
                    level,
                    findings,
                    sanitized: false,
                });
            }

            // ── Batch summary (only when multiple files) ──────────────────
            if targets.len() > 1 {
                print_batch_summary(&batch, batch_start.elapsed().as_millis(), caps);
            }

            // ── Sanitize prompt — una sola vez al final, para todos los
            //    candidatos High/Critical que sean .unitypackage ────────────
            {
                use scoring::RiskLevel;

                let candidates: Vec<usize> = batch
                    .iter()
                    .enumerate()
                    .filter(|(_, r)| {
                        let is_unitypackage = r.path
                            .extension()
                            .map(|e| e.eq_ignore_ascii_case("unitypackage"))
                            .unwrap_or(false);
                        let has_critical_finding = r.findings
                            .iter()
                            .any(|f| f.severity == report::Severity::Critical);
                        let needs_sanitize =
                            matches!(r.level, RiskLevel::High | RiskLevel::Critical)
                            || has_critical_finding;
                        is_unitypackage && needs_sanitize
                    })
                    .map(|(i, _)| i)
                    .collect();

                if !candidates.is_empty() {
                    // Construir lista de archivos candidatos para mostrar en el prompt
                    let candidate_refs: Vec<(&std::path::Path, &[report::Finding])> = candidates
                        .iter()
                        .map(|&i| (batch[i].path.as_path(), batch[i].findings.as_slice()))
                        .collect();

                    if prompt_sanitize_batch(&candidate_refs, caps) {
                        for &i in &candidates {
                            let path = &batch[i].path.clone();
                            let out = default_sanitize_output(path);
                            run_sanitize_command(path, &out, "high", false, false, caps);
                            batch[i].sanitized = true;
                        }
                    }
                }
            }

            // ── Offer to save txt report ──────────────────────────────────
            if prompt_save_report(caps) {
                let txt = build_txt_from_batch(&targets, &batch, caps);
                let report_path = suggest_report_path(&targets);
                match std::fs::write(&report_path, &txt) {
                    Ok(_) => {
                        if caps.unicode {
                            println!("  {} Report saved to: {}", "✓".green(), report_path.display());
                        } else {
                            println!("  Report saved to: {}", report_path.display());
                        }
                    }
                    Err(e) => {
                        eprintln!("  {} Could not save report: {e}", "ERROR:".red());
                    }
                }
            }

            // ── Pause before closing ──────────────────────────────────────
            wait_for_keypress(caps);

            if any_critical {
                std::process::exit(2);
            }
        }

        // No arguments: print help
        (None, true, _) => {
            print_banner(caps);
            use clap::CommandFactory;
            Cli::command().print_help().unwrap();
            println!();
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Batch result accumulator
// ─────────────────────────────────────────────────────────────────────────────

struct BatchResult {
    path: PathBuf,
    level: scoring::RiskLevel,
    findings: Vec<report::Finding>,
    sanitized: bool,
    // report: Option<report::ScanReport>,
}

// ─────────────────────────────────────────────────────────────────────────────
// File collection
// ─────────────────────────────────────────────────────────────────────────────

fn canonicalize_clean(path: &std::path::Path) -> std::path::PathBuf {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
 
    #[cfg(target_os = "windows")]
    {
        let s = canonical.to_string_lossy();
        if let Some(stripped) = s.strip_prefix(r"\\?\") {
            return std::path::PathBuf::from(stripped);
        }
    }
 
    canonical
}

/// Expand a list of paths into a deduplicated list of scannable files.
///
/// - Regular files are included as-is (any extension).
/// - Directories are walked recursively; only `.unitypackage` files are collected.
/// - Duplicates (same canonical path) are removed.
fn collect_unitypackages(paths: &[PathBuf], caps: TermCaps) -> Vec<PathBuf> {
    let mut results: Vec<PathBuf> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for path in paths {
        if !path.exists() {
            eprintln!(
                "  {} Path not found, skipping: {}",
                "WARN:".yellow(),
                path.display()
            );
            let _ = caps; // suppress unused warning
            continue;
        }

        if path.is_file() {
            let canonical = canonicalize_clean(path);
            if seen.insert(canonical.clone()) {
                results.push(canonical);
            }
        } else if path.is_dir() {
            collect_from_dir(path, &mut results, &mut seen);
        }
    }

    results
}

/// Recursively collect `.unitypackage` files from a directory.
fn collect_from_dir(
    dir: &std::path::Path,
    results: &mut Vec<PathBuf>,
    seen: &mut std::collections::HashSet<PathBuf>,
) {
    let read_dir = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            eprintln!("  WARN: Cannot read directory {}: {e}", dir.display());
            return;
        }
    };

    let mut entries: Vec<_> = read_dir.flatten().collect();
    // Sort for deterministic order across platforms
    entries.sort_by_key(|e| e.path());

    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            collect_from_dir(&path, results, seen);
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("unitypackage"))
            .unwrap_or(false)
        {
            let canonical = canonicalize_clean(&path);
            if seen.insert(canonical.clone()) {
                results.push(canonical);
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Interactive prompts
// ─────────────────────────────────────────────────────────────────────────────

/// Ask the user whether to continue when the batch has more than 6 files.
fn prompt_continue_large_batch(count: usize, caps: TermCaps) -> bool {
    use std::io::{self, Write};
 
    let sep = if caps.unicode {
        "  ════════════════════════════════════════════════════"
    } else {
        "  ===================================================="
    };
 
    println!();
    println!("{sep}");
    println!("    Large Batch Detected");
    println!("{sep}");
    println!();
    println!("  Found {count} .unitypackage files to scan.");
    println!("  Scanning a large number of files may take several minutes.");
    println!();
    println!("  [Y] Yes, scan all {count} files (or press Enter)");
    println!("  [N] No, cancel");
    print!("\n  > ");
    let _ = io::stdout().flush();
 
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return true;
    }
    let answer = input.trim().to_lowercase();
    answer.is_empty() || answer == "y"
}

/// Print a visual separator before each file in a multi-file batch.
fn print_file_header(idx: usize, total: usize, path: &std::path::Path, caps: TermCaps) {
    if total <= 1 {
        return;
    }
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    if caps.unicode {
        println!();
        println!(
            "{}",
            format!("  ┄┄┄  [{idx}/{total}] {filename}  ┄┄┄").bright_cyan()
        );
        println!();
    } else {
        println!();
        println!("  --- [{idx}/{total}] {filename} ---");
        println!();
    }
}

/// Ask the user whether to save the batch report to a txt file.
fn prompt_save_report(caps: TermCaps) -> bool {
    use std::io::{self, Write};
 
    let sep = if caps.unicode {
        "  ════════════════════════════════════════════════════"
    } else {
        "  ===================================================="
    };
 
    println!();
    println!("{sep}");
    println!("    Save Report");
    println!("{sep}");
    println!();
    println!("  Would you like to save the scan results to a text file?");
    println!();
    println!("  [Y] Yes, save report (or press Enter)");
    println!("  [N] No");
    print!("\n  > ");
    let _ = io::stdout().flush();
 
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return true;
    }
    let answer = input.trim().to_lowercase();
    answer.is_empty() || answer == "y"
}

/// Print a summary table after scanning multiple files.
fn print_batch_summary(batch: &[BatchResult], total_ms: u128, caps: TermCaps) {
    let sep  = if caps.unicode { "═".repeat(52) } else { "=".repeat(52) };
    let thin = if caps.unicode { "─".repeat(52) } else { "-".repeat(52) };
 
    println!();
    println!("  {sep}");
    if caps.unicode {
        println!("{}", "   BATCH SCAN SUMMARY".bold());
    } else {
        println!("   BATCH SCAN SUMMARY");
    }
    println!("  {sep}");
    println!();
 
    for (i, r) in batch.iter().enumerate() {
        let filename = r.path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?");
        let sanitize_note = if r.sanitized { " [sanitized]" } else { "" };
        let level_label = if caps.ansi {
            level_colored(r.level)
        } else {
            level_plain(r.level).to_string()
        };
        println!(
            "  [{:>2}] {:<12}  {}{}",
            i + 1, level_label, filename, sanitize_note
        );
    }
 
    println!();
    println!("  {thin}");
 
    let clean    = batch.iter().filter(|r| r.level == scoring::RiskLevel::Clean).count();
    let low      = batch.iter().filter(|r| r.level == scoring::RiskLevel::Low).count();
    let medium   = batch.iter().filter(|r| r.level == scoring::RiskLevel::Medium).count();
    let high     = batch.iter().filter(|r| r.level == scoring::RiskLevel::High).count();
    let critical = batch.iter().filter(|r| r.level == scoring::RiskLevel::Critical).count();
 
    println!("  Clean={clean}  Low={low}  Medium={medium}  High={high}  Critical={critical}");
 
    // Tiempo total
    let duration_str = if total_ms < 1_000 {
        format!("{total_ms}ms")
    } else {
        format!("{:.2}s", total_ms as f64 / 1_000.0)
    };
    if caps.unicode {
        println!("  Total time: {}", duration_str.bold());
    } else {
        println!("  Total time: {duration_str}");
    }
 
    println!("  {sep}");
    println!();
}

// ─────────────────────────────────────────────────────────────────────────────
// Txt report builders
// ─────────────────────────────────────────────────────────────────────────────

/// Build a txt report by re-scanning files to get full ScanReport structs.
/// Falls back to minimal info from BatchResult when re-scan fails.
fn build_txt_from_batch(
    targets: &[PathBuf],
    batch: &[BatchResult],
    _caps: TermCaps,
) -> String {
    use report::txt_reporter::{BatchEntry, render_batch_txt};

    // Re-scan each file to get the ScanReport (we didn't store it during the main pass
    // to avoid doubling memory for large batches)
    let mut reports: Vec<report::ScanReport> = Vec::new();
    for path in targets {
        match pipeline::run_scan(path) {
            Ok(r) => reports.push(r),
            Err(e) => {
                // Create a minimal placeholder report if re-scan fails
                eprintln!("  WARN: Could not re-read {} for report: {e}", path.display());
            }
        }
    }

    let entries: Vec<BatchEntry<'_>> = reports
        .iter()
        .zip(batch.iter())
        .map(|(report, result)| {
            let (_, level) = scoring::compute_score(&report.findings);
            BatchEntry {
                report,
                level,
                sanitized: result.sanitized,
            }
        })
        .collect();

    render_batch_txt(&entries)
}

/// Build txt output using pre-scanned data from the CLI scan command
/// (paths + batch results that don't have full ScanReport stored).
fn build_txt_for_paths(
    targets: &[PathBuf],
    batch: &[BatchResult],
    caps: TermCaps,
) -> String {
    // For CLI path, just delegate — re-scan is acceptable here
    build_txt_from_batch(targets, batch, caps)
}

/// Suggest a report output path next to the first scanned file
/// (or in the current directory for multi-file batches).
fn suggest_report_path(targets: &[PathBuf]) -> PathBuf {
    let now = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    if targets.len() == 1 {
        let stem = targets[0]
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("scan");
        targets[0]
            .with_file_name(format!("{stem}-scan-report-{now}.txt"))
    } else {
        PathBuf::from(format!("vrcstorage-scan-report-{now}.txt"))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Banner & credits
// ─────────────────────────────────────────────────────────────────────────────

fn print_banner(caps: TermCaps) {
    let version = env!("CARGO_PKG_VERSION");
    let repo    = env!("CARGO_PKG_REPOSITORY");

    if caps.unicode {
        const W: usize = 56;
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
        println!("{}", "  ACKNOWLEDGEMENTS".bold().cyan());
        println!("{}", sep.dimmed());
        println!("  Tester     : anonberry");
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
        println!("  ACKNOWLEDGEMENTS");
        println!("{sep}");
        println!("  Tester     : anonberry");
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

/// Returns `(RiskLevel, findings)`.
/// Prints the report to stdout unless output is suppressed.
fn run_scan_command(
    path: &std::path::Path,
    output: &str,
    output_file: Option<&std::path::Path>,
    verbose: bool,
    caps: TermCaps,
    hide_low: bool,
) -> (scoring::RiskLevel, Vec<report::Finding>) {
    if !path.exists() {
        eprintln!("{} File not found: {}", "ERROR:".red().bold(), path.display());
        std::process::exit(1);
    }

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

    let scan_report = match pipeline::run_scan(path) {
        Ok(r) => r,
        Err(e) => {
            if let Some(pb) = spinner { pb.finish_and_clear(); }
            eprintln!("{} {}", "ERROR:".red().bold(), e);
            std::process::exit(1);
        }
    };

    if let Some(pb) = spinner { pb.finish_and_clear(); }

    let (_, level) = scoring::compute_score(&scan_report.findings);

    match output {
        "json" => {
            let json_str = match report::json_reporter::to_json(&scan_report) {
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
        "txt" => {
            let txt = report::txt_reporter::render_single_txt(&scan_report, level, false);
            if let Some(out_path) = output_file {
                std::fs::write(out_path, &txt).expect("Failed to write output file");
                println!("Report written to {}", out_path.display());
            } else {
                println!("{txt}");
            }
        }
        _ => {
            report::cli_reporter::print_report(&scan_report, level, verbose, caps, hide_low);
            if let Some(out_path) = output_file {
                let json_str = report::json_reporter::to_json(&scan_report).unwrap_or_default();
                std::fs::write(out_path, json_str).expect("Failed to write output file");
                println!("JSON report written to {}", out_path.display());
            }
        }
    }

    let findings = scan_report.findings.clone();
    (level, findings)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

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
                "ERROR:".red().bold(), other
            );
            std::process::exit(1);
        }
    };

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
        Ok(san_report) => {
            report::sanitize_reporter::print_sanitize_report(&san_report, caps);
        }
        Err(e) => {
            eprintln!("{} {}", "ERROR:".red().bold(), e);
            std::process::exit(1);
        }
    }
}

fn default_sanitize_output(path: &std::path::Path) -> PathBuf {
    let stem = path.file_stem().unwrap_or_default().to_string_lossy();
    path.with_file_name(format!("{stem}-sanitized.unitypackage"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Export command
// ─────────────────────────────────────────────────────────────────────────────

fn run_export_command(
    path: &std::path::Path,
    output_type: &str,
    out_dir: Option<&std::path::Path>,
    skip_meta: bool,
    caps: TermCaps,
) {
    if !path.exists() {
        eprintln!("{} File not found: {}", "ERROR:".red().bold(), path.display());
        std::process::exit(1);
    }

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
        pb.set_message(format!("Exporting {}", path.display()));
        pb
    };

    let result = export::run_export(path, output_type, out_dir, skip_meta);
    spinner.finish_and_clear();

    match result {
        Ok(report) => print_export_report(&report, caps),
        Err(e) => {
            eprintln!("{} {}", "ERROR:".red().bold(), e);
            std::process::exit(1);
        }
    }
}

fn print_export_report(report: &export::ExportReport, caps: TermCaps) {
    let sep = if caps.unicode {
        "═".repeat(64)
    } else {
        "=".repeat(64)
    };
    let thin = if caps.unicode {
        "─".repeat(64)
    } else {
        "-".repeat(64)
    };
    let check = if caps.unicode { "✓" } else { "[OK]" };

    // ── Header ──────────────────────────────────────────────────────────
    println!("\n  {sep}");
    if caps.unicode {
        println!("{}", "   EXPORT REPORT".bold().cyan());
    } else {
        println!("   EXPORT REPORT");
    }
    println!("  {sep}");

    // ── Input ───────────────────────────────────────────────────────────
    if caps.unicode {
        println!("\n{}", "  INPUT".bold().white());
    } else {
        println!("\n  INPUT");
    }
    println!("  {thin}");
    println!("    {}", report.input_path.display());

    // ── Output ──────────────────────────────────────────────────────────
    if caps.unicode {
        println!("\n{}", "  OUTPUT".bold().white());
    } else {
        println!("\n  OUTPUT");
    }
    println!("  {thin}");
    let output_type_str = match report.output_type {
        export::ExportType::Folder => "folder",
        export::ExportType::Zip => "zip",
    };
    if caps.unicode {
        println!(
            "    Path : {}",
            report.output_path.display().to_string().bold()
        );
    } else {
        println!("    Path : {}", report.output_path.display());
    }
    println!("    Type : {output_type_str}");

    // ── Stats ───────────────────────────────────────────────────────────
    if caps.unicode {
        println!("\n{}", "  STATS".bold().white());
    } else {
        println!("\n  STATS");
    }
    println!("  {thin}");
    println!("    Total entries  : {}", report.total_entries);
    println!("    Assets         : {}", report.exported_assets);
    println!("    .meta files    : {}", report.exported_meta);
    if report.skip_meta {
        if caps.unicode {
            println!("    {} .meta export was disabled (--skip-meta)", "Note:".dimmed());
        } else {
            println!("    Note: .meta export was disabled (--skip-meta)");
        }
    }
    if report.skipped_empty > 0 {
        println!("    Skipped (empty): {}", report.skipped_empty);
    }
    if report.skipped_unsafe > 0 {
        println!(
            "    {} Skipped (unsafe path): {}",
            "WARNING:".yellow().bold(),
            report.skipped_unsafe
        );
    }
    for w in &report.warnings {
        println!("    {} {}", "WARNING:".yellow().bold(), w);
    }

    // ── Summary ─────────────────────────────────────────────────────────
    println!("\n  {sep}");
    let total = report.exported_assets + report.exported_meta;
    if caps.unicode {
        println!(
            "  {} Successfully exported {} entries.",
            check.green().bold(),
            total
        );
    } else {
        println!("  {check} Successfully exported {total} entries.");
    }
    println!("  {sep}");
    println!();
}

// ─────────────────────────────────────────────────────────────────────────────
// Sanitize prompt helpers
// ─────────────────────────────────────────────────────────────────────────────

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

fn build_action_list(findings: &[report::Finding]) -> Vec<String> {
    use std::collections::{BTreeMap, BTreeSet};

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
				script_apis.entry(loc).or_default();
			}
		} else {
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

fn prompt_sanitize_batch(
    candidates: &[(&std::path::Path, &[report::Finding])],
    caps: TermCaps,
) -> bool {
    use std::io::{self, Write};

    let sep = if caps.unicode {
        "  ════════════════════════════════════════════════════"
    } else {
        "  ===================================================="
    };

    println!();
    println!("{sep}");
    if caps.unicode {
        println!("{}", "    Sanitize".bold());
    } else {
        println!("    Sanitize");
    }
    println!("{sep}");
    println!();

    if candidates.len() == 1 {
        println!("  Threats (High/Critical) were detected in this package.");
    } else {
        println!(
            "  Threats (High/Critical) were detected in {} packages.",
            candidates.len()
        );
    }
    println!("  Would you like to create sanitized copies?");
    println!();

    // Mostrar acciones por archivo
    for (file, findings) in candidates {
        let out_name = {
            let stem = file.file_stem().unwrap_or_default().to_string_lossy();
            format!("{stem}-sanitized.unitypackage")
        };
        let actions = build_action_list(findings);

        if caps.unicode {
            println!("  {}", file.display().to_string().bold().white());
        } else {
            println!("  {}", file.display());
        }
        println!("  -> Output: {out_name}");

        if actions.is_empty() {
            println!("     · All dangerous assets will be neutralized");
        } else {
            for action in &actions {
                println!("  {action}");
            }
        }
        println!();
    }

    println!("  Threshold  : HIGH");
    println!();
    println!("  [Y] Yes, sanitize all (or press Enter)");
    println!("  [N] No");
    print!("\n  > ");
    let _ = io::stdout().flush();

    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return true;
    }
    let answer = input.trim().to_lowercase();
    answer.is_empty() || answer == "y"
}

// ─────────────────────────────────────────────────────────────────────────────
// Level formatting helpers
// ─────────────────────────────────────────────────────────────────────────────

fn level_colored(level: scoring::RiskLevel) -> String {
    use scoring::RiskLevel;
    match level {
        RiskLevel::Clean    => "■ CLEAN".green().bold().to_string(),
        RiskLevel::Low      => "■ LOW".blue().bold().to_string(),
        RiskLevel::Medium   => "■ MEDIUM".bright_yellow().bold().to_string(),
        RiskLevel::High     => "■ HIGH".yellow().bold().to_string(),
        RiskLevel::Critical => "■ CRITICAL".red().bold().to_string(),
    }
}

fn level_plain(level: scoring::RiskLevel) -> &'static str {
    use scoring::RiskLevel;
    match level {
        RiskLevel::Clean    => "CLEAN",
        RiskLevel::Low      => "LOW",
        RiskLevel::Medium   => "MEDIUM",
        RiskLevel::High     => "HIGH",
        RiskLevel::Critical => "CRITICAL",
    }
}