mod analysis;
mod config;
mod ingestion;
mod pipeline;
mod report;
mod scoring;
mod server;
mod terminal;
mod utils;

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
            run_scan_command(&path, &output, output_file.as_deref(), false, caps);
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
            run_scan_command(&file, "cli", None, true, caps);
            // Pause only here: the window was opened by double-click / drag-and-drop
            // and would close immediately otherwise.
            wait_for_keypress(caps);
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

fn run_scan_command(
    path: &std::path::Path,
    output: &str,
    output_file: Option<&std::path::Path>,
    verbose: bool,
    caps: TermCaps,
) {
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

    // Exit with code 2 for CRITICAL (lets CI pipelines auto-block)
    use scoring::RiskLevel;
    if level == RiskLevel::Critical {
        std::process::exit(2);
    }
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
