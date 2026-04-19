mod analysis;
mod ingestion;
mod pipeline;
mod report;
mod scoring;
mod server;
mod utils;

use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "vrcstorage-scanner",
    version = "0.1.0",
    author = "VRCStorage Team",
    about = "Static analysis scanner for Unity/VRChat packages\n\
             Detects malicious scripts, dangerous DLLs, and suspicious assets.\n\n\
             TIP: You can drag-and-drop a file onto this executable to scan it directly.",
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
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match (cli.command, cli.file) {
        // Explicit subcommand: vrcstorage-scanner scan <FILE> [OPTIONS]
        (Some(Command::Scan { path, output, output_file }), _) => {
            run_scan_command(&path, &output, output_file.as_deref(), false);
        }
        // Server mode: vrcstorage-scanner serve [--port N]
        (Some(Command::Serve { port }), _) => {
            let addr = SocketAddr::from(([0, 0, 0, 0], port));
            if let Err(e) = server::serve(addr).await {
                eprintln!("Server error: {e}");
                std::process::exit(1);
            }
        }
        // Drag-and-drop / shorthand: vrcstorage-scanner <FILE>
        (None, Some(file)) => {
            // verbose = true: show plain-English explanations for non-programmers
            run_scan_command(&file, "cli", None, true);
            // Pause so the user can read the output before the window closes.
            wait_for_keypress();
        }
        // No arguments: print help
        (None, None) => {
            use clap::CommandFactory;
            Cli::command().print_help().unwrap();
            println!();
            wait_for_keypress();
        }
    }
}

fn run_scan_command(
    path: &std::path::Path,
    output: &str,
    output_file: Option<&std::path::Path>,
    verbose: bool,
) {
    use colored::Colorize;

    if !path.exists() {
        eprintln!("{} File not found: {}", "ERROR:".red().bold(), path.display());
        std::process::exit(1);
    }

    let report = match pipeline::run_scan(path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{} {}", "ERROR:".red().bold(), e);
            std::process::exit(1);
        }
    };

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
            report::cli_reporter::print_report(&report, level, verbose);
            if let Some(out_path) = output_file {
                let json_str = report::json_reporter::to_json(&report).unwrap_or_default();
                std::fs::write(out_path, json_str).expect("Failed to write output file");
                println!("JSON report written to {}", out_path.display());
            }
        }
    }

    // Exit with non-zero code if risk level is CRITICAL
    use scoring::RiskLevel;
    if level == RiskLevel::Critical {
        std::process::exit(2);
    }
}

/// Waits for the user to press Enter before returning.
/// Called after drag-and-drop scans so the terminal window does not close
/// immediately and the user has time to read the results.
fn wait_for_keypress() {
    use std::io::{self, BufRead, Write};
    print!("\n\nPress ENTER to exit…");
    let _ = io::stdout().flush();
    let stdin = io::stdin();
    let _ = stdin.lock().lines().next();
}
