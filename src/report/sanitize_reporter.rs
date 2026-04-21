use colored::Colorize;
use crate::sanitize::{SanitizeReport};
use crate::terminal::TermCaps;

/// Print a formatted sanitize report to stdout.
pub fn print_sanitize_report(report: &SanitizeReport, caps: TermCaps) {
    let sep = if caps.unicode { "─" } else { "-" };
    let sep_line = sep.repeat(64);

    if caps.unicode {
        println!("\n\n  {}", "┌── SANITIZE REPORT ─────────────────────────────────────────┐".bright_cyan());
    } else {
        println!("\n\n  ┌── SANITIZE REPORT ─────────────────────────────────────────┐");
    }

    // ── Neutralized scripts ───────────────────────────────────────────────
    if !report.neutralized_scripts.is_empty() {
        let header = format!("  SCRIPTS NEUTRALIZED ({})", report.neutralized_scripts.len());
        if caps.unicode {
            println!("\n{}", header.bold().yellow());
        } else {
            println!("\n{header}");
        }

        for ns in &report.neutralized_scripts {
            if caps.unicode {
                println!("    {}", ns.original_path.white());
            } else {
                println!("    {}", ns.original_path);
            }
            for &line_no in &ns.commented_lines {
                println!("      Line {line_no:>4}  → /* SANITIZED */");
            }
            let ids: Vec<String> = ns.finding_ids.iter().map(|id| id.to_string()).collect();
            println!("      Findings : {}", ids.join(", "));
        }
    }

    // ── Removed entries ───────────────────────────────────────────────────
    if !report.removed_entries.is_empty() {
        let header = format!("  ENTRIES REMOVED ({})", report.removed_entries.len());
        if caps.unicode {
            println!("\n{}", header.bold().red());
        } else {
            println!("\n{header}");
        }

        for re in &report.removed_entries {
            let ids: Vec<String> = re.finding_ids.iter().map(|id| id.to_string()).collect();
            if caps.unicode {
                println!("    {}  {}", re.original_path.white(), ids.join(", ").dimmed());
            } else {
                println!("    {}  {}", re.original_path, ids.join(", "));
            }
        }
    }

    // ── Skipped assets ────────────────────────────────────────────────────
    if !report.skipped_assets.is_empty() {
        let header = format!(
            "  ASSETS SKIPPED — no loader script in package ({})",
            report.skipped_assets.len()
        );
        if caps.unicode {
            println!("\n{}", header.bold().blue());
        } else {
            println!("\n{header}");
        }

        for sa in &report.skipped_assets {
            if caps.unicode {
                println!("    {}  {}", sa.original_path.white(), sa.reason.dimmed());
            } else {
                println!("    {}  {}", sa.original_path, sa.reason);
            }
        }
    }

    // ── Kept entries ──────────────────────────────────────────────────────
    if report.kept_entries > 0 {
        if caps.unicode {
            println!(
                "\n  {}  — below threshold or no findings",
                format!("ENTRIES KEPT ({})", report.kept_entries).bold().green()
            );
        } else {
            println!("\n  ENTRIES KEPT ({})  — below threshold or no findings", report.kept_entries);
        }
    }

    // ── Score summary ─────────────────────────────────────────────────────
    println!("\n  {sep_line}");

    let threshold_str = format!("{}", report.threshold).to_uppercase();

    if caps.unicode {
        println!("  Original score  : {}  →  Residual score : {}",
            report.original_score.to_string().bold().red(),
            report.residual_score.to_string().bold().green(),
        );
        println!("  Threshold used  : {}", threshold_str.bold().yellow());
    } else {
        println!("  Original score  : {}  ->  Residual score : {}",
            report.original_score, report.residual_score);
        println!("  Threshold used  : {threshold_str}");
    }

    if let Some(out) = &report.output_path {
        let size_kb = std::fs::metadata(out)
            .map(|m| m.len() / 1024)
            .unwrap_or(0);
        if caps.unicode {
            println!("  Output          : {} ({} KB)", out.display().to_string().bold(), size_kb);
        } else {
            println!("  Output          : {} ({size_kb} KB)", out.display());
        }
    } else if caps.unicode {
            println!("  Output          : {}", "(dry run — no file written)".dimmed());
        } else {
            println!("  Output          : (dry run -- no file written)");
        }

    if caps.unicode {
        println!("  {}", "└────────────────────────────────────────────────────────────┘".bright_cyan());
    } else {
        println!("  └────────────────────────────────────────────────────────────┘");
    }
    println!();
}
