mod llm;
mod report;
mod rules;
mod scanner;
mod types;

use std::fs;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "secprobe",
    about = "SecProbe — AI-powered security audit tool",
    version,
    long_about = "Fast, offline, cross-platform security scanner.\nDetects OWASP Top 10 vulnerabilities with fix suggestions."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a project for security vulnerabilities
    Scan {
        /// Path to the project directory
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output format: terminal, json, html
        #[arg(short, long, default_value = "terminal")]
        format: String,

        /// Output file path (for json/html)
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,

        /// Minimum severity to report: critical, high, medium, low, info
        #[arg(long, default_value = "low")]
        min_severity: String,

        /// Enable LLM deep analysis (requires OPENAI_API_KEY, ANTHROPIC_API_KEY, or DEEPSEEK_API_KEY)
        #[arg(long)]
        llm: bool,
    },

    /// List all available security rules
    Rules,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            format,
            output,
            min_severity,
            llm,
        } => {
            if !path.exists() {
                eprintln!("Error: path '{}' does not exist", path.display());
                std::process::exit(1);
            }

            let mut result = scanner::scan_project(&path);

            let min_sev = parse_severity(&min_severity);
            result.findings.retain(|f| severity_value(f.severity) <= severity_value(min_sev));

            if llm {
                if let Some(config) = llm::LlmConfig::from_env() {
                    eprintln!("Running LLM deep analysis ({:?} / {})...", config.provider, config.model);
                    let analyses = llm::analyze_findings(&result.findings, &path, &config);
                    eprintln!("LLM analysis complete: {} findings analyzed", analyses.len());
                } else {
                    eprintln!("Warning: --llm flag set but no API key found.");
                    eprintln!("Set one of: OPENAI_API_KEY, ANTHROPIC_API_KEY, DEEPSEEK_API_KEY");
                }
            }

            match format.as_str() {
                "json" => {
                    let json = report::export_json(&result);
                    if let Some(out_path) = output {
                        fs::write(&out_path, &json).expect("Failed to write JSON report");
                        println!("JSON report saved to: {}", out_path.display());
                    } else {
                        println!("{json}");
                    }
                }
                "html" => {
                    let html = report::export_html(&result);
                    let out_path = output.unwrap_or_else(|| PathBuf::from("secprobe-report.html"));
                    fs::write(&out_path, &html).expect("Failed to write HTML report");
                    println!("HTML report saved to: {}", out_path.display());

                    #[cfg(target_os = "macos")]
                    { let _ = std::process::Command::new("open").arg(&out_path).spawn(); }
                    #[cfg(target_os = "windows")]
                    { let _ = std::process::Command::new("cmd").args(["/c", "start"]).arg(&out_path).spawn(); }
                    #[cfg(target_os = "linux")]
                    { let _ = std::process::Command::new("xdg-open").arg(&out_path).spawn(); }
                }
                _ => {
                    report::print_terminal_report(&result);
                }
            }
        }
        Commands::Rules => {
            let rules = rules::all_rules();
            println!("\nSecProbe Security Rules ({} rules)\n", rules.len());
            for r in &rules {
                let sev = match r.severity {
                    types::Severity::Critical => "CRIT",
                    types::Severity::High => "HIGH",
                    types::Severity::Medium => "MED ",
                    types::Severity::Low => "LOW ",
                    types::Severity::Info => "INFO",
                };
                let cwe = r.cwe_id.unwrap_or("-");
                println!("  {:<8} [{sev}] {cwe:<10} {}", r.id, r.title);
            }
            println!();
        }
    }
}

fn parse_severity(s: &str) -> types::Severity {
    match s.to_lowercase().as_str() {
        "critical" => types::Severity::Critical,
        "high" => types::Severity::High,
        "medium" | "med" => types::Severity::Medium,
        "low" => types::Severity::Low,
        _ => types::Severity::Info,
    }
}

fn severity_value(s: types::Severity) -> u8 {
    match s {
        types::Severity::Critical => 0,
        types::Severity::High => 1,
        types::Severity::Medium => 2,
        types::Severity::Low => 3,
        types::Severity::Info => 4,
    }
}
