use colored::Colorize;

use crate::types::*;

pub fn print_terminal_report(result: &ScanResult) {
    let summary = result.summary();

    println!();
    println!("{}", "══════════════════════════════════════════════════════════".bold());
    println!("{}", "  SecProbe - AI Security Audit Tool".bold().cyan());
    println!("{}", "══════════════════════════════════════════════════════════".bold());

    println!();
    println!("{}  {}", "Project:".bold(), result.project_path.display());
    println!("{}  {} / {} scanned", "Files:".bold(), result.scanned_files, result.total_files);
    println!("{}  {} ms", "Duration:".bold(), result.scan_duration_ms);

    if !result.languages.is_empty() {
        let langs: String = result.languages.iter()
            .map(|(l, c)| format!("{l}: {c}"))
            .collect::<Vec<_>>()
            .join(", ");
        println!("{} {langs}", "Languages:".bold());
    }

    println!();
    println!("{}", "─── Summary ─────────────────────────────────────────────".dimmed());
    print_severity_bar(&summary);

    if result.findings.is_empty() {
        println!();
        println!("{}", "  No security issues found!".green().bold());
        println!();
        return;
    }

    println!();
    println!("{}", "─── Findings ────────────────────────────────────────────".dimmed());

    let mut sorted = result.findings.clone();
    sorted.sort_by(|a, b| severity_order(a.severity).cmp(&severity_order(b.severity)));

    for (i, f) in sorted.iter().enumerate() {
        println!();
        let sev_str = format_severity(f.severity);
        println!(
            "  {} {} {} {}",
            format!("[{}/{}]", i + 1, sorted.len()).dimmed(),
            sev_str,
            f.title.bold(),
            format!("({})", f.rule_id).dimmed()
        );

        if let Some(ref cwe) = f.cwe_id {
            print!("  {cwe}");
        }
        if let Some(ref owasp) = f.owasp_category {
            print!(" | {owasp}");
        }
        println!();

        println!("  {} {}:{}", "Location:".dimmed(), f.file.display(), f.line);
        println!();

        for line in f.code_snippet.lines() {
            if line.starts_with('>') {
                println!("    {}", line.red());
            } else {
                println!("    {}", line.dimmed());
            }
        }

        println!();
        println!("  {} {}", "Fix:".yellow().bold(), f.fix_suggestion);

        if let Some(ref fix) = f.fix_code {
            println!();
            println!("  {}", "  Recommended code:".green());
            for line in fix.lines() {
                println!("    {}", line.green());
            }
        }
    }

    println!();
    println!("{}", "══════════════════════════════════════════════════════════".bold());
    println!(
        "  Total: {} issues ({} critical, {} high, {} medium, {} low)",
        summary.total.to_string().bold(),
        summary.critical.to_string().red().bold(),
        summary.high.to_string().yellow().bold(),
        summary.medium.to_string().cyan(),
        summary.low.to_string().dimmed()
    );
    println!("{}", "══════════════════════════════════════════════════════════".bold());
    println!();
}

pub fn export_json(result: &ScanResult) -> String {
    serde_json::to_string_pretty(result).unwrap_or_default()
}

pub fn export_html(result: &ScanResult) -> String {
    let summary = result.summary();
    let mut html = String::new();

    html.push_str("<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n");
    html.push_str("<meta charset=\"utf-8\">\n");
    html.push_str("<title>SecProbe Security Audit Report</title>\n");
    html.push_str("<style>\n");
    html.push_str("* { margin: 0; padding: 0; box-sizing: border-box; }\n");
    html.push_str("body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem; }\n");
    html.push_str(".container { max-width: 1000px; margin: 0 auto; }\n");
    html.push_str("h1 { font-size: 1.8rem; margin-bottom: 0.5rem; color: #38bdf8; }\n");
    html.push_str("h2 { font-size: 1.2rem; margin: 1.5rem 0 0.8rem; color: #94a3b8; border-bottom: 1px solid #334155; padding-bottom: 0.4rem; }\n");
    html.push_str(".meta { color: #64748b; font-size: 0.9rem; margin-bottom: 1.5rem; }\n");
    html.push_str(".stats { display: flex; gap: 1rem; margin: 1rem 0; flex-wrap: wrap; }\n");
    html.push_str(".stat { background: #1e293b; border-radius: 8px; padding: 1rem 1.5rem; min-width: 120px; text-align: center; }\n");
    html.push_str(".stat .num { font-size: 2rem; font-weight: 700; }\n");
    html.push_str(".stat .label { font-size: 0.8rem; color: #94a3b8; }\n");
    html.push_str(".critical .num { color: #ef4444; } .high .num { color: #f59e0b; }\n");
    html.push_str(".medium .num { color: #3b82f6; } .low .num { color: #6b7280; }\n");
    html.push_str(".finding { background: #1e293b; border-radius: 8px; padding: 1.2rem; margin: 0.8rem 0; border-left: 4px solid; }\n");
    html.push_str(".finding.sev-critical { border-color: #ef4444; } .finding.sev-high { border-color: #f59e0b; }\n");
    html.push_str(".finding.sev-medium { border-color: #3b82f6; } .finding.sev-low { border-color: #6b7280; }\n");
    html.push_str(".finding .title { font-weight: 600; font-size: 1rem; margin-bottom: 0.3rem; }\n");
    html.push_str(".finding .loc { font-size: 0.85rem; color: #64748b; }\n");
    html.push_str(".badge { display: inline-block; font-size: 0.75rem; padding: 2px 8px; border-radius: 4px; font-weight: 600; }\n");
    html.push_str(".badge-critical { background: #ef4444; color: white; } .badge-high { background: #f59e0b; color: #1e293b; }\n");
    html.push_str(".badge-medium { background: #3b82f6; color: white; } .badge-low { background: #6b7280; color: white; }\n");
    html.push_str("pre { background: #0f172a; padding: 0.8rem; border-radius: 4px; overflow-x: auto; font-size: 0.85rem; margin: 0.5rem 0; }\n");
    html.push_str(".fix { background: #064e3b; padding: 0.8rem; border-radius: 4px; margin-top: 0.5rem; font-size: 0.9rem; }\n");
    html.push_str("</style>\n</head>\n<body>\n<div class=\"container\">\n");

    html.push_str("<h1>SecProbe Security Report</h1>\n");
    html.push_str(&format!(
        "<div class=\"meta\">Project: {} | Files: {}/{} | Duration: {}ms</div>\n",
        result.project_path.display(),
        result.scanned_files,
        result.total_files,
        result.scan_duration_ms
    ));

    html.push_str("<div class=\"stats\">\n");
    html.push_str(&format!("<div class=\"stat critical\"><div class=\"num\">{}</div><div class=\"label\">Critical</div></div>\n", summary.critical));
    html.push_str(&format!("<div class=\"stat high\"><div class=\"num\">{}</div><div class=\"label\">High</div></div>\n", summary.high));
    html.push_str(&format!("<div class=\"stat medium\"><div class=\"num\">{}</div><div class=\"label\">Medium</div></div>\n", summary.medium));
    html.push_str(&format!("<div class=\"stat low\"><div class=\"num\">{}</div><div class=\"label\">Low</div></div>\n", summary.low));
    html.push_str("</div>\n");

    html.push_str("<h2>Findings</h2>\n");

    let mut sorted = result.findings.clone();
    sorted.sort_by(|a, b| severity_order(a.severity).cmp(&severity_order(b.severity)));

    for f in &sorted {
        let sev_class = match f.severity {
            Severity::Critical => "sev-critical",
            Severity::High => "sev-high",
            Severity::Medium => "sev-medium",
            _ => "sev-low",
        };
        let badge_class = match f.severity {
            Severity::Critical => "badge-critical",
            Severity::High => "badge-high",
            Severity::Medium => "badge-medium",
            _ => "badge-low",
        };

        html.push_str(&format!("<div class=\"finding {sev_class}\">\n"));
        html.push_str(&format!(
            "<div class=\"title\"><span class=\"badge {badge_class}\">{}</span> {} <small>({})</small></div>\n",
            f.severity, html_escape(&f.title), f.rule_id
        ));

        if let (Some(cwe), Some(owasp)) = (&f.cwe_id, &f.owasp_category) {
            html.push_str(&format!("<div class=\"loc\">{cwe} | {owasp}</div>\n"));
        }
        html.push_str(&format!("<div class=\"loc\">{}:{}</div>\n", f.file.display(), f.line));
        html.push_str(&format!("<pre>{}</pre>\n", html_escape(&f.code_snippet)));
        html.push_str(&format!("<div class=\"fix\">Fix: {}</div>\n", html_escape(&f.fix_suggestion)));

        if let Some(ref fix) = f.fix_code {
            html.push_str(&format!("<pre style=\"border-left:3px solid #10b981;\">{}</pre>\n", html_escape(fix)));
        }
        html.push_str("</div>\n");
    }

    html.push_str("</div>\n</body>\n</html>");
    html
}

fn format_severity(sev: Severity) -> String {
    match sev {
        Severity::Critical => "CRITICAL".red().bold().to_string(),
        Severity::High => "HIGH".yellow().bold().to_string(),
        Severity::Medium => "MEDIUM".cyan().to_string(),
        Severity::Low => "LOW".dimmed().to_string(),
        Severity::Info => "INFO".dimmed().to_string(),
    }
}

fn severity_order(sev: Severity) -> u8 {
    match sev {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    }
}

fn print_severity_bar(summary: &ScanSummary) {
    println!(
        "  {} Critical  {} High  {} Medium  {} Low  {} Info",
        format!("{}", summary.critical).red().bold(),
        format!("{}", summary.high).yellow().bold(),
        format!("{}", summary.medium).cyan(),
        format!("{}", summary.low).dimmed(),
        format!("{}", summary.info).dimmed()
    );
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
