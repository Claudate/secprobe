use secprobe_core::{report, rules, scanner, types};
use serde::Serialize;
use std::path::PathBuf;
use tauri_plugin_dialog::DialogExt;

#[derive(Serialize)]
struct ScanResponse {
    project_path: String,
    total_files: usize,
    scanned_files: usize,
    scan_duration_ms: u64,
    findings: Vec<FindingDto>,
    summary: SummaryDto,
    languages: Vec<(String, usize)>,
}

#[derive(Serialize)]
struct FindingDto {
    rule_id: String,
    title: String,
    description: String,
    severity: String,
    file: String,
    line: usize,
    code_snippet: String,
    cwe_id: Option<String>,
    owasp_category: Option<String>,
    fix_suggestion: String,
    fix_code: Option<String>,
}

#[derive(Serialize)]
struct SummaryDto {
    critical: u32,
    high: u32,
    medium: u32,
    low: u32,
    info: u32,
    total: u32,
}

#[derive(Serialize)]
struct RuleDto {
    id: &'static str,
    title: &'static str,
    severity: String,
    cwe_id: Option<&'static str>,
    owasp_category: Option<&'static str>,
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

#[tauri::command]
fn scan_project(path: String, min_severity: Option<String>) -> Result<ScanResponse, String> {
    let project_path = PathBuf::from(&path);
    if !project_path.exists() {
        return Err(format!("Path '{path}' does not exist"));
    }

    let mut result = scanner::scan_project(&project_path);

    if let Some(ms) = min_severity {
        let min = parse_severity(&ms);
        result
            .findings
            .retain(|f| severity_value(f.severity) <= severity_value(min));
    }

    let summary = result.summary();

    let findings: Vec<FindingDto> = result
        .findings
        .iter()
        .map(|f| FindingDto {
            rule_id: f.rule_id.clone(),
            title: f.title.clone(),
            description: f.description.clone(),
            severity: f.severity.to_string(),
            file: f.file.display().to_string(),
            line: f.line,
            code_snippet: f.code_snippet.clone(),
            cwe_id: f.cwe_id.clone(),
            owasp_category: f.owasp_category.clone(),
            fix_suggestion: f.fix_suggestion.clone(),
            fix_code: f.fix_code.clone(),
        })
        .collect();

    let languages: Vec<(String, usize)> = result
        .languages
        .iter()
        .map(|(lang, count)| (lang.to_string(), *count))
        .collect();

    Ok(ScanResponse {
        project_path: result.project_path.display().to_string(),
        total_files: result.total_files,
        scanned_files: result.scanned_files,
        scan_duration_ms: result.scan_duration_ms,
        findings,
        summary: SummaryDto {
            critical: summary.critical,
            high: summary.high,
            medium: summary.medium,
            low: summary.low,
            info: summary.info,
            total: summary.total,
        },
        languages,
    })
}

#[tauri::command]
fn get_rules() -> Vec<RuleDto> {
    rules::all_rules()
        .iter()
        .map(|r| RuleDto {
            id: r.id,
            title: r.title,
            severity: r.severity.to_string(),
            cwe_id: r.cwe_id,
            owasp_category: r.owasp,
        })
        .collect()
}

/// Open a native folder picker and return the selected absolute path.
#[tauri::command]
async fn select_folder(app: tauri::AppHandle) -> Option<String> {
    app.dialog()
        .file()
        .blocking_pick_folder()
        .map(|fp| fp.to_string())
}

/// Re-scan the project and export the report (json/html) via a native save dialog.
#[tauri::command]
async fn export_report(
    app: tauri::AppHandle,
    path: String,
    format: String,
) -> Result<String, String> {
    let project_path = PathBuf::from(&path);
    if !project_path.exists() {
        return Err(format!("Path '{path}' does not exist"));
    }

    let result = scanner::scan_project(&project_path);
    let (content, ext) = match format.as_str() {
        "html" => (report::export_html(&result), "html"),
        _ => (report::export_json(&result), "json"),
    };

    let default_name = format!("secprobe-report.{ext}");
    let picked = app
        .dialog()
        .file()
        .set_file_name(&default_name)
        .add_filter("SecProbe Report", &[ext])
        .blocking_save_file();

    match picked {
        Some(fp) => {
            let out = PathBuf::from(fp.to_string());
            std::fs::write(&out, content).map_err(|e| e.to_string())?;
            Ok(out.display().to_string())
        }
        None => Err("cancelled".to_string()),
    }
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            scan_project,
            get_rules,
            select_folder,
            export_report
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
