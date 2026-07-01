use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use rayon::prelude::*;
use walkdir::WalkDir;

use crate::rules::{all_rules, compile_rule};
use crate::types::*;

const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "target",
    "__pycache__",
    ".venv",
    "vendor",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "coverage",
    ".idea",
    ".vscode",
    ".cursor",
];

const MAX_FILE_SIZE: u64 = 1_048_576; // 1 MB

pub fn scan_project(project_path: &Path) -> ScanResult {
    let start = Instant::now();

    let files = collect_files(project_path);
    let total_files = files.len();

    let rules = all_rules();
    let compiled: Vec<_> = rules
        .iter()
        .filter_map(|r| compile_rule(r).map(|re| (r.clone(), re)))
        .collect();

    let findings: Vec<Finding> = files
        .par_iter()
        .flat_map(|(path, lang)| scan_file(path, *lang, &compiled))
        .collect();

    let mut lang_counts = std::collections::HashMap::new();
    for (_, lang) in &files {
        if *lang != Language::Unknown {
            *lang_counts.entry(*lang).or_insert(0usize) += 1;
        }
    }
    let mut languages: Vec<_> = lang_counts.into_iter().collect();
    languages.sort_by_key(|b| std::cmp::Reverse(b.1));

    ScanResult {
        project_path: project_path.to_path_buf(),
        total_files,
        scanned_files: files
            .iter()
            .filter(|(_, l)| *l != Language::Unknown)
            .count(),
        findings,
        scan_duration_ms: start.elapsed().as_millis() as u64,
        languages,
    }
}

fn collect_files(root: &Path) -> Vec<(PathBuf, Language)> {
    WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| {
            if e.file_type().is_dir() {
                let name = e.file_name().to_string_lossy();
                return !SKIP_DIRS.contains(&name.as_ref());
            }
            true
        })
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            e.metadata()
                .map(|m| m.len() < MAX_FILE_SIZE)
                .unwrap_or(false)
        })
        .map(|e| {
            let ext = e.path().extension().and_then(|s| s.to_str()).unwrap_or("");
            let lang = Language::from_extension(ext);
            (e.path().to_path_buf(), lang)
        })
        .filter(|(_, lang)| *lang != Language::Unknown)
        .collect()
}

fn scan_file(
    path: &Path,
    lang: Language,
    rules: &[(crate::rules::Rule, regex::Regex)],
) -> Vec<Finding> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let lines: Vec<&str> = content.lines().collect();
    let mut findings = Vec::new();
    let mut finding_id = 0u32;

    for (rule, re) in rules {
        if !rule.languages.contains(&lang) {
            continue;
        }

        for (line_idx, line) in lines.iter().enumerate() {
            if let Some(m) = re.find(line) {
                let snippet_start = line_idx.saturating_sub(2);
                let snippet_end = (line_idx + 3).min(lines.len());
                let snippet: String = lines[snippet_start..snippet_end]
                    .iter()
                    .enumerate()
                    .map(|(i, l)| {
                        let num = snippet_start + i + 1;
                        let marker = if snippet_start + i == line_idx {
                            ">"
                        } else {
                            " "
                        };
                        format!("{marker} {num:4} | {l}")
                    })
                    .collect::<Vec<_>>()
                    .join("\n");

                finding_id += 1;
                findings.push(Finding {
                    id: format!("F-{:04}", finding_id),
                    rule_id: rule.id.to_string(),
                    title: rule.title.to_string(),
                    description: rule.description.to_string(),
                    severity: rule.severity,
                    confidence: 0.85,
                    file: path.to_path_buf(),
                    line: line_idx + 1,
                    column: m.start() + 1,
                    code_snippet: snippet,
                    language: lang,
                    cwe_id: rule.cwe_id.map(|s| s.to_string()),
                    owasp_category: rule.owasp.map(|s| s.to_string()),
                    fix_suggestion: rule.fix_suggestion.to_string(),
                    fix_code: rule.fix_example.map(|s| s.to_string()),
                });
            }
        }
    }

    findings
}
