use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::types::Finding;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    pub provider: LlmProvider,
    pub api_key: String,
    pub model: String,
    pub base_url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LlmProvider {
    OpenAI,
    Anthropic,
    DeepSeek,
    Custom,
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            provider: LlmProvider::OpenAI,
            api_key: String::new(),
            model: "gpt-4o-mini".into(),
            base_url: None,
        }
    }
}

impl LlmConfig {
    pub fn from_env() -> Option<Self> {
        if let Ok(key) = std::env::var("OPENAI_API_KEY") {
            return Some(Self {
                provider: LlmProvider::OpenAI,
                api_key: key,
                model: std::env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4o-mini".into()),
                base_url: std::env::var("OPENAI_BASE_URL").ok(),
            });
        }
        if let Ok(key) = std::env::var("ANTHROPIC_API_KEY") {
            return Some(Self {
                provider: LlmProvider::Anthropic,
                api_key: key,
                model: std::env::var("ANTHROPIC_MODEL")
                    .unwrap_or_else(|_| "claude-sonnet-4-20250514".into()),
                base_url: None,
            });
        }
        if let Ok(key) = std::env::var("DEEPSEEK_API_KEY") {
            return Some(Self {
                provider: LlmProvider::DeepSeek,
                api_key: key,
                model: "deepseek-chat".into(),
                base_url: Some("https://api.deepseek.com".into()),
            });
        }
        None
    }

    fn api_url(&self) -> String {
        match self.provider {
            LlmProvider::OpenAI | LlmProvider::DeepSeek | LlmProvider::Custom => {
                let base = self.base_url.as_deref().unwrap_or("https://api.openai.com");
                format!("{base}/v1/chat/completions")
            }
            LlmProvider::Anthropic => "https://api.anthropic.com/v1/messages".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepAnalysis {
    pub finding_id: String,
    pub exploitability: String,
    pub impact: String,
    pub attack_scenario: String,
    pub detailed_fix: String,
    pub confidence_adjustment: f64,
    pub is_false_positive: bool,
    pub reasoning: String,
}

fn build_analysis_prompt(finding: &Finding, file_content: &str) -> String {
    let context_start = finding.line.saturating_sub(15);
    let lines: Vec<&str> = file_content.lines().collect();
    let context_end = (finding.line + 15).min(lines.len());
    let context: String = lines[context_start..context_end]
        .iter()
        .enumerate()
        .map(|(i, l)| format!("{:4} | {l}", context_start + i + 1))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"You are a senior security researcher. Analyze this potential vulnerability.

## Finding
- Rule: {} ({})
- Severity: {:?}
- File: {}:{}
- CWE: {}
- OWASP: {}

## Code (lines {}-{})
```
{context}
```

## Description
{}

Respond ONLY with valid JSON (no markdown fences):
{{"exploitability":"trivial|moderate|difficult|theoretical","impact":"critical|high|moderate|low","attack_scenario":"2-3 sentence scenario","is_false_positive":false,"detailed_fix":"exact code fix","confidence":0.85,"reasoning":"why"}}"#,
        finding.title,
        finding.rule_id,
        finding.severity,
        finding.file.display(),
        finding.line,
        finding.cwe_id.as_deref().unwrap_or("N/A"),
        finding.owasp_category.as_deref().unwrap_or("N/A"),
        context_start + 1,
        context_end,
        finding.description
    )
}

fn call_openai_compatible(config: &LlmConfig, prompt: &str) -> Result<String, String> {
    let body = serde_json::json!({
        "model": config.model,
        "messages": [
            {"role": "system", "content": "You are a security vulnerability analyst. Respond only in valid JSON."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.2,
        "max_tokens": 1024
    });

    let mut resp = ureq::post(&config.api_url())
        .header("Authorization", &format!("Bearer {}", config.api_key))
        .header("Content-Type", "application/json")
        .send_json(&body)
        .map_err(|e| format!("HTTP error: {e}"))?;

    let json: serde_json::Value = resp
        .body_mut()
        .read_json()
        .map_err(|e| format!("JSON parse error: {e}"))?;

    json["choices"][0]["message"]["content"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "No content in response".into())
}

fn call_anthropic(config: &LlmConfig, prompt: &str) -> Result<String, String> {
    let body = serde_json::json!({
        "model": config.model,
        "max_tokens": 1024,
        "messages": [
            {"role": "user", "content": prompt}
        ],
        "system": "You are a security vulnerability analyst. Respond only in valid JSON.",
        "temperature": 0.2
    });

    let mut resp = ureq::post(&config.api_url())
        .header("x-api-key", &config.api_key)
        .header("anthropic-version", "2023-06-01")
        .header("Content-Type", "application/json")
        .send_json(&body)
        .map_err(|e| format!("HTTP error: {e}"))?;

    let json: serde_json::Value = resp
        .body_mut()
        .read_json()
        .map_err(|e| format!("JSON parse error: {e}"))?;

    json["content"][0]["text"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "No content in response".into())
}

fn call_llm(config: &LlmConfig, prompt: &str) -> Result<String, String> {
    match config.provider {
        LlmProvider::Anthropic => call_anthropic(config, prompt),
        _ => call_openai_compatible(config, prompt),
    }
}

fn parse_llm_response(finding_id: &str, raw: &str) -> DeepAnalysis {
    let cleaned = raw
        .trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();

    if let Ok(v) = serde_json::from_str::<serde_json::Value>(cleaned) {
        return DeepAnalysis {
            finding_id: finding_id.to_string(),
            exploitability: v["exploitability"]
                .as_str()
                .unwrap_or("unknown")
                .to_string(),
            impact: v["impact"].as_str().unwrap_or("unknown").to_string(),
            attack_scenario: v["attack_scenario"].as_str().unwrap_or("N/A").to_string(),
            detailed_fix: v["detailed_fix"].as_str().unwrap_or("N/A").to_string(),
            confidence_adjustment: v["confidence"].as_f64().unwrap_or(0.5),
            is_false_positive: v["is_false_positive"].as_bool().unwrap_or(false),
            reasoning: v["reasoning"].as_str().unwrap_or("N/A").to_string(),
        };
    }

    DeepAnalysis {
        finding_id: finding_id.to_string(),
        exploitability: "parse_error".into(),
        impact: "unknown".into(),
        attack_scenario: "Failed to parse LLM response".into(),
        detailed_fix: raw.to_string(),
        confidence_adjustment: 0.5,
        is_false_positive: false,
        reasoning: format!("Raw LLM output: {cleaned}"),
    }
}

pub fn analyze_findings(
    findings: &[Finding],
    _project_path: &Path,
    config: &LlmConfig,
) -> Vec<DeepAnalysis> {
    let max_analyze = 10.min(findings.len());

    findings[..max_analyze]
        .iter()
        .enumerate()
        .filter_map(|(i, f)| {
            let file_content = std::fs::read_to_string(&f.file).ok()?;
            let prompt = build_analysis_prompt(f, &file_content);

            eprint!("  [{}/{}] Analyzing {} ... ", i + 1, max_analyze, f.rule_id);

            match call_llm(config, &prompt) {
                Ok(response) => {
                    eprintln!("done");
                    Some(parse_llm_response(&f.id, &response))
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    Some(DeepAnalysis {
                        finding_id: f.id.clone(),
                        exploitability: "error".into(),
                        impact: "unknown".into(),
                        attack_scenario: format!("LLM call failed: {e}"),
                        detailed_fix: f.fix_suggestion.clone(),
                        confidence_adjustment: f.confidence,
                        is_false_positive: false,
                        reasoning: e,
                    })
                }
            }
        })
        .collect()
}
