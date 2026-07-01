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
                model: std::env::var("ANTHROPIC_MODEL").unwrap_or_else(|_| "claude-sonnet-4-20250514".into()),
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

pub fn build_analysis_prompt(finding: &Finding, file_content: &str) -> String {
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
        r#"You are a senior security researcher. Analyze this potential vulnerability finding.

## Finding
- **Rule**: {} ({})
- **Severity**: {:?}
- **File**: {}:{}
- **CWE**: {}
- **OWASP**: {}

## Code Context (lines {}-{})
```
{context}
```

## Description
{}

## Task
Analyze this finding and provide:
1. **Exploitability**: How easy is it to exploit? (trivial / moderate / difficult / theoretical)
2. **Impact**: What's the worst-case impact? (critical / high / moderate / low)
3. **Attack Scenario**: Describe a realistic attack scenario in 2-3 sentences
4. **Is False Positive**: Is this likely a false positive? (true/false) with reasoning
5. **Detailed Fix**: Provide the exact code fix for this specific instance
6. **Confidence**: Your confidence this is a real issue (0.0-1.0)

Respond in JSON format:
```json
{{
  "exploitability": "...",
  "impact": "...",
  "attack_scenario": "...",
  "is_false_positive": false,
  "detailed_fix": "...",
  "confidence": 0.85,
  "reasoning": "..."
}}
```"#,
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

pub fn analyze_findings(
    findings: &[Finding],
    _project_path: &Path,
    _config: &LlmConfig,
) -> Vec<DeepAnalysis> {
    findings
        .iter()
        .filter_map(|f| {
            let file_content = std::fs::read_to_string(&f.file).ok()?;
            let _prompt = build_analysis_prompt(f, &file_content);

            Some(DeepAnalysis {
                finding_id: f.id.clone(),
                exploitability: "pending_llm_call".into(),
                impact: "pending_llm_call".into(),
                attack_scenario: "LLM analysis not yet implemented — run with --llm flag after setting API key".into(),
                detailed_fix: f.fix_suggestion.clone(),
                confidence_adjustment: f.confidence,
                is_false_positive: false,
                reasoning: "Static analysis only — LLM deep analysis requires API key configuration".into(),
            })
        })
        .collect()
}
