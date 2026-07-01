# SecProbe — AI-Powered Security Audit Tool

<p align="center">
  <strong>Fast, offline, cross-platform code security scanner</strong>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#features">Features</a> •
  <a href="#rules">Rules</a> •
  <a href="#usage">Usage</a> •
  <a href="README_CN.md">中文文档</a>
</p>

---

## What is SecProbe?

SecProbe is a **Rust-powered** security audit tool that scans your codebase for vulnerabilities in seconds — no cloud API, no signup, fully offline.

Unlike general-purpose AI assistants (Claude Code, Codex), SecProbe is purpose-built for security:

| Feature | Claude Code / Codex | SecProbe |
|---|---|---|
| **Focus** | General coding assistant | **Security-only** — goes deep |
| **Scan mode** | Manual "find vulnerabilities" prompt | **Auto full-project scan** |
| **Rule engine** | None — relies on LLM guessing | **Deterministic regex rules + CWE mapping** |
| **False positives** | High (LLM hallucination) | **Low** — pattern-based with confidence scoring |
| **Speed** | Slow (LLM round-trips) | **Millisecond scanning** (Rust + rayon parallelism) |
| **Offline** | Requires internet | **100% offline** — sensitive code never leaves your machine |
| **Reports** | Chat-style, not archivable | **Professional HTML/JSON/SARIF reports** |
| **Compliance** | None | **OWASP Top 10 + CWE mapping** |
| **Fix code** | Suggestions only | **Ready-to-apply fix patches** |

## Quick Start

```bash
# Build
cargo build --release

# Scan current directory
./target/release/secprobe scan .

# Scan a project with HTML report
./target/release/secprobe scan /path/to/project -f html

# JSON output for CI/CD integration
./target/release/secprobe scan . -f json -o report.json

# List all security rules
./target/release/secprobe rules
```

## Features

### 28 Security Rules (OWASP Top 10 Coverage)

| ID | Vulnerability | CWE | Severity | Languages |
|---|---|---|---|---|
| SEC-001 | SQL Injection | CWE-89 | CRITICAL | JS/TS/Python |
| SEC-002 | SQL Injection (Python f-string) | CWE-89 | CRITICAL | Python |
| SEC-010 | Cross-Site Scripting (XSS) | CWE-79 | HIGH | JS/TS |
| SEC-020 | Command Injection | CWE-78 | CRITICAL | JS/TS |
| SEC-021 | Command Injection (Python) | CWE-78 | CRITICAL | Python |
| SEC-030 | Path Traversal | CWE-22 | HIGH | JS/TS/Python |
| SEC-040 | Hardcoded Secrets | CWE-798 | HIGH | All |
| SEC-050 | Weak Cryptography | CWE-327 | MEDIUM | All |
| SEC-060 | Insecure Deserialization | CWE-502 | CRITICAL | JS/TS/Python |
| SEC-070 | SSRF | CWE-918 | HIGH | JS/TS/Python |
| SEC-080 | JWT Misconfiguration | CWE-347 | HIGH | JS/TS/Python |
| SEC-090 | CORS Misconfiguration | CWE-942 | MEDIUM | JS/TS/Python/Go |
| SEC-100 | Prototype Pollution | CWE-1321 | HIGH | JS/TS |
| SEC-110 | Insecure Randomness | CWE-330 | MEDIUM | JS/TS/Python |
| SEC-120 | NoSQL Injection | CWE-943 | HIGH | JS/TS |
| SEC-130 | Open Redirect | CWE-601 | MEDIUM | JS/TS/Python |
| SEC-140 | Error Info Leakage | CWE-209 | MEDIUM | JS/TS/Python |
| SEC-150 | ReDoS | CWE-1333 | MEDIUM | JS/TS/Python |
| SEC-160 | Missing Rate Limiting | CWE-307 | MEDIUM | JS/TS |
| SEC-170 | Cleartext Password Storage | CWE-312 | CRITICAL | JS/TS/Python |
| SEC-180 | Missing Security Headers | CWE-693 | LOW | JS/TS |
| SEC-190 | Insecure Cookie Config | CWE-614 | MEDIUM | JS/TS |
| SEC-200 | XML External Entity (XXE) | CWE-611 | HIGH | JS/TS/Python/Java |
| SEC-210 | Log Injection | CWE-117 | LOW | JS/TS/Python |
| SEC-300 | SQL Injection (Go) | CWE-89 | CRITICAL | Go |
| SEC-301 | Command Injection (Go) | CWE-78 | CRITICAL | Go |
| SEC-400 | SQL Injection (Java) | CWE-89 | CRITICAL | Java |
| SEC-401 | Insecure Deserialization (Java) | CWE-502 | CRITICAL | Java |

### Output Formats

- **Terminal** — Colorized output with code snippets and fix suggestions
- **HTML** — Dark-themed professional report, auto-opens in browser
- **JSON** — Machine-readable for CI/CD pipeline integration

### Performance

- **Rust + rayon** parallel scanning — thousands of files in milliseconds
- Auto-skips `node_modules`, `.git`, `target`, `__pycache__`, etc.
- Max file size limit (1 MB) to avoid binary files

## Usage

```bash
secprobe scan <path> [options]

Options:
  -f, --format <format>       Output format: terminal, json, html [default: terminal]
  -o, --output <file>         Output file path (for json/html)
      --min-severity <level>  Minimum severity: critical, high, medium, low [default: low]
```

### Examples

```bash
# Full scan with terminal output
secprobe scan ./my-project

# Only critical and high severity
secprobe scan . --min-severity high

# Generate HTML report
secprobe scan . -f html -o audit-report.html

# CI/CD integration
secprobe scan . -f json -o results.json --min-severity medium
```

## Desktop App

SecProbe ships a cross-platform desktop app (Windows / macOS / Linux) built with **Tauri 2** — pick or drag in a folder, scan, and browse findings visually in a dark, security-themed UI.

```bash
# Prerequisite: Tauri CLI v2
cargo install tauri-cli --version "^2"

# Run in dev mode
cargo tauri dev

# Build a production bundle (.app / .dmg / .msi / .deb / .AppImage)
cargo tauri build
```

**Highlights:** native folder picker & OS-level drag-and-drop, live severity filtering, expandable finding cards (code snippet + CWE/OWASP tags + fix suggestion), and one-click JSON / HTML report export.

## Architecture

```
SecProbe
├── src/                  — Rust core (shared library + CLI)
│   ├── main.rs           — CLI entry (clap)
│   ├── lib.rs            — Library crate root (secprobe_core)
│   ├── types.rs          — Core data structures
│   ├── rules.rs          — 28 security rules with CWE/OWASP mapping
│   ├── scanner.rs        — Parallel file scanner (rayon + walkdir)
│   ├── llm.rs            — Optional LLM deep analysis (OpenAI/Anthropic/DeepSeek)
│   └── report.rs         — Terminal / JSON / HTML report generators
├── src-tauri/            — Tauri 2 desktop backend (Rust commands)
├── src-ui/               — Desktop frontend (HTML / CSS / JS, dark theme)
└── Cargo.toml            — Cargo workspace (core + desktop)
```

## Roadmap

- [ ] Tree-sitter AST-based analysis (Go, Java, Rust, PHP support)
- [ ] Cross-file data flow tracking (taint analysis)
- [ ] LLM-enhanced deep analysis (optional, for complex patterns)
- [ ] SARIF output (GitHub/GitLab security tab integration)
- [x] Tauri desktop app with visual dashboard
- [ ] VS Code extension for real-time scanning

## License

This project is licensed under the **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.

- You are free to use, share, and adapt this software for **non-commercial purposes**.
- **Commercial use is prohibited** without explicit written permission.
- See [LICENSE](LICENSE) for details.
