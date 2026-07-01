# SecProbe — AI 驱动的安全审计工具

<p align="center">
  <strong>极速、离线、跨平台的代码安全扫描器</strong>
</p>

<p align="center">
  <a href="#快速开始">快速开始</a> •
  <a href="#功能特性">功能特性</a> •
  <a href="#安全规则">安全规则</a> •
  <a href="#使用方法">使用方法</a> •
  <a href="README.md">English</a>
</p>

---

## SecProbe 是什么？

SecProbe 是一款**基于 Rust 构建**的安全审计工具，能在数秒内扫描代码库中的安全漏洞 — 无需云 API、无需注册、完全离线运行。

与通用 AI 编程助手（Claude Code、Codex）不同，SecProbe 专为安全审计而生：

| 特性 | Claude Code / Codex | SecProbe |
|---|---|---|
| **定位** | 通用编程助手 | **安全审计专家** — 只做安全，做到极致 |
| **扫描方式** | 手动提问"有没有漏洞" | **自动全项目扫描** |
| **规则引擎** | 无 — 依赖 LLM 随机判断 | **确定性正则规则 + CWE 映射** |
| **误报率** | 高（LLM 幻觉） | **低** — 基于模式匹配，带置信度评分 |
| **速度** | 慢（每次调 LLM） | **毫秒级扫描**（Rust + rayon 并行） |
| **离线能力** | 必须联网 | **100% 离线** — 敏感代码不出你的电脑 |
| **报告** | 聊天形式，不可存档 | **专业 HTML/JSON 报告** |
| **合规** | 无 | **OWASP Top 10 + CWE 标准映射** |
| **修复** | 文字建议 | **直接给出修复代码** |

## 快速开始

```bash
# 编译
cargo build --release

# 扫描当前目录
./target/release/secprobe scan .

# 扫描项目并生成 HTML 报告
./target/release/secprobe scan /path/to/project -f html

# JSON 输出（用于 CI/CD 集成）
./target/release/secprobe scan . -f json -o report.json

# 查看所有安全规则
./target/release/secprobe rules
```

## 功能特性

### 25 条安全规则（OWASP Top 10 覆盖）

| 编号 | 漏洞类型 | CWE | 严重度 | 支持语言 |
|---|---|---|---|---|
| SEC-001 | SQL 注入 | CWE-89 | 严重 | JS/TS/Python |
| SEC-002 | SQL 注入 (Python f-string) | CWE-89 | 严重 | Python |
| SEC-010 | 跨站脚本 (XSS) | CWE-79 | 高 | JS/TS |
| SEC-020 | 命令注入 | CWE-78 | 严重 | JS/TS |
| SEC-021 | 命令注入 (Python) | CWE-78 | 严重 | Python |
| SEC-030 | 路径遍历 | CWE-22 | 高 | JS/TS/Python |
| SEC-040 | 硬编码密钥 | CWE-798 | 高 | 全语言 |
| SEC-050 | 弱加密算法 | CWE-327 | 中 | 全语言 |
| SEC-060 | 不安全的反序列化 | CWE-502 | 严重 | JS/TS/Python |
| SEC-070 | 服务端请求伪造 (SSRF) | CWE-918 | 高 | JS/TS/Python |
| SEC-080 | JWT 配置问题 | CWE-347 | 高 | JS/TS/Python |
| SEC-090 | CORS 配置不安全 | CWE-942 | 中 | JS/TS/Python/Go |
| SEC-100 | 原型链污染 | CWE-1321 | 高 | JS/TS |
| SEC-110 | 不安全的随机数 | CWE-330 | 中 | JS/TS/Python |
| SEC-120 | NoSQL 注入 | CWE-943 | 高 | JS/TS |
| SEC-130 | 开放重定向 | CWE-601 | 中 | JS/TS/Python |
| SEC-140 | 错误信息泄露 | CWE-209 | 中 | JS/TS/Python |
| SEC-150 | 正则 DoS (ReDoS) | CWE-1333 | 中 | JS/TS/Python |
| SEC-160 | 缺少速率限制 | CWE-307 | 中 | JS/TS |
| SEC-170 | 明文存储密码 | CWE-312 | 严重 | JS/TS/Python |
| SEC-180 | 安全头缺失 | CWE-693 | 低 | JS/TS |
| SEC-190 | Cookie 配置不安全 | CWE-614 | 中 | JS/TS |
| SEC-200 | XML 外部实体 (XXE) | CWE-611 | 高 | JS/TS/Python/Java |
| SEC-210 | 日志注入 | CWE-117 | 低 | JS/TS/Python |
| SEC-300 | SQL 注入 (Go) | CWE-89 | 严重 | Go |
| SEC-301 | 命令注入 (Go) | CWE-78 | 严重 | Go |
| SEC-400 | SQL 注入 (Java) | CWE-89 | 严重 | Java |
| SEC-401 | 不安全反序列化 (Java) | CWE-502 | 严重 | Java |

### 输出格式

- **终端** — 彩色输出，含代码片段和修复建议
- **HTML** — 暗色主题专业报告，自动在浏览器打开
- **JSON** — 机器可读格式，便于 CI/CD 集成

### 性能

- **Rust + rayon** 并行扫描 — 数千文件毫秒级完成
- 自动跳过 `node_modules`、`.git`、`target`、`__pycache__` 等目录
- 文件大小限制（1 MB），避免扫描二进制文件

## 使用方法

```bash
secprobe scan <路径> [选项]

选项:
  -f, --format <格式>         输出格式: terminal, json, html [默认: terminal]
  -o, --output <文件>         输出文件路径 (用于 json/html)
      --min-severity <级别>   最低严重度: critical, high, medium, low [默认: low]
```

### 示例

```bash
# 完整扫描，终端输出
secprobe scan ./my-project

# 只显示严重和高危
secprobe scan . --min-severity high

# 生成 HTML 报告
secprobe scan . -f html -o audit-report.html

# CI/CD 集成
secprobe scan . -f json -o results.json --min-severity medium
```

## 项目结构

```
SecProbe
├── src/
│   ├── main.rs       — CLI 入口 (clap)
│   ├── types.rs      — 核心数据结构
│   ├── rules.rs      — 13 条安全规则（含 CWE/OWASP 映射）
│   ├── scanner.rs    — 并行文件扫描器 (rayon + walkdir)
│   └── report.rs     — 终端 / JSON / HTML 报告生成器
└── Cargo.toml
```

## 发展路线

- [ ] Tree-sitter AST 分析（支持 Go、Java、Rust、PHP）
- [ ] 跨文件数据流追踪（污点分析）
- [ ] LLM 增强深度分析（可选，用于复杂模式）
- [ ] SARIF 输出（GitHub/GitLab 安全标签集成）
- [ ] Tauri 桌面应用（可视化仪表盘）
- [ ] VS Code 插件（实时扫描）

## 许可证

本项目采用 **CC BY-NC 4.0（知识共享 署名-非商业性使用 4.0 国际）** 许可。

- 你可以自由使用、分享和改编本软件，仅限**非商业用途**。
- **禁止商业使用**，除非获得明确的书面授权。
- 详见 [LICENSE](LICENSE) 文件。
