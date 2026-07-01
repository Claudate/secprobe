use regex::Regex;

use crate::types::{Language, Severity};

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub severity: Severity,
    pub cwe_id: Option<&'static str>,
    pub owasp: Option<&'static str>,
    pub languages: &'static [Language],
    pub pattern: &'static str,
    pub fix_suggestion: &'static str,
    pub fix_example: Option<&'static str>,
}

pub fn all_rules() -> Vec<Rule> {
    vec![
        // SQL Injection
        Rule {
            id: "SEC-001",
            title: "SQL 注入风险",
            description: "检测到字符串拼接构造 SQL 查询，可能导致 SQL 注入攻击",
            severity: Severity::Critical,
            cwe_id: Some("CWE-89"),
            owasp: Some("A03:2021-Injection"),
            languages: &[Language::JavaScript, Language::TypeScript, Language::Python],
            pattern: r#"(?i)(query|execute|exec)\s*\(\s*[`"'].*\$\{|(?i)(query|execute|exec)\s*\(\s*.*\+\s*.*(?:req|input|param|user|body)"#,
            fix_suggestion: "使用参数化查询或 ORM，不要拼接用户输入到 SQL 字符串中",
            fix_example: Some("db.query('SELECT * FROM users WHERE id = $1', [userId])"),
        },
        Rule {
            id: "SEC-002",
            title: "SQL 注入风险 (Python)",
            description: "检测到 f-string 或 format 构造 SQL 查询",
            severity: Severity::Critical,
            cwe_id: Some("CWE-89"),
            owasp: Some("A03:2021-Injection"),
            languages: &[Language::Python],
            pattern: r#"(?i)(cursor\.execute|\.execute)\s*\(\s*f["']|(?i)(cursor\.execute|\.execute)\s*\(\s*["'].*\.format\s*\("#,
            fix_suggestion: "使用参数化查询：cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
            fix_example: Some("cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"),
        },

        // XSS
        Rule {
            id: "SEC-010",
            title: "跨站脚本 (XSS) 风险",
            description: "检测到 innerHTML 或 dangerouslySetInnerHTML 使用，可能导致 XSS",
            severity: Severity::High,
            cwe_id: Some("CWE-79"),
            owasp: Some("A03:2021-Injection"),
            languages: &[Language::JavaScript, Language::TypeScript],
            pattern: r"\.innerHTML\s*=|dangerouslySetInnerHTML|document\.write\s*\(",
            fix_suggestion: "使用 textContent 替代 innerHTML，或使用 DOMPurify 净化 HTML",
            fix_example: Some("element.textContent = userInput; // 安全\n// 或使用 DOMPurify: element.innerHTML = DOMPurify.sanitize(userInput);"),
        },

        // Command Injection
        Rule {
            id: "SEC-020",
            title: "命令注入风险",
            description: "检测到使用 exec/spawn/system 执行外部命令，可能存在命令注入",
            severity: Severity::Critical,
            cwe_id: Some("CWE-78"),
            owasp: Some("A03:2021-Injection"),
            languages: &[Language::JavaScript, Language::TypeScript],
            pattern: r"(?:child_process|exec|execSync|spawn|spawnSync)\s*\(.*(?:req\.|input|param|user|body|query)",
            fix_suggestion: "使用 execFile/spawnSync 的数组参数形式，避免 shell 解释",
            fix_example: Some("execFile('ls', ['-la', safeDir]) // 安全：数组参数不经过 shell"),
        },
        Rule {
            id: "SEC-021",
            title: "命令注入风险 (Python)",
            description: "检测到 os.system/subprocess.call 使用 shell=True 或字符串拼接",
            severity: Severity::Critical,
            cwe_id: Some("CWE-78"),
            owasp: Some("A03:2021-Injection"),
            languages: &[Language::Python],
            pattern: r#"(?:os\.system|os\.popen|subprocess\.call|subprocess\.run|subprocess\.Popen)\s*\(.*(?:shell\s*=\s*True|f["']|\+)"#,
            fix_suggestion: "使用 subprocess.run 的列表参数形式，设置 shell=False",
            fix_example: Some("subprocess.run(['ls', '-la', safe_dir], shell=False)"),
        },

        // Path Traversal
        Rule {
            id: "SEC-030",
            title: "路径遍历风险",
            description: "检测到文件操作中直接使用用户输入，可能导致路径遍历攻击",
            severity: Severity::High,
            cwe_id: Some("CWE-22"),
            owasp: Some("A01:2021-Broken Access Control"),
            languages: &[Language::JavaScript, Language::TypeScript, Language::Python],
            pattern: r"(?:readFile|writeFile|readFileSync|createReadStream|open)\s*\(.*(?:req\.|params\.|query\.|body\.)|(?:\.\.\/|\.\.\\)",
            fix_suggestion: "使用 path.resolve 验证路径，确保在允许的目录范围内",
            fix_example: Some("const safePath = path.resolve(baseDir, userInput);\nif (!safePath.startsWith(baseDir)) throw new Error('路径越界');"),
        },

        // Hardcoded Secrets
        Rule {
            id: "SEC-040",
            title: "硬编码密钥/密码",
            description: "检测到代码中硬编码的密钥、密码或 Token",
            severity: Severity::High,
            cwe_id: Some("CWE-798"),
            owasp: Some("A07:2021-Identification and Authentication Failures"),
            languages: &[Language::JavaScript, Language::TypeScript, Language::Python, Language::Go, Language::Java],
            pattern: r#"(?i)(?:password|passwd|secret|api_?key|access_?token|private_?key)\s*[:=]\s*["'][A-Za-z0-9+/=_\-]{8,}"#,
            fix_suggestion: "使用环境变量或密钥管理服务存储敏感信息",
            fix_example: Some("const apiKey = process.env.API_KEY; // 从环境变量读取"),
        },

        // Weak Crypto
        Rule {
            id: "SEC-050",
            title: "弱加密算法",
            description: "检测到使用 MD5/SHA1 等不安全的加密算法",
            severity: Severity::Medium,
            cwe_id: Some("CWE-327"),
            owasp: Some("A02:2021-Cryptographic Failures"),
            languages: &[Language::JavaScript, Language::TypeScript, Language::Python, Language::Go, Language::Java],
            pattern: r#"(?i)(?:createHash|hashlib\.)\s*\(\s*["'](?:md5|sha1)["']\)|(?i)MD5\.Create|MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-1)["']\)"#,
            fix_suggestion: "使用 SHA-256 或更强的哈希算法；密码存储使用 bcrypt/scrypt/argon2",
            fix_example: Some("crypto.createHash('sha256').update(data).digest('hex')"),
        },

        // Insecure Deserialization
        Rule {
            id: "SEC-060",
            title: "不安全的反序列化",
            description: "检测到使用 eval/pickle 等可能导致远程代码执行的反序列化操作",
            severity: Severity::Critical,
            cwe_id: Some("CWE-502"),
            owasp: Some("A08:2021-Software and Data Integrity Failures"),
            languages: &[Language::JavaScript, Language::TypeScript, Language::Python],
            pattern: r"(?:eval|Function)\s*\(.*(?:req|input|user|body|param)|pickle\.loads?\s*\(|yaml\.(?:load|unsafe_load)\s*\(",
            fix_suggestion: "避免 eval/pickle 处理不可信数据；使用 JSON.parse 或 yaml.safe_load",
            fix_example: Some("import yaml\ndata = yaml.safe_load(user_input)  # 安全的 YAML 解析"),
        },

        // SSRF
        Rule {
            id: "SEC-070",
            title: "服务端请求伪造 (SSRF) 风险",
            description: "检测到用户可控的 URL 被用于服务端请求",
            severity: Severity::High,
            cwe_id: Some("CWE-918"),
            owasp: Some("A10:2021-Server-Side Request Forgery"),
            languages: &[Language::JavaScript, Language::TypeScript, Language::Python],
            pattern: r"(?:fetch|axios|request|urllib|requests\.get|requests\.post|http\.get)\s*\(.*(?:req\.|params\.|query\.|body\.|user)",
            fix_suggestion: "验证并白名单过滤用户提供的 URL，禁止访问内网地址",
            fix_example: Some("const url = new URL(userInput);\nif (!ALLOWED_HOSTS.includes(url.hostname)) throw new Error('不允许的主机');"),
        },

        // JWT Issues
        Rule {
            id: "SEC-080",
            title: "JWT 安全配置问题",
            description: "检测到 JWT 使用 none 算法或弱密钥",
            severity: Severity::High,
            cwe_id: Some("CWE-347"),
            owasp: Some("A07:2021-Identification and Authentication Failures"),
            languages: &[Language::JavaScript, Language::TypeScript, Language::Python],
            pattern: r#"(?i)(?:algorithm|algorithms)\s*[:=]\s*\[?\s*["']none["']|jwt\.(?:sign|verify|encode|decode)\s*\(.*(?:["']secret["']|["']password["'])"#,
            fix_suggestion: "使用 RS256 或 ES256 算法，密钥从环境变量读取且足够长",
            fix_example: Some("jwt.verify(token, process.env.JWT_PUBLIC_KEY, { algorithms: ['RS256'] })"),
        },

        // CORS Misconfiguration
        Rule {
            id: "SEC-090",
            title: "CORS 配置不安全",
            description: "检测到 CORS 允许任意来源或反射 Origin 头",
            severity: Severity::Medium,
            cwe_id: Some("CWE-942"),
            owasp: Some("A05:2021-Security Misconfiguration"),
            languages: &[Language::JavaScript, Language::TypeScript, Language::Python, Language::Go],
            pattern: r#"(?i)(?:Access-Control-Allow-Origin|cors)\s*[:=]\s*["']\*["']|origin\s*:\s*true"#,
            fix_suggestion: "设置明确的 CORS 允许域名白名单，不要使用通配符 *",
            fix_example: Some("app.use(cors({ origin: ['https://your-domain.com'] }))"),
        },

        // Prototype Pollution
        Rule {
            id: "SEC-100",
            title: "原型链污染风险",
            description: "检测到不安全的对象合并操作，可能导致原型链污染",
            severity: Severity::High,
            cwe_id: Some("CWE-1321"),
            owasp: Some("A03:2021-Injection"),
            languages: &[Language::JavaScript, Language::TypeScript],
            pattern: r"(?:Object\.assign|_\.merge|_\.extend|_\.defaults|\.prototype\[)",
            fix_suggestion: "使用 Object.create(null) 创建无原型对象，或验证键名不含 __proto__",
            fix_example: Some("const safe = Object.create(null);\nfor (const [k, v] of Object.entries(input)) {\n  if (k !== '__proto__' && k !== 'constructor') safe[k] = v;\n}"),
        },

        // Insecure Random
        Rule {
            id: "SEC-110",
            title: "不安全的随机数生成",
            description: "在安全场景中使用 Math.random 或 random 模块的非加密随机数",
            severity: Severity::Medium,
            cwe_id: Some("CWE-330"),
            owasp: Some("A02:2021-Cryptographic Failures"),
            languages: &[Language::JavaScript, Language::TypeScript, Language::Python],
            pattern: r"(?i)(?:Math\.random|random\.random|random\.randint)\s*\(\s*\).*(?:token|secret|key|password|session|nonce|salt)",
            fix_suggestion: "使用 crypto.randomBytes/crypto.randomUUID (Node) 或 secrets 模块 (Python)",
            fix_example: Some("const token = crypto.randomUUID(); // 安全的随机 token"),
        },

        // NoSQL Injection
        Rule {
            id: "SEC-120",
            title: "NoSQL 注入风险",
            description: "检测到 MongoDB 查询中直接使用用户输入，可能导致 NoSQL 注入",
            severity: Severity::High,
            cwe_id: Some("CWE-943"),
            owasp: Some("A03:2021-Injection"),
            languages: &[Language::JavaScript, Language::TypeScript],
            pattern: r"\.find\s*\(\s*\{.*(?:req\.body|req\.query|req\.params)|\.aggregate\s*\(\s*\[.*\$where",
            fix_suggestion: "验证并净化用户输入类型，使用 mongoose 的 schema 验证",
            fix_example: Some("const id = String(req.params.id); // 强制类型转换\ndb.collection.find({ _id: id })"),
        },

        // ──────────── V1.1 Extended Rules ────────────

        // Open Redirect
        Rule {
            id: "SEC-130",
            title: "开放重定向漏洞",
            description: "用户可控的 URL 被用于 HTTP 重定向，可能导致钓鱼攻击",
            severity: Severity::Medium,
            cwe_id: Some("CWE-601"),
            owasp: Some("A01:2021-Broken Access Control"),
            languages: &[Language::JavaScript, Language::TypeScript, Language::Python],
            pattern: r"(?:redirect|res\.redirect|redirect_to|return redirect)\s*\(.*(?:req\.|params\.|query\.|body\.|user|url)",
            fix_suggestion: "验证重定向目标是否在白名单域名内，禁止跳转到外部 URL",
            fix_example: Some("const url = new URL(target, 'https://your-domain.com');\nif (url.origin !== 'https://your-domain.com') throw new Error('禁止外部重定向');"),
        },

        // Information Exposure via Error Message
        Rule {
            id: "SEC-140",
            title: "错误信息泄露敏感数据",
            description: "堆栈跟踪或详细错误信息可能泄露给终端用户",
            severity: Severity::Medium,
            cwe_id: Some("CWE-209"),
            owasp: Some("A05:2021-Security Misconfiguration"),
            languages: &[Language::JavaScript, Language::TypeScript, Language::Python],
            pattern: r"(?:res\.(?:send|json|status)\s*\(.*(?:err\.stack|error\.stack|traceback)|(?:\.send|\.json)\s*\(\s*(?:err|error)\s*\))",
            fix_suggestion: "只返回通用错误信息给用户，详细错误记录到服务端日志",
            fix_example: Some("res.status(500).json({ error: 'Internal server error' });\nlogger.error(err.stack); // 服务端日志"),
        },

        // Unsafe Regex (ReDoS)
        Rule {
            id: "SEC-150",
            title: "正则表达式拒绝服务 (ReDoS)",
            description: "检测到可能导致灾难性回溯的正则表达式模式",
            severity: Severity::Medium,
            cwe_id: Some("CWE-1333"),
            owasp: Some("A05:2021-Security Misconfiguration"),
            languages: &[Language::JavaScript, Language::TypeScript, Language::Python],
            pattern: r"(?:new RegExp|re\.compile)\s*\(.*(?:\.\*\.\*|\.\+\.\+|\(\.\*\)\+|\(\.\+\)\*)",
            fix_suggestion: "避免嵌套量词，使用原子组或占有量词，设置超时限制",
            fix_example: Some("// 避免: /(.+)+/\n// 改用: /[^\\s]+/ 或设置匹配超时"),
        },

        // Missing Rate Limiting
        Rule {
            id: "SEC-160",
            title: "缺少速率限制的敏感端点",
            description: "登录/注册/密码重置等敏感端点未检测到速率限制中间件",
            severity: Severity::Medium,
            cwe_id: Some("CWE-307"),
            owasp: Some("A07:2021-Identification and Authentication Failures"),
            languages: &[Language::JavaScript, Language::TypeScript],
            pattern: r#"(?:app|router)\.\s*(?:post|put)\s*\(\s*["'](?:/login|/signin|/register|/signup|/reset|/forgot)["']"#,
            fix_suggestion: "为敏感端点添加速率限制中间件（如 express-rate-limit）",
            fix_example: Some("const limiter = rateLimit({ windowMs: 15*60*1000, max: 5 });\napp.post('/login', limiter, loginHandler);"),
        },

        // Cleartext Storage of Password
        Rule {
            id: "SEC-170",
            title: "明文存储密码",
            description: "检测到密码可能以明文形式存储或传输",
            severity: Severity::Critical,
            cwe_id: Some("CWE-312"),
            owasp: Some("A02:2021-Cryptographic Failures"),
            languages: &[Language::JavaScript, Language::TypeScript, Language::Python],
            pattern: r#"(?i)(?:password|passwd)\s*[:=]\s*(?:req\.body|request\.|input|params)\[?[."']"#,
            fix_suggestion: "使用 bcrypt/scrypt/argon2 哈希存储密码，永远不要明文存储",
            fix_example: Some("const hash = await bcrypt.hash(password, 12);\nawait db.users.update({ password: hash });"),
        },

        // Missing HTTP Security Headers
        Rule {
            id: "SEC-180",
            title: "HTTP 安全头缺失",
            description: "检测到显式禁用安全头或缺少 helmet 等安全中间件配置",
            severity: Severity::Low,
            cwe_id: Some("CWE-693"),
            owasp: Some("A05:2021-Security Misconfiguration"),
            languages: &[Language::JavaScript, Language::TypeScript],
            pattern: r#"(?:X-Frame-Options|Content-Security-Policy|X-Content-Type-Options)\s*[:=]\s*["'](?:ALLOWALL|disabled|none)["']|helmet\s*\(\s*\{.*(?:false|disabled)"#,
            fix_suggestion: "使用 helmet 中间件设置安全头：X-Frame-Options, CSP, HSTS 等",
            fix_example: Some("app.use(helmet()); // 一行代码设置所有安全头"),
        },

        // Insecure Cookie Configuration
        Rule {
            id: "SEC-190",
            title: "Cookie 安全配置不当",
            description: "Cookie 未设置 HttpOnly/Secure/SameSite 标志",
            severity: Severity::Medium,
            cwe_id: Some("CWE-614"),
            owasp: Some("A05:2021-Security Misconfiguration"),
            languages: &[Language::JavaScript, Language::TypeScript],
            pattern: r#"(?:cookie|session)\s*\(\s*\{(?:(?!httpOnly|secure|sameSite).)*\}|(?:httpOnly|secure)\s*:\s*false"#,
            fix_suggestion: "设置 cookie 的 httpOnly, secure, sameSite 属性",
            fix_example: Some("res.cookie('session', token, {\n  httpOnly: true,\n  secure: true,\n  sameSite: 'strict'\n});"),
        },

        // XML External Entity (XXE)
        Rule {
            id: "SEC-200",
            title: "XML 外部实体注入 (XXE)",
            description: "XML 解析器未禁用外部实体，可能导致文件泄露或 SSRF",
            severity: Severity::High,
            cwe_id: Some("CWE-611"),
            owasp: Some("A05:2021-Security Misconfiguration"),
            languages: &[Language::JavaScript, Language::TypeScript, Language::Python, Language::Java],
            pattern: r"(?:parseXML|xml2js|etree\.parse|DocumentBuilder|SAXParser|XMLReader).*(?:external|resolve|dtd|entity)",
            fix_suggestion: "禁用 XML 解析器的外部实体和 DTD 处理",
            fix_example: Some("// Node.js: xml2js 默认安全\n// Python: etree.parse(source, parser=etree.XMLParser(resolve_entities=False))"),
        },

        // Log Injection
        Rule {
            id: "SEC-210",
            title: "日志注入风险",
            description: "用户输入直接写入日志，可能导致日志伪造或注入攻击",
            severity: Severity::Low,
            cwe_id: Some("CWE-117"),
            owasp: Some("A09:2021-Security Logging and Monitoring Failures"),
            languages: &[Language::JavaScript, Language::TypeScript, Language::Python],
            pattern: r"(?:console\.log|logger\.info|logger\.warn|logger\.error|logging\.info)\s*\(.*(?:req\.body|req\.query|req\.params|request\.|user_input)",
            fix_suggestion: "对用户输入进行净化后再写入日志，过滤换行符和控制字符",
            fix_example: Some("const safeInput = userInput.replace(/[\\r\\n]/g, '');\nlogger.info(`User action: ${safeInput}`);"),
        },

        // Go: SQL Injection
        Rule {
            id: "SEC-300",
            title: "SQL 注入风险 (Go)",
            description: "Go 代码中检测到字符串拼接构造 SQL 查询",
            severity: Severity::Critical,
            cwe_id: Some("CWE-89"),
            owasp: Some("A03:2021-Injection"),
            languages: &[Language::Go],
            pattern: r#"(?:db\.(?:Query|Exec|QueryRow)|\.(?:Query|Exec))\s*\(\s*(?:fmt\.Sprintf|.*\+)"#,
            fix_suggestion: "使用参数化查询：db.Query(\"SELECT * FROM users WHERE id = $1\", id)",
            fix_example: Some("rows, err := db.Query(\"SELECT * FROM users WHERE id = $1\", userID)"),
        },

        // Go: Command Injection
        Rule {
            id: "SEC-301",
            title: "命令注入风险 (Go)",
            description: "Go 代码中检测到 exec.Command 使用用户输入",
            severity: Severity::Critical,
            cwe_id: Some("CWE-78"),
            owasp: Some("A03:2021-Injection"),
            languages: &[Language::Go],
            pattern: r"exec\.Command\s*\(.*(?:r\.FormValue|r\.URL\.Query|c\.Param|c\.Query|input|userInput)",
            fix_suggestion: "验证用户输入，使用白名单，避免将用户输入作为命令参数",
            fix_example: Some("cmd := exec.Command(\"ls\", \"-la\", filepath.Clean(safeDir))"),
        },

        // Java: SQL Injection
        Rule {
            id: "SEC-400",
            title: "SQL 注入风险 (Java)",
            description: "Java 代码中检测到字符串拼接构造 SQL 查询",
            severity: Severity::Critical,
            cwe_id: Some("CWE-89"),
            owasp: Some("A03:2021-Injection"),
            languages: &[Language::Java],
            pattern: r#"(?:createQuery|createNativeQuery|executeQuery|prepareStatement)\s*\(\s*["'].*\s*\+|Statement\s+.*=.*createStatement"#,
            fix_suggestion: "使用 PreparedStatement 参数化查询",
            fix_example: Some("PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\nps.setInt(1, userId);"),
        },

        // Java: Insecure Deserialization
        Rule {
            id: "SEC-401",
            title: "不安全的反序列化 (Java)",
            description: "Java ObjectInputStream 反序列化不可信数据可能导致 RCE",
            severity: Severity::Critical,
            cwe_id: Some("CWE-502"),
            owasp: Some("A08:2021-Software and Data Integrity Failures"),
            languages: &[Language::Java],
            pattern: r"ObjectInputStream|readObject\s*\(\s*\)|XMLDecoder|XStream\.fromXML",
            fix_suggestion: "使用安全的序列化格式（JSON），或配置反序列化白名单",
            fix_example: Some("// 使用 JSON 替代 Java 序列化\nObjectMapper mapper = new ObjectMapper();\nUser user = mapper.readValue(jsonStr, User.class);"),
        },
    ]
}

pub fn compile_rule(rule: &Rule) -> Option<Regex> {
    Regex::new(rule.pattern).ok()
}
