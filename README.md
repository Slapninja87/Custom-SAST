# 🛡️ Custom SAST Engine v2.0

A lightweight, zero-dependency Static Application Security Testing (SAST) scanner built in Node.js. Scans JavaScript and TypeScript codebases line-by-line using a prioritized regex rule registry, generates color-coded terminal output, produces JSON and HTML reports, and returns CI/CD-compatible exit codes to block insecure builds automatically.

---

## ⚙️ How It Works

The engine recursively walks a target directory, filters to supported file types, strips comments to eliminate false positives on commented-out code, and tests each line against 20 security rules. Results are sorted by severity and written to a JSON artifact and an HTML dashboard.

**Key design decisions:**
- **Comment stripping** — lines starting with `//` are stripped before rule matching to prevent false positives on commented-out code
- **File type routing** — certain rules only fire on relevant file types (e.g. `dangerouslySetInnerHTML` only on `.jsx`/`.tsx`, secret rules on `.env` files)
- **Stateless regex** — each rule creates a fresh `RegExp` instance per line to avoid JavaScript's stateful regex lastIndex bug
- **Inline suppression** — individual findings can be silenced per line without disabling the rule globally

---

## 🔍 Security Rules

| Rule ID   | Vulnerability                              | Severity | File Scope    |
| :-------- | :----------------------------------------- | :------- | :------------ |
| SAST-001  | Hardcoded Cryptographic Secret / Token     | CRITICAL | All           |
| SAST-001B | Hardcoded Secret in .env File              | HIGH     | `.env` only   |
| SAST-002  | SQL Injection via String Interpolation     | HIGH     | All           |
| SAST-003  | Dangerous Dynamic Code Execution (eval)    | HIGH     | All           |
| SAST-005  | Path Traversal via User Input              | HIGH     | All           |
| SAST-006  | NoSQL Injection Pattern                    | HIGH     | All           |
| SAST-007  | Command Injection via Shell String         | HIGH     | All           |
| SAST-008  | React dangerouslySetInnerHTML (XSS)        | HIGH     | `.jsx`/`.tsx` |
| SAST-009  | Reflected XSS via Response Write           | HIGH     | All           |
| SAST-010  | Prototype Pollution Vector                 | MEDIUM   | All           |
| SAST-011  | Weak Cryptographic Primitive (MD5 / SHA-1) | MEDIUM   | All           |
| SAST-012  | Insecure Random Number Generation          | MEDIUM   | All           |
| SAST-013  | JWT Algorithm Confusion (alg: none)        | HIGH     | All           |
| SAST-014  | Insecure HTTP (Non-TLS) External Call      | MEDIUM   | All           |
| SAST-015  | Insecure Cookie Configuration              | MEDIUM   | All           |
| SAST-016  | CORS Wildcard Origin                       | MEDIUM   | All           |
| SAST-018  | Sensitive Data in console.log              | LOW      | All           |
| SAST-019  | Verbose Error Disclosure to Client         | LOW      | All           |
| SAST-020  | Unsafe Deserialization of User Input       | MEDIUM   | All           |

---

## 📂 Project Structure

```
custom-sast/
│
├── target_app/
│   └── index.js          # Deliberately vulnerable test fixture (fake credentials)
│
├── sast-scanner.js       # Core engine — rules, file walker, report generator
├── package.json
├── .gitignore
└── README.md
```

---

## 🚀 Setup & Usage

**Requirements:** Node.js 16+ (no npm install needed — uses built-in modules only)

**Basic scan:**
```bash
node sast-scanner.js ./target_app
```

**Scan a different directory:**
```bash
node sast-scanner.js ./src
```

**Skip HTML report (JSON only):**
```bash
node sast-scanner.js ./src --no-html
```

**Custom report filename:**
```bash
node sast-scanner.js ./src --output my-scan-2024
```

**Via npm script:**
```bash
npm run scan
```

---

## 🔕 Inline Suppression

To suppress a specific rule on a single line without disabling it globally, add a `sast-ignore` comment:

```js
const apiKey = process.env.API_KEY || 'fallback_test_key'; // sast-ignore SAST-001
```

Multiple rules can be suppressed on the same line:
```js
const query = `SELECT * FROM logs WHERE id = ${id}`; // sast-ignore SAST-001, SAST-002
```

---

## 📊 Output

**Terminal** — color-coded findings sorted by severity with a summary breakdown table:

```
[CRITICAL] src/config.js:12
   Rule:    Hardcoded Cryptographic Secret / Token (SAST-001)
   Snippet: const apiKey = 'AIzaSyA1_unprotected_cloud_key';
   Fix:     Plain-text credential found in source. Rotate immediately...

┌──────────┬──────────────────────────────┐
│ CRITICAL │  2  ██                       │
│ HIGH     │  2  ██                       │
│ MEDIUM   │  1  █                        │
│ LOW      │  0                           │
└──────────┴──────────────────────────────┘
```

**`sast-report.json`** — machine-readable findings array for integration with dashboards, ticketing systems, or custom tooling.

**`sast-report.html`** — dark-themed browser dashboard with severity cards, sortable findings table, and remediation guidance. Open directly in any browser.

---

## 🔄 CI/CD Integration

The scanner exits with code `1` if any `CRITICAL` or `HIGH` findings are detected, breaking the pipeline automatically.

**GitHub Actions example:**
```yaml
name: SAST Security Scan

on: [push, pull_request]

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - name: Run SAST scan
        run: node sast-scanner.js ./src --no-html
```

**GitLab CI example:**
```yaml
sast-scan:
  image: node:20-alpine
  script:
    - node sast-scanner.js ./src --no-html
  artifacts:
    paths:
      - sast-report.json
    when: always
```

---

## ⚠️ Known Limitations

**Regex vs AST** — This engine uses line-by-line regex matching. A motivated developer can bypass it by splitting strings across multiple variables or lines:

```js
const chunk1 = "SELE";
const chunk2 = "CT * FROM users WHERE id = ";
const query  = chunk1 + chunk2 + userInputId; // missed by regex
```

For production-grade taint analysis, the engine would need to parse code into an Abstract Syntax Tree (AST) using a parser like [acorn](https://github.com/acornjs/acorn) or [esprima](https://esprima.org/) and track untrusted data from source to sink. This is the planned next evolution of the engine.

**Supported languages** — currently scans `.js`, `.jsx`, `.ts`, `.tsx`, `.json`, `.env`. Python, Go, and other languages are not yet supported.

---

## 🗺️ Roadmap

- [ ] AST-based taint analysis via acorn
- [ ] Python rule set
- [ ] SARIF report output for GitHub Code Scanning integration
- [ ] Custom rule config file (`sast.config.json`)
- [ ] Severity threshold flag (`--fail-on MEDIUM`)
