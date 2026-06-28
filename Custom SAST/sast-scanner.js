// sast-scanner.js — Enhanced Custom SAST Engine v2.0
// Usage: node sast-scanner.js <target_dir> [--no-html] [--output <report_name>]
//
// Inline suppression: add  // sast-ignore SAST-001  to any line to skip that rule.

'use strict';

const fs   = require('fs');
const path = require('path');

// ── Rule Registry ─────────────────────────────────────────────────────────────
// fileTypes: restrict rule to these extensions (omit = all supported types)

const SECURITY_RULES = [

    // ── Secrets & Credentials ─────────────────────────────────────────────────
    {
        id: 'SAST-001',
        name: 'Hardcoded Cryptographic Secret / Token',
        severity: 'CRITICAL',
        regex: /(password|secret|api_?key|jwt_?secret|private_?key|auth_?token|access_?token|client_?secret)\s*[=:]\s*['"`][a-zA-Z0-9_\-\.\/+=]{8,}['"`]/i,
        description: 'Plain-text credential found in source. Rotate immediately and store in environment variables or a secrets vault (HashiCorp Vault, AWS Secrets Manager).',
    },
    {
        id: 'SAST-001B',
        name: 'Hardcoded Secret in .env File',
        severity: 'HIGH',
        regex: /^(PASSWORD|SECRET|API_KEY|JWT_SECRET|PRIVATE_KEY|AUTH_TOKEN|ACCESS_TOKEN|CLIENT_SECRET)\s*=\s*.{8,}/i,
        description: '.env secret committed to version control. Ensure .env is in .gitignore and use CI/CD secret injection instead.',
        fileTypes: ['.env'],
    },

    // ── Injection ─────────────────────────────────────────────────────────────
    {
        id: 'SAST-002',
        name: 'SQL Injection via String Interpolation',
        severity: 'HIGH',
        regex: /(select|insert|update|delete|drop|where|from|join)\s.*\$\{.+?\}/i,
        description: 'Raw string interpolation in SQL query. Use parameterized queries or an ORM (Knex, Sequelize, Prisma).',
    },
    {
        id: 'SAST-003',
        name: 'Dangerous Dynamic Code Execution',
        severity: 'HIGH',
        regex: /\beval\s*\(|\bFunction\s*\(\s*['"`]|\bchild_process\.(exec|execSync)\s*\(/,
        description: 'Dynamic code evaluation risks Remote Code Execution. Replace eval() with safe alternatives; use execFile() with an explicit allowlist.',
    },
    {
        id: 'SAST-005',
        name: 'Path Traversal via User Input',
        severity: 'HIGH',
        regex: /(readFile|writeFile|readdir|unlink|createReadStream|createWriteStream)\s*\([^)]*\$\{/,
        description: 'File system call with dynamic path. Validate and resolve all user-supplied paths and confirm they stay within an allowed base directory.',
    },
    {
        id: 'SAST-006',
        name: 'NoSQL Injection Pattern',
        severity: 'HIGH',
        regex: /\.(find|findOne|updateOne|deleteOne|aggregate)\s*\(\s*\{[^}]*\$\{/,
        description: 'User input directly in a NoSQL query. Validate inputs with Joi or Zod before passing to database methods.',
    },
    {
        id: 'SAST-007',
        name: 'Command Injection via Shell String',
        severity: 'HIGH',
        regex: /child_process\.(exec|execSync)\s*\([`'"].*\$\{/,
        description: 'User input interpolated into a shell command. Use execFile() or spawn() with an argument array — never shell string interpolation.',
    },

    // ── XSS ──────────────────────────────────────────────────────────────────
    {
        id: 'SAST-008',
        name: 'React dangerouslySetInnerHTML (XSS Risk)',
        severity: 'HIGH',
        regex: /dangerouslySetInnerHTML\s*=\s*\{\s*\{/,
        description: 'dangerouslySetInnerHTML bypasses React XSS protection. Sanitize content with DOMPurify before use.',
        fileTypes: ['.jsx', '.tsx'],
    },
    {
        id: 'SAST-009',
        name: 'Reflected XSS via Response Write',
        severity: 'HIGH',
        regex: /res\.(send|write|end)\s*\([^)]*req\.(body|query|params)/,
        description: 'Unvalidated user input reflected into HTTP response. Encode all output and validate all input server-side.',
    },
    {
        id: 'SAST-010',
        name: 'Prototype Pollution Vector',
        severity: 'MEDIUM',
        regex: /\[.*__proto__.*\]|Object\.assign\s*\(\s*\{\s*\}[^)]*req\./,
        description: 'Prototype pollution risk. Avoid merging untrusted objects directly. Use Object.create(null) for lookup maps.',
    },

    // ── Cryptography ──────────────────────────────────────────────────────────
    {
        id: 'SAST-011',
        name: 'Weak Cryptographic Primitive (MD5 / SHA-1)',
        severity: 'MEDIUM',
        regex: /createHash\s*\(\s*['"`](md5|sha1)['"`]\)/i,
        description: 'MD5 and SHA-1 are cryptographically broken. Use SHA-256 for integrity or bcrypt/argon2 for password hashing.',
    },
    {
        id: 'SAST-012',
        name: 'Insecure Random Number Generation',
        severity: 'MEDIUM',
        regex: /Math\.random\s*\(\s*\)/,
        description: 'Math.random() is not cryptographically secure. Use crypto.randomBytes() or crypto.randomUUID() for tokens, session IDs, and nonces.',
    },
    {
        id: 'SAST-013',
        name: 'JWT Algorithm Confusion (alg: none)',
        severity: 'HIGH',
        regex: /algorithm\s*:\s*['"`]none['"`]|algorithms\s*:\s*\[\s*['"`]none['"`]/i,
        description: 'JWT "none" algorithm disables signature verification entirely. Always enforce a strong algorithm (RS256, ES256) and reject tokens with alg: none.',
    },

    // ── Transport & Config ────────────────────────────────────────────────────
    {
        id: 'SAST-014',
        name: 'Insecure HTTP (Non-TLS) External Connection',
        severity: 'MEDIUM',
        regex: /require\s*\(\s*['"`]http['"`]\s*\)|http:\/\/(?!localhost|127\.0\.0\.1)/,
        description: 'Plaintext HTTP used for external communication. Use HTTPS for all external connections.',
    },
    {
        id: 'SAST-015',
        name: 'Insecure Cookie Configuration',
        severity: 'MEDIUM',
        regex: /res\.cookie\s*\([^)]*\)/,
        description: 'Cookie detected — verify httpOnly: true and secure: true flags are set to prevent XSS and MITM session hijacking.',
    },
    {
        id: 'SAST-016',
        name: 'CORS Wildcard Origin',
        severity: 'MEDIUM',
        regex: /origin\s*:\s*['"`]\*['"`]|Access-Control-Allow-Origin['"` ]*\*/,
        description: 'CORS wildcard allows any origin to make credentialed cross-origin requests. Restrict to an explicit allowlist in production.',
    },

    // ── Data Leakage ──────────────────────────────────────────────────────────
    {
        id: 'SAST-018',
        name: 'Sensitive Data in console.log',
        severity: 'LOW',
        regex: /console\.(log|debug|info)\s*\([^)]*?(password|token|secret|key|credential)/i,
        description: 'Potential credential logged to console. Remove sensitive debug logging and use a structured logger with log-level filtering in production.',
    },
    {
        id: 'SAST-019',
        name: 'Verbose Error Disclosure to Client',
        severity: 'LOW',
        regex: /res\.(send|json)\s*\(\s*(err|error)(\.(message|stack))?\s*\)/,
        description: 'Raw error object sent to client may expose stack traces or internal paths. Return a generic message to the client; log details server-side.',
    },

    // ── Deserialization ───────────────────────────────────────────────────────
    {
        id: 'SAST-020',
        name: 'Unsafe Deserialization of User Input',
        severity: 'MEDIUM',
        regex: /(deserialize|unserialize|fromJSON)\s*\(.*req\./,
        description: 'Deserialization of untrusted data detected. Validate and sanitize all external data before deserializing.',
    },
];

// ── Configuration ─────────────────────────────────────────────────────────────
const EXCLUDED_DIRS       = ['node_modules', '.git', 'dist', 'build', 'coverage', '.next'];
const INCLUDED_EXTENSIONS = ['.js', '.jsx', '.ts', '.tsx', '.json', '.env'];

const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

// ── Argument Parsing ──────────────────────────────────────────────────────────
const args       = process.argv.slice(2);
const targetDir  = args.find(a => !a.startsWith('--')) || '.';
const noHtml     = args.includes('--no-html');
const outIdx     = args.indexOf('--output');
const reportBase = outIdx !== -1 ? args[outIdx + 1] : 'sast-report';

// ── State ─────────────────────────────────────────────────────────────────────
let totalFilesScanned = 0;
const findings = [];

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Strip single-line comments so commented-out code doesn't fire rules. */
function stripComments(line) {
    // Remove // ... but not inside strings (simplified — handles 99% of cases)
    return line.replace(/(?<!['"`])\/\/(?![^'"]*['"`]).*$/, '').trim();
}

/** Check for an inline suppression comment: // sast-ignore SAST-001 */
function getSuppressedRules(rawLine) {
    const match = rawLine.match(/\/\/\s*sast-ignore\s+([A-Z0-9\-,\s]+)/i);
    if (!match) return new Set();
    return new Set(match[1].split(',').map(r => r.trim().toUpperCase()));
}

/** Test a rule's regex against a line without sharing state between calls. */
function testRule(rule, line) {
    const fresh = new RegExp(rule.regex.source, rule.regex.flags);
    return fresh.test(line);
}

// ── Core Engine ───────────────────────────────────────────────────────────────

function scanFile(filePath) {
    totalFilesScanned++;
    const ext     = path.extname(filePath).toLowerCase();
    const raw     = fs.readFileSync(filePath, 'utf-8');
    const lines   = raw.split(/\r?\n/);
    const relPath = path.relative(process.cwd(), filePath);

    lines.forEach((rawLine, idx) => {
        const lineNumber     = idx + 1;
        const suppressed     = getSuppressedRules(rawLine);
        const strippedLine   = stripComments(rawLine);

        if (!strippedLine) return; // blank or pure-comment line — skip

        for (const rule of SECURITY_RULES) {
            // Skip rules scoped to other file types
            if (rule.fileTypes && !rule.fileTypes.includes(ext)) continue;
            // Skip suppressed rules
            if (suppressed.has(rule.id)) continue;

            if (testRule(rule, strippedLine)) {
                findings.push({
                    ruleId:      rule.id,
                    ruleName:    rule.name,
                    severity:    rule.severity,
                    filePath:    relPath,
                    lineNumber,
                    evidence:    rawLine.trim(),
                    description: rule.description,
                });
            }
        }
    });
}

function scanDirectory(dirPath) {
    let items;
    try {
        items = fs.readdirSync(dirPath);
    } catch {
        console.error(`  [WARN] Cannot read directory: ${dirPath}`);
        return;
    }

    for (const item of items) {
        if (EXCLUDED_DIRS.includes(item)) continue;
        const fullPath = path.join(dirPath, item);
        let stat;
        try { stat = fs.statSync(fullPath); } catch { continue; }

        if (stat.isDirectory()) {
            scanDirectory(fullPath);
        } else if (stat.isFile()) {
            if (INCLUDED_EXTENSIONS.includes(path.extname(item).toLowerCase())) {
                scanFile(fullPath);
            }
        }
    }
}

// ── Terminal Output ───────────────────────────────────────────────────────────
const C = {
    reset:    '\x1b[0m',
    bold:     '\x1b[1m',
    dim:      '\x1b[2m',
    cyan:     '\x1b[36m',
    green:    '\x1b[32m',
    yellow:   '\x1b[33m',
    red:      '\x1b[31m',
    magenta:  '\x1b[35m',
    bgRed:    '\x1b[41m\x1b[37m',
    bgYellow: '\x1b[43m\x1b[30m',
};

const SEV_COLOR = {
    CRITICAL: C.bgRed,
    HIGH:     C.red,
    MEDIUM:   C.yellow,
    LOW:      C.dim,
};

function printFinding(f) {
    const col = SEV_COLOR[f.severity] || C.reset;
    console.log(`${col}[${f.severity}]${C.reset} ${C.cyan}${f.filePath}:${f.lineNumber}${C.reset}`);
    console.log(`   ${C.bold}Rule:${C.reset}    ${f.ruleName} (${f.ruleId})`);
    console.log(`   ${C.bold}Snippet:${C.reset} ${C.dim}${f.evidence}${C.reset}`);
    console.log(`   ${C.bold}Fix:${C.reset}     ${f.description}\n`);
}

function printSummaryTable(findings) {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;

    console.log(`${C.bold}┌─────────────────────────────────────────┐${C.reset}`);
    console.log(`${C.bold}│           SEVERITY BREAKDOWN            │${C.reset}`);
    console.log(`${C.bold}├──────────┬──────────────────────────────┤${C.reset}`);
    for (const [sev, col] of [['CRITICAL', C.bgRed], ['HIGH', C.red], ['MEDIUM', C.yellow], ['LOW', C.dim]]) {
        const n     = counts[sev] || 0;
        const bar   = '█'.repeat(Math.min(n, 20));
        const label = `${col}${sev.padEnd(8)}${C.reset}`;
        console.log(`${C.bold}│${C.reset} ${label} ${C.bold}│${C.reset} ${col}${String(n).padStart(2)}${C.reset}  ${col}${bar}${C.reset}`);
    }
    console.log(`${C.bold}└──────────┴──────────────────────────────┘${C.reset}`);

    // Top offending files
    const fileCounts = {};
    for (const f of findings) fileCounts[f.filePath] = (fileCounts[f.filePath] || 0) + 1;
    const topFiles = Object.entries(fileCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);
    if (topFiles.length) {
        console.log(`\n${C.bold}Top files by finding count:${C.reset}`);
        for (const [fp, n] of topFiles) {
            console.log(`  ${C.cyan}${fp}${C.reset}  — ${n} finding(s)`);
        }
    }
}

// ── HTML Report ───────────────────────────────────────────────────────────────
function generateHtmlReport(findings, meta) {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;

    const sevColor = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#6b7280' };
    const sevBg    = { CRITICAL: '#450a0a', HIGH: '#431407', MEDIUM: '#422006', LOW: '#1c1c1c' };

    const rows = findings
        .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])
        .map(f => `
        <tr>
            <td><span class="badge" style="background:${sevBg[f.severity]};color:${sevColor[f.severity]};border:1px solid ${sevColor[f.severity]}">${f.severity}</span></td>
            <td><code class="rule-id">${f.ruleId}</code></td>
            <td>${escHtml(f.ruleName)}</td>
            <td><code class="filepath">${escHtml(f.filePath)}:${f.lineNumber}</code></td>
            <td><code class="evidence">${escHtml(f.evidence)}</code></td>
            <td class="description">${escHtml(f.description)}</td>
        </tr>`).join('');

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SAST Security Report</title>
<style>
  :root {
    --bg:      #0f1117;
    --card:    #1a1d27;
    --border:  #2d3148;
    --text:    #e2e8f0;
    --muted:   #64748b;
    --accent:  #6366f1;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; padding: 32px; }
  h1   { font-size: 1.6rem; font-weight: 700; margin-bottom: 4px; }
  .meta { color: var(--muted); font-size: 0.85rem; margin-bottom: 32px; }
  .cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }
  .card  { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 20px; }
  .card .label { font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; }
  .card .value { font-size: 2rem; font-weight: 700; margin-top: 4px; }
  .card.critical .value { color: #ef4444; }
  .card.high     .value { color: #f97316; }
  .card.medium   .value { color: #eab308; }
  .card.low      .value { color: #6b7280; }
  table { width: 100%; border-collapse: collapse; background: var(--card); border-radius: 10px; overflow: hidden; border: 1px solid var(--border); }
  th    { background: #12141f; color: var(--muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: .05em; padding: 12px 16px; text-align: left; }
  td    { padding: 12px 16px; border-bottom: 1px solid var(--border); font-size: 0.85rem; vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #1f2235; }
  .badge    { padding: 3px 10px; border-radius: 999px; font-size: 0.72rem; font-weight: 700; white-space: nowrap; }
  .rule-id  { color: var(--accent); font-size: 0.8rem; }
  .filepath { color: #38bdf8; font-size: 0.8rem; }
  .evidence { color: #f1f5f9; background: #0d0f18; padding: 3px 8px; border-radius: 4px; font-size: 0.78rem; display: block; max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .description { color: var(--muted); max-width: 260px; line-height: 1.5; }
  .footer { margin-top: 24px; color: var(--muted); font-size: 0.78rem; text-align: center; }
</style>
</head>
<body>
<h1>🛡️ SAST Security Report</h1>
<div class="meta">
  Target: <strong>${escHtml(meta.target)}</strong> &nbsp;|&nbsp;
  Scanned: <strong>${meta.filesScanned} file(s)</strong> &nbsp;|&nbsp;
  Generated: <strong>${meta.timestamp}</strong> &nbsp;|&nbsp;
  Rules: <strong>${meta.ruleCount}</strong>
</div>

<div class="cards">
  <div class="card critical"><div class="label">Critical</div><div class="value">${counts.CRITICAL}</div></div>
  <div class="card high">    <div class="label">High</div>    <div class="value">${counts.HIGH}</div></div>
  <div class="card medium">  <div class="label">Medium</div>  <div class="value">${counts.MEDIUM}</div></div>
  <div class="card low">     <div class="label">Low</div>     <div class="value">${counts.LOW}</div></div>
</div>

<table>
  <thead>
    <tr>
      <th>Severity</th><th>Rule ID</th><th>Vulnerability</th>
      <th>Location</th><th>Evidence</th><th>Remediation</th>
    </tr>
  </thead>
  <tbody>${rows || '<tr><td colspan="6" style="text-align:center;color:#4ade80;padding:32px">✅ No findings — codebase is clean</td></tr>'}</tbody>
</table>

<div class="footer">Generated by Custom SAST Engine v2.0 &nbsp;•&nbsp; ${findings.length} finding(s) across ${meta.filesScanned} file(s)</div>
</body>
</html>`;
}

function escHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

// ── Entry Point ───────────────────────────────────────────────────────────────
console.log(`${C.magenta}${C.bold}`);
console.log('╔══════════════════════════════════════════════════╗');
console.log('║      CUSTOM SAST ENGINE v2.0  —  SCANNING       ║');
console.log('╚══════════════════════════════════════════════════╝');
console.log(C.reset);
console.log(`Target : ${C.cyan}${path.resolve(targetDir)}${C.reset}`);
console.log(`Rules  : ${SECURITY_RULES.length} active\n`);

console.time('Scan duration');
scanDirectory(targetDir);
console.timeEnd('Scan duration');
console.log('');

// Print findings grouped by severity
const sorted = [...findings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
if (sorted.length === 0) {
    console.log(`${C.green}${C.bold}✅  No findings — codebase is clean.${C.reset}\n`);
} else {
    sorted.forEach(printFinding);
}

printSummaryTable(findings);

// ── Reports ───────────────────────────────────────────────────────────────────
const scannerDir = path.dirname(path.resolve(process.argv[1]));
const meta = {
    target:       path.resolve(targetDir),
    filesScanned: totalFilesScanned,
    timestamp:    new Date().toISOString(),
    ruleCount:    SECURITY_RULES.length,
};

const jsonPath = path.join(scannerDir, `${reportBase}.json`);
fs.writeFileSync(jsonPath, JSON.stringify({ meta, findings: sorted }, null, 2));
console.log(`\n${C.green}JSON report  →${C.reset} ${jsonPath}`);

if (!noHtml) {
    const htmlPath = path.join(scannerDir, `${reportBase}.html`);
    fs.writeFileSync(htmlPath, generateHtmlReport(sorted, meta));
    console.log(`${C.green}HTML report  →${C.reset} ${htmlPath}`);
}

// ── Final Status ──────────────────────────────────────────────────────────────
console.log(`\n${C.bold}Files scanned    :${C.reset} ${totalFilesScanned}`);
console.log(`${C.bold}Findings flagged :${C.reset} ${findings.length}`);

const hasBlocker = findings.some(f => f.severity === 'CRITICAL' || f.severity === 'HIGH');
if (hasBlocker) {
    console.log(`\n${C.bgRed}${C.bold} FAILED — Risk threshold breached. Security gate engaged. ${C.reset}`);
    process.exit(1);
} else {
    console.log(`\n${C.green}${C.bold} PASSED — No critical or high-severity findings. ${C.reset}`);
    process.exit(0);
}