// Tauri v2 exposes APIs under window.__TAURI__ when `withGlobalTauri` is true.
const TAURI = window.__TAURI__ || null;
const invoke = TAURI?.core?.invoke ?? null;
const tauriEvent = TAURI?.event ?? null;

let scanResult = null;
let currentPath = null;
let currentFilter = 'all';

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

document.addEventListener('DOMContentLoaded', () => {
  const dropzone = $('#dropzone');
  const scanBtn = $('#scanBtn');
  const clearPathBtn = $('#clearPath');

  dropzone.addEventListener('click', openFolder);

  // HTML5 dragover feedback (browser preview only — real drops handled by Tauri events).
  dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.classList.add('dragover');
  });
  dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
  });

  // Native Tauri drag & drop (returns real filesystem paths).
  if (tauriEvent?.listen) {
    tauriEvent.listen('tauri://drag-enter', () => dropzone.classList.add('dragover'));
    tauriEvent.listen('tauri://drag-leave', () => dropzone.classList.remove('dragover'));
    tauriEvent.listen('tauri://drag-drop', (e) => {
      dropzone.classList.remove('dragover');
      const paths = e?.payload?.paths || [];
      if (paths.length) setPath(paths[0]);
    });
  }

  clearPathBtn.addEventListener('click', () => setPath(null));
  scanBtn.addEventListener('click', startScan);

  $$('.filter-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      $$('.filter-btn').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      currentFilter = btn.dataset.severity;
      renderFindings();
    });
  });

  $('#exportJson').addEventListener('click', () => exportReport('json'));
  $('#exportHtml').addEventListener('click', () => exportReport('html'));
});

async function openFolder() {
  if (invoke) {
    try {
      const path = await invoke('select_folder');
      if (path) setPath(path);
    } catch (err) {
      console.error('select_folder failed', err);
    }
  } else {
    // Browser preview fallback.
    setPath('/demo/project');
  }
}

function setPath(path) {
  currentPath = path;
  if (path) {
    $('#selectedPath').style.display = 'flex';
    $('#pathText').textContent = path;
    $('#dropzone').style.display = 'none';
    $('#scanBtn').disabled = false;
  } else {
    $('#selectedPath').style.display = 'none';
    $('#dropzone').style.display = 'flex';
    $('#scanBtn').disabled = true;
    scanResult = null;
    $('#summaryPanel').style.display = 'none';
    showView('welcome');
  }
}

async function startScan() {
  if (!currentPath) return;
  const minSeverity = $('#minSeverity').value;

  showView('scanning');
  $('#scanBtn').disabled = true;

  try {
    if (invoke) {
      scanResult = await invoke('scan_project', { path: currentPath, minSeverity });
    } else {
      await new Promise((r) => setTimeout(r, 800));
      scanResult = generateDemoData();
    }
    updateSummary();
    renderFindings();
    showView('results');
    $('#summaryPanel').style.display = 'block';
  } catch (err) {
    toast('Scan failed: ' + err, 'error');
    showView('welcome');
  }
  $('#scanBtn').disabled = false;
}

function showView(view) {
  ['welcome', 'scanning', 'results'].forEach((v) => {
    $(`#${v}`).style.display = v === view ? '' : 'none';
  });
}

function updateSummary() {
  if (!scanResult) return;
  const s = countSeverities();
  $('#critCount').textContent = s.CRITICAL;
  $('#highCount').textContent = s.HIGH;
  $('#medCount').textContent = s.MEDIUM;
  $('#lowCount').textContent = s.LOW;
  $('#fileCount').textContent = scanResult.scanned_files;
  $('#scanTime').textContent = scanResult.scan_duration_ms;
}

function countSeverities() {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  if (!scanResult) return counts;
  for (const f of scanResult.findings) {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
  }
  return counts;
}

function renderFindings() {
  const list = $('#findingsList');
  if (!scanResult || !scanResult.findings.length) {
    list.innerHTML = '<div class="welcome" style="height:auto;padding:3rem 0"><h3>No issues found!</h3></div>';
    return;
  }

  let findings = [...scanResult.findings];
  if (currentFilter !== 'all') {
    findings = findings.filter((f) => f.severity === currentFilter);
  }

  const sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  findings.sort((a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9));

  if (!findings.length) {
    list.innerHTML = '<div class="welcome" style="height:auto;padding:3rem 0"><h3>No findings for this filter</h3></div>';
    return;
  }

  list.innerHTML = findings
    .map(
      (f) => `
    <div class="finding-card sev-${f.severity}" onclick="toggleFinding(this)">
      <div class="fc-header">
        <span class="badge badge-${f.severity}">${f.severity}</span>
        <span class="fc-title">${esc(f.title)}</span>
        <span class="fc-rule">${esc(f.rule_id)}</span>
      </div>
      <div class="fc-location">${esc(f.file)}:${f.line}</div>
      <div class="fc-detail">
        ${
          f.cwe_id || f.owasp_category
            ? `<div class="meta-tags">${f.cwe_id ? `<span>${esc(f.cwe_id)}</span>` : ''}${f.owasp_category ? `<span>${esc(f.owasp_category)}</span>` : ''}</div>`
            : ''
        }
        ${f.code_snippet ? `<pre>${esc(f.code_snippet)}</pre>` : ''}
        <div class="fix-box">
          <h4>Fix Suggestion</h4>
          <p>${esc(f.fix_suggestion)}</p>
          ${f.fix_code ? `<pre>${esc(f.fix_code)}</pre>` : ''}
        </div>
      </div>
    </div>`
    )
    .join('');
}

function toggleFinding(el) {
  el.classList.toggle('expanded');
}

function esc(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

async function exportReport(format) {
  if (!scanResult) return;
  if (invoke) {
    try {
      const saved = await invoke('export_report', { path: currentPath, format });
      if (saved) toast(`Report saved: ${saved}`, 'success');
    } catch (err) {
      if (String(err) !== 'cancelled') toast('Export failed: ' + err, 'error');
    }
  } else if (format === 'json') {
    const blob = new Blob([JSON.stringify(scanResult, null, 2)], { type: 'application/json' });
    downloadBlob(blob, 'secprobe-report.json');
  } else {
    toast('HTML export requires the desktop app', 'error');
  }
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

let toastTimer = null;
function toast(msg, kind = 'info') {
  let el = $('#toast');
  if (!el) {
    el = document.createElement('div');
    el.id = 'toast';
    document.body.appendChild(el);
  }
  el.textContent = msg;
  el.className = `toast toast-${kind} show`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 3200);
}

function generateDemoData() {
  return {
    project_path: '/demo/project',
    total_files: 42,
    scanned_files: 38,
    scan_duration_ms: 23,
    languages: [['TypeScript', 30], ['Python', 8]],
    findings: [
      {
        rule_id: 'SEC-001', title: 'SQL Injection', description: 'SQL injection via string concatenation',
        severity: 'CRITICAL', file: 'src/api/users.ts', line: 45,
        code_snippet: '  43 | const id = req.params.id;\n  44 | // vulnerable query\n> 45 | db.query(`SELECT * FROM users WHERE id = ${id}`);',
        cwe_id: 'CWE-89', owasp_category: 'A03:2021-Injection',
        fix_suggestion: 'Use parameterized queries', fix_code: "db.query('SELECT * FROM users WHERE id = $1', [id])"
      },
      {
        rule_id: 'SEC-040', title: 'Hardcoded Secret', description: 'API key hardcoded in source',
        severity: 'HIGH', file: 'src/config.ts', line: 12,
        code_snippet: '  11 | export const config = {\n> 12 |   apiKey: "sk-1234567890abcdef",\n  13 |   endpoint: "https://api.example.com"',
        cwe_id: 'CWE-798', owasp_category: 'A07:2021',
        fix_suggestion: 'Use environment variables', fix_code: 'const apiKey = process.env.API_KEY;'
      },
      {
        rule_id: 'SEC-050', title: 'Weak Crypto', description: 'MD5 used for hashing',
        severity: 'MEDIUM', file: 'src/auth.py', line: 23,
        code_snippet: '  22 |     import hashlib\n> 23 |     return hashlib.md5(pw.encode()).hexdigest()',
        cwe_id: 'CWE-327', owasp_category: 'A02:2021',
        fix_suggestion: 'Use bcrypt or argon2', fix_code: "import bcrypt\nhash = bcrypt.hashpw(pw.encode(), bcrypt.gensalt())"
      }
    ]
  };
}
