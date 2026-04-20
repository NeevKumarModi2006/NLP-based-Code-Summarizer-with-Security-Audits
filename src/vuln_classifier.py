"""
Vulnerability Classification & Formatting Utilities
=====================================================
Shared by main_big.py and main_folder.py.

Provides:
  - CWE-to-category mapping (regex + keyword fallback)
  - Cached file-line extraction for snippets
  - Severity normalization (ERROR → HIGH, etc.)
  - Stronger deduplication logic
  - Formatted vulnerability table builder
"""

import re
import threading
from collections import Counter

# ──────────────────────────────────────────────────────────────────────────────
# CWE → Human-Readable Category
# ──────────────────────────────────────────────────────────────────────────────

CWE_CATEGORY_MAP = {
    'CWE-89':   'SQL Injection',
    'CWE-78':   'Command Injection',
    'CWE-94':   'Code Injection',
    'CWE-502':  'Deserialization',
    'CWE-79':   'XSS',
    'CWE-327':  'Weak Cryptography',
    'CWE-338':  'Weak PRNG',
    'CWE-336':  'Predictable Seed',
    'CWE-337':  'Predictable Seed',
    'CWE-798':  'Hardcoded Secrets',
    'CWE-259':  'Hardcoded Secrets',
    'CWE-321':  'Hardcoded Secrets',
    'CWE-22':   'Path Traversal',
    'CWE-918':  'SSRF',
    'CWE-611':  'XXE',
    'CWE-120':  'Buffer Overflow',
    'CWE-134':  'Format String',
    'CWE-190':  'Integer Overflow',
    'CWE-770':  'Resource Exhaustion',
    'CWE-295':  'TLS/SSL Bypass',
    'CWE-347':  'JWT Weakness',
    'CWE-352':  'CSRF',
    'CWE-601':  'Open Redirect',
    'CWE-377':  'Race Condition',
    'CWE-330':  'Thread Safety',
    'CWE-532':  'Info Exposure (Logs)',
    'CWE-209':  'Info Exposure (Logs)',
    'CWE-90':   'LDAP Injection',
    'CWE-643':  'XPath Injection',
    'CWE-943':  'NoSQL Injection',
    'CWE-942':  'CORS Misconfiguration',
    'CWE-1321': 'Prototype Pollution',
    'CWE-1333': 'ReDoS',
}

# Keyword fallback when CWE tag is missing from the message
KEYWORD_FALLBACK = {
    'sql':           'SQL Injection',
    'command':       'Command Injection',
    'exec':          'Command Injection',
    'os.system':     'Command Injection',
    'popen':         'Command Injection',
    'eval':          'Code Injection',
    'pickle':        'Deserialization',
    'yaml.load':     'Deserialization',
    'deserializ':    'Deserialization',
    'xss':           'XSS',
    'innerhtml':     'XSS',
    'document.write': 'XSS',
    'md5':           'Weak Cryptography',
    'sha-1':         'Weak Cryptography',
    'sha1':          'Weak Cryptography',
    'des ':          'Weak Cryptography',
    'password':      'Hardcoded Secrets',
    'secret':        'Hardcoded Secrets',
    'api_key':       'Hardcoded Secrets',
    'hardcoded':     'Hardcoded Secrets',
    'path traversal': 'Path Traversal',
    'ssrf':          'SSRF',
    'xxe':           'XXE',
    'buffer':        'Buffer Overflow',
    'strcpy':        'Buffer Overflow',
    'strcat':        'Buffer Overflow',
    'sprintf':       'Buffer Overflow',
    'gets(':         'Buffer Overflow',
    'format string': 'Format String',
    'csrf':          'CSRF',
    'cors':          'CORS Misconfiguration',
    'prototype':     'Prototype Pollution',
    'jwt':           'JWT Weakness',
    'tls':           'TLS/SSL Bypass',
    'ssl':           'TLS/SSL Bypass',
    'redirect':      'Open Redirect',
    'random':        'Weak PRNG',
    'prng':          'Weak PRNG',
    'log4shell':     'Known CVE',
}


def classify_vulnerability(message: str) -> tuple:
    """
    Extract CWE/CVE ID and map to a human-readable category.
    Uses regex extraction first, then keyword fallback.
    Returns (cwe_id, category_name).
    """
    if not message:
        return ('N/A', 'Other')

    # Try CWE tag first
    match = re.search(r'\[CWE-\d+\]', message)
    if match:
        cwe = match.group().strip('[]')
        category = CWE_CATEGORY_MAP.get(cwe, 'Other')
        return (cwe, category)

    # Try CVE tag
    match = re.search(r'\[CVE-[\d-]+\]', message)
    if match:
        return (match.group().strip('[]'), 'Known CVE')

    # Keyword fallback
    msg_lower = message.lower()
    for keyword, category in KEYWORD_FALLBACK.items():
        if keyword in msg_lower:
            return ('N/A', category)

    return ('N/A', 'Other')


# ──────────────────────────────────────────────────────────────────────────────
# Severity Normalization
# ──────────────────────────────────────────────────────────────────────────────

SEVERITY_DISPLAY = {
    'ERROR':   'HIGH',
    'WARNING': 'MEDIUM',
    'INFO':    'LOW',
    'HIGH':    'HIGH',
    'MEDIUM':  'MEDIUM',
    'LOW':     'LOW',
}


def normalize_severity(raw: str) -> str:
    """Map ERROR/WARNING/INFO → HIGH/MEDIUM/LOW for display."""
    return SEVERITY_DISPLAY.get(raw.upper(), raw.upper())


# ──────────────────────────────────────────────────────────────────────────────
# Cached File-Line Extraction
# ──────────────────────────────────────────────────────────────────────────────

_file_cache = {}
_cache_lock = threading.Lock()


def get_file_lines(file_path: str) -> list:
    """Read and cache file lines. Thread-safe."""
    with _cache_lock:
        if file_path not in _file_cache:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    _file_cache[file_path] = f.readlines()
            except Exception:
                _file_cache[file_path] = []
        return _file_cache[file_path]


def extract_snippet(file_path: str, line_num: int, max_len: int = 100) -> str:
    """Get a specific line from a file (cached). 1-indexed."""
    lines = get_file_lines(file_path)
    if 1 <= line_num <= len(lines):
        return lines[line_num - 1].strip()[:max_len]
    return ''


def clear_file_cache():
    """Clear the file content cache (call between runs if needed)."""
    with _cache_lock:
        _file_cache.clear()


# ──────────────────────────────────────────────────────────────────────────────
# Deduplication
# ──────────────────────────────────────────────────────────────────────────────

def deduplicate_findings(findings: list) -> list:
    """
    Remove duplicate findings using (file, line, message) as the key.
    Stronger than (check_id, line) — catches cross-scanner duplicates.
    """
    seen = set()
    unique = []
    for f in findings:
        key = (
            f.get('file', ''),
            f.get('line', 0),
            f.get('message', ''),
        )
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# ──────────────────────────────────────────────────────────────────────────────
# Formatted Vulnerability Table
# ──────────────────────────────────────────────────────────────────────────────

def format_vuln_table(findings: list, file_path: str = None,
                      indent: str = '  ', show_snippet: bool = True) -> str:
    """
    Build a formatted vulnerability table string.

    Output example:
      Line   17  [HIGH]    SQL Injection (CWE-89)      — SQL Injection via f-string in execute()
                           └─ cursor.execute(f"SELECT * FROM users WHERE id={uid}")
    """
    if not findings:
        return f"{indent}No vulnerabilities detected."

    sorted_findings = sorted(findings, key=lambda f: f.get('line', 0))
    lines = []

    for f in sorted_findings:
        line_num = f.get('line', 0)
        sev_raw = f.get('severity', 'INFO').upper()
        sev_display = normalize_severity(sev_raw)
        message = f.get('message', '')
        chunk = f.get('original_chunk', '')

        cwe_id, category = classify_vulnerability(message)
        cwe_tag = f" ({cwe_id})" if cwe_id != 'N/A' else ''

        # Truncate message for display (strip the [CWE-xxx] prefix if present)
        msg_short = re.sub(r'^\[CWE-\d+\]\s*', '', message)
        msg_short = re.sub(r'^\[CVE-[\d-]+\]\s*', '', msg_short)
        if len(msg_short) > 60:
            msg_short = msg_short[:57] + '...'

        chunk_tag = f"  (chunk: {chunk})" if chunk else ''

        lines.append(
            f"{indent}Line {line_num:>4d}  [{sev_display:<6s}]  "
            f"{category}{cwe_tag:<24s} — {msg_short}{chunk_tag}"
        )

        # Snippet line
        if show_snippet and file_path:
            snippet = extract_snippet(file_path, line_num)
            if snippet:
                lines.append(f"{indent}{'':>14s}|-- {snippet}")

    return '\n'.join(lines)


# ──────────────────────────────────────────────────────────────────────────────
# Aggregation Helpers
# ──────────────────────────────────────────────────────────────────────────────

def vuln_type_summary(findings: list) -> list:
    """
    Return a ranked list of (category, count) across all findings.
    Example: [('SQL Injection', 8), ('Command Injection', 5), ...]
    """
    counter = Counter()
    for f in findings:
        _, category = classify_vulnerability(f.get('message', ''))
        counter[category] += 1
    return counter.most_common()
