import argparse
import os
import sys
import subprocess
import json
import logging
import time
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.ast_parser import ASTParser
from src.feature_extractor import FeatureExtractor
from src.scanner import Scanner
from src.enrichment import PromptEnricher
from src.inference import InferenceEngine
from src.vuln_classifier import (
    classify_vulnerability, normalize_severity, deduplicate_findings,
    format_vuln_table, vuln_type_summary, extract_snippet, clear_file_cache,
)


LANG_MAP = {'.py': 'python', '.java': 'java', '.js': 'javascript', '.c': 'c'}

# Files with MORE than this many lines of code are routed through the
# chunked big-file pipeline (AST-based chunking + Meta-Transformer pass)
# instead of the single-pass CodeT5 approach. This prevents the model from
# silently truncating the tail of large files at the 512-token boundary.
BIG_FILE_THRESHOLD = 200  # lines

# Directories to skip entirely — never descend into these
SKIP_DIRS = {
    'node_modules',
    '__pycache__',
    '.git',
    '.vite',
    'dist',
    'build',
    '.cache',
    '.next',
    'venv',
    '.venv',
    'env',
    '.tox',
    'target',       # Java/Maven build output
    'out',
    '.idea',
    '.vscode',
}

logging.basicConfig(level=logging.WARNING)
log = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Thread-safe printing
# ──────────────────────────────────────────────────────────────────────────────

_print_lock = threading.Lock()


def safe_print(*args, **kwargs):
    """Thread-safe wrapper around print()."""
    with _print_lock:
        print(*args, **kwargs)


def risk_label(score: float) -> str:
    if score >= 8: return "CRITICAL"
    if score >= 5: return "HIGH"
    if score >= 2: return "MEDIUM"
    return "LOW"


# ──────────────────────────────────────────────────────────────────────────────
# STAGE A — BULK SEMGREP SCAN (one call for the whole directory)
# ──────────────────────────────────────────────────────────────────────────────

def bulk_semgrep_scan(dir_path: str) -> dict:
    """
    Run Semgrep once on the entire directory.
    Returns dict mapping absolute file path → list of finding dicts.
    Falls back to empty dict if Semgrep is unavailable.
    """
    findings_map = defaultdict(list)

    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        rules_path = os.path.join(script_dir, 'rules.yaml')
        config = rules_path if os.path.exists(rules_path) else 'p/security-audit'

        # Setup PATH so semgrep is findable on Windows
        env = os.environ.copy()
        appdata = os.environ.get('APPDATA', '')
        user_scripts = os.path.join(appdata, 'Python', 'Python313', 'Scripts')
        if os.path.exists(user_scripts):
            env['PATH'] = user_scripts + os.pathsep + env.get('PATH', '')

        cmd = f'semgrep scan --config "{config}" --json --quiet "{dir_path}"'
        result = subprocess.run(cmd, capture_output=True, text=True, env=env, shell=True, encoding='utf-8', errors='ignore')

        if result.stdout:
            raw = result.stdout.strip()
            start = raw.find('{')
            end   = raw.rfind('}') + 1
            if start != -1 and end > start:
                data = json.loads(raw[start:end])
                for item in data.get('results', []):
                    path = os.path.realpath(item.get('path', ''))
                    findings_map[path].append({
                        'check_id': item.get('check_id'),
                        'file':     path,
                        'line':     item.get('start', {}).get('line', 0),
                        'message':  item.get('extra', {}).get('message', ''),
                        'severity': item.get('extra', {}).get('severity', 'INFO').upper(),
                        'snippet':  item.get('extra', {}).get('lines', '').strip(),
                    })

    except Exception as e:
        log.warning(f"Bulk Semgrep scan failed: {e}")

    return dict(findings_map)


# ──────────────────────────────────────────────────────────────────────────────
# STAGE B — PER-FILE AI ANALYSIS
# ──────────────────────────────────────────────────────────────────────────────

def _calculate_risk_score(findings: list, file_path: str) -> float:
    """Simple severity-weighted score, capped at 10.0."""
    if not findings:
        return 0.0
    weights = {'HIGH': 3.0, 'MEDIUM': 2.0, 'LOW': 0.5}
    total = sum(weights.get(normalize_severity(f.get('severity', 'INFO')).upper(), 0.5) for f in findings)
    import math
    try:
        line_count = sum(1 for _ in open(file_path, 'r', encoding='utf-8', errors='ignore'))
    except Exception:
        line_count = 100
    density = total / math.log(max(line_count, 2)) * 5.0
    return round(min(10.0, density), 1)


def analyze_single_file(file_path: str, semgrep_findings: list,
                         inference: InferenceEngine) -> dict:
    """
    Given pre-computed Semgrep findings, run AST + CodeT5 for one file.
    Unsupported extensions are ignored — returns None.
    """
    ext = os.path.splitext(file_path)[1].lower()
    language = LANG_MAP.get(ext)
    if not language:
        return None  # skip unsupported file types

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()
    except Exception as e:
        return {'file': file_path, 'error': str(e)}

    # AST features
    try:
        ast_parser = ASTParser()
        feat_extractor = FeatureExtractor()
        tree = ast_parser.parse(code, language)
        features = feat_extractor.extract_features(tree, code, language)
    except Exception:
        features = {'sources': [], 'sinks': [], 'complexity': 0}

    # If Semgrep gave us nothing for this file, run fallback scan
    findings = semgrep_findings
    if not findings:
        try:
            scanner = Scanner()
            findings, _ = scanner.scan_file(file_path)
        except Exception:
            findings = []

    risk_score = _calculate_risk_score(findings, file_path)

    # ── AI Summary — adaptive routing ──────────────────────────────
    # Large files are silently truncated by CodeT5 at ~512 tokens.
    # Files exceeding BIG_FILE_THRESHOLD lines are routed through the
    # chunked pipeline from main_big.py (AST chunking + Meta-Transformer)
    # to guarantee the entire file is analysed by the model.
    line_count = code.count('\n') + 1
    fname = os.path.basename(file_path)

    if line_count > BIG_FILE_THRESHOLD:
        # Big-file path: import lazily to avoid circular deps at module load time
        try:
            from main_big import chunk_file, analyze_chunk, meta_summarize
            from main_big import safe_print as big_safe_print

            chunks = chunk_file(file_path)

            # Parallel chunk processing (4 threads) with error isolation
            chunk_results = [None] * len(chunks)
            with ThreadPoolExecutor(max_workers=4) as executor:
                future_to_idx = {
                    executor.submit(
                        analyze_chunk, n, t, language, inference, s,
                        file_path, idx   # original_file + chunk_id
                    ): idx
                    for idx, (n, t, s) in enumerate(chunks)
                }
                for future in as_completed(future_to_idx):
                    idx = future_to_idx[future]
                    try:
                        chunk_results[idx] = future.result(timeout=120)
                    except Exception as e:
                        chunk_results[idx] = {
                            'name': f'chunk_{idx}',
                            'summary': f'Chunk analysis failed: {e}',
                            'risk_score': 0.0,
                            'findings': [],
                            'features': {},
                        }

            # Filter out None entries (shouldn't happen but be safe)
            chunk_results = [cr for cr in chunk_results if cr is not None]

            summary = meta_summarize(chunk_results, inference, language)
            # Merge any additional findings from chunk analyses
            for cr in chunk_results:
                for cf in cr.get('findings', []):
                    if cf not in findings:
                        findings.append(cf)
            # Deduplicate and re-score with merged findings
            findings = deduplicate_findings(findings)
            risk_score = _calculate_risk_score(findings, file_path)
        except Exception as e:
            log.warning(f"Big-file pipeline failed for {fname}, falling back to single-pass: {e}")
            code_with_name = f"// File: {fname}\n{code}"
            enricher = PromptEnricher()
            prompt = enricher.construct_prompt(findings, features, code_with_name)
            try:
                summary = inference.generate_summary(prompt)
            except Exception:
                summary = "Summary unavailable."
    else:
        # Normal single-pass path
        code_with_name = f"// File: {fname}\n{code}"
        enricher = PromptEnricher()
        prompt = enricher.construct_prompt(findings, features, code_with_name)
        try:
            summary = inference.generate_summary(prompt)
        except Exception:
            summary = "Summary unavailable."

    return {
        'file':       file_path,
        'language':   language,
        'line_count': line_count,
        'big_file':   line_count > BIG_FILE_THRESHOLD,
        'risk_score': risk_score,
        'findings':   findings,
        'features':   features,
        'summary':    summary,
    }


def _scan_one(fp: str, dir_path: str, findings: list,
              inference: InferenceEngine):
    """Worker: analyze one file and return its result. Thread-safe + error-isolated."""
    rel = os.path.relpath(fp, dir_path)
    t0 = time.time()

    try:
        result = analyze_single_file(fp, findings, inference)
    except Exception as e:
        result = {
            'file': fp,
            'error': f'Worker exception: {e}',
        }

    elapsed = time.time() - t0

    if result is None:
        safe_print(f"  Skipped  : {rel} [unsupported]")
        return None

    if 'error' in result:
        safe_print(f"  Error    : {rel} — {result['error']}")
        return result

    score = result.get('risk_score', 0.0)
    n_findings = len(result.get('findings', []))
    safe_print(
        f"  Scanned  : {rel} ... "
        f"[{risk_label(score)} {score}/10]  "
        f"{n_findings} finding(s)  {elapsed:.1f}s"
    )
    return result


def analyze_all_files(dir_path: str, semgrep_map: dict,
                      inference: InferenceEngine,
                      max_workers: int = 4) -> list:
    """
    Walk the directory and run AI analysis on every supported file.
    Files are processed in parallel using ThreadPoolExecutor.
    Skips directories listed in SKIP_DIRS.
    Returns list of result dicts.
    """
    supported = set(LANG_MAP.keys())
    seen = set()
    jobs = []  # list of (fp, findings)

    # Collect all files first
    for root, dirs, files in os.walk(dir_path):
        # Prune skip-listed dirs IN PLACE so os.walk never descends into them
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith('.')]

        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in supported:
                continue
            fp = os.path.realpath(os.path.join(root, fname))
            if fp in seen:
                continue
            seen.add(fp)
            jobs.append((fp, semgrep_map.get(fp, [])))

    print(f"  Found {len(jobs)} file(s). Scanning with {max_workers} parallel workers...\n")

    results = []
    completed = 0
    total = len(jobs)

    # Submit all jobs in parallel
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_scan_one, fp, dir_path, findings, inference): fp
            for fp, findings in jobs
        }
        for future in as_completed(futures):
            fp = futures[future]
            # Executor-level error isolation
            try:
                result = future.result(timeout=300)
            except Exception as e:
                result = {
                    'file': fp,
                    'error': f'Executor failure: {e}',
                }
            completed += 1
            pct = (completed / total) * 100 if total else 100
            safe_print(f"  [{completed}/{total}] ({pct:.0f}%) files processed")

            if result is not None:
                results.append(result)

    return results


# ──────────────────────────────────────────────────────────────────────────────
# STAGE C — PROJECT-LEVEL SECURITY MAP
# ──────────────────────────────────────────────────────────────────────────────

def project_meta_summary(results: list, dir_path: str) -> str:
    """
    Build a structured project overview by grouping per-file summaries
    by their top-level directory.

    CodeT5 is a code-to-summary model — asking it 'describe this project'
    causes it to echo the instruction back. Instead we build the overview
    from the already-generated per-file summaries, grouped by folder.
    """
    groups = defaultdict(list)
    for r in sorted(results, key=lambda x: x['file']):
        rel = os.path.relpath(r['file'], dir_path)
        parts = rel.replace('\\', '/').split('/')
        group = parts[0] if len(parts) > 1 else 'root'
        fname = os.path.basename(r['file'])
        s = r.get('summary', '').strip()
        if s:
            groups[group].append(f"{fname} — {s}")

    if not groups:
        return "No summaries could be generated."

    total = sum(len(v) for v in groups.values())
    lines = [
        f"Project contains {total} source file(s) across "
        f"{len(groups)} component(s):\n"
    ]
    for group, entries in sorted(groups.items()):
        lines.append(f"  [{group}]  ({len(entries)} file(s))")
        for entry in entries:
            if len(entry) > 72:
                entry = entry[:69] + "..."
            lines.append(f"    * {entry}")
        lines.append("")

    return '\n'.join(lines)


def build_project_map(results: list, dir_path: str,
                      inference: InferenceEngine) -> str:
    """
    Aggregate per-file results into a Project-Level Security Map string.
    Sections:
    - Project Overview (meta-summary)
    - Stats & severity breakdown
    - Top-5 riskiest files
    - Most common vulnerability types
    - Cross-file vulnerability patterns
    - Per-file AI summaries with vulnerability detail (alphabetical)
    """
    lines = []
    sep = "=" * 65

    lines.append(sep)
    lines.append("  PROJECT-LEVEL SECURITY MAP")
    lines.append(f"  Directory : {dir_path}")
    lines.append(f"  Files     : {len(results)}")
    lines.append(sep)

    # Filter out errored files
    good = [r for r in results if 'error' not in r]
    errored = [r for r in results if 'error' in r]

    if not good:
        lines.append("\n  [!] No files could be analyzed.")
        return '\n'.join(lines)

    # ── PROJECT OVERVIEW ─────────────────────────────────────────
    lines.append(f"\n  {'─'*63}")
    lines.append("  PROJECT OVERVIEW")
    lines.append(f"  {'─'*63}")
    overview = project_meta_summary(good, dir_path)
    for ov_line in overview.splitlines():
        lines.append(ov_line)

    # ── STATS ────────────────────────────────────────────────────
    total_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    check_id_files = defaultdict(list)
    all_findings_global = []

    from src.vuln_classifier import normalize_severity
    for r in good:
        for f in r.get('findings', []):
            sev = normalize_severity(f.get('severity', 'INFO')).upper()
            total_counts[sev] = total_counts.get(sev, 0) + 1
            cid = f.get('check_id', 'unknown')
            rel = os.path.relpath(r['file'], dir_path)
            if rel not in check_id_files[cid]:
                check_id_files[cid].append(rel)
            all_findings_global.append(f)

    total_issues = sum(total_counts.values())
    lines.append(f"\n  {'─'*63}")
    lines.append("  SECURITY STATS")
    lines.append(f"  {'─'*63}")
    lines.append(f"  Total Issues : {total_issues}")
    lines.append(f"    High Vulnerability   : {total_counts.get('HIGH', 0)}")
    lines.append(f"    Medium Vulnerability : {total_counts.get('MEDIUM', 0)}")
    lines.append(f"    Low Vulnerability    : {total_counts.get('LOW', 0)}")

    # ── TOP RISKIEST FILES ───────────────────────────────────────
    ranked_risk = sorted(good, key=lambda r: r['risk_score'], reverse=True)
    lines.append(f"\n  {'─'*63}")
    lines.append("  TOP RISKIEST FILES")
    lines.append(f"  {'─'*63}")
    for r in ranked_risk[:5]:
        rel = os.path.relpath(r['file'], dir_path)
        label = risk_label(r['risk_score'])
        n = len(r.get('findings', []))
        lines.append(f"  [{label:8s}] {r['risk_score']:4.1f}/10  {rel}  ({n} finding(s))")

    # ── MOST COMMON VULNERABILITY TYPES ──────────────────────────
    type_counts = vuln_type_summary(all_findings_global)
    if type_counts:
        lines.append(f"\n  {'─'*63}")
        lines.append("  MOST COMMON VULNERABILITY TYPES")
        lines.append(f"  {'─'*63}")
        for rank, (category, count) in enumerate(type_counts[:10], 1):
            lines.append(f"  {rank}. {category:<28s} — {count} occurrence(s)")

    # ── CROSS-FILE PATTERNS ──────────────────────────────────────
    cross = {cid: fps for cid, fps in check_id_files.items() if len(fps) >= 2}
    if cross:
        lines.append(f"\n  {'─'*63}")
        lines.append("  CROSS-FILE VULNERABILITY PATTERNS")
        lines.append(f"  {'─'*63}")
        for cid, fps in sorted(cross.items(), key=lambda x: -len(x[1]))[:10]:
            lines.append(f"  {cid}")
            for fp in fps:
                lines.append(f"     → {fp}")

    # ── PER-FILE AI SUMMARIES + VULNERABILITY DETAIL ─────────────
    sorted_alpha = sorted(good, key=lambda r: r['file'])
    lines.append(f"\n  {'─'*63}")
    lines.append("  PER-FILE AI SUMMARIES")
    lines.append(f"  {'─'*63}")
    for r in sorted_alpha:
        rel = os.path.relpath(r['file'], dir_path)
        label = risk_label(r['risk_score'])
        summary = r.get('summary', 'N/A').strip()
        file_findings = r.get('findings', [])
        big_tag = "  [BIG-FILE]" if r.get('big_file', False) else ""

        lines.append(f"")
        lines.append(f"  {rel}  [{label}  {r['risk_score']}/10]{big_tag}")
        lines.append(f"  {summary}")

        # Per-file vulnerability detail table
        if file_findings:
            lines.append(f"    Vulnerabilities ({len(file_findings)}):")
            vuln_table = format_vuln_table(
                file_findings, r['file'], indent='    ', show_snippet=False
            )
            lines.append(vuln_table)

    # ── FILES WITH ERRORS ────────────────────────────────────────
    if errored:
        lines.append(f"\n  {'─'*63}")
        lines.append("  FILES WITH ERRORS (skipped)")
        for r in errored:
            rel = os.path.relpath(r['file'], dir_path)
            lines.append(f"  {rel} — {r['error']}")

    lines.append(f"\n{sep}\n")
    return '\n'.join(lines)


# ──────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="AI Security Auditor — Directory-Wide Scanner with Project Security Map"
    )
    parser.add_argument(
        "--dir", required=True,
        help="Path to directory to scan"
    )
    parser.add_argument(
        "--output",
        help="Optional: save the project security map to this file"
    )
    args = parser.parse_args()

    if not os.path.isdir(args.dir):
        print(f"[!] Directory not found: {args.dir}")
        sys.exit(1)

    dir_path = os.path.realpath(args.dir)

    # Clear cached file contents from any previous run
    clear_file_cache()

    print("[*] Loading CodeT5 model...")
    inference = InferenceEngine()
    print("[*] Model loaded.\n")

    # Stage A — bulk Semgrep
    print("[*] Running bulk Semgrep scan on directory...")
    semgrep_map = bulk_semgrep_scan(dir_path)
    total_semgrep = sum(len(v) for v in semgrep_map.values())
    print(f"    Semgrep found {total_semgrep} finding(s) across {len(semgrep_map)} file(s)\n")

    # Stage B — per-file AI analysis
    print("[*] Analyzing files...\n")
    results = analyze_all_files(dir_path, semgrep_map, inference)

    if not results:
        print("[!] No supported source files found.")
        sys.exit(0)

    # Stage C — project map
    project_map = build_project_map(results, dir_path, inference)
    try:
        print(project_map)
    except UnicodeEncodeError:
        print(project_map.encode(sys.stdout.encoding, errors='replace').decode(sys.stdout.encoding))

    # Save if requested
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as out:
            out.write(project_map)
        print(f"[*] Project map saved to: {args.output}")
