import argparse
import os
import sys
import subprocess
import json
import logging
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from src.ast_parser import ASTParser
from src.feature_extractor import FeatureExtractor
from src.scanner import Scanner
from src.enrichment import PromptEnricher
from src.inference import InferenceEngine


LANG_MAP = {'.py': 'python', '.java': 'java', '.js': 'javascript', '.c': 'c'}

BIG_FILE_THRESHOLD = 200

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
    'target',
    'out',
    '.idea',
    '.vscode',
}

logging.basicConfig(level=logging.WARNING)
log = logging.getLogger(__name__)


def risk_label(score: float) -> str:
    if score >= 8: return "CRITICAL"
    if score >= 5: return "HIGH"
    if score >= 2: return "MEDIUM"
    return "LOW"


def bulk_semgrep_scan(dir_path: str) -> dict:
    """this will run semgrep once on the entire directory and return findings grouped by file path."""
    findings_map = defaultdict(list)

    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        rules_path = os.path.join(script_dir, 'src', 'rules.yaml')
        config = rules_path if os.path.exists(rules_path) else 'p/security-audit'

        env = os.environ.copy()
        appdata = os.environ.get('APPDATA', '')
        user_scripts = os.path.join(appdata, 'Python', 'Python313', 'Scripts')
        if os.path.exists(user_scripts):
            env['PATH'] = user_scripts + os.pathsep + env.get('PATH', '')

        cmd = f'semgrep scan --config "{config}" --json --quiet "{dir_path}"'
        result = subprocess.run(cmd, capture_output=True, text=True, env=env, shell=True)

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


def _calculate_risk_score(findings: list, file_path: str) -> float:
    """this will compute a severity-weighted score capped at 10.0."""
    if not findings:
        return 0.0
    weights = {'ERROR': 3.0, 'WARNING': 2.0, 'INFO': 0.5}
    total = sum(weights.get(f.get('severity', 'INFO').upper(), 0.5) for f in findings)
    import math
    try:
        line_count = sum(1 for _ in open(file_path, 'r', encoding='utf-8', errors='ignore'))
    except Exception:
        line_count = 100
    density = total / math.log(max(line_count, 2)) * 5.0
    return round(min(10.0, density), 1)


def analyze_single_file(file_path: str, semgrep_findings: list,
                         inference: InferenceEngine) -> dict:
    """this will run AST + CodeT5 on one file given pre-computed semgrep findings."""
    ext = os.path.splitext(file_path)[1].lower()
    language = LANG_MAP.get(ext)
    if not language:
        return None

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()
    except Exception as e:
        return {'file': file_path, 'error': str(e)}

    try:
        ast_parser = ASTParser()
        feat_extractor = FeatureExtractor()
        tree = ast_parser.parse(code, language)
        features = feat_extractor.extract_features(tree, code, language)
    except Exception:
        features = {'sources': [], 'sinks': [], 'complexity': 0}

    findings = semgrep_findings
    if not findings:
        try:
            scanner = Scanner()
            findings, _ = scanner.scan_file(file_path)
        except Exception:
            findings = []

    risk_score = _calculate_risk_score(findings, file_path)

    line_count = code.count('\n') + 1
    fname = os.path.basename(file_path)

    if line_count > BIG_FILE_THRESHOLD:
        try:
            from main_big import chunk_file, analyze_chunk, meta_summarize
            chunks = chunk_file(file_path)
            chunk_results = [analyze_chunk(n, t, language, inference) for n, t in chunks]
            summary = meta_summarize(chunk_results, inference)
            for cr in chunk_results:
                for cf in cr.get('findings', []):
                    if cf not in findings:
                        findings.append(cf)
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


_print_lock = threading.Lock()


def _scan_one(fp: str, dir_path: str, findings: list,
              inference: InferenceEngine):
    rel = os.path.relpath(fp, dir_path)
    result = analyze_single_file(fp, findings, inference)
    if result is None:
        with _print_lock:
            print(f"  Skipped  : {rel} [unsupported]")
        return None
    score = result.get('risk_score', 0.0)
    with _print_lock:
        print(f"  Scanned  : {rel} ... [{risk_label(score)} {score}/10]")
    return result


def analyze_all_files(dir_path: str, semgrep_map: dict,
                      inference: InferenceEngine,
                      max_workers: int = 4) -> list:
    """this will walk the directory and run AI analysis on every supported file in parallel."""
    supported = set(LANG_MAP.keys())
    seen = set()
    jobs = []

    for root, dirs, files in os.walk(dir_path):
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
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_scan_one, fp, dir_path, findings, inference): fp
            for fp, findings in jobs
        }
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                results.append(result)

    return results


def project_meta_summary(results: list, dir_path: str) -> str:
    """this will build a structured project overview by grouping per-file summaries by directory."""
    groups = defaultdict(list)
    for r in sorted(results, key=lambda x: x['file']):
        rel = os.path.relpath(r['file'], dir_path)
        parts = rel.replace('\\', '/').split('/')
        group = parts[0] if len(parts) > 1 else 'root'
        fname = os.path.basename(r['file'])
        s = r.get('summary', '').strip()
        if s:
            groups[group].append(f"{fname} -- {s}")

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
    """this will aggregate per-file results into a project-level security map."""
    lines = []
    sep = "=" * 65

    lines.append(sep)
    lines.append("  PROJECT-LEVEL SECURITY MAP")
    lines.append(f"  Directory : {dir_path}")
    lines.append(f"  Files     : {len(results)}")
    lines.append(sep)

    good = [r for r in results if 'error' not in r]
    errored = [r for r in results if 'error' in r]

    if not good:
        lines.append("\n  [!] No files could be analyzed.")
        return '\n'.join(lines)

    lines.append(f"\n  {'-'*63}")
    lines.append("  PROJECT OVERVIEW")
    lines.append(f"  {'-'*63}")
    overview = project_meta_summary(good, dir_path)
    for ov_line in overview.splitlines():
        lines.append(ov_line)

    total_counts = {'ERROR': 0, 'WARNING': 0, 'INFO': 0}
    check_id_files = defaultdict(list)

    for r in good:
        for f in r.get('findings', []):
            sev = f.get('severity', 'INFO').upper()
            total_counts[sev] = total_counts.get(sev, 0) + 1
            cid = f.get('check_id', 'unknown')
            rel = os.path.relpath(r['file'], dir_path)
            if rel not in check_id_files[cid]:
                check_id_files[cid].append(rel)

    total_issues = sum(total_counts.values())
    lines.append(f"\n  {'-'*63}")
    lines.append("  SECURITY STATS")
    lines.append(f"  {'-'*63}")
    lines.append(f"  Total Issues : {total_issues}")
    lines.append(f"    ERROR   (High)   : {total_counts.get('ERROR', 0)}")
    lines.append(f"    WARNING (Medium) : {total_counts.get('WARNING', 0)}")
    lines.append(f"    INFO    (Low)    : {total_counts.get('INFO', 0)}")

    ranked_risk = sorted(good, key=lambda r: r['risk_score'], reverse=True)
    lines.append(f"\n  {'-'*63}")
    lines.append("  TOP RISKIEST FILES")
    lines.append(f"  {'-'*63}")
    for r in ranked_risk[:5]:
        rel = os.path.relpath(r['file'], dir_path)
        label = risk_label(r['risk_score'])
        n = len(r.get('findings', []))
        lines.append(f"  [{label:8s}] {r['risk_score']:4.1f}/10  {rel}  ({n} finding(s))")

    cross = {cid: fps for cid, fps in check_id_files.items() if len(fps) >= 2}
    if cross:
        lines.append(f"\n  {'-'*63}")
        lines.append("  CROSS-FILE VULNERABILITY PATTERNS")
        lines.append(f"  {'-'*63}")
        for cid, fps in sorted(cross.items(), key=lambda x: -len(x[1]))[:10]:
            lines.append(f"  {cid}")
            for fp in fps:
                lines.append(f"     -> {fp}")

    sorted_alpha = sorted(good, key=lambda r: r['file'])
    lines.append(f"\n  {'-'*63}")
    lines.append("  PER-FILE AI SUMMARIES")
    lines.append(f"  {'-'*63}")
    for r in sorted_alpha:
        rel = os.path.relpath(r['file'], dir_path)
        label = risk_label(r['risk_score'])
        summary = r.get('summary', 'N/A').strip()
        lines.append(f"")
        lines.append(f"  {rel}  [{label}  {r['risk_score']}/10]")
        lines.append(f"  {summary}")

    if errored:
        lines.append(f"\n  {'-'*63}")
        lines.append("  FILES WITH ERRORS (skipped)")
        for r in errored:
            rel = os.path.relpath(r['file'], dir_path)
            lines.append(f"  {rel} -- {r['error']}")

    lines.append(f"\n{sep}\n")
    return '\n'.join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="AI Security Auditor -- Directory-Wide Scanner with Project Security Map"
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

    print("[*] Loading CodeT5 model...")
    inference = InferenceEngine()
    print("[*] Model loaded.\n")

    print("[*] Running bulk Semgrep scan on directory...")
    semgrep_map = bulk_semgrep_scan(dir_path)
    total_semgrep = sum(len(v) for v in semgrep_map.values())
    print(f"    Semgrep found {total_semgrep} finding(s) across {len(semgrep_map)} file(s)\n")

    print("[*] Analyzing files...\n")
    results = analyze_all_files(dir_path, semgrep_map, inference)

    if not results:
        print("[!] No supported source files found.")
        sys.exit(0)

    project_map = build_project_map(results, dir_path, inference)
    try:
        print(project_map)
    except UnicodeEncodeError:
        print(project_map.encode(sys.stdout.encoding, errors='replace').decode(sys.stdout.encoding))

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as out:
            out.write(project_map)
        print(f"[*] Project map saved to: {args.output}")
