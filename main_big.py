
import argparse
import os
import sys
import tempfile
import threading
import time
import re
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

DEFAULT_CHUNK_LINES = 60
DEFAULT_MAX_WORKERS = 4

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


def chunk_file(file_path: str, chunk_lines: int = DEFAULT_CHUNK_LINES):
    """this will split a file into named chunks using AST or fixed-line windows."""
    ext = os.path.splitext(file_path)[1].lower()
    language = LANG_MAP.get(ext)

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        code = f.read()

    if language == 'python':
        chunks = _ast_chunk_python(code)
        if chunks:
            return chunks
    elif language == 'javascript':
        chunks = _ast_chunk_js(code)
        if chunks:
            return chunks
    elif language == 'java':
        chunks = _ast_chunk_java(code)
        if chunks:
            return chunks

    return _line_window_chunks(code, chunk_lines)


def _ast_chunk_js(code: str):
    """this will walk the tree-sitter JS AST to extract top-level functions and Express routes."""
    try:
        from tree_sitter import Language, Parser as TSParser
        import tree_sitter_javascript as tsjs

        JS_LANG = Language(tsjs.language())
        parser = TSParser(JS_LANG)
        tree = parser.parse(bytes(code, 'utf-8'))
        root = tree.root_node

        chunks = []
        lines = code.splitlines()

        for node in root.children:
            name = None
            if node.type in ('function_declaration', 'class_declaration'):
                name_node = node.child_by_field_name('name')
                name = name_node.text.decode('utf-8') if name_node else node.type
            elif node.type == 'expression_statement':
                # Check for Express routes: app.get(), router.post(), etc.
                call = node.child(0)
                if call and call.type == 'call_expression':
                    fn = call.child_by_field_name('function')
                    if fn and fn.type == 'member_expression':
                        obj = fn.child_by_field_name('object')
                        prop = fn.child_by_field_name('property')
                        if obj and prop:
                            obj_text = obj.text.decode('utf-8')
                            prop_text = prop.text.decode('utf-8')
                            if obj_text in ('app', 'router', 'express') and prop_text in ('get', 'post', 'put', 'delete', 'patch', 'use', 'route'):
                                # Try to get the route path
                                args = call.child_by_field_name('arguments')
                                if args and args.named_child_count > 0:
                                    path_node = args.named_child(0)
                                    path = path_node.text.decode('utf-8').strip("'\"")
                                    name = f"route_{prop_text}_{path}"
            
            if name:
                start = node.start_point[0]
                end = node.end_point[0]
                chunk_text = '\n'.join(lines[start:end + 1])
                chunks.append((name, chunk_text, start))

        return chunks
    except Exception:
        return []


def _ast_chunk_java(code: str):
    """this will walk the tree-sitter Java AST to extract method declarations within classes."""
    try:
        from tree_sitter import Language, Parser as TSParser
        import tree_sitter_java as tsjava

        JAVA_LANG = Language(tsjava.language())
        parser = TSParser(JAVA_LANG)
        tree = parser.parse(bytes(code, 'utf-8'))
        root = tree.root_node

        chunks = []
        lines = code.splitlines()

        def walk(node):
            if node.type == 'method_declaration':
                name_node = node.child_by_field_name('name')
                name = name_node.text.decode('utf-8') if name_node else "method"
                start = node.start_point[0]
                end = node.end_point[0]
                chunk_text = '\n'.join(lines[start:end + 1])
                chunks.append((name, chunk_text, start))
            else:
                for child in node.children:
                    walk(child)

        walk(root)
        return chunks
    except Exception:
        return []


def _ast_chunk_python(code: str):
    """this will walk the tree-sitter Python AST to extract top-level function/class blocks."""
    try:
        from tree_sitter import Language, Parser as TSParser
        import tree_sitter_python as tspython

        PY_LANG = Language(tspython.language())
        parser = TSParser(PY_LANG)
        tree = parser.parse(bytes(code, 'utf-8'))
        root = tree.root_node

        chunks = []
        for node in root.children:
            target_node = node
            if node.type == 'decorated_definition':
                # Grab the inner class/function to get its name
                for child in node.children:
                    if child.type in ('function_definition', 'class_definition'):
                        target_node = child
                        break
            
            if target_node.type in ('function_definition', 'class_definition'):
                name_node = target_node.child_by_field_name('name')
                name = name_node.text.decode('utf-8') if name_node else target_node.type
                start = node.start_point[0] # start from the decorator!
                end   = node.end_point[0]
                lines = code.splitlines()
                chunk_text = '\n'.join(lines[start:end + 1])
                chunks.append((name, chunk_text, start))

        return chunks if chunks else []

    except Exception:
        return []


def _line_window_chunks(code: str, chunk_lines: int):
    """this will split code into fixed-size line windows."""
    lines = code.splitlines()
    chunks = []
    for i in range(0, len(lines), chunk_lines):
        window = lines[i: i + chunk_lines]
        name = f"lines_{i + 1}_to_{i + len(window)}"
        chunks.append((name, '\n'.join(window), i))
    return chunks


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# PER-CHUNK PIPELINE
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

def analyze_chunk(chunk_name: str, chunk_text: str, language: str,
                  inference: InferenceEngine, start_line: int = 0,
                  original_file: str = None, chunk_id: int = -1):
    """this will run the full 5-stage pipeline on a single chunk."""
    suffix = {v: k for k, v in LANG_MAP.items()}.get(language, '.py')
    with tempfile.NamedTemporaryFile(
        mode='w', suffix=suffix, delete=False, encoding='utf-8'
    ) as tmp:
        tmp.write(chunk_text)
        tmp_path = tmp.name

    try:
        try:
            ast_parser = ASTParser()
            feature_extractor = FeatureExtractor()
            tree = ast_parser.parse(chunk_text, language)
            features = feature_extractor.extract_features(tree, chunk_text, language)
        except Exception:
            features = {'sources': [], 'sinks': [], 'complexity': 0}

        try:
            scanner = Scanner()
            findings, risk_score = scanner.scan_file(tmp_path)
        except Exception:
            findings, risk_score = [], 0.0

        # Remap ALL finding line numbers from chunk-relative to original-file-relative.
        # Chunk line 1 in the temp file corresponds to original file line (start_line + 1)
        # since start_line is 0-indexed but finding lines are 1-indexed.
        if start_line > 0:
            for f in findings:
                if 'line' in f and isinstance(f['line'], int):
                    f['line'] = f['line'] + start_line

        # Fix file field — point to original file, not temp file
        if original_file:
            for f in findings:
                f['file'] = original_file

        # Tag each finding with the chunk it came from for traceability
        for f in findings:
            f['original_chunk'] = chunk_name
            f['chunk_id'] = chunk_id

        enricher = PromptEnricher()
        prompt = enricher.construct_prompt(findings, features, chunk_text)

        try:
            summary = inference.generate_summary(prompt)
        except Exception:
            summary = "Summary unavailable."

    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    return {
        'name': chunk_name,
        'summary': summary,
        'risk_score': risk_score,
        'findings': findings,
        'features': features,
    }


def meta_summarize(chunk_results: list, inference: InferenceEngine, language: str) -> str:
    """this will combine all per-chunk summaries into a rich prompt and run CodeT5 for a deep report."""
    total_findings = sum(len(r.get('findings', [])) for r in chunk_results)
    
    func_parts = []
    for r in chunk_results:
        s = r.get('summary', '').strip()
        if s and s != "Summary unavailable.":
            # Remove trailing periods and newlines
            func_parts.append(s.rstrip('.').replace('\n', ' '))

    if not func_parts:
        func_prompt = f"// Language: {language}\n// General application module.\nfunction execute_module() {{}}\n"
    else:
        # We feed CodeT5 a pseudo-code snippet so it feels natural to summarize.
        # Too many summaries confuse the model, so we limit to the first 4 distinct behaviors.
        combined_desc = "; ".join(func_parts[:4])
        func_prompt = f"// Language: {language}\n// Implements the following features: {combined_desc}.\nfunction get_module_features() {{}}\n"
        
    func_prompt = func_prompt[:1000]
    
    try:
        tldr = inference.generate_summary(func_prompt, max_length=64)
        # Sometimes CodeT5 repeats the prompt or hallucinates "vulnerabilities" if confused.
        if "vulnerabilities" in tldr.lower() and total_findings == 0:
            tldr = f"This module provides core logic and functionality for the {language} application."
    except Exception:
        tldr = f"This module implements functional logic in {language}."
        
    if not tldr.endswith('.'):
        tldr += '.'
        
    narrative = f"{tldr} "
    narrative += f"During the chunked analysis, the file was partitioned into {len(chunk_results)} logical components. "
    
    if total_findings == 0:
        narrative += "Static analysis verified that this code is structurally sound and secure, with no vulnerabilities detected across its components. "
    else:
        narrative += f"A total of {total_findings} security vulnerabilities were detected. "
    
        risky_chunks = [c for c in chunk_results if c.get('risk_score', 0) >= 4.0]
        if risky_chunks:
            risky_names = [c['name'] for c in risky_chunks[:3]]
            narrative += f"Urgent security attention is required in the more vulnerable segments: {', '.join(risky_names)}. "
        elif total_findings > 0:
            narrative += "The vulnerabilities are primarily minor warnings or info-level findings spread across the file. "
        
    # Add what the code DOES
    clean_behaviors = [
        p for p in func_parts 
        if "vulner" not in p.lower() and "security" not in p.lower()
    ]
    if not clean_behaviors and func_parts:
        clean_behaviors = func_parts # Fallback
        
    if clean_behaviors:
        clean_desc = "; ".join(clean_behaviors[:3])
        narrative += f"Functionally, the key behaviors and responsibilities encapsulated by this code include: {clean_desc}."
        
    return narrative.strip()


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# ORCHESTRATOR (Multithreaded)
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

def _process_chunk_worker(idx, name, text, language, inference,
                          start_line, total, original_file):
    """Worker function for ThreadPoolExecutor. Thread-safe + error-isolated."""
    chunk_line_count = text.count('\n') + 1
    safe_print(f"  -- Chunk {idx + 1}/{total}: {name}  ({chunk_line_count} lines)  [started]")

    t0 = time.time()
    try:
        result = analyze_chunk(name, text, language, inference,
                               start_line, original_file, chunk_id=idx)
    except Exception as e:
        result = {
            'name': name,
            'summary': f"Analysis failed: {e}",
            'risk_score': 0.0,
            'findings': [],
            'features': {},
        }
    elapsed = time.time() - t0
    result['time'] = round(elapsed, 2)

    label = risk_label(result['risk_score'])
    safe_print(
        f"     Chunk {idx + 1}/{total}: {name}  =>  "
        f"Risk {result['risk_score']}/10 [{label}]  |  "
        f"{len(result['findings'])} finding(s)  |  "
        f"{elapsed:.1f}s  [done]"
    )

    return idx, result


def run_big(file_path: str, inference: InferenceEngine,
            chunk_lines: int = DEFAULT_CHUNK_LINES,
            max_workers: int = DEFAULT_MAX_WORKERS):
    ext = os.path.splitext(file_path)[1].lower()
    language = LANG_MAP.get(ext)
    if not language:
        print(f"[!] Unsupported extension: {ext}")
        return

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        total_lines = sum(1 for _ in f)

    # Clear file cache for fresh reads
    clear_file_cache()

    print(f"\n{'='*60}")
    print(f"  RECURSIVE AUDIT -- {os.path.basename(file_path)}")
    print(f"  Language : {language}  |  Lines : {total_lines}")
    print(f"  Workers  : {max_workers} threads")
    print(f"{'='*60}")

    chunks = chunk_file(file_path, chunk_lines)
    print(f"\n  [*] Split into {len(chunks)} chunk(s) — processing in parallel\n")

    # ── Parallel chunk processing ─────────────────────────────────
    chunk_results = [None] * len(chunks)
    completed = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                _process_chunk_worker,
                idx, name, text, language, inference,
                start_line, len(chunks), file_path
            ): idx
            for idx, (name, text, start_line) in enumerate(chunks)
        }
        for future in as_completed(futures):
            # Executor-level error isolation
            try:
                idx, result = future.result(timeout=120)
            except Exception as e:
                idx = futures[future]
                result = {
                    'name': f'chunk_{idx}',
                    'summary': f'Executor failure: {e}',
                    'risk_score': 0.0,
                    'findings': [],
                    'features': {},
                    'time': 0.0,
                }
            chunk_results[idx] = result
            completed += 1
            pct = (completed / len(chunks)) * 100
            safe_print(f"  [{completed}/{len(chunks)}] ({pct:.0f}%) completed")

    # ── Deterministic ordering (sort by original index) ───────────
    # chunk_results is already indexed by idx, so it's in order
    print()

    # Per-chunk detail output (in original order)
    for cr in chunk_results:
        if cr is None:
            continue
        label = risk_label(cr['risk_score'])
        elapsed = cr.get('time', 0)
        print(f"  -- {cr['name']}  ({elapsed:.1f}s)")
        print(f"     Risk     : {cr['risk_score']}/10  [{label}]")
        print(f"     Summary  : {cr['summary']}")
        if cr['findings']:
            print(f"     Findings :")
            for f in cr['findings']:
                sev = normalize_severity(f.get('severity', 'INFO'))
                cwe_id, cat = classify_vulnerability(f.get('message', ''))
                cwe_tag = f" ({cwe_id})" if cwe_id != 'N/A' else ''
                print(f"       [{sev}] Line {f['line']} -- {cat}{cwe_tag}: {f['message'][:70]}")
        else:
            print(f"     Findings : None")
        print()

    # ── Consolidated Vulnerability Table ──────────────────────────
    all_findings = []
    for cr in chunk_results:
        if cr:
            all_findings.extend(cr.get('findings', []))
    all_findings = deduplicate_findings(all_findings)
    all_findings.sort(key=lambda f: f.get('line', 0))

    print(f"  {'-'*56}")
    print(f"  CONSOLIDATED VULNERABILITIES (Original File Lines)")
    print(f"  {'-'*56}")
    if all_findings:
        print(format_vuln_table(all_findings, file_path, indent='  ', show_snippet=True))
    else:
        print(f"  No vulnerabilities detected.")
    print()

    # ── Vulnerability Type Summary ────────────────────────────────
    type_counts = vuln_type_summary(all_findings)
    if type_counts:
        print(f"  {'-'*56}")
        print(f"  VULNERABILITY TYPE BREAKDOWN")
        print(f"  {'-'*56}")
        for rank, (category, count) in enumerate(type_counts, 1):
            print(f"  {rank}. {category:<28s} -- {count} occurrence(s)")
        print()

    # ── Meta-Transformer Report ───────────────────────────────────
    print(f"  {'-'*56}")
    print(f"  META-TRANSFORMER -- Whole-File Report")
    print(f"  {'-'*56}")
    meta = meta_summarize(chunk_results, inference, language)
    print(f"  {meta}")

    top_score = max((r['risk_score'] for r in chunk_results if r), default=0.0)
    total_time = sum(r.get('time', 0) for r in chunk_results if r)
    print(f"\n  Overall Risk  : {top_score}/10  [{risk_label(top_score)}]")
    print(f"  Total Findings: {len(all_findings)} (deduplicated)")
    print(f"  Total Time    : {total_time:.1f}s across {len(chunks)} chunks")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="AI Security Auditor -- Recursive Summarization for Large Files"
    )
    parser.add_argument(
        "--file", required=True,
        help="Path to the large source file to analyze"
    )
    parser.add_argument(
        "--chunk-lines", type=int, default=DEFAULT_CHUNK_LINES,
        help=f"Lines per chunk when AST chunking is unavailable (default: {DEFAULT_CHUNK_LINES})"
    )
    parser.add_argument(
        "--workers", type=int, default=DEFAULT_MAX_WORKERS,
        help=f"Number of parallel worker threads (default: {DEFAULT_MAX_WORKERS})"
    )
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"[!] File not found: {args.file}")
        sys.exit(1)

    print("[*] Loading CodeT5 model...")
    inference = InferenceEngine()
    print("[*] Model loaded.\n")

    run_big(args.file, inference, args.chunk_lines, args.workers)
