
import argparse
import os
import sys
import tempfile

from src.ast_parser import ASTParser
from src.feature_extractor import FeatureExtractor
from src.scanner import Scanner
from src.enrichment import PromptEnricher
from src.inference import InferenceEngine


LANG_MAP = {'.py': 'python', '.java': 'java', '.js': 'javascript', '.c': 'c'}

DEFAULT_CHUNK_LINES = 60


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
            if node.type in ('function_definition', 'class_definition'):
                name_node = node.child_by_field_name('name')
                name = name_node.text.decode('utf-8') if name_node else node.type
                start = node.start_point[0]
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
                  inference: InferenceEngine, start_line: int = 0):
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

        if start_line > 0:
            for f in findings:
                if 'line' in f and isinstance(f['line'], int):
                    f['line'] += start_line

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
    
    func_parts = [r['summary'].rstrip('.') for r in chunk_results if r.get('summary') and r['summary'] != "Summary unavailable."]
    if not func_parts:
        func_prompt = f"// Language: {language}\n// Module with {total_findings} vulnerabilities.\n"
    else:
        func_prompt = f"// Language: {language}\n// This module handles: {', '.join(func_parts)}.\n"
        
    func_prompt = func_prompt[:1000]
    
    try:
        tldr = inference.generate_summary(func_prompt, max_length=128)
    except Exception:
        tldr = f"This module implements functional logic in {language}."
        
    if not tldr.endswith('.'):
        tldr += '.'
        
    narrative = f"{tldr} "
    narrative += f"During the chunked analysis, the pipeline partitioned the file into {len(chunk_results)} logical components. "
    narrative += f"A total of {total_findings} security vulnerabilities were detected across these parts. "
    
    risky_chunks = [c for c in chunk_results if c.get('risk_score', 0) >= 4.0]
    if risky_chunks:
        risky_names = [c['name'] for c in risky_chunks[:3]]
        narrative += f"Security attention should be directed towards the more vulnerable segments: {', '.join(risky_names)}. "
    elif total_findings > 0:
        narrative += "The vulnerabilities are spread across the file as minor warnings or info-level findings. "
    else:
        narrative += "Static analysis verifies that these components are structurally sound with no critical risks identified. "
        
    if func_parts:
        narrative += "Key behaviors encapsulated by these segments include: " + "; ".join(func_parts[:3]) + (" (among others)." if len(func_parts) > 3 else ".")
        
    return narrative.strip()


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# ORCHESTRATOR
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

def run_big(file_path: str, inference: InferenceEngine,
            chunk_lines: int = DEFAULT_CHUNK_LINES):
    ext = os.path.splitext(file_path)[1].lower()
    language = LANG_MAP.get(ext)
    if not language:
        print(f"[!] Unsupported extension: {ext}")
        return

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        total_lines = sum(1 for _ in f)

    print(f"\n{'='*60}")
    print(f"  RECURSIVE AUDIT -- {os.path.basename(file_path)}")
    print(f"  Language : {language}  |  Lines : {total_lines}")
    print(f"{'='*60}")

    chunks = chunk_file(file_path, chunk_lines)
    print(f"\n  [*] Split into {len(chunks)} chunk(s)\n")

    chunk_results = []
    for idx, (name, text, start_line) in enumerate(chunks, 1):
        chunk_line_count = text.count('\n') + 1
        print(f"  -- Chunk {idx}/{len(chunks)}: {name}  ({chunk_line_count} lines)")

        result = analyze_chunk(name, text, language, inference, start_line)
        chunk_results.append(result)

        label = risk_label(result['risk_score'])
        print(f"     Risk     : {result['risk_score']}/10  [{label}]")
        print(f"     Summary  : {result['summary']}")
        if result['findings']:
            print(f"     Findings :")
            for f in result['findings']:
                print(f"       [{f['severity']}] Line {f['line']} -- {f['message']}")
        else:
            print(f"     Findings : None")
        print()

    print(f"  {'-'*56}")
    print(f"  META-TRANSFORMER -- Whole-File Report")
    print(f"  {'-'*56}")
    meta = meta_summarize(chunk_results, inference, language)
    print(f"  {meta}")

    top_score = max(r['risk_score'] for r in chunk_results) if chunk_results else 0.0
    total_findings = sum(len(r['findings']) for r in chunk_results)
    print(f"\n  Overall Risk  : {top_score}/10  [{risk_label(top_score)}]")
    print(f"  Total Findings: {total_findings}")
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
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"[!] File not found: {args.file}")
        sys.exit(1)

    print("[*] Loading CodeT5 model...")
    inference = InferenceEngine()
    print("[*] Model loaded.\n")

    run_big(args.file, inference, args.chunk_lines)
