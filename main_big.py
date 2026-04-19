
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

    return _line_window_chunks(code, chunk_lines)


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


def meta_summarize(chunk_results: list, inference: InferenceEngine) -> str:
    """this will combine all per-chunk summaries and run CodeT5 a second time for a whole-file narrative."""
    parts = []
    for r in chunk_results:
        label = risk_label(r['risk_score'])
        parts.append(
            f"[{r['name']}] Risk={label}({r['risk_score']}/10): {r['summary']}"
        )

    combined = " | ".join(parts)
    meta_prompt = f"The following components are performed in this file: {combined}. Based on these, the main focus of this entire module is to"[:900]

    try:
        return inference.generate_summary(meta_prompt, max_length=180)
    except Exception:
        return "Meta-summary generation failed."


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
    meta = meta_summarize(chunk_results, inference)
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
