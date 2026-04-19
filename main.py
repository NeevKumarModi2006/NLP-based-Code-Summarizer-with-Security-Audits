
import argparse
import sys
import os

from src.ast_parser import ASTParser
from src.feature_extractor import FeatureExtractor
from src.scanner import Scanner
from src.enrichment import PromptEnricher
from src.inference import InferenceEngine


LANG_MAP = {'.py': 'python', '.java': 'java', '.js': 'javascript', '.c': 'c'}


def risk_label(score: float) -> str:
    if score >= 8:
        return "CRITICAL"
    if score >= 5:
        return "HIGH"
    if score >= 2:
        return "MEDIUM"
    return "LOW"


def analyze_file(file_path: str, inference: InferenceEngine):
    """this will run the 5-stage pipeline on a single file."""
    print(f"\n{'='*55}")
    print(f"  Analyzing: {os.path.basename(file_path)}")
    print(f"{'='*55}")

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()
    except Exception as e:
        print(f"  [!] Error reading file: {e}")
        return

    ext = os.path.splitext(file_path)[1].lower()
    language = LANG_MAP.get(ext)
    if not language:
        print(f"  [!] Unsupported extension: {ext}")
        return

    lines = code.count('\n') + 1
    print(f"  Language : {language}")
    print(f"  Lines    : {lines}")

    print("\n  [1/5] AST Parsing & Feature Extraction ...")
    try:
        ast_parser        = ASTParser()
        feature_extractor = FeatureExtractor()
        tree     = ast_parser.parse(code, language)
        features = feature_extractor.extract_features(tree, code, language)
    except Exception as e:
        print(f"       Error: {e}")
        features = {'sources': [], 'sinks': [], 'complexity': 0}
    print("       Done")

    print("  [2/5] Security Scanner (Semgrep + Fallback) ...")
    try:
        scanner = Scanner()
        findings, risk_score = scanner.scan_file(file_path)
    except Exception as e:
        print(f"       Error: {e}")
        findings, risk_score = [], 0.0
    print("       Done")

    print("  [3/5] CodeT5 Model ready")

    print("  [4/5] Prompt Engineering ...")
    enricher = PromptEnricher()
    prompt   = enricher.construct_prompt(findings, features, code)
    print("       Done")

    print("  [5/5] Generating AI Summary ...")
    try:
        summary = inference.generate_summary(prompt)
    except Exception as e:
        print(f"       Error: {e}")
        summary = "Summary generation failed."
    print("       Done")

    label = risk_label(risk_score)
    print(f"\n{'-'*55}")
    print(f"  RISK SCORE  : {risk_score}/10  [{label}]")
    print(f"{'-'*55}")

    print("\n  AI SUMMARY:")
    print(f"  {summary}")

    print(f"\n  AST FEATURES:")
    print(f"    Sources    : {features.get('sources', []) or ['none']}")
    print(f"    Sinks      : {features.get('sinks',   []) or ['none']}")
    print(f"    Complexity : {features.get('complexity', 0)}")

    print(f"\n  FINDINGS ({len(findings)}):")
    if findings:
        for f in findings:
            print(f"    [{f['severity']}] Line {f['line']} -- {f['message']}")
    else:
        print("    No vulnerabilities detected.")
    print(f"{'='*55}\n")


def scan_directory(dir_path: str, inference: InferenceEngine):
    """this will walk a directory recursively and analyze every supported file."""
    supported_exts = set(LANG_MAP.keys())
    found = []

    for root, _, files in os.walk(dir_path):
        for fname in files:
            if os.path.splitext(fname)[1].lower() in supported_exts:
                found.append(os.path.join(root, fname))

    if not found:
        print(f"[!] No supported source files found in: {dir_path}")
        return

    print(f"[*] Found {len(found)} file(s) to scan in: {dir_path}")
    for fp in found:
        analyze_file(fp, inference)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="AI Security Auditor -- CLI (mirrors web/app2.py pipeline)"
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--file",
        help="Path to a single source code file to analyze"
    )
    group.add_argument(
        "--dir",
        help="Path to a directory; all supported files inside will be scanned"
    )

    args = parser.parse_args()

    print("[*] Loading CodeT5 model (Salesforce/codet5-base-multi-sum)...")
    inference = InferenceEngine()
    print("[*] Model loaded.\n")

    if args.file:
        if not os.path.isfile(args.file):
            print(f"[!] File not found: {args.file}")
            sys.exit(1)
        analyze_file(args.file, inference)

    elif args.dir:
        if not os.path.isdir(args.dir):
            print(f"[!] Directory not found: {args.dir}")
            sys.exit(1)
        scan_directory(args.dir, inference)
