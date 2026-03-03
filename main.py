# Author: Neev Modi

import argparse
import sys
import os
from src.ast_parser import ASTParser
from src.feature_extractor import FeatureExtractor
from src.scanner import Scanner
from src.enrichment import PromptEnricher
from src.inference import InferenceEngine

def analyze_file(file_path):
    print(f"[*] Analyzing {file_path}...")

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            code = f.read()
    except Exception as e:
        print(f"[!] Error reading file: {e}")
        return

    ext = os.path.splitext(file_path)[1].lower()
    lang_map = {'.py': 'python', '.java': 'java', '.js': 'javascript', '.c': 'c'}
    language = lang_map.get(ext)

    if not language:
        print(f"[!] Unsupported extension: {ext}")
        return

    print("[*] Parsing AST and extracting features...")
    ast_parser = ASTParser()
    feature_extractor = FeatureExtractor()

    try:
        tree = ast_parser.parse(code, language)
        features = feature_extractor.extract_features(tree, code, language)
    except Exception as e:
        print(f"[!] AST Parsing failed: {e}")
        features = {}

    print("[*] Running Security Scan...")
    scanner = Scanner()
    findings, risk_score = scanner.scan_file(file_path)

    print("[*] Generating NLP Summary...")
    enricher = PromptEnricher()
   # prompt = enricher.construct_prompt(findings, features, code)

    inference = InferenceEngine()
    summary = inference.generate_summary(prompt)

    print("\n" + "="*50)
    print(f"SECURITY REPORT: {file_path}")
    print("="*50)
    print(f"Risk Score: {risk_score}/10.0")
    print("-" * 20)
    print("Code Summary & Security Implications:")
    print(summary)
    print("-" * 20)
    print("Detailed Findings:")
    for f in findings:
        print(f"- [{f['severity']}] {f['message']} (Line {f['line']})")
    print("="*50)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NLP-Based Security Code Summarizer")
    parser.add_argument("--file", required=True, help="Path to source code file")
    args = parser.parse_args()

    analyze_file(args.file)
