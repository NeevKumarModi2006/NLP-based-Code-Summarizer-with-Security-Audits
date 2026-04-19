
import os
import sys
import subprocess
from src.ast_parser import ASTParser
from src.feature_extractor import FeatureExtractor
from src.scanner import Scanner

def debug_step_1_ast(file_path, code):
    print("\n[DEBUG] === STEP 1: AST & Feature Extraction ===")
    print(f"[INPUT] File: {file_path}")
    
    try:
        ast_parser = ASTParser()
        feature_extractor = FeatureExtractor()
        
        # Parse
        print("[ACTION] Parsing AST...")
        tree = ast_parser.parse(code, 'python')
        print(f"[OUTPUT] AST Root Node: {tree.root_node}")

        # Extract
        print("[ACTION] Extracting Features...")
        features = feature_extractor.extract_features(tree, code, 'python')
        print(f"[OUTPUT] Extracted Features: {features}")
        
        # Validation
        if 'subprocess.Popen' in features['sinks'] or 'eval' in features['sinks']:
            print("[SUCCESS] Sinks detected.")
        else:
            print("[FAILURE] Sinks NOT detected. Check FeatureExtractor.")
            
        return features
    except Exception as e:
        print(f"[ERROR] Step 1 Failed: {e}")
        sys.exit(1)

def debug_step_2_scanner(file_path):
    print("\n[DEBUG] === STEP 2: Semgrep Scanner ===")
    print(f"[INPUT] Scanning File: {file_path}")
    
    scanner = Scanner()
    
    # Run Scan
    print("[ACTION] Running Scanner.scan_file()...")
    findings, risk = scanner.scan_file(file_path)
    
    print(f"[OUTPUT] Findings Count: {len(findings)}")
    print(f"[OUTPUT] Risk Score: {risk}")
    
    if len(findings) > 0:
        print("[SUCCESS] Findings found (Semgrep or Fallback).")
        for f in findings:
            print(f" - [{f['severity']}] {f['message']}")
        return findings, risk
    else:
        print("[FAILURE] No findings detected.")
        return [], 0.0

def debug_step_3_nlp(findings, features, code):
    print("\n[DEBUG] === STEP 3: NLP Engine ===")
    from src.enrichment import PromptEnricher
    from src.inference import InferenceEngine
    
    # Enrich
    print("[ACTION] Constructing Prompt...")
    enricher = PromptEnricher()
    prompt = enricher.construct_prompt(findings, features, code)
    print(f"[OUTPUT] Prompt Preview:\n{prompt[:300]}...")
    
    # Validation: Check Prompt Structure (Simplified)
    if "Summarize:" in prompt and "Security findings:" in prompt.lower():
        print("[SUCCESS] Prompt follows simplified template.")
    else:
        print(f"[FAILURE] Prompt malformed. Got: {prompt[:100]}")
        
    # Inference
    print("[ACTION] Running CodeT5 Inference (Strict Parameters)...")
    try:
        inference = InferenceEngine()
        summary = inference.generate_summary(prompt)
        print(f"\n[OUTPUT] Summary:\n{summary}")
        
    except Exception as e:
        print(f"[FAILURE] NLP Engine Crashed: {e}")

if __name__ == "__main__":
    target_file = "dangerous.py"
    if not os.path.exists(target_file):
        print(f"[ERROR] {target_file} not found.")
        sys.exit(1)
        
    with open(target_file, 'r') as f:
        code_content = f.read()

    # Step 1
    features = debug_step_1_ast(target_file, code_content)
    
    # Step 2
    findings, risk = debug_step_2_scanner(target_file)
    
    # Step 3
    if findings:
        debug_step_3_nlp(findings, features, code_content)
    else:
        print("\n[STOP] Skipping Step 3 because Step 2 failed (no findings).")
