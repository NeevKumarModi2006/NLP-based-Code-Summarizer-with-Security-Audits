
import sys
import os

# Add src to path
sys.path.append(os.getcwd())

from src.scanner import Scanner

def test_risk_logic():
    scanner = Scanner()
    dummy_path = "test.py" # File path shouldn't matter anymore
    
    scenarios = [
        ("Single ERROR", [{'severity': 'ERROR'}], 7.0),
        ("Two ERRORs", [{'severity': 'ERROR'}, {'severity': 'ERROR'}], 8.0),
        ("ERROR + WARNING", [{'severity': 'ERROR'}, {'severity': 'WARNING'}], 7.5),
        ("Single WARNING", [{'severity': 'WARNING'}], 4.0),
        ("Two WARNINGs", [{'severity': 'WARNING'}, {'severity': 'WARNING'}], 4.5),
        ("Single INFO", [{'severity': 'INFO'}], 1.0),
        ("Mixed Bag", [{'severity': 'INFO'}, {'severity': 'ERROR'}, {'severity': 'WARNING'}], 7.6), # 7.0 (Base ERR) + 0.5 (WARN) + 0.1 (INFO)
        ("Empty", [], 0.0)
    ]
    
    print("--- Testing Risk Score Logic ---")
    all_passed = True
    for name, findings, expected in scenarios:
        score = scanner._calculate_risk_score(findings, dummy_path)
        if score == expected:
            print(f"✅ {name}: Got {score} (Expected {expected})")
        else:
            print(f"❌ {name}: Got {score} (Expected {expected})")
            all_passed = False
            
    if all_passed:
        print("\nAll tests passed!")
    else:
        print("\nSome tests failed.")

if __name__ == "__main__":
    test_risk_logic()
