import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.enrichment import PromptEnricher
from src.inference import InferenceEngine

def test_nlp():
    print("Loading Model...")
    inference = InferenceEngine()
    enricher = PromptEnricher()
    
    code = """
def calculate_area(radius):
    import math
    if radius < 0:
        return 0
    return math.pi * radius * radius
    """
    
    findings = [] # Safe file
    features = {}
    
    print("\nConstructing Prompt...")
    prompt = enricher.construct_prompt(findings, features, code)
    print(f"Prompt:\n---\n{prompt}\n---")
    
    print("\nGenerating Summary...")
    try:
        summary = inference.generate_summary(prompt)
        print(f"\n[FINAL SUMMARY]:\n{summary}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_nlp()
