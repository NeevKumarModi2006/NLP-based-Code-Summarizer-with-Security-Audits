# Author: Neev Modi

import os
import sys
import json

sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

try:
    from src.ast_parser import ASTParser
    from src.feature_extractor import FeatureExtractor
except ImportError as e:
    print(f"Error importing modules: {e}")
    sys.exit(1)

def run_demo(target_dir):
    output_dir = "outputs"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"=> Created output directory: {output_dir}")

    output_file_path = os.path.join(output_dir, "results.txt")

    parser = ASTParser()
    extractor = FeatureExtractor()

    with open(output_file_path, 'w', encoding='utf-8') as out:
        out.write("="*50 + "\n")
        out.write(f"PHASE 3 DELIVERABLES DEMO - BATCH REPORT\n")
        out.write("="*50 + "\n\n")

    if not os.path.exists(target_dir):
        print(f"!! Target directory not found: {target_dir}")
        return

    files = [f for f in os.listdir(target_dir) if os.path.isfile(os.path.join(target_dir, f))]

    count = 0
    for filename in files:
        target_file = os.path.join(target_dir, filename)

        ext = os.path.splitext(target_file)[1].lower()
        lang_map = {'.py': 'python', '.java': 'java', '.js': 'javascript', '.c': 'c'}
        language = lang_map.get(ext)

        if not language:
            continue

        count += 1
        print(f"=> Analyzing file {count}: {filename}")

        try:
            with open(target_file, 'r', encoding='utf-8', errors='ignore') as f:
                code_content = f.read()

            tree = parser.parse(code_content, language)
            root_node = tree.root_node

            def print_node(node, depth=0):
                if depth > 5: return "..."
                out = "  " * depth + f"{node.type} ({node.start_point} - {node.end_point})\n"
                for child in node.children:
                    out += print_node(child, depth + 1)
                return out

            ast_dump = print_node(root_node)

            features = extractor.extract_features(tree, code_content, language)

            with open(output_file_path, 'a', encoding='utf-8') as out:
                out.write("*"*50 + "\n")
                out.write(f"FILE: {filename}\n")
                out.write("*"*50 + "\n\n")

                out.write("-" * 20 + "\n")
                out.write("1. AST PARSER OUTPUT (Tree Structure)\n")
                out.write("-" * 20 + "\n")
                out.write(f"{ast_dump[:2000]} ... (truncated)\n\n")

                out.write("-" * 20 + "\n")
                out.write("2. EXTRACTED FEATURES (JSON)\n")
                out.write("-" * 20 + "\n")
                out.write(json.dumps(features, indent=4))
                out.write("\n\n")
                out.write("\n\n")

        except Exception as e:
            print(f"!! Error processing {filename}: {e}")

    print(f"=> Success! Processed {count} files.")
    print(f"=> Results written to: {output_file_path}")

if __name__ == "__main__":
    target_dir = "tests"
    if not os.path.exists(target_dir):
        print(f"! 'tests' directory not found. Please create it.")
    else:
        run_demo(target_dir)
