import os
import sys

# Add the project root to sys.path
sys.path.append(os.getcwd())

from main_big import chunk_file

test_files = ['tests/test_js_chunking.js', 'tests/test_java_chunking.java']

for test_file in test_files:
    print(f"\n--- Testing: {test_file} ---")
    chunks = chunk_file(test_file)
    print(f"Total chunks found: {len(chunks)}")
    for name, _, start in chunks:
        print(f"Chunk: {name} at line {start + 1}")
