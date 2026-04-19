# NLP-Based Code Summarizer with Security Audits

**Author: Neev Modi**

An AI-powered static code analysis tool that combines Abstract Syntax Tree (AST) parsing, feature extraction, and a CodeT5 NLP model to generate human-readable security summaries of source code. Supports Python, Java, JavaScript, and C.

---

## Pipeline Overview

The tool runs a **5-stage analysis pipeline** on any uploaded source file:

```
[Source File]
      |
      v
[Stage 1] AST Parsing & Feature Extraction
      |
      v
[Stage 2] Security Scanning (Semgrep + AST/Regex Fallback)
      |
      v
[Stage 3] Load CodeT5 NLP Model
      |
      v
[Stage 4] Prompt Engineering
      |
      v
[Stage 5] AI Summary Generation
      |
      v
[Security Report + Risk Score + Energy Profile]
```

---

## Features

| Feature | Description |
|---|---|
| **Single File Audit** | Upload one file, get a full 5-stage security report |
| **Directory Bulk Scan** | Recursively scan an entire project folder |
| **Large File Audit** | AST-aware chunking for files over 200 lines with Meta-Transformer summary |
| **Energy Monitor** | Real-time CPU/Memory/Energy profiling via psutil + Intel RAPL |
| **React Dashboard** | Interactive CPU & Memory timeseries charts |
| **130 Custom Rules** | Covering 40 CWE identifiers across 4 languages |

---

## Project Structure

```
CD/
|-- main.py                  # CLI entry point for single-file analysis
|-- main_big.py              # AST-aware chunked pipeline for large files
|-- main_folder.py           # Directory bulk scan orchestrator
|-- rules.yaml               # 130 Semgrep rules (40 CWEs, 4 languages)
|-- requirements.txt         # Python dependencies
|-- cwe_report.txt           # CWE coverage report
|-- .gitignore
|-- README.md
|
|-- src/
|   |-- ast_parser.py        # Tree-sitter AST parser (4 languages)
|   |-- feature_extractor.py # Source/sink/complexity extraction
|   |-- scanner.py           # Semgrep + regex fallback scanner
|   |-- enrichment.py        # Prompt constructor
|   |-- inference.py         # CodeT5 model wrapper
|
|-- web/
|   |-- app.py               # Streamlit frontend (3-tab dashboard)
|   |-- energy_monitor.py    # Real-time hardware profiler (psutil/RAPL/TDP)
|   |-- frontend/            # React energy visualization dashboard
|       |-- src/App.jsx       # Main React component (charts)
|       |-- package.json
|       |-- vite.config.js
|
|-- tests/                   # Sample vulnerable code files for testing
|-- outputs/                 # Batch analysis results (gitignored)
```

---

## Setup & Installation

### 1. Clone the repository

```bash
git clone https://github.com/NeevKumarModi2006/NLP-BASED-CODE-SUMMARIZER-WITH-SECURITY-AUDITS.git
cd NLP-BASED-CODE-SUMMARIZER-WITH-SECURITY-AUDITS
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. Install React frontend dependencies

```bash
cd web/frontend
npm install
cd ../..
```

### 4. Run the web UI

```bash
# Terminal 1: Start React energy dashboard
cd web/frontend && npm run dev

# Terminal 2: Start Streamlit
python -m streamlit run web/app.py
```

### 5. Run CLI (single file)

```bash
python main.py --file tests/test1.py
```

---

## Rule Coverage

| Language | Rules |
|---|---|
| Python | 47 |
| JavaScript | 35 |
| C | 24 |
| Java | 24 |
| **Total** | **130 rules across 40 CWEs** |

---

## Dependencies

| Package | Purpose |
|---|---|
| `streamlit` | Web UI framework |
| `tree-sitter` | AST parsing engine |
| `tree-sitter-python/java/c/javascript` | Language grammars |
| `transformers` | HuggingFace CodeT5 model |
| `torch` | PyTorch backend for inference |
| `psutil` | CPU/Memory/Energy monitoring |
| `semgrep` | Static analysis engine |

---

## Supported Languages

| Language | Extension |
|---|---|
| Python | `.py` |
| Java | `.java` |
| JavaScript | `.js` |
| C | `.c` |

---

## License

This project was developed as a Compiler Design course project.  
**Author: Neev Modi**
