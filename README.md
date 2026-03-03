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
[Security Report + Risk Score]
```

---

## Stage Details

### Stage 1 — AST Parsing & Feature Extraction

**Module:** `src/ast_parser.py`, `src/feature_extractor.py`

- The source file is parsed into an **Abstract Syntax Tree (AST)** using [Tree-sitter](https://tree-sitter.github.io/tree-sitter/).
- Supported languages: Python, Java, JavaScript, C.
- Tree-sitter S-expression **queries** are run on the AST to extract:
  - **Function calls** (`@func` captures)
  - **Branch points** (`@branch` captures) — `if`, `for`, `while`, `switch`, `catch`, boolean operators
- Extracted calls are matched against predefined **sources** (user input entry points) and **sinks** (dangerous functions).
- **Cyclomatic Complexity** is computed from total branch count.

**Sources detected (examples):**

| Language | Sources |
|---|---|
| Python | `input`, `sys.argv`, `request.args`, `open` |
| JavaScript | `prompt`, `req.body`, `process.argv` |
| Java | `Scanner`, `System.in`, `getParameter` |
| C | `scanf`, `gets`, `read` |

**Sinks detected (examples):**

| Language | Sinks |
|---|---|
| Python | `eval`, `exec`, `os.system`, `pickle.loads`, `subprocess.Popen` |
| JavaScript | `eval`, `document.write`, `child_process.exec`, `element.innerHTML` |
| Java | `Runtime.exec`, `ProcessBuilder`, `Statement.execute` |
| C | `system`, `strcpy`, `sprintf`, `gets`, `popen` |

---

### Stage 2 — Security Scanning

**Module:** `src/scanner.py`

- Runs **Semgrep** static analysis rules on the file for known vulnerability patterns.
- Falls back to AST/Regex-based scanning when Semgrep is unavailable.
- Returns a list of **findings** with severity (`ERROR`, `WARNING`, `INFO`), message, and line number.
- Computes a **Risk Score** from 0.0 to 10.0 based on finding severity counts.

---

### Stage 3 — Load CodeT5 Model

**Module:** `src/inference.py`

- Loads **Salesforce/codet5-base-multi-sum** from HuggingFace Transformers.
- Model is cached after first load (`@st.cache_resource`) to avoid repeated loading.
- Automatically uses GPU (`cuda`) if available, otherwise falls back to CPU.

---

### Stage 4 — Prompt Engineering

**Module:** `src/enrichment.py`

- Constructs a structured **prompt** by combining:
  - The raw source code
  - Extracted features (sources, sinks, complexity)
  - Security findings from Stage 2
- The enriched prompt gives the NLP model full context about the code's security posture.

---

### Stage 5 — AI Summary Generation

**Module:** `src/inference.py` → `InferenceEngine.generate_summary()`

- The enriched prompt is tokenized (max 512 tokens) and fed into CodeT5.
- Uses **beam search** (`num_beams=4`) for higher-quality generation.
- Decodes the output into a plain-English security summary.

---

## Output

After the pipeline completes, the UI displays:

| Section | Description |
|---|---|
| **Risk Score Gauge** | Visual 0–10 score with severity label (LOW / MEDIUM / HIGH / CRITICAL) |
| **AI-Generated Summary** | Plain-English explanation of what the code does and its security implications |
| **Vulnerability Findings** | Per-finding cards with severity, message, and line number |
| **AST Feature Extraction** | Detected data sources, dangerous sinks, and cyclomatic complexity |

---

## Project Structure

```
CD/
|-- main.py                  # CLI entry point for single-file analysis
|-- demo_phase.py            # Batch demo runner for the tests/ directory
|-- requirements.txt         # Python dependencies
|-- .gitignore
|-- README.md
|
|-- src/
|   |-- ast_parser.py        # Tree-sitter AST parser (4 languages)
|   |-- feature_extractor.py # Query-based source/sink/complexity extraction
|   |-- scanner.py           # Semgrep + fallback security scanner
|   |-- enrichment.py        # Prompt constructor
|   |-- inference.py         # CodeT5 model wrapper
|   |-- rules.yaml           # Custom Semgrep rules
|
|-- web/
|   |-- app.py               # Streamlit frontend (main UI)
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

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the web UI

```bash
streamlit run web/app.py
```

### 4. Run CLI (single file)

```bash
python main.py --file tests/test1.py
```

### 5. Run batch demo

```bash
python demo_phase.py
```
Results are written to `outputs/results.txt`.

---

## Dependencies

| Package | Purpose |
|---|---|
| `streamlit` | Web UI framework |
| `tree-sitter` | AST parsing engine |
| `tree-sitter-python/java/c/javascript` | Language grammars |
| `transformers` | HuggingFace CodeT5 model |
| `torch` | PyTorch backend for inference |

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
