import os
import sys
import torch
import tempfile
import time
import json

if hasattr(torch, 'classes'):
    torch.classes.__path__ = [os.path.join(torch.__path__[0], torch.classes.__file__)]

import streamlit as st

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.ast_parser import ASTParser
from src.feature_extractor import FeatureExtractor
from src.scanner import Scanner
from src.enrichment import PromptEnricher
from src.inference import InferenceEngine
from web.energy_monitor import measure_energy

st.set_page_config(
    page_title="AI Security Auditor",
    page_icon="https://api.iconify.design/tabler:shield-lock.svg",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown(
    '<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@3.24.0/dist/tabler-icons.min.css">',
    unsafe_allow_html=True
)

st.markdown("""
<style>
/* ═══════════════════════════════════════════════════
   DESIGN TOKENS
   ═══════════════════════════════════════════════════ */
:root {
    --bg:          #F8FAFC;
    --surface:     #FFFFFF;
    --border:      #E2E8F0;
    --border-soft: #F1F5F9;

    --accent:      #3B82F6;
    --accent-bg:   #EFF6FF;
    --accent-rim:  #BFDBFE;

    --danger:      #EF4444;
    --danger-bg:   #FEF2F2;
    --warning:     #F59E0B;
    --warning-bg:  #FFFBEB;

    --ink:         #0F172A;
    --ink-2:       #334155;
    --ink-muted:   #64748B;
    --ink-faint:   #94A3B8;

    --mono: ui-monospace, 'SF Mono', Menlo, Consolas, monospace;
    --sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    --radius: 8px;
    --shadow-sm: 0 1px 3px rgba(15,23,42,.06), 0 1px 2px rgba(15,23,42,.04);
    --shadow-md: 0 4px 12px rgba(15,23,42,.08), 0 2px 4px rgba(15,23,42,.04);
}

/* ═══════════════════════════════════════════════════
   BASE RESETS
   ═══════════════════════════════════════════════════ */
html, body { font-family: var(--sans); }
.stApp    { background-color: var(--bg); }
.block-container {
    padding-top: 2rem;
    max-width: 1400px;
}
#MainMenu, footer, header { visibility: hidden; }

/* ═══════════════════════════════════════════════════
   SIDEBAR
   ═══════════════════════════════════════════════════ */
section[data-testid="stSidebar"] {
    background: var(--surface);
    border-right: 1px solid var(--border);
}

/* ═══════════════════════════════════════════════════
   STREAMLIT WIDGET OVERRIDES  (scoped, no !important)
   ═══════════════════════════════════════════════════ */

/* Text / markdown */
.stMarkdown p,
.stMarkdown span,
.stMarkdown li,
.stMarkdown h1,
.stMarkdown h2,
.stMarkdown h3,
.stMarkdown h4 { color: var(--ink); }

/* Labels */
.stTextInput > label > div > p,
.stSelectbox  > label > div > p { color: var(--ink); }

/* Text input field */
.stTextInput input {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    color: var(--ink);
}
.stTextInput input:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(59,130,246,.12);
    outline: none;
}

/* Code blocks */
.stCodeBlock {
    border-radius: var(--radius);
    border: 1px solid var(--border);
}

/* Expander */
details > summary p { color: var(--ink); font-weight: 600; }

/* Tabs */
[data-testid="stTabs"] [role="tab"] {
    color: var(--ink-muted);
    font-weight: 600;
    font-size: 0.9rem;
}
[data-testid="stTabs"] [role="tab"][aria-selected="true"] {
    color: var(--ink);
    border-bottom: 2px solid var(--accent);
}
[data-testid="stTabs"] [role="tab"]:hover {
    color: var(--ink);
    background: var(--bg);
    border-radius: 6px 6px 0 0;
}

/* Buttons — Primary */
[data-testid="stBaseButton-primary"] button {
    background: var(--accent);
    color: #fff;
    font-weight: 600;
    border: none;
    border-radius: var(--radius);
    padding: 0.6rem 2rem;
    transition: background .15s, box-shadow .15s;
}
[data-testid="stBaseButton-primary"] button:hover {
    background: #2563EB;
    box-shadow: var(--shadow-md);
}

/* Buttons — Secondary */
[data-testid="stBaseButton-secondary"] button {
    background: var(--surface);
    color: var(--ink);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    font-weight: 600;
    transition: border-color .15s, background .15s;
}
[data-testid="stBaseButton-secondary"] button:hover {
    background: var(--bg);
    border-color: var(--accent);
}

/* Link button */
[data-testid="stLinkButton"] a {
    background: var(--surface);
    color: var(--ink);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    font-weight: 600;
}
[data-testid="stLinkButton"] a:hover {
    background: var(--bg);
    border-color: var(--accent);
}

/* Metric widget */
[data-testid="stMetricValue"] { color: var(--ink); }
[data-testid="stMetricLabel"] > div > p { color: var(--ink-muted); }

/* Spinner */
[data-testid="stSpinner"] p { color: var(--ink-muted); }

/* Alerts */
[data-testid="stAlert"] p { color: var(--ink); }

/* Toast */
[data-testid="stToast"] p { color: var(--ink); }

/* Progress */
[data-testid="stProgress"] p { color: var(--ink-muted); }

/* File uploader — keep dark bg for contrast on the drop zone */
[data-testid="stFileUploadDropzone"] {
    background: #1E2130;
    border: 2px dashed #3D4560;
    border-radius: var(--radius);
}
[data-testid="stFileUploadDropzone"] * { color: #CBD5E1; }

[data-testid="stBaseButton-secondary"][data-test-id*="upload"] button,
[data-testid="stFileUploader"] [data-testid="stBaseButton-secondary"] button {
    background: #2A2F45;
    color: #CBD5E1;
    border-color: #3D4560;
}

/* ═══════════════════════════════════════════════════
   SIDEBAR COMPONENTS
   ═══════════════════════════════════════════════════ */
.sb-section-title {
    font-size: 0.65rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 2px;
    color: var(--ink-muted);
    margin: 18px 0 8px 0;
    padding-bottom: 6px;
    border-bottom: 1px solid var(--accent-rim);
}
.sb-lang-row { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 4px; }
.sb-lang {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 4px 10px;
    font-size: 0.78rem;
    color: var(--ink);
    display: flex;
    align-items: center;
    gap: 5px;
}
.sb-step-row {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 5px 0;
    font-size: 0.83rem;
    color: var(--ink);
}
.sb-step-num {
    width: 18px; height: 18px;
    border-radius: 50%;
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--ink-muted);
    font-size: 0.65rem;
    font-weight: 700;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
}
.model-pill {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 10px 14px;
    font-family: var(--mono);
    font-size: 0.77rem;
    color: var(--ink);
    word-break: break-all;
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 6px 0 14px 0;
}
.model-pill .ti { color: var(--ink-muted); font-size: 1rem; flex-shrink: 0; }

/* ═══════════════════════════════════════════════════
   HERO BANNER
   ═══════════════════════════════════════════════════ */
.hero-banner {
    background: var(--surface);
    border: 1px solid var(--accent-rim);
    border-radius: var(--radius);
    padding: 40px 48px;
    margin-bottom: 32px;
    position: relative;
    overflow: hidden;
    box-shadow: var(--shadow-sm);
}
.hero-banner::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    background: var(--accent);
}
.hero-title {
    font-size: 2.8rem;
    font-weight: 900;
    letter-spacing: -1px;
    color: var(--ink);
    margin: 0 0 8px 0;
    display: flex;
    align-items: center;
    gap: 14px;
}
.hero-title-icon { color: var(--accent); font-size: 2.4rem; }
.hero-sub { font-size: 1rem; color: var(--ink-muted); font-weight: 400; margin: 0; }

/* ═══════════════════════════════════════════════════
   METRIC CARDS
   ═══════════════════════════════════════════════════ */
.metric-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 20px 24px;
    text-align: center;
    box-shadow: var(--shadow-sm);
    transition: box-shadow .15s;
}
.metric-card:hover { box-shadow: var(--shadow-md); }
.metric-value {
    font-size: 2rem;
    font-weight: 800;
    line-height: 1;
    color: var(--ink);
}
.metric-label {
    font-size: 0.75rem;
    color: var(--ink-muted);
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-top: 6px;
}

/* ═══════════════════════════════════════════════════
   FEATURE CARDS (homepage)
   ═══════════════════════════════════════════════════ */
.feat-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 24px 20px;
    text-align: center;
    box-shadow: var(--shadow-sm);
    transition: border-color .15s, box-shadow .15s;
}
.feat-card:hover {
    border-color: var(--accent-rim);
    box-shadow: var(--shadow-md);
}
.feat-icon { font-size: 2rem; margin-bottom: 12px; display: block; color: var(--accent); }
.feat-title { font-weight: 700; font-size: 1rem; margin-bottom: 6px; color: var(--ink); }
.feat-desc  { font-size: 0.8rem; color: var(--ink-muted); line-height: 1.5; }

/* ═══════════════════════════════════════════════════
   RISK GAUGE
   ═══════════════════════════════════════════════════ */
.gauge-container {
    background: var(--surface);
    border-radius: var(--radius);
    border: 1px solid var(--border);
    padding: 28px;
    text-align: center;
    margin-bottom: 20px;
    box-shadow: var(--shadow-sm);
}
.gauge-label {
    font-size: 0.75rem;
    color: var(--ink-muted);
    text-transform: uppercase;
    letter-spacing: 1.5px;
    margin-bottom: 12px;
}
.gauge-score {
    font-size: 4rem;
    font-weight: 900;
    line-height: 1;
    font-family: var(--mono);
}
.gauge-score-denom {
    font-size: 1.5rem;
    color: var(--ink-faint);
}
.gauge-bar-bg {
    background: var(--bg);
    border-radius: 99px;
    height: 10px;
    margin: 16px 0 8px 0;
    overflow: hidden;
    border: 1px solid var(--border);
}
.gauge-bar-fill { height: 100%; border-radius: 99px; }
.gauge-range { font-size: 0.75rem; color: var(--ink-muted); }

/* ═══════════════════════════════════════════════════
   FINDING CARDS
   ═══════════════════════════════════════════════════ */
.finding-card {
    border-radius: var(--radius);
    padding: 14px 18px;
    margin-bottom: 10px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-left: 4px solid var(--border);
}
.finding-HIGH   { border-left-color: var(--danger);  background: var(--danger-bg); }
.finding-MEDIUM { border-left-color: var(--warning); background: var(--warning-bg); }
.finding-LOW    { border-left-color: var(--accent);  background: var(--accent-bg); }

.finding-header {
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    font-weight: 700;
    margin-bottom: 4px;
    display: flex;
    align-items: center;
    gap: 6px;
}
.finding-msg  { font-size: 0.9rem; color: var(--ink); }
.finding-line {
    font-size: 0.75rem;
    color: var(--ink-muted);
    margin-top: 4px;
    font-family: var(--mono);
}

/* ═══════════════════════════════════════════════════
   TAGS
   ═══════════════════════════════════════════════════ */
.tag-container { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }
.tag {
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--ink);
    border-radius: 6px;
    padding: 3px 10px;
    font-size: 0.78rem;
    font-family: var(--mono);
}
.tag.sink    { border-color: var(--danger); color: var(--danger); background: var(--danger-bg); }
.tag.none    { color: var(--ink-faint); }

/* ═══════════════════════════════════════════════════
   SECTION HEADERS
   ═══════════════════════════════════════════════════ */
.section-header {
    font-size: 0.8rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: var(--ink);
    padding: 0 0 8px 0;
    border-bottom: 2px solid var(--border);
    margin-bottom: 16px;
    display: flex;
    align-items: center;
    gap: 8px;
}
.section-header i { color: var(--accent); }

/* ═══════════════════════════════════════════════════
   SUMMARY BOX
   ═══════════════════════════════════════════════════ */
.summary-box {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 20px 24px;
    font-size: 0.96rem;
    line-height: 1.7;
    color: var(--ink);
    box-shadow: var(--shadow-sm);
}

/* ═══════════════════════════════════════════════════
   PIPELINE STEPS
   ═══════════════════════════════════════════════════ */
.pipeline-step {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 14px;
    background: var(--surface);
    border-radius: var(--radius);
    margin-bottom: 8px;
    font-size: 0.85rem;
    border: 1px solid var(--border);
    color: var(--ink);
}
.step-status {
    margin-left: auto;
    font-size: 0.75rem;
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 4px;
}
.step-done .step-status { color: var(--accent); }
.step-run  .step-status { color: var(--accent); }
.step-wait .step-status { color: var(--ink-faint); }

/* ═══════════════════════════════════════════════════
   TABLER ICON HELPERS
   ═══════════════════════════════════════════════════ */
.ti     { vertical-align: -0.125em; }
.ti-lg  { font-size: 1.4rem; vertical-align: -0.2em; }
.ti-hero { font-size: 2.4rem; vertical-align: -0.25em; margin-right: 10px; }
.ti-step { font-size: 1rem; vertical-align: -0.12em; }
</style>
""", unsafe_allow_html=True)


@st.cache_resource(show_spinner=False)
def load_inference_engine():
    return InferenceEngine()

def risk_color(score: float) -> str:
    if score >= 8: return "var(--danger)"
    if score >= 5: return "var(--warning)"
    if score >= 2: return "var(--accent)"
    return "var(--ink-muted)"

def risk_label(score: float) -> str:
    if score >= 8:  return "CRITICAL"
    if score >= 5:  return "HIGH"
    if score >= 2:  return "MEDIUM"
    return "LOW"

def severity_icon_html(sev: str) -> str:
    icons = {
        "HIGH":   '<i class="ti ti-circle-x"></i>',
        "MEDIUM": '<i class="ti ti-alert-triangle"></i>',
        "LOW":    '<i class="ti ti-info-circle"></i>',
    }
    return icons.get(sev.upper(), '<i class="ti ti-circle"></i>')


def render_gauge(score: float):
    color = risk_color(score)
    label = risk_label(score)
    pct   = int((score / 10.0) * 100)
    st.markdown(f"""
    <div class="gauge-container">
        <div class="gauge-label"><i class="ti ti-shield-half-filled" style="margin-right:5px;"></i>Risk Score</div>
        <div class="gauge-score" style="color:{color};">{score}<span class="gauge-score-denom">/10</span></div>
        <div style="font-size:0.8rem;font-weight:700;letter-spacing:2px;color:{color};margin-top:4px;">{label}</div>
        <div class="gauge-bar-bg">
            <div class="gauge-bar-fill" style="width:{pct}%;background-color:{color};"></div>
        </div>
        <div class="gauge-range">0 &mdash; Safe &nbsp;&nbsp;&nbsp; 10 &mdash; Critical</div>
    </div>""", unsafe_allow_html=True)


def render_finding(f: dict):
    from src.vuln_classifier import normalize_severity
    sev   = normalize_severity(f.get('severity', 'INFO')).upper()
    msg   = f.get('message', '')
    line  = f.get('line', '?')
    icon  = severity_icon_html(sev)
    
    hdr_color = {
        "HIGH":   "var(--danger)",
        "MEDIUM": "var(--warning)",
    }.get(sev, "var(--accent)")

    st.markdown(f"""
    <div class="finding-card finding-{sev}">
        <div class="finding-header" style="color:{hdr_color};">{icon} {sev} VULNERABILITY</div>
        <div class="finding-msg">{msg}</div>
        <div class="finding-line"><i class="ti ti-code" style="margin-right:4px;"></i>Line {line}</div>
    </div>""", unsafe_allow_html=True)


def render_tags(items: list, kind: str = "source"):
    if not items:
        st.markdown('<div class="tag-container"><span class="tag none">none detected</span></div>', unsafe_allow_html=True)
        return
    tags_html = "".join(f'<span class="tag {kind}">{x}</span>' for x in set(items))
    st.markdown(f'<div class="tag-container">{tags_html}</div>', unsafe_allow_html=True)


# ═══════════════════════════════════════════════════
# SIDEBAR
# ═══════════════════════════════════════════════════
with st.sidebar:
    st.markdown("""
    <div style="font-size:1.1rem;font-weight:800;color:var(--ink);display:flex;align-items:center;gap:8px;padding-bottom:12px;border-bottom:1px solid var(--border);">
        <i class="ti ti-settings-2" style="color:var(--accent);font-size:1.2rem;"></i> Settings
    </div>
    
    <div class="sb-section-title">Supported Languages</div>
    <div class="sb-lang-row">
        <span class="sb-lang"><i class="ti ti-brand-python" style="color:var(--accent);"></i> Python</span>
        <span class="sb-lang"><i class="ti ti-coffee" style="color:var(--accent);"></i> Java</span>
        <span class="sb-lang"><i class="ti ti-brand-javascript" style="color:var(--accent);"></i> JS</span>
        <span class="sb-lang"><i class="ti ti-letter-c" style="color:var(--accent);"></i> C</span>
    </div>
    
    <div class="sb-section-title">Pipeline Stages</div>
    <div class="sb-step-row"><span class="sb-step-num">1</span><i class="ti ti-binary-tree" style="color:var(--accent);"></i> AST Parsing</div>
    <div class="sb-step-row"><span class="sb-step-num">2</span><i class="ti ti-cpu" style="color:var(--accent);"></i> Feature Extraction</div>
    <div class="sb-step-row"><span class="sb-step-num">3</span><i class="ti ti-shield-search" style="color:var(--accent);"></i> Security Scanning</div>
    <div class="sb-step-row"><span class="sb-step-num">4</span><i class="ti ti-pencil" style="color:var(--accent);"></i> Prompt Engineering</div>
    <div class="sb-step-row"><span class="sb-step-num">5</span><i class="ti ti-message-2" style="color:var(--accent);"></i> NLP Inference</div>
    
    <div class="sb-section-title">Model</div>
    <div class="model-pill">
        <i class="ti ti-brain"></i>Salesforce/codet5-base-multi-sum
    </div>
    
    <div class="sb-section-title">Scanner</div>
    <div style="font-size:0.83rem;color:var(--ink);display:flex;align-items:center;gap:6px;">
        <i class="ti ti-shield-check" style="color:var(--accent);"></i> Semgrep + AST/Regex Fallback
    </div>
    
    <div class="sb-section-title">Processing</div>
    <div style="font-size:0.83rem;color:var(--ink);display:flex;align-items:center;gap:6px;">
        <i class="ti ti-cpu" style="color:var(--accent);"></i> 4 Parallel Threads (Big Files)
    </div>

    <div style="margin-top:32px; margin-bottom: 12px;">
        <div class="sb-section-title">Visualisation</div>
    </div>
    """, unsafe_allow_html=True)
    
    st.link_button("View Advanced Analytics (React Frontend)", "http://localhost:5173", use_container_width=True)
    
    st.markdown("""
    <div style="margin-top:24px;padding-top:16px;border-top:1px solid var(--border);font-size:0.7rem;color:var(--ink-muted);text-align:center;">
        <i class="ti ti-lock" style="margin-right:4px;"></i> AI Security Auditor v2.0
    </div>
    """, unsafe_allow_html=True)


# ═══════════════════════════════════════════════════
# HERO
# ═══════════════════════════════════════════════════
st.markdown("""
<div class="hero-banner">
    <div class="hero-title">
        <i class="ti ti-shield-lock hero-title-icon"></i>
        AI Security Auditor
    </div>
    <p class="hero-sub">NLP-powered code analysis &nbsp;&middot;&nbsp; AST feature extraction &nbsp;&middot;&nbsp; Real-time vulnerability detection</p>
</div>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════
# TABS + INPUTS
# ═══════════════════════════════════════════════════
tab_file, tab_dir, tab_big = st.tabs(["Single File Audit", "Directory Bulk Scan", "Large File Audit"])
uploaded_file = None
dir_path_input = ""
big_file_path  = ""
run_big_btn    = False

with tab_file:
    uploaded_file = st.file_uploader(
        "Drop a source file to begin analysis",
        type=['py', 'java', 'c', 'js'],
        help="Supported: .py .java .c .js"
    )

with tab_big:
    st.markdown("""<div style='font-size:0.85rem;color:var(--ink-muted);margin-bottom:12px;'>
        <i class='ti ti-info-circle'></i>&nbsp;
        Files over <b style='color:var(--ink);'>200 lines</b> are split into chunks via AST-aware segmentation.
        Each chunk is independently scanned and summarised, then a <b style='color:var(--ink);'>Meta-Transformer</b>
        pass produces a single whole-file narrative.
    </div>""", unsafe_allow_html=True)
    big_uploaded = st.file_uploader(
        "Browse and select a large source file",
        type=['py', 'java', 'c', 'js'],
        help="Supported: .py .java .js .c -- files over 200 lines use chunked analysis",
        key="big_uploader"
    )
    if big_uploaded:
        run_big_btn = st.button("Run Chunked Audit", type="primary", use_container_width=True)



with tab_dir:
    dir_path_input = st.text_input("Enter absolute local folder path to scan:")
    c_btn1, c_btn2 = st.columns(2)
    with c_btn1:
        run_btn = st.button("Run Full Directory Audit", type="primary", use_container_width=True)
    with c_btn2:
        demo_btn = st.button("Load Demo Directory Data (Fast)", use_container_width=True)

if not (uploaded_file or run_btn or demo_btn or run_big_btn or big_uploaded):
    st.markdown("<br>", unsafe_allow_html=True)
    c1, c2, c3, c4 = st.columns(4)
    cards = [
        ("ti-binary-tree",   "AST Analysis",   "Deep structural parsing via Tree-sitter"),
        ("ti-brain",         "AI Summaries",   "CodeT5 generates human-readable explanations"),
        ("ti-bug",           "Vuln Detection", "Semgrep + custom AST/Regex hybrid scanner"),
        ("ti-chart-bar",     "Risk Scoring",   "Quantitative 0-10 score with severity breakdown"),
    ]
    for col, (icon, title, desc) in zip([c1, c2, c3, c4], cards):
        with col:
            st.markdown(f"""
            <div class="feat-card">
                <i class="ti {icon} feat-icon"></i>
                <div class="feat-title">{title}</div>
                <div class="feat-desc">{desc}</div>
            </div>""", unsafe_allow_html=True)
    st.stop()


# ═══════════════════════════════════════════════════
# DIRECTORY SCAN
# ═══════════════════════════════════════════════════
if run_btn or demo_btn:
    if run_btn and not os.path.isdir(dir_path_input):
        st.error("Directory not found or path empty! Please provide a valid absolute directory path.")
        st.stop()
        
    st.markdown('''<div class="section-header">
        <i class="ti ti-folder"></i> Directory Scan
    </div>''', unsafe_allow_html=True)
    
    import json
    from main_folder import bulk_semgrep_scan, analyze_all_files, build_project_map
    inference = load_inference_engine()

    pipeline_ph = st.empty()
    
    if demo_btn:
        pipeline_ph.markdown("### <i class='ti ti-loader-2'></i> Loading Full Directory Demo Data...", unsafe_allow_html=True)
        time.sleep(0.5)
        demo_res_path = os.path.join(os.path.dirname(__file__), "demo_assets", "demo_results.json")
        demo_energy_path = os.path.join(os.path.dirname(__file__), "demo_assets", "demo_energy.json")
        
        with open(demo_res_path, 'r') as f:
            results_arr = json.load(f)
            
        dir_path_input = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        
        reports_dir = os.path.join(os.path.dirname(__file__), "frontend", "public", "reports")
        os.makedirs(reports_dir, exist_ok=True)
        
        import shutil
        shutil.copyfile(demo_energy_path, os.path.join(reports_dir, "latest_report.json"))
        
    else:
        pipeline_ph.markdown("### <i class='ti ti-loader-2'></i> Running Bulk Directory Scan... This may take a while.", unsafe_allow_html=True)
        with measure_energy(sample_interval_s=0.2) as col:
            col.begin_phase("Semgrep Bulk Scan")
            semgrep_map = bulk_semgrep_scan(dir_path_input)
            col.begin_phase("AI Parallel Processing")
            results_arr = analyze_all_files(dir_path_input, semgrep_map, inference)
            col.begin_phase("Map Assembly")
            project_map = build_project_map(results_arr, dir_path_input, inference)
            col.end_phase()
        
        reports_dir = os.path.join(os.path.dirname(__file__), "frontend", "public", "reports")
        os.makedirs(reports_dir, exist_ok=True)
        with open(os.path.join(reports_dir, "latest_report.json"), "w") as f:
            json.dump(col.report.to_dict(), f)
        
    pipeline_ph.empty()
    
    st.markdown('''<div class="section-header">
        <i class="ti ti-chart-bar"></i> Directory Pipeline Results
    </div>''', unsafe_allow_html=True)
    
    total_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    from src.vuln_classifier import normalize_severity
    for r in results_arr:
        if 'error' in r: continue
        for f in r.get('findings', []):
            sev = normalize_severity(f.get('severity', 'INFO')).upper()
            if sev in total_counts:
                total_counts[sev] += 1
            else:
                total_counts['LOW'] += 1
            
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f"""<div class="metric-card"><div class="metric-value">{len(results_arr)}</div><div class="metric-label">Files Scanned</div></div>""", unsafe_allow_html=True)
    with c2:
        st.markdown(f"""<div class="metric-card"><div class="metric-value" style="color:var(--danger);">{total_counts['HIGH']}</div><div class="metric-label">High Vulnerability</div></div>""", unsafe_allow_html=True)
    with c3:
        st.markdown(f"""<div class="metric-card"><div class="metric-value" style="color:var(--warning);">{total_counts['MEDIUM']}</div><div class="metric-label">Medium Vulnerability</div></div>""", unsafe_allow_html=True)
    with c4:
        st.markdown(f"""<div class="metric-card"><div class="metric-value" style="color:var(--accent);">{total_counts['LOW']}</div><div class="metric-label">Low Vulnerability</div></div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown('''<div class="section-header">
        <i class="ti ti-article"></i> Project AI Overview
    </div>''', unsafe_allow_html=True)
    
    from collections import defaultdict
    groups = defaultdict(list)
    for r in sorted(results_arr, key=lambda x: x.get('file', '')):
        if 'error' in r: continue
        rel = os.path.relpath(r['file'], dir_path_input).replace('\\', '/')
        parts = rel.split('/')
        group = parts[0] if len(parts) > 1 else 'root'
        fname = os.path.basename(r.get('file', ''))
        s = r.get('summary', '').strip()
        groups[group].append({'fname': fname, 'summary': s, 'score': r.get('risk_score', 0)})
    
    for group, entries in sorted(groups.items()):
        with st.expander(f"{group.upper()} ({len(entries)} file{'s' if len(entries)>1 else ''})"):
            for e in entries:
                st.markdown(
                    f"**{e['fname']}** &nbsp;&mdash;&nbsp; "
                    f"<span style='color:var(--ink-muted);'>{e['summary']}</span> "
                    f"<span style='color:var(--ink-muted);font-size:0.85rem;'>*(Score: {e['score']}/10)*</span>",
                    unsafe_allow_html=True
                )
    
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown('''<div class="section-header">
        <i class="ti ti-skull"></i> Top 5 Riskiest Files
    </div>''', unsafe_allow_html=True)
    ranked_risk = sorted([r for r in results_arr if 'error' not in r], key=lambda x: x.get('risk_score', 0), reverse=True)
    for r in ranked_risk[:5]:
        rel_path = os.path.relpath(r['file'], dir_path_input)
        sev = "HIGH" if r.get('risk_score',0) >= 8 else "MEDIUM" if r.get('risk_score',0) >= 5 else "LOW"
        st.markdown(f"""
        <div class="finding-card finding-{sev}">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span style="font-weight:600; font-size:0.9rem; color:var(--ink);">{rel_path}</span>
                <span style="font-family:var(--mono); font-weight:800; font-size:1rem; color:var(--ink);">{r.get('risk_score',0)}/10</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.link_button("Open Advanced Analytics (React Frontend)", "http://localhost:5173", use_container_width=True)
    st.stop()


# ═══════════════════════════════════════════════════
# LARGE FILE AUDIT
# ═══════════════════════════════════════════════════
if big_uploaded:
    LANG_MAP_BIG = {'.py': 'python', '.java': 'java', '.js': 'javascript', '.c': 'c'}

    ext_big  = os.path.splitext(big_uploaded.name)[1].lower()
    lang_big = LANG_MAP_BIG.get(ext_big)
    if not lang_big:
        st.error(f"Unsupported file type `{ext_big}`. Supported: .py .java .js .c")
        st.stop()

    big_code  = big_uploaded.getvalue().decode('utf-8', errors='ignore')
    big_lines = big_code.count('\n') + 1

    if not run_big_btn:
        left, right = st.columns([1, 1], gap="large")
        with left:
            st.markdown("""<div class="section-header"><i class="ti ti-file-code"></i> Source Code</div>""", unsafe_allow_html=True)
            fi1, fi2, fi3 = st.columns(3)
            with fi1: st.markdown(f"""<div class="metric-card"><div class="metric-value" style="font-size:1.1rem;word-break:break-all;">{big_uploaded.name}</div><div class="metric-label"><i class="ti ti-file"></i> File</div></div>""", unsafe_allow_html=True)
            with fi2: st.markdown(f"""<div class="metric-card"><div class="metric-value">{lang_big}</div><div class="metric-label"><i class="ti ti-code"></i> Language</div></div>""", unsafe_allow_html=True)
            with fi3: st.markdown(f"""<div class="metric-card"><div class="metric-value">{big_lines}</div><div class="metric-label"><i class="ti ti-list-numbers"></i> Lines</div></div>""", unsafe_allow_html=True)
            st.markdown("<br>", unsafe_allow_html=True)
            st.code(big_code, language=lang_big or "text", line_numbers=True)
            
        with right:
            st.markdown("""<div class="section-header"><i class="ti ti-binary-tree-2"></i> Large File Scan</div>""", unsafe_allow_html=True)
            st.markdown("""
            <div style="text-align:center;padding:50px 20px;color:var(--ink-muted);">
                <i class="ti ti-bolt" style="font-size:3rem;display:block;margin-bottom:16px;color:var(--accent);"></i>
                <div style="font-size:1rem;font-weight:600;color:var(--ink);">Ready to audit</div>
                <div style="font-size:0.85rem;margin-top:8px;">Scroll to the top of the Large File tab and click <b>Run Chunked Audit</b>.</div>
            </div>""", unsafe_allow_html=True)
        st.stop()

    import tempfile
    _tmp_big = tempfile.NamedTemporaryFile(delete=False, suffix=ext_big, mode='w', encoding='utf-8')
    _tmp_big.write(big_code)
    _tmp_big.close()
    big_file_path = _tmp_big.name
    _big_tmp_cleanup = True

    st.markdown(f'''<div class="section-header">
        <i class="ti ti-binary-tree-2"></i> Chunked Audit &mdash;
        <span style="font-weight:400;font-size:0.85rem;">{big_uploaded.name}</span>
    </div>''', unsafe_allow_html=True)

    m1, m2, m3 = st.columns(3)
    with m1:
        st.markdown(f"""<div class="metric-card"><div class="metric-value">{big_lines}</div><div class="metric-label"><i class="ti ti-list-numbers"></i> Total Lines</div></div>""", unsafe_allow_html=True)
    with m2:
        st.markdown(f"""<div class="metric-card"><div class="metric-value">{lang_big.capitalize()}</div><div class="metric-label"><i class="ti ti-code"></i> Language</div></div>""", unsafe_allow_html=True)
    with m3:
        st.markdown(f"""<div class="metric-card"><div class="metric-value">Chunked</div><div class="metric-label"><i class="ti ti-cut"></i> Mode</div></div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    prog_ph  = st.empty()
    status_ph = st.empty()

    try:
        from main_big import chunk_file, analyze_chunk, meta_summarize
        from src.vuln_classifier import deduplicate_findings
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import threading

        inference_big = load_inference_engine()
        _completed_count = [0]
        _progress_lock = threading.Lock()

        with measure_energy(sample_interval_s=0.2) as col_big:
            col_big.begin_phase("Chunking")
            with st.spinner("Chunking file and initialising NLP..."):
                chunks = chunk_file(big_file_path)
            col_big.begin_phase("Chunk Analysis (4 threads)")

            status_ph.markdown(
                f"<small style='color:var(--ink-muted);'>Processing <b style='color:var(--ink);'>{len(chunks)} chunks</b> "
                f"across <b style='color:var(--ink);'>4 parallel threads</b>...</small>",
                unsafe_allow_html=True
            )

            chunk_results = [None] * len(chunks)

            def _analyze_and_track(idx, cname, ctext, start_line):
                return idx, analyze_chunk(cname, ctext, lang_big, inference_big, start_line)

            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = {
                    executor.submit(_analyze_and_track, idx, cname, ctext, start_line): (idx, cname)
                    for idx, (cname, ctext, start_line) in enumerate(chunks)
                }
                for future in as_completed(futures):
                    idx, cname = futures[future]
                    _, cr = future.result()
                    chunk_results[idx] = cr
                    
                    _completed_count[0] += 1
                    prog_ph.progress(
                        _completed_count[0] / len(chunks),
                        text=f"Chunk {_completed_count[0]}/{len(chunks)} done — {cname}"
                    )

            prog_ph.progress(1.0, text="Meta-Transformer pass...")
            col_big.begin_phase("Meta-Transformer")
            with st.spinner("Meta-Transformer assembling global summary..."):
                meta_sum = meta_summarize(chunk_results, inference_big, lang_big)
            col_big.end_phase()

        prog_ph.empty()
        status_ph.empty()

        reports_dir_big = os.path.join(os.path.dirname(__file__), "frontend", "public", "reports")
        os.makedirs(reports_dir_big, exist_ok=True)
        with open(os.path.join(reports_dir_big, "latest_report.json"), "w") as _f:
            json.dump(col_big.report.to_dict(), _f)

        top_score = max(cr['risk_score'] for cr in chunk_results) if chunk_results else 0.0
        render_gauge(top_score)

        st.markdown('''<div class="section-header">
            <i class="ti ti-message-2"></i> Meta-Transformer Summary
        </div>''', unsafe_allow_html=True)
        st.markdown(f'<div class="summary-box">{meta_sum}</div>', unsafe_allow_html=True)

        all_findings = []
        for cr in chunk_results:
            all_findings.extend(cr.get('findings', []))
        all_findings = deduplicate_findings(all_findings)
        all_findings.sort(key=lambda f: f.get('line', 0))

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('''<div class="section-header">
            <i class="ti ti-alert-triangle"></i> Consolidated Vulnerabilities
            <span style="font-weight:400;font-size:0.78rem;color:var(--ink-muted);margin-left:8px;">(original file line numbers, deduplicated)</span>
        </div>''', unsafe_allow_html=True)

        if all_findings:
            sev_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            from src.vuln_classifier import normalize_severity
            for f in all_findings:
                norm_sev = normalize_severity(f.get('severity', 'INFO')).upper()
                sev_counts[norm_sev] = sev_counts.get(norm_sev, 0) + 1
            vc1, vc2, vc3, vc4 = st.columns(4)
            with vc1:
                st.markdown(f"""<div class="metric-card"><div class="metric-value">{len(all_findings)}</div><div class="metric-label">Total</div></div>""", unsafe_allow_html=True)
            with vc2:
                st.markdown(f"""<div class="metric-card"><div class="metric-value" style="color:var(--danger);">{sev_counts.get('HIGH',0)}</div><div class="metric-label">High Vulnerability</div></div>""", unsafe_allow_html=True)
            with vc3:
                st.markdown(f"""<div class="metric-card"><div class="metric-value" style="color:var(--warning);">{sev_counts.get('MEDIUM',0)}</div><div class="metric-label">Medium Vulnerability</div></div>""", unsafe_allow_html=True)
            with vc4:
                st.markdown(f"""<div class="metric-card"><div class="metric-value" style="color:var(--accent);">{sev_counts.get('LOW',0)}</div><div class="metric-label">Low Vulnerability</div></div>""", unsafe_allow_html=True)
            st.markdown("<br>", unsafe_allow_html=True)

            for fnd in all_findings:
                chunk_src = fnd.get('original_chunk', '')
                chunk_badge = (
                    f" <span style='font-size:0.68rem;color:var(--ink-muted);font-family:var(--mono);'>chunk: {chunk_src}</span>"
                    if chunk_src else ""
                )
                sev = normalize_severity(fnd.get('severity', 'INFO')).upper()
                icon = severity_icon_html(sev)
                hdr_color = {"HIGH": "var(--danger)", "MEDIUM": "var(--warning)"}.get(sev, "var(--accent)")
                st.markdown(f"""
                <div class="finding-card finding-{sev}">
                    <div class="finding-header" style="color:{hdr_color};">{icon} {sev} VULNERABILITY{chunk_badge}</div>
                    <div class="finding-msg">{fnd.get('message', '')}</div>
                    <div class="finding-line"><i class="ti ti-code" style="margin-right:4px;"></i>Line {fnd.get('line', '?')}</div>
                </div>""", unsafe_allow_html=True)
        else:
            st.markdown("""<div class="finding-card finding-LOW">
                <div class="finding-header" style="color:var(--accent);">
                    <i class="ti ti-circle-check"></i> CLEAN
                </div>
                <div class="finding-msg">No vulnerabilities detected across any chunks.</div>
            </div>""", unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('''<div class="section-header">
            <i class="ti ti-layout-list"></i> Per-Chunk Breakdown
        </div>''', unsafe_allow_html=True)

        for cr in chunk_results:
            n_findings = len(cr.get('findings', []))
            with st.expander(f"{cr['name']}   |   Score: {cr['risk_score']}/10   |   {n_findings} finding(s)"):
                st.markdown(f"<div class='summary-box' style='margin-bottom:12px;'>{cr['summary']}</div>", unsafe_allow_html=True)
                if cr.get('findings'):
                    for fnd in cr['findings']:
                        render_finding(fnd)
                else:
                    st.markdown("<small style='color:var(--ink-muted);'>No findings in this chunk.</small>", unsafe_allow_html=True)

                feats = cr.get('features', {})
                fa2, fb2 = st.columns(2)
                with fa2:
                    st.markdown("<div style='font-size:0.78rem;font-weight:600;color:var(--ink-muted);margin-bottom:4px;'><i class='ti ti-database-import'></i> Sources</div>", unsafe_allow_html=True)
                    render_tags(feats.get('sources', []), 'source')
                with fb2:
                    st.markdown("<div style='font-size:0.78rem;font-weight:600;color:var(--ink-muted);margin-bottom:4px;'><i class='ti ti-skull'></i> Sinks</div>", unsafe_allow_html=True)
                    render_tags(feats.get('sinks', []), 'sink')

    except Exception as e:
        prog_ph.empty()
        status_ph.empty()
        st.error(f"Large file pipeline error: {e}")
    finally:
        try:
            if _big_tmp_cleanup:
                os.unlink(big_file_path)
        except Exception:
            pass

    st.markdown("<br>", unsafe_allow_html=True)
    st.link_button("Open Advanced Analytics (React Frontend)", "http://localhost:5173", use_container_width=True)
    st.stop()


# ═══════════════════════════════════════════════════
# SINGLE FILE AUDIT
# ═══════════════════════════════════════════════════
elif uploaded_file:
    code_content = uploaded_file.getvalue().decode("utf-8", errors="ignore")
    ext      = os.path.splitext(uploaded_file.name)[1].lower()
    lang_map = {'.py': 'python', '.java': 'java', '.js': 'javascript', '.c': 'c'}
    language = lang_map.get(ext)


left, right = st.columns([1, 1], gap="large")

with left:
    st.markdown("""
    <div class="section-header">
        <i class="ti ti-file-code"></i> Source Code
    </div>""", unsafe_allow_html=True)
    
    fi1, fi2, fi3 = st.columns(3)
    with fi1:
        st.markdown(f"""<div class="metric-card">
            <div class="metric-value" style="font-size:1.1rem;word-break:break-all;">{uploaded_file.name}</div>
            <div class="metric-label"><i class="ti ti-file"></i> File</div></div>""", unsafe_allow_html=True)
    with fi2:
        st.markdown(f"""<div class="metric-card">
            <div class="metric-value">{language or "unknown"}</div>
            <div class="metric-label"><i class="ti ti-code"></i> Language</div></div>""", unsafe_allow_html=True)
    with fi3:
        lines = code_content.count('\n') + 1
        st.markdown(f"""<div class="metric-card">
            <div class="metric-value">{lines}</div>
            <div class="metric-label"><i class="ti ti-list-numbers"></i> Lines</div></div>""", unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    st.code(code_content, language=language or "text", line_numbers=True)

with right:
    st.markdown("""
    <div class="section-header">
        <i class="ti ti-shield-search"></i> Security Audit
    </div>""", unsafe_allow_html=True)
    
    if not language:
        st.error(f"Unsupported file type: `{ext}`")
        st.stop()

    run_btn = st.button("Run Full Security Audit", type="primary", use_container_width=True)

    if run_btn:
        steps = [
            ("ti-binary-tree",    "AST Parsing & Feature Extraction"),
            ("ti-shield-search",  "Security Scanner (Semgrep + Fallback)"),
            ("ti-brain",          "Loading CodeT5 Model"),
            ("ti-pencil",         "Prompt Engineering"),
            ("ti-message-2",      "Generating AI Summary"),
        ]
        pipeline_ph = st.empty()
        
        def render_pipeline(done_up_to: int):
            html = ""
            for i, (icon, name) in enumerate(steps):
                if i < done_up_to:
                    cls  = "step-done"
                    stat = '<i class="ti ti-circle-check"></i> Done'
                elif i == done_up_to:
                    cls  = "step-run"
                    stat = '<i class="ti ti-loader-2"></i> Running...'
                else:
                    cls  = "step-wait"
                    stat = '<i class="ti ti-minus"></i>'
                html += (
                    f'<div class="pipeline-step {cls}">'
                    f'<i class="ti {icon} ti-step"></i>{name}'
                    f'<span class="step-status">{stat}</span>'
                    f'</div>'
                )
            pipeline_ph.markdown(html, unsafe_allow_html=True)

        results = {}
        with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
            tmp.write(uploaded_file.getvalue())
            tmp_path = tmp.name

        try:
            with measure_energy(sample_interval_s=0.2) as col:
                render_pipeline(0)
                col.begin_phase("AST & Features")
                ast_parser        = ASTParser()
                feature_extractor = FeatureExtractor()
                tree     = ast_parser.parse(code_content, language)
                features = feature_extractor.extract_features(tree, code_content, language)
                results['features'] = features
                col.end_phase()
                
                render_pipeline(1)
                col.begin_phase("Semgrep Scan")
                scanner = Scanner()
                findings, risk_score = scanner.scan_file(tmp_path)
                results['findings']   = findings
                results['risk_score'] = risk_score
                col.end_phase()
                
                render_pipeline(2)
                col.begin_phase("Model Prep")
                inference = load_inference_engine()
                col.end_phase()
                
                render_pipeline(3)
                col.begin_phase("Prompt Engine")
                enricher = PromptEnricher()
                prompt   = enricher.construct_prompt(findings, features, code_content)
                col.end_phase()
                
                render_pipeline(4)
                col.begin_phase("CodeT5 Gen")
                summary = inference.generate_summary(prompt)
                results['summary'] = summary
                col.end_phase()
                
                render_pipeline(5)
                time.sleep(0.3)
                pipeline_ph.empty()
            
            reports_dir = os.path.join(os.path.dirname(__file__), "frontend", "public", "reports")
            os.makedirs(reports_dir, exist_ok=True)
            with open(os.path.join(reports_dir, "latest_report.json"), "w") as f:
                json.dump(col.report.to_dict(), f)
            
        except Exception as e:
            pipeline_ph.empty()
            st.error(f"Pipeline error: {e}")
            st.stop()
        finally:
            try: os.unlink(tmp_path)
            except: pass

        render_gauge(results['risk_score'])
        
        st.markdown("""
        <div class="section-header">
            <i class="ti ti-message-2"></i> AI-Generated Summary
        </div>""", unsafe_allow_html=True)
        st.markdown(f'<div class="summary-box">{results["summary"]}</div>', unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("""
        <div class="section-header">
            <i class="ti ti-alert-triangle"></i> Vulnerability Findings
        </div>""", unsafe_allow_html=True)
        if results['findings']:
            for f in results['findings']:
                render_finding(f)
        else:
            st.markdown("""<div class="finding-card finding-LOW">
                <div class="finding-header" style="color:var(--accent);">
                    <i class="ti ti-circle-check"></i> CLEAN
                </div>
                <div class="finding-msg">No vulnerabilities detected by static analysis.</div>
            </div>""", unsafe_allow_html=True)
        
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("""
        <div class="section-header">
            <i class="ti ti-binary-tree"></i> AST Feature Extraction
        </div>""", unsafe_allow_html=True)
        f  = results['features']
        fa, fb = st.columns(2)
        with fa:
            st.markdown("<div style='font-size:0.8rem;font-weight:600;color:var(--ink-muted);margin-bottom:4px;'><i class='ti ti-database-import'></i> Data Sources</div>", unsafe_allow_html=True)
            render_tags(f.get('sources', []), "source")
        with fb:
            st.markdown("<div style='font-size:0.8rem;font-weight:600;color:var(--ink-muted);margin-bottom:4px;'><i class='ti ti-skull'></i> Dangerous Sinks</div>", unsafe_allow_html=True)
            render_tags(f.get('sinks', []), "sink")
            
        complexity = f.get('complexity', 0)
        st.markdown(f"""
        <div class="metric-card" style="margin-top:12px;text-align:left;display:flex;align-items:center;gap:16px;">
            <i class="ti ti-git-branch" style="font-size:1.8rem;color:var(--ink);flex-shrink:0;"></i>
            <div>
                <div style="font-size:0.7rem;color:var(--ink-muted);text-transform:uppercase;letter-spacing:1px;">Cyclomatic Complexity</div>
                <div style="font-size:1.8rem;font-weight:800;color:var(--ink);">{complexity}</div>
            </div>
        </div>""", unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        st.link_button("Open Advanced Analytics (React Frontend)", "http://localhost:5173", use_container_width=True)

    else:
        st.markdown("""
        <div style="text-align:center;padding:60px 20px;color:var(--ink-muted);">
            <i class="ti ti-bolt" style="font-size:3rem;display:block;margin-bottom:16px;color:var(--accent);"></i>
            <div style="font-size:1rem;font-weight:600;color:var(--ink);">Ready to audit</div>
            <div style="font-size:0.85rem;margin-top:8px;">Click the button above to run the full 5-stage analysis pipeline</div>
        </div>""", unsafe_allow_html=True)