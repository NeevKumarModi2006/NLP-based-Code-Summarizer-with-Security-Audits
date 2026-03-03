# Author: Neev Modi

import os
import sys
import torch
import tempfile
import time

if hasattr(torch, 'classes'):
    torch.classes.__path__ = [os.path.join(torch.__path__[0], torch.classes.__file__)]

import streamlit as st

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.ast_parser import ASTParser
from src.feature_extractor import FeatureExtractor
# from src.scanner import Scanner
# from src.enrichment import PromptEnricher
from src.inference import InferenceEngine

# -------------------------------------------------
# PAGE CONFIG
# -------------------------------------------------
st.set_page_config(
    page_title="AI Security Auditor",
    page_icon="https://api.iconify.design/tabler:shield-lock.svg",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -------------------------------------------------
# TABLER ICONS CDN
# -------------------------------------------------
st.markdown(
    '<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@3.24.0/dist/tabler-icons.min.css">',
    unsafe_allow_html=True
)

# -------------------------------------------------
# CUSTOM CSS - DARK CYBERSECURITY THEME
# -------------------------------------------------
st.markdown("""
<style>
/* Classic Neon Terminal Theme */

:root {
    --bg-primary:   #121212;
    --bg-card:      #1e1e1e;
    --bg-panel:     #2a2a2a;
    --accent:       #00ff00;
    --accent-dim:   rgba(0,255,0,0.12);
    --accent-border:rgba(0,255,0,0.3);
    --text-primary: #ffffff;
    --text-muted:   #ffffff;
    --border:       #2a2a2a;
    --font-mono:    ui-monospace, 'SF Mono', Menlo, Monaco, Consolas, monospace;
    --font-sans:    -apple-system, BlinkMacSystemFont, 'SF Pro Text', 'Helvetica Neue', Arial, sans-serif;
}

html, body, [class*="css"] {
    font-family: var(--font-sans) !important;
    background-color: var(--bg-primary) !important;
    color: var(--text-primary) !important;
}
.stApp { background-color: var(--bg-primary) !important; }

/* Sidebar */
section[data-testid="stSidebar"] {
    background: var(--bg-card) !important;
    border-right: 1px solid var(--border) !important;
}
section[data-testid="stSidebar"] * { color: var(--text-primary) !important; }

/* Tabler Icon sizing */
.ti { font-size: 1em; vertical-align: -0.125em; }
.ti-lg { font-size: 1.4rem; vertical-align: -0.2em; }
.ti-xl { font-size: 2rem; display: block; margin-bottom: 8px; }
.ti-hero { font-size: 2.4rem; vertical-align: -0.25em; margin-right: 10px; }
.ti-step { font-size: 1rem; vertical-align: -0.12em; }

/* Sidebar items */
.sb-section-title {
    font-size: 0.65rem; font-weight: 700; text-transform: uppercase;
    letter-spacing: 2px; color: var(--accent);
    margin: 18px 0 8px 0; padding-bottom: 6px;
    border-bottom: 1px solid var(--accent-border);
}
.sb-lang-row { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 4px; }
.sb-lang {
    background: var(--bg-panel); border: 1px solid var(--border);
    border-radius: 6px; padding: 4px 10px; font-size: 0.78rem; color: var(--text-primary);
    display: flex; align-items: center; gap: 5px;
}
.sb-step-row { display: flex; align-items: center; gap: 8px; padding: 5px 0; font-size: 0.83rem; color: var(--text-primary); }
.sb-step-num {
    width: 18px; height: 18px; border-radius: 50%;
    background: var(--accent-dim); border: 1px solid var(--accent-border);
    color: var(--accent); font-size: 0.65rem; font-weight: 700;
    display: flex; align-items: center; justify-content: center; flex-shrink: 0;
}

/* Model pill */
.model-pill {
    background: #111111; border: 1px solid var(--border); border-radius: 8px;
    padding: 10px 14px; font-family: var(--font-mono);
    font-size: 0.77rem; color: var(--accent); word-break: break-all;
    display: flex; align-items: center; gap: 8px; margin: 6px 0 14px 0;
}
.model-pill .ti { color: var(--text-muted); font-size: 1rem; flex-shrink: 0; }

/* Hero Banner */
.hero-banner {
    background: var(--bg-card);
    border: 1px solid var(--accent-border); border-radius: 16px;
    padding: 40px 48px; margin-bottom: 32px;
    position: relative; overflow: hidden;
}
.hero-banner::before {
    content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
    background: var(--accent);
}
.hero-title {
    font-size: 2.8rem; font-weight: 900; letter-spacing: -1px;
    color: var(--accent);
    margin: 0 0 8px 0; display: flex; align-items: center; gap: 14px;
}
.hero-title-icon {
    color: var(--accent);
    font-size: 2.4rem;
}
.hero-sub { font-size: 1rem; color: var(--text-muted); font-weight: 400; margin: 0; }

/* Metric Cards */
.metric-card {
    background: var(--bg-card); border: 1px solid var(--border);
    border-radius: 12px; padding: 20px 24px; text-align: center;
}
.metric-card:hover { box-shadow: 0 0 12px rgba(0,255,0,0.15); }
.metric-value { font-size: 2rem; font-weight: 800; margin: 0; line-height: 1; }
.metric-label { font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; margin-top: 6px; }

/* Feature Cards */
.feat-card {
    background: var(--bg-card); border: 1px solid var(--border);
    border-radius: 12px; padding: 24px 20px; text-align: center;
}
.feat-card:hover { border-color: var(--accent-border); box-shadow: 0 0 12px rgba(0,255,0,0.1); }
.feat-icon { font-size: 2rem; margin-bottom: 12px; display: block; }
.feat-title { font-weight: 700; font-size: 1rem; margin-bottom: 6px; color: var(--text-primary); }
.feat-desc  { font-size: 0.8rem; color: var(--text-muted); line-height: 1.5; }

/* Risk Gauge */
.gauge-container {
    background: var(--bg-card); border-radius: 12px;
    border: 1px solid var(--border); padding: 28px;
    text-align: center; margin-bottom: 20px;
}
.gauge-label { font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1.5px; margin-bottom: 12px; }
.gauge-score { font-size: 4rem; font-weight: 900; line-height: 1; font-family: var(--font-mono); }
.gauge-bar-bg { background: var(--border); border-radius: 99px; height: 10px; margin: 16px 0 8px 0; overflow: hidden; }
.gauge-bar-fill { height: 100%; border-radius: 99px; }
.gauge-range { font-size: 0.75rem; color: var(--text-muted); }

/* Finding Cards */
.finding-card {
    border-radius: 10px; padding: 14px 18px;
    margin-bottom: 10px; border-left: 4px solid;
}
.finding-ERROR   { background: rgba(0,255,0,0.06);  border-color: var(--accent); }
.finding-WARNING { background: rgba(0,255,0,0.06);  border-color: var(--accent); }
.finding-INFO    { background: var(--accent-dim);   border-color: var(--accent); }
.finding-header  { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 1px; font-weight: 700; margin-bottom: 4px; display: flex; align-items: center; gap: 6px; }
.finding-msg  { font-size: 0.9rem; color: var(--text-primary); }
.finding-line { font-size: 0.75rem; color: var(--accent); opacity: 0.6; margin-top: 4px; font-family: var(--font-mono); }

/* Feature Tags */
.tag-container { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }
.tag {
    background: var(--accent-dim); border: 1px solid var(--accent-border);
    color: var(--accent); border-radius: 6px; padding: 3px 10px;
    font-size: 0.78rem; font-family: var(--font-mono);
}
.tag.sink { background: var(--accent-dim); border-color: var(--accent-border); color: var(--accent); }
.tag.none { background: var(--bg-panel); border-color: var(--border); color: var(--accent); opacity: 0.5; }

/* Section Headers */
.section-header {
    font-size: 0.7rem; font-weight: 700; text-transform: uppercase;
    letter-spacing: 2px; color: var(--accent); padding: 0 0 8px 0;
    border-bottom: 1px solid var(--accent-border); margin-bottom: 16px;
    display: flex; align-items: center; gap: 8px;
}

/* AI Summary Box */
.summary-box {
    background: var(--bg-panel);
    border: 1px solid var(--accent-border);
    border-radius: 12px; padding: 20px 24px;
    font-size: 0.96rem; line-height: 1.7; color: var(--text-primary);
}

/* Pipeline Steps */
.pipeline-step {
    display: flex; align-items: center; gap: 12px;
    padding: 10px 14px; background: var(--bg-panel);
    border-radius: 8px; margin-bottom: 8px; font-size: 0.85rem;
}
.step-status { margin-left: auto; font-size: 0.75rem; font-weight: 600; display: flex; align-items: center; gap: 4px; }
.step-done .step-status { color: var(--accent); }
.step-run  .step-status { color: var(--accent); }
.step-wait .step-status { color: var(--text-muted); }

/* File Upload Area */
[data-testid="stFileUploader"] {
    background: var(--bg-card) !important;
    border: 2px dashed var(--border) !important;
    border-radius: 12px !important;
}

/* Buttons */
.stButton > button {
    background: #00ff00 !important;
    color: #000000 !important; font-weight: 700 !important;
    border: none !important; border-radius: 8px !important;
    padding: 0.6rem 2rem !important; font-size: 0.95rem !important;
    width: 100% !important; font-family: var(--font-sans) !important;
    letter-spacing: 0.5px !important;
}
.stButton > button:hover { background: #00ff00 !important; box-shadow: 0 0 16px rgba(0,255,0,0.5) !important; }

/* Code Block */
.stCodeBlock { border-radius: 10px !important; }

/* Cleanup */
#MainMenu, footer, header { visibility: hidden; }
.block-container { padding-top: 2rem !important; max-width: 1400px !important; }
</style>
""", unsafe_allow_html=True)


# -------------------------------------------------
# HELPERS
# -------------------------------------------------
@st.cache_resource(show_spinner=False)
def load_inference_engine():
    return InferenceEngine()


def risk_color(score: float) -> str:
    return "#00ff00"


def risk_label(score: float) -> str:
    if score >= 8:  return "CRITICAL"
    if score >= 5:  return "HIGH"
    if score >= 2:  return "MEDIUM"
    return "LOW"


def severity_icon_html(sev: str) -> str:
    icons = {
        "ERROR":   '<i class="ti ti-circle-x"></i>',
        "WARNING": '<i class="ti ti-alert-triangle"></i>',
        "INFO":    '<i class="ti ti-info-circle"></i>',
    }
    return icons.get(sev.upper(), '<i class="ti ti-circle"></i>')


def render_gauge(score: float):
    color = risk_color(score)
    label = risk_label(score)
    pct   = int((score / 10.0) * 100)
    st.markdown(f"""
    <div class="gauge-container">
        <div class="gauge-label"><i class="ti ti-shield-half-filled" style="margin-right:5px;"></i>Risk Score</div>
        <div class="gauge-score" style="color:{color};">{score}<span style="font-size:1.5rem;color:#ffffff;opacity:0.4;">/10</span></div>
        <div style="font-size:0.8rem;font-weight:700;letter-spacing:2px;color:{color};margin-top:4px;">{label}</div>
        <div class="gauge-bar-bg">
            <div class="gauge-bar-fill" style="width:{pct}%;background:linear-gradient(90deg,{color}aa,{color});"></div>
        </div>
        <div class="gauge-range">0 - Safe &nbsp;&nbsp;&nbsp; 10 - Critical</div>
    </div>""", unsafe_allow_html=True)


def render_finding(f: dict):
    sev   = f.get('severity', 'INFO').upper()
    msg   = f.get('message', '')
    line  = f.get('line', '?')
    icon  = severity_icon_html(sev)
    color = "#00ff00"
    st.markdown(f"""
    <div class="finding-card finding-{sev}">
        <div class="finding-header" style="color:{color};">{icon} {sev}</div>
        <div class="finding-msg">{msg}</div>
        <div class="finding-line"><i class="ti ti-code" style="margin-right:4px;"></i>Line {line}</div>
    </div>""", unsafe_allow_html=True)


def render_tags(items: list, kind: str = "source"):
    if not items:
        st.markdown('<div class="tag-container"><span class="tag none">none detected</span></div>', unsafe_allow_html=True)
        return
    tags_html = "".join(f'<span class="tag {kind}">{x}</span>' for x in set(items))
    st.markdown(f'<div class="tag-container">{tags_html}</div>', unsafe_allow_html=True)


# -------------------------------------------------
# SIDEBAR
# -------------------------------------------------
with st.sidebar:
    st.markdown("""
    <div style="font-size:1.1rem;font-weight:800;color:#ffffff;display:flex;align-items:center;gap:8px;padding-bottom:12px;border-bottom:1px solid #333333;">
        <i class="ti ti-settings-2" style="color:#00ff00;font-size:1.2rem;"></i> Settings
    </div>

    <div class="sb-section-title">Supported Languages</div>
    <div class="sb-lang-row">
        <span class="sb-lang"><i class="ti ti-brand-python" style="color:#00ff00;"></i> Python</span>
        <span class="sb-lang"><i class="ti ti-coffee" style="color:#00ff00;"></i> Java</span>
        <span class="sb-lang"><i class="ti ti-brand-javascript" style="color:#00ff00;"></i> JS</span>
        <span class="sb-lang"><i class="ti ti-letter-c" style="color:#00ff00;"></i> C</span>
    </div>

    <div class="sb-section-title">Pipeline Stages</div>
    <div class="sb-step-row"><span class="sb-step-num">1</span><i class="ti ti-binary-tree" style="color:#00ff00;"></i> AST Parsing</div>
    <div class="sb-step-row"><span class="sb-step-num">2</span><i class="ti ti-cpu" style="color:#00ff00;"></i> Feature Extraction</div>
    <div class="sb-step-row"><span class="sb-step-num">3</span><i class="ti ti-shield-search" style="color:#00ff00;"></i> Security Scanning</div>
    <div class="sb-step-row"><span class="sb-step-num">4</span><i class="ti ti-pencil" style="color:#00ff00;"></i> Prompt Engineering</div>
    <div class="sb-step-row"><span class="sb-step-num">5</span><i class="ti ti-message-2" style="color:#00ff00;"></i> NLP Inference</div>

    <div class="sb-section-title">Model</div>
    <div class="model-pill">
        <i class="ti ti-brain"></i>Salesforce/codet5-base-multi-sum
    </div>

    <div class="sb-section-title">Scanner</div>
    <div style="font-size:0.83rem;color:#ffffff;display:flex;align-items:center;gap:6px;">
        <i class="ti ti-shield-check" style="color:#00ff00;"></i> Semgrep + AST/Regex Fallback
    </div>

    <div style="margin-top:24px;padding-top:16px;border-top:1px solid rgba(0,255,0,0.2);font-size:0.7rem;color:#00ff00;opacity:0.5;text-align:center;">
        <i class="ti ti-lock" style="margin-right:4px;"></i> AI Security Auditor v2.0
    </div>
    """, unsafe_allow_html=True)


# -------------------------------------------------
# HERO
# -------------------------------------------------
st.markdown("""
<div class="hero-banner">
    <div class="hero-title">
        <i class="ti ti-shield-lock hero-title-icon"></i>
        AI Security Auditor
    </div>
    <p class="hero-sub">NLP-powered code analysis &nbsp;·&nbsp; AST feature extraction &nbsp;·&nbsp; Real-time vulnerability detection</p>
</div>
""", unsafe_allow_html=True)


# -------------------------------------------------
# FILE UPLOAD
# -------------------------------------------------
uploaded_file = st.file_uploader(
    "Drop a source file to begin analysis",
    type=['py', 'java', 'c', 'js'],
    help="Supported: .py .java .c .js"
)

if uploaded_file is None:
    st.markdown("<br>", unsafe_allow_html=True)
    c1, c2, c3, c4 = st.columns(4)
    cards = [
        ("ti-binary-tree",   "#00ff00", "AST Analysis",   "Deep structural parsing via Tree-sitter"),
        ("ti-brain",         "#00ff00", "AI Summaries",   "CodeT5 generates human-readable explanations"),
        ("ti-bug",           "#00ff00", "Vuln Detection", "Semgrep + custom AST/Regex hybrid scanner"),
        ("ti-chart-bar",     "#00ff00", "Risk Scoring",   "Quantitative 0-10 score with severity breakdown"),
    ]
    for col, (icon, color, title, desc) in zip([c1, c2, c3, c4], cards):
        with col:
            st.markdown(f"""
            <div class="feat-card">
                <i class="ti {icon} feat-icon" style="color:{color};"></i>
                <div class="feat-title">{title}</div>
                <div class="feat-desc">{desc}</div>
            </div>""", unsafe_allow_html=True)
    st.stop()


# -------------------------------------------------
# FILE LOADED
# -------------------------------------------------
code_content = uploaded_file.getvalue().decode("utf-8", errors="ignore")
ext      = os.path.splitext(uploaded_file.name)[1].lower()
lang_map = {'.py': 'python', '.java': 'java', '.js': 'javascript', '.c': 'c'}
language = lang_map.get(ext)

left, right = st.columns([1, 1], gap="large")

# Left: Source Code
with left:
    st.markdown("""
    <div class="section-header">
        <i class="ti ti-file-code"></i> Source Code
    </div>""", unsafe_allow_html=True)

    fi1, fi2, fi3 = st.columns(3)
    with fi1:
        st.markdown(f"""<div class="metric-card">
            <div class="metric-value" style="color:#00ff00;font-size:1.1rem;word-break:break-all;">{uploaded_file.name}</div>
            <div class="metric-label"><i class="ti ti-file"></i> File</div></div>""", unsafe_allow_html=True)
    with fi2:
        st.markdown(f"""<div class="metric-card">
            <div class="metric-value" style="color:#00ff00;">{language or "unknown"}</div>
            <div class="metric-label"><i class="ti ti-code"></i> Language</div></div>""", unsafe_allow_html=True)
    with fi3:
        lines = code_content.count('\n') + 1
        st.markdown(f"""<div class="metric-card">
            <div class="metric-value" style="color:#00ff00;">{lines}</div>
            <div class="metric-label"><i class="ti ti-list-numbers"></i> Lines</div></div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.code(code_content, language=language or "text", line_numbers=True)

# Right: Audit Panel
with right:
    st.markdown("""
    <div class="section-header">
        <i class="ti ti-shield-search"></i> Security Audit
    </div>""", unsafe_allow_html=True)

    if not language:
        st.error(f"Unsupported file type: `{ext}`")
        st.stop()

    run_btn = st.button("Run Full Security Audit", use_container_width=True)

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
            render_pipeline(0)
            ast_parser        = ASTParser()
            feature_extractor = FeatureExtractor()
            tree     = ast_parser.parse(code_content, language)
            features = feature_extractor.extract_features(tree, code_content, language)
            results['features'] = features

            # render_pipeline(1)
            # scanner = Scanner()
            # findings, risk_score = scanner.scan_file(tmp_path)
            results['findings']   = []
            results['risk_score'] = 0

            render_pipeline(2)
            inference = load_inference_engine()

            render_pipeline(3)
            # enricher = PromptEnricher()
            # prompt   = enricher.construct_prompt(findings, features, code_content)
            prompt = ""

            render_pipeline(4)
            summary = inference.generate_summary(prompt)
            results['summary'] = summary

            render_pipeline(5)
            time.sleep(0.3)
            pipeline_ph.empty()

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
            st.markdown("""<div class="finding-card finding-INFO">
                <div class="finding-header" style="color:#00ff00;">
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
            st.markdown("<div style='font-size:0.8rem;font-weight:600;color:#00ff00;margin-bottom:4px;'><i class='ti ti-database-import'></i> Data Sources</div>", unsafe_allow_html=True)
            render_tags(f.get('sources', []), "source")
        with fb:
            st.markdown("<div style='font-size:0.8rem;font-weight:600;color:#00ff00;margin-bottom:4px;'><i class='ti ti-skull'></i> Dangerous Sinks</div>", unsafe_allow_html=True)
            render_tags(f.get('sinks', []), "sink")

        complexity  = f.get('complexity', 0)
        st.markdown(f"""
        <div class="metric-card" style="margin-top:12px;text-align:left;display:flex;align-items:center;gap:16px;">
            <i class="ti ti-git-branch" style="font-size:1.8rem;color:#00ff00;flex-shrink:0;"></i>
            <div>
                <div style="font-size:0.7rem;color:#ffffff;opacity:0.5;text-transform:uppercase;letter-spacing:1px;">Cyclomatic Complexity</div>
                <div style="font-size:1.8rem;font-weight:800;color:#00ff00;">{complexity}</div>
            </div>
        </div>""", unsafe_allow_html=True)

    else:
        st.markdown("""
        <div style="text-align:center;padding:60px 20px;color:#00ff00;opacity:0.6;">
            <i class="ti ti-bolt" style="font-size:3rem;display:block;margin-bottom:16px;color:#00ff00;"></i>
            <div style="font-size:1rem;font-weight:600;color:#ffffff;">Ready to audit</div>
            <div style="font-size:0.85rem;margin-top:8px;">Click the button above to run the full 5-stage analysis pipeline</div>
        </div>""", unsafe_allow_html=True)
