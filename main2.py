import streamlit as st
import sys
import os
import time
import json
from datetime import datetime
from urllib.parse import urlparse

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ─── Page Config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Bug Bounty Hunter Platform",
    page_icon="🎯",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&family=Exo+2:wght@300;400;600&display=swap');

/* ─── Global Theme ─── */
:root {
    --bg-primary: #050a0f;
    --bg-secondary: #0a1520;
    --bg-card: #0d1e2e;
    --accent-green: #00ff9d;
    --accent-cyan: #00d4ff;
    --accent-red: #ff3366;
    --accent-orange: #ff6b35;
    --accent-yellow: #ffd700;
    --text-primary: #e0f0ff;
    --text-secondary: #7aa8cc;
    --border: #1a3a5c;
}

html, body, [data-testid="stAppViewContainer"] {
    background-color: var(--bg-primary) !important;
    color: var(--text-primary) !important;
    font-family: 'Exo 2', sans-serif !important;
}

/* Animated scanline effect */
[data-testid="stAppViewContainer"]::before {
    content: '';
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(0, 255, 157, 0.015) 2px,
        rgba(0, 255, 157, 0.015) 4px
    );
    pointer-events: none;
    z-index: 9999;
}

/* Sidebar */
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #050e1a 0%, #071525 100%) !important;
    border-right: 1px solid var(--accent-green) !important;
}

[data-testid="stSidebar"] * { color: var(--text-primary) !important; }

/* Title */
h1, h2, h3 { font-family: 'Orbitron', monospace !important; }

.main-title {
    font-family: 'Orbitron', monospace;
    font-size: 2.4rem;
    font-weight: 900;
    background: linear-gradient(90deg, #00ff9d, #00d4ff, #00ff9d);
    background-size: 200%;
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    animation: shimmer 3s infinite linear;
    text-shadow: none;
    letter-spacing: 2px;
    margin-bottom: 0;
}

.subtitle {
    font-family: 'Share Tech Mono', monospace;
    color: var(--text-secondary);
    font-size: 0.85rem;
    letter-spacing: 3px;
    margin-top: 4px;
}

@keyframes shimmer {
    0% { background-position: 0% center; }
    100% { background-position: 200% center; }
}

/* Cards */
.stat-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    text-align: center;
    position: relative;
    overflow: hidden;
    transition: border-color 0.3s;
}

.stat-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent, var(--accent-cyan), transparent);
}

.stat-card:hover { border-color: var(--accent-cyan); }

.stat-number {
    font-family: 'Orbitron', monospace;
    font-size: 2.5rem;
    font-weight: 700;
    line-height: 1;
}

.stat-label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.7rem;
    letter-spacing: 2px;
    color: var(--text-secondary);
    margin-top: 8px;
}

/* Severity badges */
.sev-critical { color: #ff3366 !important; font-weight: bold; }
.sev-high { color: #ff6b35 !important; font-weight: bold; }
.sev-medium { color: #ffd700 !important; font-weight: bold; }
.sev-low { color: #00ff9d !important; }
.sev-info { color: #00d4ff !important; }

/* Finding card */
.finding-card {
    background: var(--bg-card);
    border-left: 3px solid var(--accent-cyan);
    border-radius: 0 8px 8px 0;
    padding: 16px 20px;
    margin: 10px 0;
    font-family: 'Exo 2', sans-serif;
}

.finding-card.critical { border-left-color: #ff3366; background: linear-gradient(90deg, rgba(255,51,102,0.08), var(--bg-card)); }
.finding-card.high { border-left-color: #ff6b35; background: linear-gradient(90deg, rgba(255,107,53,0.06), var(--bg-card)); }
.finding-card.medium { border-left-color: #ffd700; background: linear-gradient(90deg, rgba(255,215,0,0.05), var(--bg-card)); }
.finding-card.low { border-left-color: #00ff9d; }

/* Terminal */
.terminal {
    background: #000d1a;
    border: 1px solid var(--accent-green);
    border-radius: 8px;
    padding: 20px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.8rem;
    color: var(--accent-green);
    max-height: 300px;
    overflow-y: auto;
    margin: 10px 0;
}

.terminal-line { margin: 3px 0; }
.terminal-line.info { color: #00d4ff; }
.terminal-line.warning { color: #ffd700; }
.terminal-line.error { color: #ff3366; }
.terminal-line.finding { color: #00ff9d; font-weight: bold; }

/* Buttons */
.stButton > button {
    background: linear-gradient(135deg, #00ff9d20, #00d4ff20) !important;
    border: 1px solid var(--accent-green) !important;
    color: var(--accent-green) !important;
    font-family: 'Orbitron', monospace !important;
    font-size: 0.75rem !important;
    letter-spacing: 2px !important;
    border-radius: 4px !important;
    transition: all 0.3s !important;
}

.stButton > button:hover {
    background: linear-gradient(135deg, #00ff9d40, #00d4ff40) !important;
    box-shadow: 0 0 20px rgba(0, 255, 157, 0.3) !important;
    transform: translateY(-1px) !important;
}

/* Input fields */
.stTextInput > div > div > input,
.stSelectbox > div > div,
.stMultiSelect > div > div {
    background: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    color: var(--text-primary) !important;
    font-family: 'Share Tech Mono', monospace !important;
}

/* Progress bar */
.stProgress > div > div > div {
    background: linear-gradient(90deg, var(--accent-green), var(--accent-cyan)) !important;
}

/* Expander */
.streamlit-expanderHeader {
    background: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    color: var(--text-primary) !important;
    font-family: 'Share Tech Mono', monospace !important;
}

/* Tabs */
.stTabs [data-baseweb="tab-list"] {
    background: var(--bg-secondary) !important;
    border-bottom: 1px solid var(--border) !important;
}

.stTabs [data-baseweb="tab"] {
    color: var(--text-secondary) !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.8rem !important;
    letter-spacing: 1px !important;
}

.stTabs [aria-selected="true"] {
    color: var(--accent-cyan) !important;
    border-bottom: 2px solid var(--accent-cyan) !important;
}

/* Scrollbar */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg-primary); }
::-webkit-scrollbar-thumb { background: var(--accent-green); border-radius: 3px; }

/* Risk gauge */
.risk-gauge {
    font-family: 'Orbitron', monospace;
    font-size: 3rem;
    font-weight: 900;
    text-align: center;
}

.risk-bar-container {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 20px;
    height: 12px;
    overflow: hidden;
    margin: 8px 0;
}

/* Blink animation for live indicators */
@keyframes blink {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.3; }
}
.blink { animation: blink 1.2s infinite; }

/* Module status badges */
.module-badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 12px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.65rem;
    letter-spacing: 1px;
    margin: 2px;
}
.badge-ready { background: #00ff9d20; border: 1px solid #00ff9d; color: #00ff9d; }
.badge-running { background: #00d4ff20; border: 1px solid #00d4ff; color: #00d4ff; }
.badge-done { background: #ffd70020; border: 1px solid #ffd700; color: #ffd700; }
.badge-error { background: #ff336620; border: 1px solid #ff3366; color: #ff3366; }

/* Metric override */
[data-testid="metric-container"] {
    background: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-radius: 8px !important;
    padding: 12px !important;
}
</style>
""", unsafe_allow_html=True)


# ─── Session State Init ─────────────────────────────────────────────────────────
def init_state():
    defaults = {
        "scan_results": {},
        "all_findings": [],
        "scan_running": False,
        "scan_done": False,
        "terminal_logs": [],
        "active_module": None,
        "subdomains": [],
        "open_ports": [],
        "dir_findings": [],
        "param_results": {},
        "xss_findings": [],
        "sqli_findings": [],
        "ssrf_findings": [],
        "api_results": {},
        "cloud_results": {},
        "network_results": {},
        "scan_start_time": None,
        "target_url": "",
        "domain": "",
        "scope_violations": [],
        "scope_summary": {},
        "program_name": "Bug Bounty Assessment",
        "company_name": "",
        "tester_name": "Security Researcher",
        "engagement_id": "",
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

init_state()


# ─── Helpers ───────────────────────────────────────────────────────────────────
def add_log(level: str, message: str):
    ts = datetime.now().strftime("%H:%M:%S")
    st.session_state.terminal_logs.append({"ts": ts, "level": level, "msg": message})

def sev_color(sev: str) -> str:
    return {"CRITICAL": "#ff3366", "HIGH": "#ff6b35", "MEDIUM": "#ffd700", "LOW": "#00ff9d", "INFO": "#00d4ff"}.get(sev, "#aaa")

def sev_emoji(sev: str) -> str:
    return {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "🔵"}.get(sev, "⚪")

def count_by_severity(findings: list) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1
    return counts

def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


# ─── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown('<div class="main-title" style="font-size:1.3rem;">🎯 BBH PLATFORM</div>', unsafe_allow_html=True)
    st.markdown('<div class="subtitle">BUG BOUNTY HUNTER v1.0</div>', unsafe_allow_html=True)
    st.divider()

    st.markdown("### 🎯 TARGET")
    target_input = st.text_input("URL / Domain", placeholder="https://example.com", label_visibility="collapsed")

    st.markdown("### ⚙️ SCAN MODULES")

    col1, col2 = st.columns(2)
    with col1:
        do_subdomains = st.checkbox("Subdomains", value=True)
        do_ports = st.checkbox("Port Scan", value=True)
        do_dirs = st.checkbox("Dir Fuzzing", value=True)
        do_params = st.checkbox("Param Discovery", value=True)
    with col2:
        do_xss = st.checkbox("XSS", value=True)
        do_sqli = st.checkbox("SQLi", value=True)
        do_ssrf = st.checkbox("SSRF/XXE", value=True)
        do_api = st.checkbox("API Tests", value=True)

    col3, col4 = st.columns(2)
    with col3:
        do_cloud = st.checkbox("Cloud", value=True)
    with col4:
        do_network = st.checkbox("Headers", value=True)

    st.markdown("### 🔒 SCOPE DEFINITION")
    st.caption("Domains the scanner is authorized to test")
    extra_scope_input = st.text_area(
        "Extra in-scope domains (one per line)",
        placeholder="api.example.com\nstaging.example.com",
        height=70,
        label_visibility="collapsed"
    )
    out_of_scope_input = st.text_area(
        "Out-of-scope (one per line)",
        placeholder="payments.example.com\nhealthcare.example.com",
        height=50,
        label_visibility="collapsed"
    )
    st.divider()
    port_range = st.selectbox("Range", ["common", "top1000", "full"], label_visibility="collapsed")

    st.divider()
    launch_btn = st.button("🚀 LAUNCH SCAN", use_container_width=True)
    clear_btn = st.button("🗑️ CLEAR RESULTS", use_container_width=True)

    if clear_btn:
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        init_state()
        st.rerun()

    st.divider()
    st.markdown("### 📊 SCAN STATUS")
    if st.session_state.scan_running:
        st.markdown('<span class="blink" style="color:#00d4ff;">⬤</span> **SCANNING...**', unsafe_allow_html=True)
        mod = st.session_state.active_module
        if mod:
            st.markdown(f'<span style="color:#7aa8cc;font-size:0.8rem;">Module: {mod}</span>', unsafe_allow_html=True)
    elif st.session_state.scan_done:
        st.markdown('<span style="color:#00ff9d;">⬤</span> **COMPLETE**', unsafe_allow_html=True)
        dur = ""
        if st.session_state.scan_start_time:
            elapsed = time.time() - st.session_state.scan_start_time
            dur = f"{int(elapsed//60)}m {int(elapsed%60)}s"
        st.markdown(f'<span style="color:#7aa8cc;font-size:0.8rem;">Duration: {dur}</span>', unsafe_allow_html=True)
    else:
        st.markdown('<span style="color:#3a5a7c;">⬤</span> **IDLE**', unsafe_allow_html=True)

    if st.session_state.all_findings:
        counts = count_by_severity(st.session_state.all_findings)
        st.markdown(f"""
        <div style='font-size:0.75rem; font-family: Share Tech Mono; margin-top:10px;'>
            <span style='color:#ff3366;'>● {counts['CRITICAL']} CRIT</span> &nbsp;
            <span style='color:#ff6b35;'>● {counts['HIGH']} HIGH</span><br>
            <span style='color:#ffd700;'>● {counts['MEDIUM']} MED</span> &nbsp;
            <span style='color:#00ff9d;'>● {counts['LOW']} LOW</span>
        </div>
        """, unsafe_allow_html=True)


# ─── Main Area Header ──────────────────────────────────────────────────────────
st.markdown('<h1 class="main-title">BUG BOUNTY HUNTER PLATFORM</h1>', unsafe_allow_html=True)
st.markdown('<p class="subtitle">FULL-SCOPE AUTOMATED SECURITY ASSESSMENT PLATFORM</p>', unsafe_allow_html=True)
st.markdown('<hr style="border-color: #1a3a5c; margin: 8px 0 20px 0;">', unsafe_allow_html=True)


# ─── Scan Launch Logic ─────────────────────────────────────────────────────────
if launch_btn and target_input:
    # Reset state
    for key in ["scan_results", "all_findings", "subdomains", "open_ports", "dir_findings",
                "param_results", "xss_findings", "sqli_findings", "ssrf_findings",
                "api_results", "cloud_results", "network_results", "terminal_logs",
                "scope_violations"]:
        st.session_state[key] = {} if key.endswith("results") else []

    target_url = normalize_url(target_input)
    domain = urlparse(target_url).netloc or target_input

    st.session_state.target_url = target_url
    st.session_state.domain = domain
    st.session_state.scan_running = True
    st.session_state.scan_done = False
    st.session_state.scan_start_time = time.time()

    # ── Build scope definition ──────────────────────────────────────────────
    from utils.scope_manager import ScopeDefinition, ScopeManager, build_scope_from_target

    extra_domains = [d.strip() for d in extra_scope_input.strip().splitlines() if d.strip()]
    oos_domains   = [d.strip() for d in out_of_scope_input.strip().splitlines() if d.strip()]

    scope_def = build_scope_from_target(target_url, extra_domains)
    scope_def.out_of_scope_domains = oos_domains
    scope_def.program_name = st.session_state.get("program_name", "Bug Bounty")
    scope_def.tester_name  = st.session_state.get("tester_name", "Security Researcher")

    scope_mgr = ScopeManager(scope_def)

    # Validate scope before starting
    warnings = scope_mgr.validate_scope_completeness()
    for w in warnings:
        add_log("warning", f"[SCOPE] {w}")

    st.session_state.scope_summary = {
        "in_scope_domains":     scope_def.in_scope_domains,
        "out_of_scope_domains": scope_def.out_of_scope_domains,
    }
    add_log("info", f"[SCOPE] In-scope: {scope_def.in_scope_domains}")
    if oos_domains:
        add_log("info", f"[SCOPE] Excluded: {oos_domains}")

    add_log("info", f"Target: {target_url}")
    add_log("info", f"Domain: {domain}")
    add_log("info", "Scan initiated. Buckle up.")

    # ── Live scan area ──
    scan_placeholder = st.empty()
    progress_bar = st.progress(0)
    status_text = st.empty()

    total_modules = sum([do_subdomains, do_ports, do_dirs, do_params, do_xss, do_sqli, do_ssrf, do_api, do_cloud, do_network])
    module_num = 0

    def update_progress(frac, msg=""):
        overall = (module_num + frac) / max(total_modules, 1)
        progress_bar.progress(min(overall, 1.0))
        status_text.markdown(f'<span style="font-family:Share+Tech+Mono;color:#00d4ff;font-size:0.85rem;">⟶ {msg}</span>', unsafe_allow_html=True)

    # ── MODULE 1: Subdomain Enumeration ──
    if do_subdomains:
        st.session_state.active_module = "SUBDOMAIN ENUM"
        add_log("info", "[+] Starting subdomain enumeration...")
        update_progress(0, "Subdomain enumeration...")
        try:
            from modules.recon.subdomain_enum import run_subdomain_enum
            results = run_subdomain_enum(domain, use_crtsh=True, progress_callback=update_progress)
            st.session_state.subdomains = results
            takeover = [s for s in results if s.get("takeover_possible")]
            add_log("finding", f"[✓] Found {len(results)} subdomains, {len(takeover)} potential takeovers")
            if takeover:
                for t in takeover:
                    st.session_state.all_findings.append({
                        "type": "Potential Subdomain Takeover",
                        "url": f"https://{t['subdomain']}",
                        "param": "DNS CNAME",
                        "payload": t.get("cname", ""),
                        "severity": "HIGH",
                        "evidence": f"CNAME {t.get('cname')} may be unclaimed",
                        "cvss": 8.1,
                        "remediation": "Verify and reclaim the dangling CNAME record",
                    })
        except Exception as e:
            add_log("error", f"[!] Subdomain enum error: {e}")
        module_num += 1

    # ── MODULE 2: Port Scan ──
    if do_ports:
        st.session_state.active_module = "PORT SCAN"
        add_log("info", f"[+] Port scanning {domain}...")
        update_progress(0, f"Port scanning {domain}...")
        try:
            from modules.recon.port_scanner import run_port_scan, get_risk_summary
            ports = run_port_scan(domain, port_range=port_range, progress_callback=update_progress)
            st.session_state.open_ports = ports
            risk = get_risk_summary(ports)
            add_log("finding", f"[✓] {len(ports)} open ports, risk: {risk['risk_level']}")
            for p in risk.get("risky_ports", []):
                st.session_state.all_findings.append({
                    "type": f"Risky Service Exposed: Port {p['port']} ({p['service']})",
                    "url": f"{domain}:{p['port']}",
                    "param": "Network",
                    "payload": f"Port {p['port']}",
                    "severity": "HIGH",
                    "evidence": f"Service {p['service']} exposed on port {p['port']}. Banner: {p.get('banner', 'N/A')[:100]}",
                    "cvss": 7.5,
                    "remediation": "Restrict access via firewall. Assess if service needs to be internet-facing.",
                })
        except Exception as e:
            add_log("error", f"[!] Port scan error: {e}")
        module_num += 1

    # ── MODULE 3: Directory Fuzzing ──
    if do_dirs:
        st.session_state.active_module = "DIR FUZZING"
        add_log("info", "[+] Starting directory fuzzing...")
        update_progress(0, "Directory fuzzing...")
        try:
            from modules.recon.dir_fuzzer import run_dir_fuzzer
            dir_results = run_dir_fuzzer(target_url, progress_callback=update_progress)
            st.session_state.dir_findings = dir_results
            critical_dirs = [d for d in dir_results if d["severity"] in {"CRITICAL", "HIGH"}]
            add_log("finding", f"[✓] {len(dir_results)} paths found, {len(critical_dirs)} critical/high")
            for d in dir_results:
                if d["severity"] in {"CRITICAL", "HIGH"}:
                    st.session_state.all_findings.append({
                        "type": f"Exposed Path: /{d['path']}",
                        "url": d["url"],
                        "param": "URL Path",
                        "payload": f"GET /{d['path']}",
                        "severity": d["severity"],
                        "evidence": f"HTTP {d['status_code']}, Content-Length: {d['content_length']}",
                        "cvss": 7.5 if d["severity"] == "CRITICAL" else 5.3,
                        "remediation": "Restrict or remove access to sensitive paths",
                    })
        except Exception as e:
            add_log("error", f"[!] Dir fuzzing error: {e}")
        module_num += 1

    # ── MODULE 4: Parameter Discovery ──
    if do_params:
        st.session_state.active_module = "PARAM DISCOVERY"
        add_log("info", "[+] Parameter discovery...")
        update_progress(0, "Parameter discovery...")
        try:
            from modules.recon.param_discovery import run_param_discovery
            param_results = run_param_discovery(target_url, progress_callback=update_progress)
            st.session_state.param_results = param_results
            reflected = param_results.get("common_params_reflected", [])
            add_log("finding", f"[✓] {len(reflected)} reflected parameters found")
        except Exception as e:
            add_log("error", f"[!] Param discovery error: {e}")
        module_num += 1

    # ── MODULE 5: XSS ──
    if do_xss:
        st.session_state.active_module = "XSS SCANNER"
        add_log("info", "[+] XSS testing...")
        update_progress(0, "XSS vulnerability scanning...")
        try:
            from modules.vuln_scan.xss_scanner import run_xss_scanner
            reflected_params = [p["param"] for p in st.session_state.param_results.get("common_params_reflected", [])]
            xss_findings = run_xss_scanner(target_url, params=reflected_params, progress_callback=update_progress)
            st.session_state.xss_findings = xss_findings
            st.session_state.all_findings.extend(xss_findings)
            add_log("finding", f"[✓] {len(xss_findings)} XSS issues found")
        except Exception as e:
            add_log("error", f"[!] XSS scan error: {e}")
        module_num += 1

    # ── MODULE 6: SQLi ──
    if do_sqli:
        st.session_state.active_module = "SQLI SCANNER"
        add_log("info", "[+] SQL injection testing...")
        update_progress(0, "SQL injection testing...")
        try:
            from modules.vuln_scan.sqli_scanner import run_sqli_scanner
            reflected_params = [p["param"] for p in st.session_state.param_results.get("common_params_reflected", [])]
            sqli_findings = run_sqli_scanner(target_url, params=reflected_params, progress_callback=update_progress)
            st.session_state.sqli_findings = sqli_findings
            st.session_state.all_findings.extend(sqli_findings)
            add_log("finding", f"[✓] {len(sqli_findings)} SQLi issues found")
        except Exception as e:
            add_log("error", f"[!] SQLi scan error: {e}")
        module_num += 1

    # ── MODULE 7: SSRF/XXE ──
    if do_ssrf:
        st.session_state.active_module = "SSRF/XXE"
        add_log("info", "[+] SSRF/XXE testing...")
        update_progress(0, "SSRF/XXE vulnerability testing...")
        try:
            from modules.vuln_scan.ssrf_xxe_scanner import run_ssrf_xxe_scanner
            ssrf_findings = run_ssrf_xxe_scanner(target_url, progress_callback=update_progress)
            st.session_state.ssrf_findings = ssrf_findings
            st.session_state.all_findings.extend(ssrf_findings)
            add_log("finding", f"[✓] {len(ssrf_findings)} SSRF/XXE issues found")
        except Exception as e:
            add_log("error", f"[!] SSRF/XXE error: {e}")
        module_num += 1

    # ── MODULE 8: API ──
    if do_api:
        st.session_state.active_module = "API SCANNER"
        add_log("info", "[+] API security testing...")
        update_progress(0, "API security testing...")
        try:
            from modules.api_testing.api_scanner import run_api_scanner
            api_results = run_api_scanner(target_url, progress_callback=update_progress)
            st.session_state.api_results = api_results
            st.session_state.all_findings.extend(api_results.get("all_findings", []))
            add_log("finding", f"[✓] {len(api_results.get('all_findings', []))} API issues found")
        except Exception as e:
            add_log("error", f"[!] API scan error: {e}")
        module_num += 1

    # ── MODULE 9: Cloud ──
    if do_cloud:
        st.session_state.active_module = "CLOUD SCANNER"
        add_log("info", "[+] Cloud security assessment...")
        update_progress(0, "Cloud infrastructure scanning...")
        try:
            from modules.cloud.cloud_scanner import run_cloud_scanner
            cloud_results = run_cloud_scanner(target_url, domain, progress_callback=update_progress)
            st.session_state.cloud_results = cloud_results
            st.session_state.all_findings.extend(cloud_results.get("all_findings", []))
            add_log("finding", f"[✓] {len(cloud_results.get('all_findings', []))} cloud issues found")
        except Exception as e:
            add_log("error", f"[!] Cloud scan error: {e}")
        module_num += 1

    # ── MODULE 10: Network/Headers ──
    if do_network:
        st.session_state.active_module = "NETWORK/HEADERS"
        add_log("info", "[+] Network & headers assessment...")
        update_progress(0, "Security headers & CORS testing...")
        try:
            from modules.network.network_scanner import run_network_scanner
            network_results = run_network_scanner(target_url, domain, progress_callback=update_progress)
            st.session_state.network_results = network_results
            st.session_state.all_findings.extend(network_results.get("all_findings", []))
            add_log("finding", f"[✓] {len(network_results.get('all_findings', []))} security header issues found")
        except Exception as e:
            add_log("error", f"[!] Network scan error: {e}")
        module_num += 1

    progress_bar.progress(1.0)
    status_text.empty()
    st.session_state.scan_running = False
    st.session_state.scan_done = True
    st.session_state.active_module = None
    add_log("info", f"[✓] Scan complete. {len(st.session_state.all_findings)} total findings.")
    st.rerun()


# ─── Main Dashboard Tabs ───────────────────────────────────────────────────────
if not st.session_state.scan_done and not st.session_state.all_findings:
    # ── Welcome Screen ──
    st.markdown("""
    <div style="text-align:center; padding: 60px 20px; background: linear-gradient(135deg, #050a0f, #0d1e2e); border: 1px solid #1a3a5c; border-radius: 12px; margin: 20px 0;">
        <div style="font-family: Orbitron, monospace; font-size: 1.2rem; color: #00ff9d; letter-spacing: 4px; margin-bottom: 20px;">SYSTEM READY</div>
        <div style="font-family: Share Tech Mono, monospace; color: #7aa8cc; font-size: 0.85rem; letter-spacing: 2px; margin-bottom: 30px;">AWAITING TARGET ACQUISITION</div>
        <div style="font-family: Share Tech Mono, monospace; color: #3a5a7c; font-size: 0.75rem;">
            Enter a target URL in the sidebar → Configure modules → Launch scan
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("### 🛡️ AVAILABLE MODULES")
    cols = st.columns(5)
    modules = [
        ("🌐", "SUBDOMAIN ENUM", "crt.sh + DNS brute-force"),
        ("🔌", "PORT SCANNER", "TCP connect on 70+ ports"),
        ("📁", "DIR FUZZER", "150+ sensitive path checks"),
        ("🔍", "PARAM DISCOVERY", "HTML + common params"),
        ("⚡", "XSS SCANNER", "14 reflected/stored payloads"),
        ("💉", "SQLI SCANNER", "Error + Boolean blind"),
        ("🎣", "SSRF/XXE", "Cloud metadata + XML injection"),
        ("🔌", "API SCANNER", "REST/GraphQL + BOLA testing"),
        ("☁️", "CLOUD SCANNER", "S3/Azure/GCP/Firebase"),
        ("🛡️", "HEADERS/CORS", "15+ security header checks"),
    ]
    for i, (icon, name, desc) in enumerate(modules):
        with cols[i % 5]:
            st.markdown(f"""
            <div class="stat-card" style="margin-bottom:10px;">
                <div style="font-size:1.5rem;">{icon}</div>
                <div style="font-family: Orbitron, monospace; font-size: 0.6rem; color: #00d4ff; letter-spacing: 1px; margin: 6px 0;">{name}</div>
                <div style="font-size: 0.65rem; color: #5a8aac;">{desc}</div>
            </div>
            """, unsafe_allow_html=True)

else:
    # ── Results Dashboard ──
    all_findings = st.session_state.all_findings
    counts = count_by_severity(all_findings)

    # Summary metrics
    from modules.reporting.report_gen import calculate_risk_score
    risk_score = calculate_risk_score(all_findings)
    risk_color = "#ff3366" if risk_score >= 8 else "#ff6b35" if risk_score >= 6 else "#ffd700" if risk_score >= 4 else "#00ff9d"

    col1, col2, col3, col4, col5, col6 = st.columns(6)
    with col1:
        st.markdown(f"""<div class="stat-card"><div class="stat-number" style="color:{risk_color};">{risk_score}</div><div class="stat-label">RISK SCORE</div></div>""", unsafe_allow_html=True)
    with col2:
        st.markdown(f"""<div class="stat-card"><div class="stat-number" style="color:#ff3366;">{counts['CRITICAL']}</div><div class="stat-label">CRITICAL</div></div>""", unsafe_allow_html=True)
    with col3:
        st.markdown(f"""<div class="stat-card"><div class="stat-number" style="color:#ff6b35;">{counts['HIGH']}</div><div class="stat-label">HIGH</div></div>""", unsafe_allow_html=True)
    with col4:
        st.markdown(f"""<div class="stat-card"><div class="stat-number" style="color:#ffd700;">{counts['MEDIUM']}</div><div class="stat-label">MEDIUM</div></div>""", unsafe_allow_html=True)
    with col5:
        st.markdown(f"""<div class="stat-card"><div class="stat-number" style="color:#00ff9d;">{counts['LOW']}</div><div class="stat-label">LOW</div></div>""", unsafe_allow_html=True)
    with col6:
        st.markdown(f"""<div class="stat-card"><div class="stat-number" style="color:#00d4ff;">{len(all_findings)}</div><div class="stat-label">TOTAL</div></div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Tabs
    tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8 = st.tabs([
        "🎯 FINDINGS", "🌐 RECON", "⚡ VULNS", "🔌 API", "☁️ CLOUD", "🛡️ NETWORK", "📟 TERMINAL", "📄 REPORT"
    ])

    # ── TAB 1: All Findings ──
    with tab1:
        st.markdown(f"### 🎯 All Findings — `{st.session_state.target_url}`")

        if not all_findings:
            st.success("✅ No vulnerabilities found! Target appears clean.")
        else:
            sev_filter = st.multiselect("Filter by Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                                         default=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])

            sorted_findings = sorted(
                [f for f in all_findings if f.get("severity") in sev_filter],
                key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(x.get("severity"), 99)
            )

            for i, finding in enumerate(sorted_findings):
                sev = finding.get("severity", "INFO")
                sev_c = sev_color(sev)
                css_class = sev.lower()

                with st.expander(f"{sev_emoji(sev)} [{sev}] {finding.get('type', 'Unknown')} — {finding.get('url', '')[:60]}", expanded=(sev == "CRITICAL")):
                    col_a, col_b = st.columns([2, 1])
                    with col_a:
                        st.markdown(f"**URL:** `{finding.get('url', 'N/A')}`")
                        st.markdown(f"**Parameter:** `{finding.get('param', 'N/A')}`")
                        st.markdown(f"**Evidence:** {finding.get('evidence', 'N/A')}")
                        if finding.get('payload') and finding.get('payload') != 'N/A':
                            st.code(finding.get('payload', ''), language="text")
                    with col_b:
                        st.markdown(f"**Severity:** <span style='color:{sev_c};font-weight:bold;'>{sev}</span>", unsafe_allow_html=True)
                        cvss = finding.get('cvss', 'N/A')
                        st.markdown(f"**CVSS:** `{cvss}`")
                        st.markdown(f"**Remediation:**\n{finding.get('remediation', 'See OWASP')}")

    # ── TAB 2: Recon ──
    with tab2:
        st.markdown("### 🌐 Reconnaissance Results")

        r1, r2 = st.columns(2)
        with r1:
            subs = st.session_state.subdomains
            st.markdown(f"#### Subdomains ({len(subs)} found)")
            if subs:
                takeover = [s for s in subs if s.get("takeover_possible")]
                if takeover:
                    st.warning(f"⚠️ {len(takeover)} potential subdomain takeover(s) detected!")
                for s in subs[:50]:
                    icon = "⚠️" if s.get("takeover_possible") else "✅"
                    ips = ", ".join(s.get("ips", []))
                    cname = s.get("cname", "")
                    st.markdown(f"`{icon} {s['subdomain']}` → `{ips or cname}`")
                if len(subs) > 50:
                    st.caption(f"... and {len(subs) - 50} more")

        with r2:
            ports = st.session_state.open_ports
            st.markdown(f"#### Open Ports ({len(ports)} found)")
            if ports:
                for p in ports:
                    risky_icon = "⚠️" if p.get("risky") else "✅"
                    st.markdown(f"`{risky_icon} {p['port']}/tcp` — **{p.get('service', '?')}** {f'*({p[\"banner\"][:50]})*' if p.get('banner') else ''}")

        st.divider()
        dirs = st.session_state.dir_findings
        st.markdown(f"#### Directory Fuzzing ({len(dirs)} paths found)")
        if dirs:
            for d in dirs[:60]:
                if d["severity"] in {"CRITICAL", "HIGH", "MEDIUM"}:
                    c = sev_color(d["severity"])
                    st.markdown(f"<span style='color:{c};'>[{d['severity']}]</span> `{d['url']}` — HTTP {d['status_code']}", unsafe_allow_html=True)

    # ── TAB 3: Vulns ──
    with tab3:
        st.markdown("### ⚡ Vulnerability Scan Results")

        v1, v2, v3 = st.columns(3)
        with v1:
            xss = st.session_state.xss_findings
            st.markdown(f"#### XSS ({len(xss)} found)")
            if xss:
                for f in xss:
                    st.markdown(f"🔴 **{f['type']}**\n- Param: `{f['param']}`\n- `{f['payload'][:60]}`")
            else:
                st.markdown("✅ No XSS found")

        with v2:
            sqli = st.session_state.sqli_findings
            st.markdown(f"#### SQLi ({len(sqli)} found)")
            if sqli:
                for f in sqli:
                    st.markdown(f"🔴 **{f['type']}**\n- Param: `{f['param']}`\n- {f['evidence'][:80]}")
            else:
                st.markdown("✅ No SQLi found")

        with v3:
            ssrf = st.session_state.ssrf_findings
            st.markdown(f"#### SSRF/XXE ({len(ssrf)} found)")
            if ssrf:
                for f in ssrf:
                    st.markdown(f"🔴 **{f['type']}**\n- Param: `{f['param']}`\n- {f['evidence'][:80]}")
            else:
                st.markdown("✅ No SSRF/XXE found")

    # ── TAB 4: API ──
    with tab4:
        st.markdown("### 🔌 API Security Testing")
        api = st.session_state.api_results
        if api:
            endpoints = api.get("endpoints_discovered", [])
            st.markdown(f"#### Endpoints Discovered ({len(endpoints)})")
            for e in endpoints:
                icon = "📜" if e.get("is_swagger_docs") else "🔌"
                c = "🟢" if e["status"] == 200 else "🟡"
                st.markdown(f"{c} {icon} `{e['url']}` — HTTP {e['status']}")

            findings = api.get("all_findings", [])
            if findings:
                st.markdown(f"#### API Findings ({len(findings)})")
                for f in findings:
                    st.markdown(f"{sev_emoji(f['severity'])} **{f['type']}**\n- {f['evidence'][:120]}")

    # ── TAB 5: Cloud ──
    with tab5:
        st.markdown("### ☁️ Cloud Security Assessment")
        cloud = st.session_state.cloud_results
        if cloud:
            s3 = [r for r in cloud.get("s3_results", []) if r.get("exists")]
            if s3:
                st.markdown(f"#### S3 Buckets Found ({len(s3)})")
                for b in s3:
                    icon = "🔓" if b.get("public") else "🔒"
                    listable = "LISTABLE" if b.get("listable") else "EXISTS"
                    st.markdown(f"{icon} `{b['bucket']}` — {listable}")

            all_cloud_findings = cloud.get("all_findings", [])
            if all_cloud_findings:
                st.markdown(f"#### Cloud Findings ({len(all_cloud_findings)})")
                for f in all_cloud_findings:
                    st.markdown(f"{sev_emoji(f['severity'])} **{f['type']}**\n- `{f['url']}`\n- {f['evidence']}")
            else:
                st.success("✅ No exposed cloud resources found")

    # ── TAB 6: Network/Headers ──
    with tab6:
        st.markdown("### 🛡️ Network Security & Headers")
        net = st.session_state.network_results
        if net:
            h1, h2 = st.columns(2)
            with h1:
                header_f = net.get("header_findings", [])
                st.markdown(f"#### Security Headers ({len(header_f)} issues)")
                for f in header_f:
                    st.markdown(f"{sev_emoji(f['severity'])} {f['type']}")

            with h2:
                cors_f = net.get("cors_findings", [])
                ssl_f = net.get("ssl_findings", [])
                st.markdown(f"#### CORS Issues ({len(cors_f)})")
                for f in cors_f:
                    st.markdown(f"{sev_emoji(f['severity'])} **{f['type']}**\n- {f['evidence']}")
                st.markdown(f"#### SSL/TLS Issues ({len(ssl_f)})")
                for f in ssl_f:
                    st.markdown(f"{sev_emoji(f['severity'])} {f['type']}")
                if not cors_f and not ssl_f:
                    st.success("✅ CORS and SSL appear properly configured")

    # ── TAB 7: Terminal ──
    with tab7:
        st.markdown("### 📟 Live Terminal Output")
        logs = st.session_state.terminal_logs
        if logs:
            terminal_html = '<div class="terminal">'
            for entry in logs:
                css_class = {
                    "info": "info", "error": "error", "warning": "warning", "finding": "finding"
                }.get(entry["level"], "")
                terminal_html += f'<div class="terminal-line {css_class}">[{entry["ts"]}] {entry["msg"]}</div>'
            terminal_html += '</div>'
            st.markdown(terminal_html, unsafe_allow_html=True)
        else:
            st.markdown('<div class="terminal"><div class="terminal-line">Awaiting scan...</div></div>', unsafe_allow_html=True)

    # ── TAB 8: Report ──
    with tab8:
        st.markdown("### 📄 Professional Bug Bounty Report")
        st.markdown(
            "Generate a publication-quality PDF report suitable for submission to bug bounty programs "
            "and private pentest clients. The report includes full attack narratives, step-by-step "
            "reproduction chains, CVSS scoring, a risk matrix, and a prioritized remediation roadmap."
        )

        st.markdown("#### 🧑‍💼 Report Metadata")
        col_r1, col_r2 = st.columns(2)
        with col_r1:
            rpt_program   = st.text_input("Program / Engagement Name", value=st.session_state.get("program_name", "Bug Bounty Assessment"))
            rpt_company   = st.text_input("Target Company Name",        value=st.session_state.get("company_name", ""))
            rpt_tester    = st.text_input("Tester / Researcher Name",   value=st.session_state.get("tester_name", "Security Researcher"))
        with col_r2:
            rpt_eng_id    = st.text_input("Engagement ID",              value=st.session_state.get("engagement_id", f"BBH-{datetime.now().strftime('%Y%m%d')}"))
            rpt_roe       = st.text_area("Rules of Engagement",
                value="Testing limited to passive and active reconnaissance, web application vulnerability "
                      "assessment, cloud infrastructure review, and network security header analysis. "
                      "No destructive testing or data exfiltration beyond proof-of-concept was performed.",
                height=80
            )

        st.markdown("---")
        col_pdf1, col_pdf2 = st.columns(2)
        with col_pdf1:
            gen_pdf = st.button("📄 GENERATE PDF REPORT", use_container_width=True)
        with col_pdf2:
            # JSON export always available
            st.download_button(
                "⬇️ EXPORT FINDINGS (.json)",
                data=json.dumps(st.session_state.all_findings, indent=2),
                file_name=f"findings_{st.session_state.domain}_{datetime.now().strftime('%Y%m%d_%H%M')}.json",
                mime="application/json",
                use_container_width=True,
            )

        if gen_pdf:
            with st.spinner("🔨 Building PDF report — this may take 10–20 seconds..."):
                try:
                    from modules.reporting.pdf_report_gen import generate_pdf_report

                    scan_data = {
                        "target":              st.session_state.target_url,
                        "domain":              st.session_state.domain,
                        "timestamp":           datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
                        "program_name":        rpt_program,
                        "company_name":        rpt_company,
                        "tester_name":         rpt_tester,
                        "engagement_id":       rpt_eng_id,
                        "rules_of_engagement": rpt_roe,
                        "all_findings":        st.session_state.all_findings,
                        "subdomains":          st.session_state.subdomains,
                        "open_ports":          st.session_state.open_ports,
                        "terminal_logs":       st.session_state.terminal_logs,
                        "scope_violations":    st.session_state.get("scope_violations", []),
                        "scope_summary":       st.session_state.get("scope_summary", {
                            "in_scope_domains":     [st.session_state.domain, f"*.{st.session_state.domain}"],
                            "out_of_scope_domains": [],
                        }),
                    }

                    import tempfile, os
                    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
                        tmp_path = tmp.name

                    generate_pdf_report(scan_data, tmp_path)

                    with open(tmp_path, "rb") as f:
                        pdf_bytes = f.read()
                    os.unlink(tmp_path)

                    fname = f"pentest_report_{st.session_state.domain}_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
                    st.success(f"✅ PDF report generated — {len(pdf_bytes)//1024} KB")
                    st.download_button(
                        "⬇️ DOWNLOAD PDF REPORT",
                        data=pdf_bytes,
                        file_name=fname,
                        mime="application/pdf",
                        use_container_width=True,
                    )

                    # Preview summary
                    st.markdown("#### 📋 Report Contents Preview")
                    counts = {sev: sum(1 for f in st.session_state.all_findings if f.get("severity") == sev)
                              for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]}
                    st.markdown(f"""
                    The generated PDF contains:
                    - **Cover page** with risk score badge and engagement metadata
                    - **Table of contents** with all {len(st.session_state.all_findings)} findings
                    - **Executive summary** for CISO-level readers
                    - **Scope & Rules of Engagement** section with any blocked out-of-scope requests
                    - **Risk matrix heat map** plotting findings by impact × likelihood
                    - **{len(st.session_state.all_findings)} detailed findings**, each with:
                      - Step-by-step attack narrative (exactly how the intrusion was performed)
                      - Exact payloads used and server responses
                      - CVSS score bar chart
                      - Remediation guidance + OWASP/CWE references
                    - **Reconnaissance appendix** ({len(st.session_state.subdomains)} subdomains, {len(st.session_state.open_ports)} open ports)
                    - **Prioritized remediation roadmap** by severity timeline
                    - **Raw scan logs** appendix
                    """)

                except Exception as e:
                    st.error(f"PDF generation failed: {e}")
                    import traceback
                    st.code(traceback.format_exc())
