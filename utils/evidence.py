"""
evidence.py — Live Evidence Capture Layer

This is the most critical addition to the platform. Every time a scanner
makes an HTTP request and observes something interesting, it MUST record
a full EvidenceRecord here. This is what separates a real pentest report
from a generic scanner output dump.

The evidence record captures:
  - The exact raw HTTP request that was sent (method, URL, headers, body)
  - The exact raw HTTP response that came back (status, headers, body excerpt)
  - A before/after diff for blind techniques (boolean SQLi, timing attacks)
  - A human-readable explanation of WHY the response proves vulnerability
  - The tool used, why it was chosen, and what it achieves
  - The chronological timestamp so the report can tell a time-ordered story
  - The attack phase (recon, scanning, exploitation) for narrative structure
"""

import time
import textwrap
from dataclasses import dataclass, field
from typing import Optional, List, Dict
from datetime import datetime
import requests


@dataclass
class HttpTransaction:
    """
    A complete HTTP request/response pair — the raw forensic evidence.
    Every finding must have at least one of these to be credible.
    """
    # Request side
    method: str = "GET"
    url: str = ""
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: str = ""

    # Response side
    status_code: int = 0
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body_excerpt: str = ""       # First 800 chars of response body
    response_length: int = 0
    response_time_ms: float = 0.0

    # Annotation — what to look at and why it matters
    annotation: str = ""                  # "Look at line 12 — the SQL error leaks the table name"

    def format_request(self) -> str:
        """Format as raw HTTP request text, like Burp Suite's request tab."""
        parsed_url = self.url.split("?", 1)
        path = parsed_url[0].split("/", 3)[-1] if "/" in parsed_url[0] else "/"
        path = "/" + path if not path.startswith("/") else path
        if len(parsed_url) > 1:
            path += "?" + parsed_url[1]

        host = self.url.split("/")[2] if "//" in self.url else self.url
        lines = [f"{self.method} {path} HTTP/1.1", f"Host: {host}"]
        for k, v in self.request_headers.items():
            if k.lower() not in ("host",):
                lines.append(f"{k}: {v}")
        if self.request_body:
            lines.append("")
            lines.append(self.request_body)
        return "\n".join(lines)

    def format_response(self) -> str:
        """Format as raw HTTP response text."""
        lines = [f"HTTP/1.1 {self.status_code}"]
        for k, v in self.response_headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        lines.append(self.response_body_excerpt)
        return "\n".join(lines)

    def format_diff(self, other: "HttpTransaction", label_a="TRUE condition", label_b="FALSE condition") -> str:
        """
        Format a side-by-side comparison for blind techniques.
        This shows the validator exactly why we conclude vulnerability exists
        even when no error message appears.
        """
        return (
            f"=== {label_a} ===\n"
            f"URL: {self.url}\n"
            f"Response length: {self.response_length} bytes | Status: {self.status_code}\n"
            f"Body excerpt: {self.response_body_excerpt[:200]}\n\n"
            f"=== {label_b} ===\n"
            f"URL: {other.url}\n"
            f"Response length: {other.response_length} bytes | Status: {other.status_code}\n"
            f"Body excerpt: {other.response_body_excerpt[:200]}\n\n"
            f"LENGTH DIFFERENCE: {abs(self.response_length - other.response_length)} bytes\n"
            f"CONCLUSION: Statistically significant difference proves conditional SQL execution."
        )


@dataclass
class EvidenceRecord:
    """
    The complete evidence package for a single finding.
    The PDF report renderer reads this structure directly.
    """
    # Identity
    finding_id: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))

    # Classification
    vulnerability_class: str = ""        # e.g. "SQL Injection (Error-based)"
    attack_phase: str = ""               # "Recon" | "Scanning" | "Exploitation" | "Post-exploitation"
    severity: str = "INFO"
    cvss_score: float = 0.0
    cvss_vector: str = ""

    # Tool context — WHY this tool was used and WHAT it achieves
    tool_name: str = ""
    tool_purpose: str = ""               # "We used SQLmap-style payload cycling to..."
    tool_why_chosen: str = ""            # "This technique works because the application..."
    tool_how_it_works: str = ""          # Step-level explanation of the technique

    # Target
    target_url: str = ""
    target_parameter: str = ""
    target_parameter_context: str = ""   # "GET parameter passed directly into SQL WHERE clause"

    # The payload
    payload_used: str = ""
    payload_explanation: str = ""        # "The single quote breaks the SQL string literal..."

    # Live HTTP evidence — the smoking gun
    http_transactions: List[HttpTransaction] = field(default_factory=list)
    comparison_transaction: Optional[HttpTransaction] = None  # For blind techniques

    # What the server revealed
    server_response_analysis: str = ""   # "The MySQL error on line 12 reveals the table name 'users'..."

    # Why this vulnerability EXISTS
    root_cause: str = ""                 # "The developer used string concatenation instead of..."

    # Why this vulnerability MATTERS — for CISO and business stakeholders
    vulnerability_importance: str = ""  # "SQL injection is ranked #3 in the OWASP Top 10 because..."
    business_impact: str = ""           # "An attacker could dump the entire customer database..."
    real_world_scenario: str = ""       # "In 2017, Equifax lost 147 million records via SQLi..."
    financial_impact_estimate: str = "" # "Average cost of a data breach: $4.45M (IBM 2023)"

    # Proof of exploitability
    exploitation_confirmed: bool = False
    exploitation_evidence: str = ""      # "We extracted the first row of the users table: admin@..."

    # Remediation
    immediate_fix: str = ""             # What to do right now (hours)
    long_term_fix: str = ""             # Architectural improvement (weeks)
    verification_steps: str = ""        # How to verify the fix worked

    # References
    cwe: str = ""
    owasp: str = ""
    cvss_references: List[str] = field(default_factory=list)

    # Narrative position
    attack_chain_position: int = 0      # Which step in the overall attack chain
    chains_into: str = ""               # "This finding enabled access to finding #3 (SSRF)"


def capture_http(
    session: requests.Session,
    method: str,
    url: str,
    annotation: str = "",
    **kwargs
) -> tuple[Optional[requests.Response], HttpTransaction]:
    """
    Drop-in wrapper around session.request() that captures the full
    HTTP transaction into an HttpTransaction object.

    Every scanner module should use this instead of calling session.get/post
    directly whenever it needs to record evidence.
    """
    tx = HttpTransaction()
    tx.method = method.upper()
    tx.url = url
    tx.annotation = annotation

    # Capture request headers (merge session headers + call headers)
    merged_headers = dict(session.headers)
    if "headers" in kwargs:
        merged_headers.update(kwargs["headers"])
    tx.request_headers = {k: v for k, v in merged_headers.items()
                          if k.lower() not in ("cookie", "authorization")}  # don't leak creds

    if "data" in kwargs and kwargs["data"]:
        tx.request_body = str(kwargs["data"])[:500]
    if "json" in kwargs and kwargs["json"]:
        import json
        tx.request_body = json.dumps(kwargs["json"])[:500]

    try:
        start = time.time()
        resp = session.request(method, url, **kwargs)
        elapsed = (time.time() - start) * 1000

        tx.status_code = resp.status_code
        tx.response_headers = dict(resp.headers)
        tx.response_length = len(resp.content)
        tx.response_time_ms = round(elapsed, 1)

        # Capture the most forensically useful part of the body
        body = resp.text[:1200]
        # Strip excessive whitespace but preserve structure
        import re
        body = re.sub(r'\n{3,}', '\n\n', body)
        tx.response_body_excerpt = body.strip()

        return resp, tx

    except requests.exceptions.Timeout:
        tx.status_code = 0
        tx.response_body_excerpt = "[REQUEST TIMED OUT]"
        tx.response_time_ms = -1
        return None, tx
    except Exception as e:
        tx.status_code = 0
        tx.response_body_excerpt = f"[CONNECTION ERROR: {e}]"
        return None, tx


def extract_error_context(body: str, pattern: str, context_chars: int = 200) -> str:
    """
    Extract the surrounding context around a pattern match in an HTTP response.
    This gives the validator exactly the line that proves the vulnerability,
    not just the whole response body.
    """
    import re
    match = re.search(pattern, body, re.IGNORECASE)
    if not match:
        return body[:context_chars]
    start = max(0, match.start() - 80)
    end = min(len(body), match.end() + 120)
    excerpt = body[start:end].strip()
    # Mark the exact match
    return f"...{excerpt}..."
