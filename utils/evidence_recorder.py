"""
evidence_recorder.py — Real-time forensic evidence capture

Every HTTP request and response made by any scanner module is captured
here in full. This is the foundation that makes the report credible —
instead of saying "SQLi found", the report shows the actual request
sent, the actual error that came back, and exactly what it proves.

Think of this as the scanner's black box flight recorder.
"""

import time
import json
from datetime import datetime
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field, asdict
import requests


@dataclass
class HTTPRequestRecord:
    """Full record of an outgoing HTTP request."""
    method: str
    url: str
    headers: Dict[str, str]
    params: Dict[str, str]
    body: Optional[str]
    timestamp: str
    purpose: str          # WHY this request was sent — e.g. "Injecting single quote to test SQL parsing"


@dataclass
class HTTPResponseRecord:
    """Full record of an HTTP response received."""
    status_code: int
    headers: Dict[str, str]
    body_snippet: str     # First 800 chars — enough to show the proof
    full_body_length: int
    response_time_ms: float
    content_type: str


@dataclass
class DiffEvidence:
    """
    Side-by-side comparison used for blind/boolean testing.
    Shows the baseline vs. the anomalous response so the reader
    can see with their own eyes that the server behaves differently.
    """
    baseline_request: str
    baseline_response_length: int
    baseline_status: int
    probe_request: str
    probe_response_length: int
    probe_status: int
    length_delta: int
    interpretation: str   # "Server returns 2,847 bytes for true condition, 412 for false — boolean SQLi confirmed"


@dataclass
class ToolExplanation:
    """
    Explains the tool / technique used — why this specific tool,
    how it works mechanically, and what a manual equivalent looks like.
    This is what separates a professional report from a scanner dump.
    """
    tool_name: str             # "Custom HTTP Client with error-based SQLi probes"
    why_this_tool: str         # "Error-based probing is the fastest way to confirm SQLi..."
    how_it_works: str          # "A single-quote character is appended to the parameter..."
    what_output_means: str     # "A MySQL syntax error in the response proves..."
    manual_equivalent: str     # "curl 'https://target.com/login?id=1%27' -v"
    burp_instruction: str      # "In Burp Repeater: send GET /login?id=1' — observe 500 response"


@dataclass
class BusinessImpact:
    """
    Translates the technical finding into language that matters
    to a CISO, CEO, or bug bounty triage analyst.
    """
    what_attacker_can_do: str      # Concrete attack scenario
    data_at_risk: str              # What data/systems are exposed
    worst_case_scenario: str       # If fully exploited, what happens
    affected_users: str            # Scale of impact
    regulatory_implications: str   # GDPR, PCI-DSS, HIPAA angle
    estimated_severity_rationale: str  # Why this CVSS score


@dataclass
class CVSSBreakdown:
    """Full CVSS v3.1 vector breakdown with explanation of each metric."""
    vector_string: str         # "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    base_score: float
    attack_vector: str         # "Network — exploitable remotely over the internet"
    attack_complexity: str     # "Low — no special conditions required"
    privileges_required: str   # "None — no authentication needed"
    user_interaction: str      # "None — victim interaction not required"
    scope: str                 # "Changed — impact crosses security boundaries"
    confidentiality: str       # "High — full read access to sensitive data"
    integrity: str             # "High — attacker can modify or delete data"
    availability: str          # "High — service can be disrupted"


@dataclass
class EvidenceRecord:
    """
    Complete forensic record for a single finding.
    Contains everything needed to prove the vulnerability exists,
    demonstrate how it was found, and explain why it matters.
    """
    finding_id: str
    timestamp: str
    module: str               # Which scanner found this
    vulnerability_class: str  # "SQL Injection", "XSS", "SSRF", etc.

    # The actual proof
    request: Optional[HTTPRequestRecord] = None
    response: Optional[HTTPResponseRecord] = None
    diff: Optional[DiffEvidence] = None

    # Additional evidence items (e.g. second request in a chain)
    additional_requests: List[Dict] = field(default_factory=list)

    # Explanations
    tool_explanation: Optional[ToolExplanation] = None
    business_impact: Optional[BusinessImpact] = None
    cvss_breakdown: Optional[CVSSBreakdown] = None

    # Step-by-step attack narrative
    attack_steps: List[Dict] = field(default_factory=list)

    # Exact reproduction commands
    curl_command: str = ""
    sqlmap_command: str = ""
    burp_steps: str = ""

    # What the finding proves
    proof_statement: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


class EvidenceRecorder:
    """
    Central evidence collection engine. Every scanner module
    gets an instance of this and calls record_interaction()
    for every meaningful HTTP exchange.
    """

    def __init__(self, target_url: str):
        self.target_url = target_url
        self.records: List[EvidenceRecord] = []
        self._counter = 0

    def capture_request_response(
        self,
        session: requests.Session,
        method: str,
        url: str,
        purpose: str,
        params: Dict = None,
        data: Any = None,
        headers: Dict = None,
        timeout: int = 10
    ) -> tuple[Optional[requests.Response], HTTPRequestRecord, Optional[HTTPResponseRecord]]:
        """
        Make an HTTP request and capture the full forensic record.
        Returns (response, request_record, response_record).
        """
        req_headers = dict(session.headers)
        if headers:
            req_headers.update(headers)

        req_record = HTTPRequestRecord(
            method=method,
            url=url,
            headers={k: v for k, v in req_headers.items() if k.lower() not in ('cookie',)},
            params=params or {},
            body=str(data) if data else None,
            timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            purpose=purpose
        )

        start = time.time()
        resp = None
        resp_record = None

        try:
            resp = session.request(
                method, url,
                params=params, data=data, headers=headers,
                timeout=timeout, allow_redirects=False, verify=False
            )
            elapsed_ms = (time.time() - start) * 1000

            # Capture body — truncate for storage but keep enough for proof
            try:
                body_text = resp.text[:1200]
            except Exception:
                body_text = "[binary content]"

            resp_record = HTTPResponseRecord(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body_snippet=body_text,
                full_body_length=len(resp.content),
                response_time_ms=round(elapsed_ms, 1),
                content_type=resp.headers.get("Content-Type", "")
            )
        except requests.exceptions.Timeout:
            elapsed_ms = (time.time() - start) * 1000
            resp_record = HTTPResponseRecord(
                status_code=0,
                headers={},
                body_snippet="[REQUEST TIMED OUT]",
                full_body_length=0,
                response_time_ms=round(elapsed_ms, 1),
                content_type=""
            )
        except Exception as e:
            resp_record = HTTPResponseRecord(
                status_code=0,
                headers={},
                body_snippet=f"[ERROR: {str(e)[:100]}]",
                full_body_length=0,
                response_time_ms=0,
                content_type=""
            )

        return resp, req_record, resp_record

    def new_record(self, module: str, vuln_class: str) -> EvidenceRecord:
        """Create a new evidence record for a finding being investigated."""
        self._counter += 1
        return EvidenceRecord(
            finding_id=f"FIND-{self._counter:03d}",
            timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            module=module,
            vulnerability_class=vuln_class
        )

    def save(self, record: EvidenceRecord):
        """Commit a completed evidence record."""
        self.records.append(record)

    def get_all(self) -> List[EvidenceRecord]:
        return self.records

    def export_json(self) -> str:
        return json.dumps([r.to_dict() for r in self.records], indent=2, default=str)


# ── Tool + Business Impact factories ──────────────────────────────────────────
# These build the explanatory blocks for each vulnerability class.
# This is the institutional knowledge of 30 years of pentesting — codified.

def make_tool_explanation(vuln_type: str, url: str, param: str, payload: str) -> ToolExplanation:
    t = vuln_type.lower()

    if "sql" in t and "error" in t:
        return ToolExplanation(
            tool_name="Error-based SQL Injection Probe",
            why_this_tool=(
                "Error-based SQLi probing is the most direct confirmation method. "
                "By injecting characters that break SQL syntax — specifically a single quote (') "
                "— we force the database engine to generate an error message. If that error "
                "leaks into the HTTP response, it proves beyond doubt that: (1) the application "
                "is building SQL queries by concatenating user input directly, and (2) database "
                "error messages are not suppressed. This is faster and less intrusive than "
                "time-based or UNION-based techniques."
            ),
            how_it_works=(
                "The scanner appends a single quote character to the parameter value. A correctly "
                "written application using parameterised queries would treat this as literal data "
                "and return a normal response. A vulnerable application passes the quote directly "
                "into the SQL string, causing the query to break at the parser level. The database "
                "engine (MySQL, PostgreSQL, MSSQL, Oracle) generates a syntax error. If the "
                "application propagates this error to the HTTP response body — even partially — "
                "the error string is detected in the response text."
            ),
            what_output_means=(
                "The presence of a database error string (e.g. 'You have an error in your SQL "
                "syntax', 'ORA-01756', 'pg_query(): Query failed') in the response body is "
                "definitive proof of SQL injection. It means an attacker can manipulate the "
                "SQL query logic — reading arbitrary tables, bypassing authentication, or in "
                "some configurations executing operating system commands."
            ),
            manual_equivalent=f"curl -g -k \"{url.split('?')[0]}?{param}=%27\" -v 2>&1 | grep -A5 'error\\|syntax\\|SQL'",
            burp_instruction=(
                f"1. Intercept GET {url} in Burp Proxy\n"
                f"2. Send to Repeater (Ctrl+R)\n"
                f"3. Change parameter {param} value to: '\n"
                f"4. Click Send\n"
                f"5. In Response tab: search for 'SQL', 'syntax', 'error'\n"
                f"6. A database error message confirms SQL injection"
            )
        )

    elif "sql" in t and "boolean" in t:
        return ToolExplanation(
            tool_name="Boolean-based Blind SQL Injection Differential Analysis",
            why_this_tool=(
                "When error messages are suppressed (a common but insufficient hardening measure), "
                "boolean-based blind testing reveals injection by observing differences in application "
                "behaviour rather than error text. Two logically opposite conditions are injected — "
                "one always-true (AND 1=1) and one always-false (AND 1=2). A vulnerable application "
                "returns different content for each, betraying that it is evaluating the injected logic."
            ),
            how_it_works=(
                "Two requests are sent with near-identical parameters except for the boolean condition. "
                "The true condition (1=1) causes the database to return its normal result set. The false "
                "condition (1=2) causes the database to return an empty result. The application renders "
                "different HTML for each case — either visibly (different content) or measurably "
                "(different byte count). A consistent delta of more than 50 bytes between the two "
                "responses confirms the server is evaluating injected SQL logic."
            ),
            what_output_means=(
                "Although no error is visible, the server is still vulnerable to full SQL injection. "
                "An attacker can extract the entire database content bit-by-bit using binary search "
                "over boolean queries. Tools like sqlmap automate this completely. Extraction of "
                "usernames, password hashes, emails, and all stored data is achievable."
            ),
            manual_equivalent=(
                f"# True condition (should return content):\n"
                f"curl -g -k \"{url}?{param}=1+AND+1=1--\" -s | wc -c\n"
                f"# False condition (should return empty/different):\n"
                f"curl -g -k \"{url}?{param}=1+AND+1=2--\" -s | wc -c\n"
                f"# Significant difference confirms blind SQLi"
            ),
            burp_instruction=(
                f"1. Send {url} to Burp Intruder\n"
                f"2. Set payload position on {param} value\n"
                f"3. Payload 1: 1 AND 1=1--  (true)\n"
                f"4. Payload 2: 1 AND 1=2--  (false)\n"
                f"5. Compare response lengths — difference confirms blind SQLi\n"
                f"6. Run: sqlmap -u \"{url}\" -p {param} --level=3 --dbs"
            )
        )

    elif "xss" in t:
        return ToolExplanation(
            tool_name="Reflected XSS Payload Injection via HTTP Parameter",
            why_this_tool=(
                "Reflected Cross-Site Scripting testing works by injecting HTML/JavaScript payloads "
                "into parameters and checking whether they appear unescaped in the server's response. "
                "The test payload <script>alert(1)</script> is a universally recognised benign marker "
                "— it causes no damage but its presence verbatim in the response body proves the "
                "server is echoing input without HTML-encoding it, which is the root cause of XSS."
            ),
            how_it_works=(
                "The scanner iterates through a set of XSS payloads of increasing complexity — starting "
                "with the canonical <script> tag, then event-handler injections (onerror, onload), "
                "then attribute-breaking payloads (\"), and finally filter bypass variants (mixed case, "
                "encoding). Each payload is injected into the target parameter via GET request. The "
                "response body is searched for the payload string. A verbatim match means the server "
                "is reflecting user input into an HTML context without escaping — the payload would "
                "execute as JavaScript in a victim's browser."
            ),
            what_output_means=(
                "The server is reflecting untrusted input directly into HTML without encoding < > \" ' "
                "characters. Any user who visits a URL containing this payload will have the JavaScript "
                "execute in their browser under the application's origin. This gives an attacker the "
                "ability to steal session cookies, capture keystrokes, redirect users, deface the page, "
                "or perform any action the victim could perform — without the victim being aware."
            ),
            manual_equivalent=f"curl -g -k \"{url}?{param}=%3Cscript%3Ealert(1)%3C%2Fscript%3E\" | grep -o '<script>.*</script>'",
            burp_instruction=(
                f"1. In Burp Proxy: intercept GET {url}\n"
                f"2. Send to Repeater\n"
                f"3. Set {param}=<script>alert(1)</script>\n"
                f"4. Send request\n"
                f"5. In Response: Render tab — alert box fires = confirmed XSS\n"
                f"6. In Response: Raw — search for <script>alert(1) to see reflection point"
            )
        )

    elif "ssrf" in t:
        return ToolExplanation(
            tool_name="SSRF Probe via Cloud Metadata Endpoint Redirection",
            why_this_tool=(
                "Server-Side Request Forgery testing targets parameters that accept URLs. By redirecting "
                "the server to request the AWS Instance Metadata Service (IMDS) endpoint at "
                "169.254.169.254 — a non-routable IP only reachable from within AWS infrastructure — "
                "we can determine if the server is making the request on our behalf. This IP is the "
                "definitive SSRF oracle for cloud-hosted applications: if the response contains AWS "
                "metadata, the server is vulnerable and cloud credentials may be extractable."
            ),
            how_it_works=(
                "The scanner identifies parameters that accept URL-like values (url, redirect, src, "
                "callback, etc.) and substitutes the AWS metadata endpoint. The server processes the "
                "parameter and makes an outbound HTTP request to 169.254.169.254. The metadata service "
                "responds with instance information including IAM role names. If the application "
                "reflects any part of this response — or behaves differently — SSRF is confirmed. "
                "The follow-up request to /latest/meta-data/iam/security-credentials/{role} can "
                "retrieve temporary AWS access keys."
            ),
            what_output_means=(
                "The server is making HTTP requests to attacker-controlled destinations. In cloud "
                "environments this means full AWS/GCP/Azure credential theft is possible. The IAM "
                "credentials retrieved from IMDS can be used to access S3 buckets, RDS databases, "
                "Lambda functions, and any other AWS service the EC2 role has permissions for. "
                "This often leads to complete cloud environment compromise."
            ),
            manual_equivalent=(
                f"curl -g -k \"{url}?{param}=http://169.254.169.254/latest/meta-data/\" -v\n"
                f"# If IAM role appears in response:\n"
                f"curl -g -k \"{url}?{param}=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME\""
            ),
            burp_instruction=(
                f"1. Intercept request to {url} in Burp\n"
                f"2. Set {param}=http://169.254.169.254/latest/meta-data/\n"
                f"3. Send and inspect response for 'ami-id', 'instance-id', role names\n"
                f"4. If found: follow up with /iam/security-credentials/ROLE to get AWS keys\n"
                f"5. Use Burp Collaborator for OOB SSRF detection if no reflection"
            )
        )

    elif "s3" in t or "bucket" in t:
        return ToolExplanation(
            tool_name="AWS S3 Bucket Enumeration and Public Access Check",
            why_this_tool=(
                "S3 bucket names follow predictable patterns derived from company names and subdomains. "
                "By systematically constructing candidate bucket names and issuing unauthenticated HTTP "
                "GET requests to the S3 API, we can determine if buckets exist and whether they are "
                "publicly accessible. A 200 response to a listing request is definitive proof of "
                "public access — no AWS credentials required."
            ),
            how_it_works=(
                "The scanner generates bucket name candidates by combining the target domain's root "
                "name with common suffixes (-backup, -dev, -staging, -data, -uploads, -logs, etc.). "
                "For each candidate, an unauthenticated GET request is sent to "
                "https://BUCKET.s3.amazonaws.com. A 200 response with XML content indicates the "
                "bucket exists and allows public listing. A 403 indicates the bucket exists but is "
                "private. A 404/NoSuchBucket means it does not exist. ListBucketResult XML in the "
                "response body confirms that all object keys are enumerable without authentication."
            ),
            what_output_means=(
                "A publicly listable S3 bucket exposes every file stored in it to the entire internet "
                "without authentication. Depending on contents, this could mean source code, database "
                "backups, customer PII, API keys, SSL certificates, internal documentation, or "
                "financial records are publicly downloadable. Files can also be uploaded by anyone "
                "if write permissions are misconfigured, enabling content injection attacks."
            ),
            manual_equivalent=(
                f"# Check if bucket exists and is public:\n"
                f"curl -s \"https://BUCKET_NAME.s3.amazonaws.com\" | head -20\n"
                f"# List all objects if public:\n"
                f"aws s3 ls s3://BUCKET_NAME --no-sign-request\n"
                f"# Download a file without credentials:\n"
                f"aws s3 cp s3://BUCKET_NAME/file.sql . --no-sign-request"
            ),
            burp_instruction=(
                f"1. In Burp: GET https://BUCKET.s3.amazonaws.com/\n"
                f"2. No Authorization header needed\n"
                f"3. 200 + <ListBucketResult XML = fully public\n"
                f"4. Enumerate interesting files: database.sql, .env, credentials, backup.zip\n"
                f"5. Download with: GET https://BUCKET.s3.amazonaws.com/FILENAME"
            )
        )

    elif "cors" in t:
        return ToolExplanation(
            tool_name="CORS Origin Reflection and Credentials Flag Test",
            why_this_tool=(
                "CORS misconfigurations are tested by sending requests with arbitrary Origin headers "
                "and inspecting whether the server reflects them in Access-Control-Allow-Origin. "
                "The critical combination to detect is: reflected arbitrary origin PLUS "
                "Access-Control-Allow-Credentials: true. This combination allows a malicious website "
                "to make authenticated cross-origin requests to the API and read the responses — "
                "bypassing the Same-Origin Policy entirely."
            ),
            how_it_works=(
                "Three Origin values are tested: an arbitrary external domain (https://evil.com), "
                "the null origin (for sandboxed iframe attacks), and a subdomain variant. For each, "
                "the server's CORS response headers are inspected. If Access-Control-Allow-Origin "
                "echoes back the supplied origin AND Access-Control-Allow-Credentials is true, the "
                "server will permit a cross-origin page to read authenticated API responses. This is "
                "because browsers enforce CORS only when credentials: 'include' is set — and this "
                "server configuration authorises exactly that."
            ),
            what_output_means=(
                "An attacker can host a malicious web page that makes fetch() requests to the target "
                "API with the victim's session cookies automatically included by the browser. The "
                "server, seeing a valid session, returns sensitive data. The attacker's page receives "
                "and exfiltrates this data cross-origin. No user interaction beyond visiting the "
                "malicious page is required. Account data, personal information, API keys, and "
                "any authenticated endpoint response are exposed."
            ),
            manual_equivalent=(
                f"curl -H 'Origin: https://evil.com' -H 'Cookie: session=VICTIM_TOKEN' \\\n"
                f"  {url} -v 2>&1 | grep -i 'access-control'\n"
                f"# Look for: Access-Control-Allow-Origin: https://evil.com\n"
                f"# AND:       Access-Control-Allow-Credentials: true"
            ),
            burp_instruction=(
                f"1. Send GET {url} to Burp Repeater\n"
                f"2. Add header: Origin: https://evil.com\n"
                f"3. Check response for Access-Control-Allow-Origin: https://evil.com\n"
                f"4. Check response for Access-Control-Allow-Credentials: true\n"
                f"5. Both present = exploitable. Create PoC HTML page with fetch() + credentials:include"
            )
        )

    elif "header" in t or "hsts" in t or "csp" in t:
        return ToolExplanation(
            tool_name="HTTP Security Header Analysis",
            why_this_tool=(
                "Security headers are the browser-enforced security controls that defend against "
                "entire classes of client-side attacks. Their presence or absence is verified by "
                "issuing a standard GET request and parsing the response headers. This requires "
                "no special tooling — the absence of a header is itself the finding."
            ),
            how_it_works=(
                "A GET request is sent to the target URL. The response headers are parsed and "
                "checked against a list of security-critical headers: Strict-Transport-Security "
                "(forces HTTPS), Content-Security-Policy (controls script execution), X-Frame-Options "
                "(prevents clickjacking), X-Content-Type-Options (prevents MIME sniffing), and "
                "Referrer-Policy. Each missing header represents a browser protection that is "
                "not in place. Cookie attributes (Secure, HttpOnly, SameSite) are also checked."
            ),
            what_output_means=(
                "Missing HSTS means the browser does not enforce HTTPS — a network attacker can "
                "downgrade connections. Missing CSP means no restriction on script execution — "
                "XSS attacks have maximum impact. Missing X-Frame-Options means the site can be "
                "embedded in an iframe by any page — enabling clickjacking attacks where victims "
                "are tricked into clicking UI elements they cannot see."
            ),
            manual_equivalent=f"curl -I -k {url} 2>&1 | grep -i 'strict\\|content-security\\|x-frame\\|x-content'",
            burp_instruction=(
                f"1. GET {url} in Burp\n"
                f"2. Response Headers tab\n"
                f"3. Check for: Strict-Transport-Security, Content-Security-Policy,\n"
                f"   X-Frame-Options, X-Content-Type-Options, Referrer-Policy\n"
                f"4. Each missing header = a finding"
            )
        )

    else:
        return ToolExplanation(
            tool_name="Automated Security Scanner with Manual Verification",
            why_this_tool="This vulnerability class was identified using targeted HTTP probing designed to trigger anomalous server behaviour indicative of the vulnerability.",
            how_it_works="Crafted payloads were submitted to the target parameter and server responses were analysed for indicators of vulnerability — including error messages, response differentials, and unexpected content.",
            what_output_means="The server's response demonstrates that the vulnerability exists and is exploitable by an attacker with network access to the application.",
            manual_equivalent=f"curl -g -k \"{url}\" -v",
            burp_instruction=f"Intercept request to {url} in Burp Suite and manually test the parameter with the payloads described."
        )


def make_business_impact(vuln_type: str, url: str, param: str) -> BusinessImpact:
    t = vuln_type.lower()

    if "sql" in t:
        return BusinessImpact(
            what_attacker_can_do=(
                "Extract the entire database contents without authentication: all user accounts, "
                "password hashes, emails, personal data, payment records, session tokens, and "
                "internal application data. Bypass login by injecting always-true conditions. "
                "In some database configurations (MSSQL xp_cmdshell, MySQL FILE privilege), "
                "read/write operating system files or execute OS commands."
            ),
            data_at_risk=(
                "All data stored in the connected database: user credentials, personal identifiable "
                "information (PII), financial records, API keys, internal configuration data, "
                "and any other application data. Cross-table access means all database content "
                "is reachable from a single vulnerable parameter."
            ),
            worst_case_scenario=(
                "Full database exfiltration followed by credential stuffing attacks against the "
                "user base. If password hashes are weak (MD5/SHA1), cracking yields plaintext "
                "passwords. Combined with credential reuse, this leads to account takeover across "
                "multiple platforms. Data sold on dark web marketplaces. Regulatory notification "
                "obligations triggered under GDPR Article 33 (72-hour breach notification)."
            ),
            affected_users="All users whose data is stored in the affected database tables.",
            regulatory_implications=(
                "GDPR Article 83(4): fines up to €10 million or 2% of global annual turnover "
                "for failure to implement appropriate technical measures. PCI-DSS Requirement 6.3 "
                "violation if payment card data is in scope. Mandatory breach notification to "
                "supervisory authority within 72 hours of discovery."
            ),
            estimated_severity_rationale=(
                "CVSS:3.1 base score 9.8 (Critical). Attack Vector: Network (remotely exploitable). "
                "Attack Complexity: Low (no special conditions). Privileges Required: None "
                "(unauthenticated). User Interaction: None. Scope: Unchanged. "
                "Confidentiality/Integrity/Availability: High/High/High."
            )
        )

    elif "xss" in t:
        return BusinessImpact(
            what_attacker_can_do=(
                "Steal authenticated session cookies via document.cookie, performing account "
                "takeover for any user who clicks a crafted URL. Capture keystrokes, form data, "
                "and passwords as users type them. Redirect users to phishing pages indistinguishable "
                "from the real application. Perform any action on behalf of the victim — changing "
                "email addresses, passwords, making purchases, or accessing sensitive data."
            ),
            data_at_risk=(
                "Session tokens, credentials entered on the page, personal and financial information "
                "visible to the authenticated user, and any data the user's session has access to."
            ),
            worst_case_scenario=(
                "Stored XSS (if the payload persists) affects every user who views the infected page. "
                "A reflected XSS campaign using crafted URLs sent via phishing email or social media "
                "can compromise thousands of accounts. If an admin account is hijacked, full "
                "application compromise follows."
            ),
            affected_users="Any user who can be induced to click a crafted link (reflected) or visits an infected page (stored).",
            regulatory_implications=(
                "GDPR Article 32: failure to ensure appropriate security of personal data processing. "
                "Account takeover of users constitutes a personal data breach requiring notification."
            ),
            estimated_severity_rationale=(
                "CVSS:3.1 base score 6.1 (Medium) for reflected XSS without stored persistence. "
                "Attack Vector: Network. Attack Complexity: Low. Privileges Required: None. "
                "User Interaction: Required (victim must click link). Scope: Changed (browser context). "
                "Confidentiality: Low. Integrity: Low."
            )
        )

    elif "ssrf" in t:
        return BusinessImpact(
            what_attacker_can_do=(
                "Force the server to make HTTP requests to internal network resources unreachable "
                "from the internet — internal APIs, databases, admin panels, and cloud metadata "
                "services. On AWS, retrieve IAM security credentials from the metadata service, "
                "then use those credentials to access any AWS service the EC2 role can reach: "
                "S3 buckets, RDS databases, Secrets Manager, Lambda, CloudFormation, and more."
            ),
            data_at_risk=(
                "Cloud infrastructure credentials (AWS Access Key + Secret Key + Session Token), "
                "internal service responses, secrets stored in cloud key management services, "
                "database connection strings, and any data accessible to the cloud IAM role."
            ),
            worst_case_scenario=(
                "Full cloud environment takeover. Using extracted IAM credentials, an attacker "
                "can enumerate all S3 buckets, download their contents, access RDS databases, "
                "read Secrets Manager entries containing database passwords and API keys, "
                "and potentially escalate to Administrator-level access via IAM privilege escalation."
            ),
            affected_users="The entire organisation's cloud infrastructure and all data stored within it.",
            regulatory_implications=(
                "Cloud credential compromise constitutes a security incident under most frameworks. "
                "If customer data is stored in accessible S3 buckets or databases, GDPR breach "
                "notification obligations apply. SOC2 Type II compliance is violated."
            ),
            estimated_severity_rationale=(
                "CVSS:3.1 base score 9.8 (Critical) when cloud metadata is accessible. "
                "Network-exploitable, no authentication, no user interaction, "
                "High impact across Confidentiality, Integrity, and Availability."
            )
        )

    elif "s3" in t or "bucket" in t:
        return BusinessImpact(
            what_attacker_can_do=(
                "Download all files stored in the bucket without any authentication. "
                "If the bucket contains database backups, source code, configuration files, "
                "or customer data — all of it is freely downloadable. If write access is also "
                "misconfigured, an attacker can upload malicious files, replace existing content, "
                "or delete all stored data."
            ),
            data_at_risk=(
                "All objects stored in the bucket — potentially including database dumps (.sql), "
                "application backups (.zip), environment files (.env) containing API keys and "
                "database passwords, customer exports (CSV/JSON with PII), and SSL private keys."
            ),
            worst_case_scenario=(
                "A publicly listable backup bucket containing a database dump gives an attacker "
                "all user data (emails, password hashes, PII) instantly. An .env file in the "
                "bucket typically contains database credentials, Stripe API keys, JWT secrets, "
                "and third-party API keys — each a separate critical finding in its own right."
            ),
            affected_users="All customers and users whose data has ever been stored in or backed up to the bucket.",
            regulatory_implications=(
                "GDPR Article 5(1)(f): principle of integrity and confidentiality violated. "
                "Potential fines of up to 4% of global annual turnover under Article 83(5). "
                "AWS shared responsibility model: bucket access control is the customer's responsibility — "
                "not AWS's. PCI-DSS Requirement 1.3.7 if card data is stored."
            ),
            estimated_severity_rationale=(
                "CVSS:3.1 base score 9.1 (Critical). Network-exploitable, no authentication, "
                "no user interaction required. High Confidentiality impact."
            )
        )

    else:
        return BusinessImpact(
            what_attacker_can_do="Exploit this vulnerability to gain unauthorised access to application functionality or data beyond the intended security boundary.",
            data_at_risk="Application data and functionality accessible through the affected component.",
            worst_case_scenario="Escalation to broader system access depending on application architecture and data sensitivity.",
            affected_users="Users and data within the scope of the affected application component.",
            regulatory_implications="Potential GDPR Article 32 implications if personal data is exposed through exploitation.",
            estimated_severity_rationale="Severity assessed based on exploitability, data sensitivity, and breadth of impact."
        )


def make_cvss_breakdown(vuln_type: str, cvss_score: float) -> CVSSBreakdown:
    t = vuln_type.lower()

    if "sql" in t:
        return CVSSBreakdown(
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            base_score=9.8,
            attack_vector="Network — the vulnerability is exploitable over the internet with no physical access required",
            attack_complexity="Low — no special conditions, race conditions, or target-specific knowledge needed",
            privileges_required="None — no authentication or account is required to exploit this vulnerability",
            user_interaction="None — no victim interaction is required; the attacker acts alone",
            scope="Unchanged — impact is contained within the vulnerable application's security domain",
            confidentiality="High — complete read access to all data in the connected database",
            integrity="High — attacker can modify or delete database records",
            availability="High — attacker can drop tables or lock the database, causing a denial of service"
        )
    elif "xss" in t:
        return CVSSBreakdown(
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            base_score=6.1,
            attack_vector="Network — exploitable remotely by sending a crafted URL to a victim",
            attack_complexity="Low — no special configuration or conditions required",
            privileges_required="None — attacker does not need an account on the application",
            user_interaction="Required — victim must click a crafted link or visit a page with stored payload",
            scope="Changed — the attack crosses from the server into the victim's browser security context",
            confidentiality="Low — session tokens and page data accessible; full account data requires further exploitation",
            integrity="Low — attacker can modify page content and perform actions as the victim",
            availability="None — XSS does not typically affect service availability"
        )
    elif "ssrf" in t:
        return CVSSBreakdown(
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            base_score=9.8,
            attack_vector="Network — exploitable over the internet targeting a cloud-hosted application",
            attack_complexity="Low — metadata endpoint is always available in cloud environments without authentication",
            privileges_required="None — unauthenticated access to the vulnerable parameter is sufficient",
            user_interaction="None — fully attacker-controlled, no victim involvement needed",
            scope="Changed — impact extends beyond the application to the underlying cloud infrastructure",
            confidentiality="High — IAM credentials and all accessible cloud data exposed",
            integrity="High — with extracted credentials, attacker can modify cloud resources",
            availability="High — attacker can delete S3 buckets, terminate instances, or destroy infrastructure"
        )
    else:
        return CVSSBreakdown(
            vector_string=f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            base_score=cvss_score if isinstance(cvss_score, float) else 7.5,
            attack_vector="Network — remotely exploitable",
            attack_complexity="Low — no special conditions required",
            privileges_required="None — unauthenticated",
            user_interaction="None — no victim interaction required",
            scope="Unchanged",
            confidentiality="High — sensitive data exposed",
            integrity="None",
            availability="None"
        )
