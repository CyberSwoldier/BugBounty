import requests
import urllib3
from urllib.parse import urlparse
from typing import List, Dict, Optional
import ssl
import socket
import datetime
import time

urllib3.disable_warnings()

# Security headers that should be present
REQUIRED_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Forces HTTPS connections",
        "severity": "HIGH",
        "expected": "max-age=31536000",
    },
    "Content-Security-Policy": {
        "description": "Prevents XSS and data injection",
        "severity": "HIGH",
        "expected": "default-src 'self'",
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking",
        "severity": "MEDIUM",
        "expected": "DENY or SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME sniffing",
        "severity": "MEDIUM",
        "expected": "nosniff",
    },
    "Referrer-Policy": {
        "description": "Controls referrer information",
        "severity": "LOW",
        "expected": "strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "description": "Controls browser features",
        "severity": "LOW",
        "expected": "camera=(), microphone=(), geolocation=()",
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter (deprecated but still checked)",
        "severity": "INFO",
        "expected": "1; mode=block",
    },
}

# Dangerous headers that should NOT be present
DANGEROUS_HEADERS = {
    "X-Powered-By": "Exposes technology stack",
    "Server": "Exposes server software/version",
    "X-AspNet-Version": "Exposes ASP.NET version",
    "X-AspNetMvc-Version": "Exposes ASP.NET MVC version",
    "X-Generator": "Exposes CMS/generator",
}

CORS_TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "https://evil.target.com",
]

def check_security_headers(url: str, session: requests.Session) -> List[Dict]:
    """Check security headers on a URL."""
    findings = []
    try:
        resp = session.get(url, timeout=10)
        headers = {k.lower(): v for k, v in resp.headers.items()}

        # Check missing required headers
        for header, info in REQUIRED_HEADERS.items():
            if header.lower() not in headers:
                findings.append({
                    "type": f"Missing Security Header: {header}",
                    "url": url,
                    "severity": info["severity"],
                    "evidence": f"Header '{header}' is not set. {info['description']}.",
                    "cvss": {"HIGH": 6.5, "MEDIUM": 4.3, "LOW": 2.6, "INFO": 1.0}.get(info["severity"], 3.0),
                    "remediation": f"Set {header}: {info['expected']}",
                })

        # Check CSP for weak values
        csp = headers.get("content-security-policy", "")
        if csp:
            if "unsafe-inline" in csp:
                findings.append({
                    "type": "Weak Content-Security-Policy (unsafe-inline)",
                    "url": url,
                    "severity": "MEDIUM",
                    "evidence": f"CSP contains 'unsafe-inline': {csp[:150]}",
                    "cvss": 5.4,
                    "remediation": "Remove 'unsafe-inline' from CSP directives",
                })
            if "unsafe-eval" in csp:
                findings.append({
                    "type": "Weak Content-Security-Policy (unsafe-eval)",
                    "url": url,
                    "severity": "MEDIUM",
                    "evidence": f"CSP contains 'unsafe-eval': {csp[:150]}",
                    "cvss": 5.4,
                    "remediation": "Remove 'unsafe-eval' from CSP directives",
                })

        # Check for dangerous information disclosure headers
        for header, desc in DANGEROUS_HEADERS.items():
            if header.lower() in headers:
                findings.append({
                    "type": f"Information Disclosure: {header}",
                    "url": url,
                    "severity": "LOW",
                    "evidence": f"Header '{header}: {headers[header.lower()]}' reveals {desc}",
                    "cvss": 3.7,
                    "remediation": f"Remove or obfuscate the {header} header",
                })

        # Cookie security checks
        for cookie in resp.cookies:
            cookie_findings = []
            if not cookie.secure:
                cookie_findings.append("missing Secure flag")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                cookie_findings.append("missing HttpOnly flag")
            if not cookie.has_nonstandard_attr("SameSite"):
                cookie_findings.append("missing SameSite attribute")
            if cookie_findings:
                findings.append({
                    "type": f"Insecure Cookie: {cookie.name}",
                    "url": url,
                    "severity": "MEDIUM",
                    "evidence": f"Cookie '{cookie.name}' has: {', '.join(cookie_findings)}",
                    "cvss": 4.8,
                    "remediation": "Set Secure, HttpOnly, and SameSite=Strict/Lax flags on all cookies",
                })

    except Exception as e:
        pass
    return findings

def check_cors(url: str, session: requests.Session) -> List[Dict]:
    """Test for CORS misconfigurations."""
    findings = []
    for origin in CORS_TEST_ORIGINS:
        try:
            resp = session.get(url, headers={"Origin": origin}, timeout=8)
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*":
                findings.append({
                    "type": "CORS Wildcard Origin",
                    "url": url,
                    "severity": "MEDIUM",
                    "evidence": "Access-Control-Allow-Origin: *",
                    "cvss": 5.4,
                    "remediation": "Restrict CORS to specific trusted origins",
                })
                break
            elif acao == origin and acac.lower() == "true":
                findings.append({
                    "type": "CORS Misconfiguration (Credentials + Reflected Origin)",
                    "url": url,
                    "severity": "HIGH",
                    "evidence": f"Origin '{origin}' reflected with Allow-Credentials: true",
                    "cvss": 8.1,
                    "remediation": "Validate Origin against strict allowlist before reflecting",
                })
                break
            elif acao == "null":
                findings.append({
                    "type": "CORS null Origin Allowed",
                    "url": url,
                    "severity": "HIGH",
                    "evidence": "Access-Control-Allow-Origin: null (allows sandboxed iframe attacks)",
                    "cvss": 7.4,
                    "remediation": "Remove 'null' from allowed origins",
                })
        except Exception:
            pass
        time.sleep(0.1)
    return findings

def check_ssl_tls(domain: str) -> List[Dict]:
    """Check SSL/TLS configuration."""
    findings = []
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.settimeout(10)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        conn.close()

        # Check expiration
        expire_date = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_left = (expire_date - datetime.datetime.utcnow()).days

        if days_left < 0:
            findings.append({
                "type": "SSL Certificate Expired",
                "url": f"https://{domain}",
                "severity": "CRITICAL",
                "evidence": f"Certificate expired {abs(days_left)} days ago",
                "cvss": 9.1,
            })
        elif days_left < 30:
            findings.append({
                "type": "SSL Certificate Expiring Soon",
                "url": f"https://{domain}",
                "severity": "HIGH",
                "evidence": f"Certificate expires in {days_left} days",
                "cvss": 5.9,
            })

    except ssl.SSLError as e:
        findings.append({
            "type": "SSL/TLS Error",
            "url": f"https://{domain}",
            "severity": "HIGH",
            "evidence": str(e),
            "cvss": 7.5,
        })
    except Exception:
        pass

    return findings

def run_network_scanner(target_url: str, domain: str, progress_callback=None) -> Dict:
    """Main network/headers scanner."""
    session = requests.Session()
    session.verify = False
    session.headers.update({"User-Agent": "Mozilla/5.0"})

    results = {
        "header_findings": [],
        "cors_findings": [],
        "ssl_findings": [],
        "all_findings": [],
    }

    if progress_callback:
        progress_callback(0.2, "Checking security headers...")
    results["header_findings"] = check_security_headers(target_url, session)

    if progress_callback:
        progress_callback(0.5, "Testing CORS configuration...")
    results["cors_findings"] = check_cors(target_url, session)

    if progress_callback:
        progress_callback(0.8, "Checking SSL/TLS...")
    results["ssl_findings"] = check_ssl_tls(domain)

    results["all_findings"] = (
        results["header_findings"] +
        results["cors_findings"] +
        results["ssl_findings"]
    )

    return results
