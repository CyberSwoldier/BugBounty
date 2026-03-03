import requests
import urllib3
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Optional
from bs4 import BeautifulSoup
import json
import time
import re

urllib3.disable_warnings()

API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3",
    "/graphql", "/gql",
    "/swagger", "/swagger-ui.html", "/swagger.json", "/swagger.yaml",
    "/openapi.json", "/openapi.yaml",
    "/api-docs", "/redoc",
    "/rest", "/rest/v1", "/rest/v2",
]

REST_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

BOLA_TEST_IDS = ["1", "2", "0", "-1", "99999", "../1", "admin", "null", "undefined"]

SENSITIVE_FIELDS = [
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "credit_card", "ssn", "social_security", "dob", "birth",
    "private_key", "access_key", "secret_key", "auth",
]

def discover_api_endpoints(base_url: str, session: requests.Session) -> List[Dict]:
    """Discover API endpoints and documentation."""
    found = []
    for path in API_PATHS:
        url = urljoin(base_url, path)
        try:
            resp = session.get(url, timeout=8)
            if resp.status_code in {200, 301, 302, 401, 403}:
                is_json = "application/json" in resp.headers.get("Content-Type", "")
                is_swagger = "swagger" in resp.text.lower() or "openapi" in resp.text.lower()
                found.append({
                    "url": url,
                    "status": resp.status_code,
                    "is_json": is_json,
                    "is_swagger_docs": is_swagger,
                    "content_length": len(resp.content),
                })
        except Exception:
            pass
        time.sleep(0.15)
    return found

def test_http_methods(url: str, session: requests.Session) -> List[Dict]:
    """Test which HTTP methods are allowed (method enumeration)."""
    findings = []
    allowed = []
    for method in REST_METHODS:
        try:
            resp = session.request(method, url, timeout=8)
            if resp.status_code not in {405, 501}:
                allowed.append(method)
                # TRACE method enabled is a finding
                if method == "TRACE" and resp.status_code == 200:
                    findings.append({
                        "type": "HTTP TRACE Method Enabled",
                        "url": url,
                        "severity": "LOW",
                        "evidence": "TRACE method returned 200",
                        "cvss": 4.3,
                    })
        except Exception:
            pass

    if "DELETE" in allowed or "PUT" in allowed:
        findings.append({
            "type": "Dangerous HTTP Methods Allowed",
            "url": url,
            "severity": "MEDIUM",
            "evidence": f"Allowed methods: {', '.join(allowed)}",
            "cvss": 5.3,
            "remediation": "Restrict HTTP methods to only what's needed",
        })
    return findings, allowed

def test_bola(base_url: str, session: requests.Session) -> List[Dict]:
    """Test for Broken Object Level Authorization (IDOR/BOLA)."""
    findings = []
    # Common patterns with resource IDs
    bola_endpoints = [
        "/api/v1/users/{id}",
        "/api/v1/accounts/{id}",
        "/api/v1/orders/{id}",
        "/api/users/{id}",
        "/api/profile/{id}",
    ]
    for endpoint in bola_endpoints:
        for test_id in BOLA_TEST_IDS[:4]:
            url = urljoin(base_url, endpoint.replace("{id}", test_id))
            try:
                resp = session.get(url, timeout=8)
                if resp.status_code == 200 and resp.text.strip():
                    try:
                        data = resp.json()
                        # Check for sensitive data exposure
                        data_str = json.dumps(data).lower()
                        for field in SENSITIVE_FIELDS:
                            if field in data_str:
                                findings.append({
                                    "type": "Broken Object Level Authorization (BOLA/IDOR)",
                                    "url": url,
                                    "severity": "HIGH",
                                    "evidence": f"Sensitive field '{field}' found in unauthenticated response",
                                    "cvss": 8.2,
                                    "remediation": "Implement proper object-level authorization checks",
                                })
                                break
                    except Exception:
                        pass
            except Exception:
                pass
            time.sleep(0.15)
    return findings

def test_graphql(url: str, session: requests.Session) -> List[Dict]:
    """Test GraphQL endpoint for common vulnerabilities."""
    findings = []
    graphql_url = urljoin(url, "/graphql")

    # Introspection query
    introspection = {"query": "{ __schema { types { name } } }"}
    try:
        resp = session.post(graphql_url, json=introspection, timeout=10)
        if resp.status_code == 200 and "__schema" in resp.text:
            findings.append({
                "type": "GraphQL Introspection Enabled",
                "url": graphql_url,
                "severity": "MEDIUM",
                "evidence": "Introspection query returned schema information",
                "cvss": 5.3,
                "remediation": "Disable introspection in production environments",
            })
    except Exception:
        pass

    # Test for batch query attacks
    batch = [{"query": "{ __typename }"}, {"query": "{ __typename }"}]
    try:
        resp = session.post(graphql_url, json=batch, timeout=10)
        if resp.status_code == 200 and isinstance(resp.json(), list):
            findings.append({
                "type": "GraphQL Batching Enabled",
                "url": graphql_url,
                "severity": "LOW",
                "evidence": "Batch queries accepted (potential DoS/brute-force vector)",
                "cvss": 3.7,
                "remediation": "Implement query complexity limits and rate limiting",
            })
    except Exception:
        pass

    return findings

def check_sensitive_data_exposure(url: str, session: requests.Session) -> List[Dict]:
    """Check API responses for sensitive data."""
    findings = []
    try:
        resp = session.get(url, timeout=10)
        if "application/json" in resp.headers.get("Content-Type", ""):
            data_str = resp.text.lower()
            for field in SENSITIVE_FIELDS:
                if f'"{field}"' in data_str or f"'{field}'" in data_str:
                    findings.append({
                        "type": "Sensitive Data Exposure in API Response",
                        "url": url,
                        "severity": "HIGH",
                        "evidence": f"Field '{field}' found in API response",
                        "cvss": 7.5,
                        "remediation": "Remove sensitive fields from API responses, implement field-level authorization",
                    })
    except Exception:
        pass
    return findings

def run_api_scanner(target_url: str, progress_callback=None) -> Dict:
    """Main API testing function."""
    session = requests.Session()
    session.verify = False
    session.headers.update({
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json",
    })

    results = {
        "endpoints_discovered": [],
        "method_findings": [],
        "bola_findings": [],
        "graphql_findings": [],
        "data_exposure_findings": [],
        "all_findings": [],
    }

    if progress_callback:
        progress_callback(0.1, "Discovering API endpoints...")
    results["endpoints_discovered"] = discover_api_endpoints(target_url, session)

    if progress_callback:
        progress_callback(0.3, "Testing HTTP methods...")
    method_findings, _ = test_http_methods(target_url, session)
    results["method_findings"] = method_findings

    if progress_callback:
        progress_callback(0.5, "Testing for BOLA/IDOR...")
    results["bola_findings"] = test_bola(target_url, session)

    if progress_callback:
        progress_callback(0.7, "Testing GraphQL...")
    results["graphql_findings"] = test_graphql(target_url, session)

    if progress_callback:
        progress_callback(0.9, "Checking for sensitive data exposure...")
    results["data_exposure_findings"] = check_sensitive_data_exposure(target_url, session)

    # Combine all findings
    results["all_findings"] = (
        results["method_findings"] +
        results["bola_findings"] +
        results["graphql_findings"] +
        results["data_exposure_findings"]
    )

    return results
