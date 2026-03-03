"""
scope_manager.py — Scope enforcement for ethical, authorized testing only.

The scope manager is the first line of defense ensuring the platform
never touches assets the client has not explicitly authorized. Every
module must call is_in_scope() before making any network request.
"""

import re
from urllib.parse import urlparse
from typing import List, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ScopeDefinition:
    """
    Represents a complete engagement scope definition.
    Mirrors what you'd receive in a bug bounty program's scope section
    or a pentest Statement of Work (SoW).
    """
    program_name: str = ""
    company_name: str = ""
    tester_name: str = ""
    engagement_id: str = ""
    start_date: str = ""
    end_date: str = ""

    # In-scope: wildcards like *.example.com are supported
    in_scope_domains: List[str] = field(default_factory=list)
    in_scope_ips: List[str] = field(default_factory=list)
    in_scope_urls: List[str] = field(default_factory=list)

    # Explicit exclusions — never touch these even if they match in-scope patterns
    out_of_scope_domains: List[str] = field(default_factory=list)
    out_of_scope_urls: List[str] = field(default_factory=list)

    # What test types are authorized
    allowed_test_types: List[str] = field(default_factory=lambda: [
        "recon", "port_scan", "dir_fuzz", "param_discovery",
        "xss", "sqli", "ssrf", "api", "cloud", "network_headers"
    ])

    # Notes / rules of engagement
    rules_of_engagement: str = ""
    max_request_rate: int = 30   # requests per minute ceiling


class ScopeManager:
    """
    Central scope enforcement engine.

    Think of this as the engagement guardrails. A senior pentester
    always defines scope before touching anything. This class makes
    that discipline automatic and auditable.
    """

    def __init__(self, scope: ScopeDefinition):
        self.scope = scope
        self._violation_log: List[dict] = []
        self._checked_count: int = 0

    # ── Core check ─────────────────────────────────────────────────────────────

    def is_in_scope(self, target: str) -> tuple[bool, str]:
        """
        Returns (True, reason) if the target is in scope,
        or (False, reason) explaining why it was blocked.

        Handles raw domains, URLs, and IP addresses uniformly.
        """
        self._checked_count += 1

        # Normalize — strip protocol noise so we compare apples to apples
        normalized = self._normalize(target)

        # 1. Hard exclusions take absolute priority
        for excluded in self.scope.out_of_scope_domains:
            if self._matches(normalized, excluded):
                reason = f"BLOCKED — '{target}' matches out-of-scope rule: {excluded}"
                self._log_violation(target, reason)
                return False, reason

        for excluded_url in self.scope.out_of_scope_urls:
            if target.startswith(excluded_url):
                reason = f"BLOCKED — '{target}' matches out-of-scope URL: {excluded_url}"
                self._log_violation(target, reason)
                return False, reason

        # 2. Must match at least one in-scope entry
        for domain in self.scope.in_scope_domains:
            if self._matches(normalized, domain):
                return True, f"IN SCOPE — matched rule: {domain}"

        for ip in self.scope.in_scope_ips:
            if normalized == ip or normalized.startswith(ip):
                return True, f"IN SCOPE — matched IP rule: {ip}"

        for url in self.scope.in_scope_urls:
            if target.startswith(url):
                return True, f"IN SCOPE — matched URL rule: {url}"

        reason = f"OUT OF SCOPE — '{target}' does not match any authorized target"
        self._log_violation(target, reason)
        return False, reason

    def is_test_type_allowed(self, test_type: str) -> bool:
        """Check if a given scan module is authorized for this engagement."""
        return test_type in self.scope.allowed_test_types

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _normalize(self, target: str) -> str:
        """Strip protocol and path — we compare at the domain/IP level."""
        if "://" in target:
            parsed = urlparse(target)
            return parsed.netloc.lower().split(":")[0]  # strip port too
        return target.lower().split(":")[0].split("/")[0]

    def _matches(self, target: str, pattern: str) -> bool:
        """
        Support wildcard matching so *.example.com covers
        api.example.com, staging.example.com, etc.
        """
        pattern = pattern.lower().strip()
        if pattern.startswith("*."):
            # Wildcard: *.example.com matches any subdomain of example.com
            base = pattern[2:]
            return target == base or target.endswith("." + base)
        return target == pattern

    def _log_violation(self, target: str, reason: str):
        self._violation_log.append({
            "timestamp": datetime.utcnow().isoformat(),
            "target": target,
            "reason": reason,
        })

    # ── Reporting helpers ──────────────────────────────────────────────────────

    def get_violations(self) -> List[dict]:
        return self._violation_log

    def get_summary(self) -> dict:
        return {
            "total_checked": self._checked_count,
            "violations_blocked": len(self._violation_log),
            "in_scope_domains": self.scope.in_scope_domains,
            "out_of_scope_domains": self.scope.out_of_scope_domains,
            "allowed_tests": self.scope.allowed_test_types,
        }

    def validate_scope_completeness(self) -> List[str]:
        """
        Returns a list of warnings if the scope definition looks incomplete.
        Good practice before starting any engagement.
        """
        warnings = []
        if not self.scope.in_scope_domains and not self.scope.in_scope_ips:
            warnings.append("No in-scope domains or IPs defined — all targets will be blocked!")
        if not self.scope.program_name:
            warnings.append("No program/engagement name defined")
        if not self.scope.tester_name:
            warnings.append("No tester name defined — required for report attribution")
        if not self.scope.start_date or not self.scope.end_date:
            warnings.append("No engagement dates defined")
        return warnings


def build_scope_from_target(target_url: str, extra_domains: List[str] = None) -> ScopeDefinition:
    """
    Quick-build a scope definition from a single target URL.
    Used when the user enters a target in the UI without a formal SoW.
    The root domain + all subdomains are automatically added as in-scope.
    """
    parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
    domain = parsed.netloc or target_url

    # Strip port if present
    domain = domain.split(":")[0]

    # Extract root domain (last two parts: example.com)
    parts = domain.split(".")
    root = ".".join(parts[-2:]) if len(parts) >= 2 else domain

    in_scope = [domain, f"*.{root}"]
    if extra_domains:
        in_scope.extend(extra_domains)

    return ScopeDefinition(
        in_scope_domains=in_scope,
        start_date=datetime.utcnow().strftime("%Y-%m-%d"),
        end_date=datetime.utcnow().strftime("%Y-%m-%d"),
    )
