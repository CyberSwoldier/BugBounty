import dns.resolver
import requests
import json
from typing import List, Dict, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import streamlit as st

# Common subdomains wordlist (built-in fallback)
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "webdisk", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap",
    "test", "admin", "dev", "staging", "api", "app", "blog", "shop", "store",
    "portal", "vpn", "ssh", "remote", "beta", "alpha", "preview", "demo",
    "cdn", "static", "assets", "img", "images", "media", "upload", "uploads",
    "download", "downloads", "files", "backup", "db", "database", "sql",
    "mysql", "mongo", "redis", "elastic", "kibana", "grafana", "jenkins",
    "git", "gitlab", "github", "jira", "confluence", "wiki", "docs",
    "support", "help", "forum", "community", "chat", "slack", "status",
    "monitoring", "metrics", "logs", "analytics", "tracking", "reporting",
    "internal", "intranet", "corp", "office", "hr", "finance", "legal",
    "secure", "auth", "login", "sso", "oauth", "cas", "ldap", "ad",
    "mail2", "smtp2", "mx", "mx1", "mx2", "exchange", "owa", "outlook",
    "mobile", "wap", "android", "ios", "api2", "api3", "v1", "v2", "v3",
    "old", "new", "legacy", "classic", "archive", "mirror",
]

def check_crtsh(domain: str) -> Set[str]:
    """Query crt.sh for certificate transparency logs."""
    found = set()
    try:
        resp = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                names = entry.get("name_value", "").split("\n")
                for name in names:
                    name = name.strip().lstrip("*.")
                    if name.endswith(domain) and " " not in name:
                        found.add(name)
    except Exception:
        pass
    return found

def check_dns(subdomain: str, domain: str) -> Dict:
    """Resolve a subdomain via DNS."""
    full = f"{subdomain}.{domain}"
    result = {"subdomain": full, "resolved": False, "ips": [], "cname": None}
    try:
        answers = dns.resolver.resolve(full, "A", lifetime=3)
        result["resolved"] = True
        result["ips"] = [str(r) for r in answers]
    except dns.resolver.NXDOMAIN:
        pass
    except dns.resolver.NoAnswer:
        try:
            answers = dns.resolver.resolve(full, "CNAME", lifetime=3)
            result["resolved"] = True
            result["cname"] = str(answers[0].target)
        except Exception:
            pass
    except Exception:
        pass
    return result

def detect_takeover(result: Dict) -> bool:
    """Basic subdomain takeover detection via CNAME dangling."""
    takeover_signatures = [
        "github.io", "herokuapp.com", "s3.amazonaws.com",
        "azurewebsites.net", "cloudfront.net", "fastly.net",
        "shopify.com", "tumblr.com", "wordpress.com", "ghost.io",
        "surge.sh", "bitbucket.io", "netlify.app", "vercel.app",
    ]
    cname = result.get("cname", "") or ""
    for sig in takeover_signatures:
        if sig in cname:
            return True
    return False

def run_subdomain_enum(domain: str, use_crtsh: bool = True, progress_callback=None) -> List[Dict]:
    """Main subdomain enumeration function."""
    results = []
    found_subdomains = set()

    # Step 1: crt.sh passive recon
    if use_crtsh:
        crt_subs = check_crtsh(domain)
        for sub in crt_subs:
            # Extract subdomain part
            if sub != domain:
                prefix = sub.replace(f".{domain}", "")
                found_subdomains.add(prefix)

    # Step 2: Brute force common subdomains
    for sub in COMMON_SUBDOMAINS:
        found_subdomains.add(sub)

    # Step 3: DNS resolution
    total = len(found_subdomains)
    resolved_count = 0

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_dns, sub, domain): sub for sub in found_subdomains}
        for future in as_completed(futures):
            resolved_count += 1
            if progress_callback:
                progress_callback(resolved_count / total, f"Checking {futures[future]}.{domain}")
            result = future.result()
            if result["resolved"]:
                result["takeover_possible"] = detect_takeover(result)
                results.append(result)

    return sorted(results, key=lambda x: x["subdomain"])
