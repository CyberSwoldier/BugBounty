import requests
import urllib3
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urlencode, parse_qs, urljoin
from typing import List, Dict, Set
import re
import time

urllib3.disable_warnings()

COMMON_PARAMS = [
    # General
    "id", "page", "q", "query", "search", "s", "keyword", "term",
    "url", "path", "file", "filename", "dir", "folder", "name",
    "type", "action", "method", "mode", "view", "format", "output",
    "user", "username", "email", "pass", "password", "token", "key",
    "lang", "locale", "language", "country", "region", "timezone",
    # Redirect / SSRF prone
    "redirect", "return", "return_url", "next", "continue", "goto",
    "target", "dest", "destination", "url", "link", "href", "src",
    "callback", "redir", "redirect_uri", "redirect_url", "forward",
    # SQL injection prone
    "id", "cat", "category", "product", "item", "article", "post",
    "order", "sort", "limit", "offset", "start", "end", "from", "to",
    "filter", "where", "having", "group", "field", "column", "table",
    # XSS prone
    "message", "msg", "text", "title", "content", "body", "description",
    "comment", "feedback", "review", "note", "data", "value", "input",
    # File inclusion
    "include", "require", "template", "theme", "module", "plugin",
    "config", "conf", "setting", "option", "param",
    # API
    "api_key", "apikey", "access_token", "auth_token", "bearer",
    "secret", "client_id", "client_secret", "scope", "grant_type",
    # Debug
    "debug", "test", "dev", "trace", "verbose", "log", "error",
]

def extract_params_from_html(url: str, html: str) -> Set[str]:
    """Extract parameter names from HTML forms and links."""
    params = set()
    try:
        soup = BeautifulSoup(html, "lxml")
        # Form inputs
        for inp in soup.find_all(["input", "select", "textarea"]):
            name = inp.get("name") or inp.get("id")
            if name:
                params.add(name)
        # Links with query strings
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if "?" in href:
                qs = href.split("?", 1)[1]
                for key in parse_qs(qs).keys():
                    params.add(key)
        # JavaScript variable names (basic)
        scripts = soup.find_all("script")
        for script in scripts:
            if script.string:
                js_params = re.findall(r'["\'](\w+)["\']\s*:', script.string)
                params.update(p for p in js_params if 2 < len(p) < 30)
    except Exception:
        pass
    return params

def test_param(url: str, param: str, session: requests.Session) -> Dict:
    """Test if a parameter is reflected or causes a change."""
    sentinel = "BBHUNT7331"
    try:
        resp = session.get(url, params={param: sentinel}, timeout=8)
        reflected = sentinel in resp.text
        return {
            "param": param,
            "url": url,
            "reflected": reflected,
            "status_code": resp.status_code,
            "content_length": len(resp.content),
        }
    except Exception:
        return {"param": param, "url": url, "reflected": False, "status_code": 0, "content_length": 0}

def run_param_discovery(target_url: str, progress_callback=None) -> Dict:
    """Main parameter discovery function."""
    session = requests.Session()
    session.verify = False
    session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; ParamDiscovery/1.0)"})

    results = {
        "url": target_url,
        "discovered_from_html": [],
        "common_params_reflected": [],
        "all_tested": [],
    }

    # Step 1: Fetch and parse HTML
    try:
        resp = session.get(target_url, timeout=10)
        html_params = extract_params_from_html(target_url, resp.text)
        results["discovered_from_html"] = list(html_params)
    except Exception:
        html_params = set()

    # Step 2: Test common params + discovered
    all_params = list(set(COMMON_PARAMS) | html_params)
    total = len(all_params)

    for i, param in enumerate(all_params):
        if progress_callback:
            progress_callback(i / total, f"Testing param: {param}")
        result = test_param(target_url, param, session)
        results["all_tested"].append(result)
        if result["reflected"]:
            results["common_params_reflected"].append(result)
        time.sleep(0.1)

    return results
