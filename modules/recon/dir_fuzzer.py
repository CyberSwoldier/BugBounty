import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional
import time

urllib3.disable_warnings()

# Built-in wordlist covering common paths
COMMON_PATHS = [
    # Admin panels
    "admin", "admin/", "administrator", "administrator/", "wp-admin", "wp-admin/",
    "cpanel", "phpmyadmin", "adminer", "panel", "dashboard", "manage", "manager",
    # Auth
    "login", "logout", "signin", "signup", "register", "auth", "oauth",
    "forgot-password", "reset-password", "account", "profile", "user",
    # API
    "api", "api/v1", "api/v2", "api/v3", "graphql", "swagger", "swagger-ui.html",
    "swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml", "api-docs",
    "redoc", "v1", "v2", "v3",
    # Config / Sensitive
    ".env", ".git", ".git/HEAD", ".git/config", ".gitignore", ".htaccess",
    "config.php", "config.yml", "config.yaml", "config.json", "settings.py",
    "web.config", "wp-config.php", "database.yml", ".DS_Store",
    "composer.json", "package.json", "Dockerfile", "docker-compose.yml",
    # Backup files
    "backup", "backup.zip", "backup.tar.gz", "backup.sql", "db.sql",
    "site.zip", "www.zip", "data.sql", "dump.sql", "old", "bak",
    # Info disclosure
    "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
    "security.txt", ".well-known/security.txt", "humans.txt",
    "phpinfo.php", "info.php", "test.php", "debug", "trace",
    # Common CMS
    "wp-content", "wp-includes", "wp-json", "xmlrpc.php",
    "joomla", "drupal", "magento", "laravel", "symfony",
    # Upload / Files
    "uploads", "upload", "files", "media", "images", "static", "assets",
    "downloads", "tmp", "temp", "cache",
    # Monitoring / Dev
    "actuator", "actuator/health", "actuator/env", "actuator/info",
    "health", "healthz", "status", "metrics", "monitor", "ping",
    "console", "h2-console", "jolokia", "jmx",
    # AWS / Cloud
    ".aws/credentials", "aws.json", "cloud.json", "gcp.json",
    # Misc
    "server-status", "server-info", "nginx_status", "php-fpm/status",
    "error_log", "access_log", "error.log", "access.log",
    "README.md", "CHANGELOG.md", "LICENSE", "VERSION",
]

INTERESTING_CODES = {200, 201, 301, 302, 307, 308, 401, 403, 405, 500}

def check_path(base_url: str, path: str, session: requests.Session, timeout: int = 8) -> Optional[Dict]:
    """Check a single path."""
    url = f"{base_url.rstrip('/')}/{path}"
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=False)
        if resp.status_code in INTERESTING_CODES:
            return {
                "url": url,
                "path": path,
                "status_code": resp.status_code,
                "content_length": len(resp.content),
                "content_type": resp.headers.get("Content-Type", ""),
                "redirect": resp.headers.get("Location", ""),
                "interesting": resp.status_code in {200, 201, 403, 500},
                "severity": classify_severity(path, resp.status_code),
            }
    except Exception:
        pass
    return None

def classify_severity(path: str, status: int) -> str:
    """Classify finding severity based on path and status."""
    critical_paths = {".env", ".git", ".git/HEAD", "wp-config.php", "config.php",
                      "database.yml", "phpinfo.php", "actuator/env", ".aws/credentials"}
    high_paths = {"admin", "administrator", "phpmyadmin", "adminer", "backup",
                  "swagger.json", "openapi.json", "h2-console", "jolokia"}

    clean_path = path.strip("/").lower()
    if clean_path in critical_paths and status == 200:
        return "CRITICAL"
    elif clean_path in high_paths and status == 200:
        return "HIGH"
    elif status in {200, 201} and any(kw in clean_path for kw in ["admin", "config", "backup", "db", "sql"]):
        return "HIGH"
    elif status in {200, 201}:
        return "MEDIUM"
    elif status == 403:
        return "LOW"
    elif status == 500:
        return "MEDIUM"
    return "INFO"

def run_dir_fuzzer(base_url: str, extra_paths: List[str] = None, progress_callback=None) -> List[Dict]:
    """Main directory fuzzing function."""
    paths = COMMON_PATHS.copy()
    if extra_paths:
        paths.extend(extra_paths)

    session = requests.Session()
    session.verify = False
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    })

    results = []
    total = len(paths)
    checked = 0

    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(check_path, base_url, path, session): path for path in paths}
        for future in as_completed(futures):
            checked += 1
            if progress_callback:
                progress_callback(checked / total, f"Checking /{futures[future]}")
            result = future.result()
            if result:
                results.append(result)

    return sorted(results, key=lambda x: (x["severity"] != "CRITICAL", x["severity"] != "HIGH", x["path"]))
