# 🎯 Bug Bounty Hunter Platform

A full-scope automated security assessment platform built with Streamlit, designed by a 30-year veteran bug bounty hunter mindset.

## ⚠️ Legal Disclaimer

**This tool is for AUTHORIZED security testing only.** Only use against targets you have explicit written permission to test. Unauthorized scanning is illegal. The authors assume no liability for misuse.

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
cd bug_bounty_platform
pip install -r requirements.txt
```

### 2. Install System Tools (Optional but Recommended)
```bash
# Ubuntu/Debian
sudo apt-get install nmap

# macOS
brew install nmap
```

### 3. Run the Platform
```bash
streamlit run main.py
```

The platform will open at `http://localhost:8501`

---

## 🛡️ Modules

| Module | Description |
|--------|-------------|
| **Subdomain Enum** | crt.sh passive recon + DNS brute-force (200+ subdomains), takeover detection |
| **Port Scanner** | TCP connect scan, 70+ well-known ports, banner grabbing |
| **Dir Fuzzer** | 150+ sensitive paths: admin panels, config files, backups, APIs |
| **Param Discovery** | HTML form parsing + 80+ common parameter names, reflection testing |
| **XSS Scanner** | 14 payloads, reflected/DOM/header-based XSS detection |
| **SQLi Scanner** | Error-based + Boolean blind SQLi, 20+ payloads |
| **SSRF/XXE** | Cloud metadata probing (AWS/GCP/Azure), XML injection |
| **API Scanner** | REST/GraphQL endpoint discovery, BOLA/IDOR, data exposure |
| **Cloud Scanner** | S3/Azure Blob/GCP Storage/Firebase enumeration |
| **Network/Headers** | 7 security headers, CORS misconfiguration, SSL/TLS checks |

---

## 📊 Output

- **Live Dashboard** with severity-coded findings
- **Terminal output** with real-time scan logs
- **Markdown report** downloadable for bug bounty submissions
- **JSON export** of all findings

---

## 🔧 Architecture

```
bug_bounty_platform/
├── main.py                          # Streamlit UI & orchestration
├── requirements.txt
├── modules/
│   ├── recon/
│   │   ├── subdomain_enum.py        # crt.sh + DNS brute-force
│   │   ├── port_scanner.py          # TCP port scanner
│   │   ├── dir_fuzzer.py            # Directory/path fuzzer
│   │   └── param_discovery.py       # Parameter discovery
│   ├── vuln_scan/
│   │   ├── xss_scanner.py           # XSS detection
│   │   ├── sqli_scanner.py          # SQL injection
│   │   └── ssrf_xxe_scanner.py      # SSRF + XXE
│   ├── api_testing/
│   │   └── api_scanner.py           # REST/GraphQL API testing
│   ├── cloud/
│   │   └── cloud_scanner.py         # S3/Azure/GCP/Firebase
│   ├── network/
│   │   └── network_scanner.py       # Headers, CORS, SSL
│   └── reporting/
│       └── report_gen.py            # Markdown/JSON report gen
└── utils/
    ├── http_client.py               # Shared HTTP client
    └── logger.py                    # Scan logger
```

---

## 🎯 Best Practices (From a 30-Year Veteran)

1. **Always get written permission** before scanning
2. **Start with passive recon** (crt.sh, Shodan) before active scanning
3. **Use scope management** — never scan out-of-scope assets
4. **Rate limit your requests** — don't DoS the target
5. **Document everything** — timestamps, payloads, screenshots
6. **Chain findings** — a SSRF + internal metadata = Critical escalation
7. **Report clearly** — CVSS score, PoC, remediation, business impact
