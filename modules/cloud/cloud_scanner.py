import requests
import urllib3
from typing import List, Dict
import time
import json
import re

urllib3.disable_warnings()

# S3 bucket name patterns from target domain
def generate_bucket_names(domain: str) -> List[str]:
    """Generate potential S3 bucket names from domain."""
    base = domain.split(".")[0]
    suffixes = ["", "-backup", "-dev", "-staging", "-prod", "-data", "-assets",
                "-uploads", "-files", "-logs", "-archive", "-public", "-private",
                "-images", "-media", "-static", "-api", "-app", "-web"]
    prefixes = ["", "dev-", "staging-", "prod-", "backup-", "data-", "www-"]
    names = []
    for prefix in prefixes:
        for suffix in suffixes:
            names.append(f"{prefix}{base}{suffix}")
    return list(set(names))

def check_s3_bucket(bucket_name: str, session: requests.Session) -> Dict:
    """Check if an S3 bucket exists and is publicly accessible."""
    result = {"bucket": bucket_name, "exists": False, "public": False, "listable": False, "findings": []}

    urls = [
        f"https://{bucket_name}.s3.amazonaws.com",
        f"https://s3.amazonaws.com/{bucket_name}",
    ]

    for url in urls:
        try:
            resp = session.get(url, timeout=8)
            if resp.status_code == 200:
                result["exists"] = True
                result["public"] = True
                # Check if bucket is listable (XML listing)
                if "<ListBucketResult" in resp.text or "<Contents>" in resp.text:
                    result["listable"] = True
                    result["findings"].append({
                        "type": "Public S3 Bucket (Listable)",
                        "url": url,
                        "severity": "CRITICAL",
                        "evidence": "S3 bucket contents are publicly listable",
                        "cvss": 9.1,
                        "remediation": "Set bucket ACL to private, enable block public access settings",
                    })
                else:
                    result["findings"].append({
                        "type": "Public S3 Bucket",
                        "url": url,
                        "severity": "HIGH",
                        "evidence": "S3 bucket is publicly accessible",
                        "cvss": 7.5,
                        "remediation": "Review and restrict S3 bucket permissions",
                    })
                break
            elif resp.status_code == 403:
                result["exists"] = True  # Forbidden = exists but not public
        except Exception:
            pass
    return result

def check_azure_blob(domain: str, session: requests.Session) -> List[Dict]:
    """Check for exposed Azure Blob Storage."""
    findings = []
    base = domain.split(".")[0]
    containers = ["uploads", "backups", "data", "public", "assets", "files", domain]

    for container in containers:
        url = f"https://{base}.blob.core.windows.net/{container}?restype=container&comp=list"
        try:
            resp = session.get(url, timeout=8)
            if resp.status_code == 200 and "<EnumerationResults" in resp.text:
                findings.append({
                    "type": "Public Azure Blob Container",
                    "url": url,
                    "severity": "CRITICAL",
                    "evidence": f"Azure blob container '{container}' is publicly listable",
                    "cvss": 9.1,
                    "remediation": "Set container access level to private",
                })
        except Exception:
            pass
        time.sleep(0.1)
    return findings

def check_gcp_bucket(domain: str, session: requests.Session) -> List[Dict]:
    """Check for exposed GCP Cloud Storage buckets."""
    findings = []
    base = domain.split(".")[0]
    bucket_names = [base, domain, f"{base}-backup", f"{base}-data", f"{base}-public"]

    for bucket in bucket_names:
        url = f"https://storage.googleapis.com/{bucket}"
        try:
            resp = session.get(url, timeout=8)
            if resp.status_code == 200:
                findings.append({
                    "type": "Public GCP Storage Bucket",
                    "url": url,
                    "severity": "HIGH",
                    "evidence": "GCP Storage bucket is publicly accessible",
                    "cvss": 7.5,
                    "remediation": "Remove allUsers and allAuthenticatedUsers IAM bindings",
                })
        except Exception:
            pass
        time.sleep(0.1)
    return findings

def check_metadata_endpoint(target_url: str, session: requests.Session) -> List[Dict]:
    """Check if the target itself exposes cloud metadata."""
    findings = []
    metadata_indicators = {
        "aws": ["ami-id", "instance-id", "security-credentials", "iam/info"],
        "gcp": ["computeMetadata", "project-id", "instance/service-accounts"],
        "azure": ["IMDS", "subscriptionId", "resourceGroupName"],
    }

    try:
        resp = session.get(target_url, timeout=10)
        for cloud, indicators in metadata_indicators.items():
            for indicator in indicators:
                if indicator in resp.text:
                    findings.append({
                        "type": f"Cloud Metadata Exposure ({cloud.upper()})",
                        "url": target_url,
                        "severity": "CRITICAL",
                        "evidence": f"Metadata indicator '{indicator}' found in response",
                        "cvss": 9.9,
                        "remediation": "Block access to metadata endpoints, use IMDSv2 (AWS)",
                    })
    except Exception:
        pass
    return findings

def check_firebase(domain: str, session: requests.Session) -> List[Dict]:
    """Check for publicly accessible Firebase databases."""
    findings = []
    base = domain.split(".")[0]
    firebase_urls = [
        f"https://{base}.firebaseio.com/.json",
        f"https://{base}-default-rtdb.firebaseio.com/.json",
    ]
    for url in firebase_urls:
        try:
            resp = session.get(url, timeout=8)
            if resp.status_code == 200 and resp.text not in ["null", ""]:
                findings.append({
                    "type": "Public Firebase Database",
                    "url": url,
                    "severity": "CRITICAL",
                    "evidence": "Firebase database is publicly readable",
                    "cvss": 9.1,
                    "remediation": "Configure Firebase Security Rules to restrict access",
                })
        except Exception:
            pass
    return findings

def run_cloud_scanner(target_url: str, domain: str, progress_callback=None) -> Dict:
    """Main cloud security scanner."""
    session = requests.Session()
    session.verify = False
    session.headers.update({"User-Agent": "Mozilla/5.0"})

    all_findings = []
    results = {
        "s3_results": [],
        "azure_findings": [],
        "gcp_findings": [],
        "firebase_findings": [],
        "metadata_findings": [],
        "all_findings": [],
    }

    # S3 Bucket enumeration
    if progress_callback:
        progress_callback(0.1, "Enumerating S3 buckets...")
    bucket_names = generate_bucket_names(domain)
    for i, bucket in enumerate(bucket_names[:30]):  # Limit to first 30
        if progress_callback:
            progress_callback(0.1 + (0.4 * i / 30), f"Checking S3: {bucket}")
        result = check_s3_bucket(bucket, session)
        if result["exists"]:
            results["s3_results"].append(result)
            all_findings.extend(result["findings"])
        time.sleep(0.1)

    # Azure Blob
    if progress_callback:
        progress_callback(0.55, "Checking Azure Blob Storage...")
    results["azure_findings"] = check_azure_blob(domain, session)
    all_findings.extend(results["azure_findings"])

    # GCP Storage
    if progress_callback:
        progress_callback(0.65, "Checking GCP Storage...")
    results["gcp_findings"] = check_gcp_bucket(domain, session)
    all_findings.extend(results["gcp_findings"])

    # Firebase
    if progress_callback:
        progress_callback(0.75, "Checking Firebase...")
    results["firebase_findings"] = check_firebase(domain, session)
    all_findings.extend(results["firebase_findings"])

    # Metadata endpoint
    if progress_callback:
        progress_callback(0.9, "Checking cloud metadata exposure...")
    results["metadata_findings"] = check_metadata_endpoint(target_url, session)
    all_findings.extend(results["metadata_findings"])

    results["all_findings"] = all_findings
    return results
