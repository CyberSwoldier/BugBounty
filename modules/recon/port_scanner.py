import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional
import subprocess
import json

# Well-known ports with service names
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 2375: "Docker",
    3000: "Dev-HTTP", 3306: "MySQL", 3389: "RDP", 4444: "Metasploit",
    5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
    6379: "Redis", 7001: "WebLogic", 7443: "Alt-HTTPS", 8000: "HTTP-Alt",
    8008: "HTTP-Alt", 8080: "HTTP-Proxy", 8081: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "HTTP-Alt", 9000: "PHP-FPM", 9090: "Openfire", 9200: "Elasticsearch",
    9300: "Elasticsearch-Transport", 10000: "Webmin", 11211: "Memcached",
    27017: "MongoDB", 27018: "MongoDB", 50070: "Hadoop-HDFS",
}

RISKY_PORTS = {
    21, 23, 111, 135, 139, 445, 2049, 2375, 3389, 4444,
    5900, 6379, 7001, 9200, 11211, 27017, 50070
}

def scan_port(host: str, port: int, timeout: float = 1.5) -> Optional[Dict]:
    """Attempt TCP connect to a single port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            banner = grab_banner(host, port)
            return {
                "port": port,
                "state": "open",
                "service": service,
                "banner": banner,
                "risky": port in RISKY_PORTS,
            }
    except Exception:
        pass
    return None

def grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    """Try to grab a service banner."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        if port in (80, 8080, 8000, 8008):
            sock.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
        else:
            sock.send(b"\r\n")
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        return banner[:200] if banner else ""
    except Exception:
        return ""

def run_port_scan(host: str, port_range: str = "common", custom_ports: List[int] = None,
                  progress_callback=None) -> List[Dict]:
    """Scan ports on a host."""
    if port_range == "common":
        ports = list(COMMON_PORTS.keys())
    elif port_range == "top1000":
        ports = list(range(1, 1001))
    elif port_range == "full":
        ports = list(range(1, 65536))
    elif port_range == "custom" and custom_ports:
        ports = custom_ports
    else:
        ports = list(COMMON_PORTS.keys())

    open_ports = []
    total = len(ports)
    scanned = 0

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, host, port): port for port in ports}
        for future in as_completed(futures):
            scanned += 1
            if progress_callback:
                progress_callback(scanned / total, f"Scanning port {futures[future]}")
            result = future.result()
            if result:
                open_ports.append(result)

    return sorted(open_ports, key=lambda x: x["port"])

def get_risk_summary(open_ports: List[Dict]) -> Dict:
    """Summarize risk from open ports."""
    risky = [p for p in open_ports if p.get("risky")]
    return {
        "total_open": len(open_ports),
        "risky_count": len(risky),
        "risky_ports": risky,
        "risk_level": "CRITICAL" if len(risky) > 3 else "HIGH" if len(risky) > 1 else "MEDIUM" if risky else "LOW"
    }
