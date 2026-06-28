"""Active port scan (opt-in only).

Unlike the rest of SentinelDeck, this *actively* connects to a list of common
TCP ports on the target. It runs only when the user passes ``--active``, and is
off by default so the standard scan stays passive and safe to run on any domain.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 587: "SMTP (submission)",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 9200: "Elasticsearch", 27017: "MongoDB",
}
# Ports that should rarely be exposed to the public internet.
RISKY_PORTS = {23, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 27017}


def _connect(domain: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((domain, port), timeout=timeout):
            return True
    except Exception:  # noqa: BLE001 - closed/filtered ports just fail to connect
        return False


def scan_ports(domain: str, timeout: float = 2.0, ports: dict | None = None) -> dict:
    """Connect to common TCP ports and report which are open."""
    ports = ports or COMMON_PORTS
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = pool.map(lambda p: (p, _connect(domain, p, timeout)), ports)
        open_ports = [
            {"port": p, "service": ports[p], "risky": p in RISKY_PORTS}
            for p, is_open in results if is_open
        ]
    return {
        "status": "ok",
        "scanned": len(ports),
        "open": sorted(open_ports, key=lambda x: x["port"]),
    }
