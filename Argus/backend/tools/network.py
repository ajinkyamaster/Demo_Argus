"""
Network scanning tools — Person 2 (Toolsmith).

Provides port-level misconfiguration detection for Person 1's Network Agent:
  - network_scan_tool — probes common service ports for open access and misconfigs
"""

import json
import socket
import uuid
from typing import Any

from crewai.tools import tool

SOCKET_TIMEOUT = 5.0


def _make_result(tool_name: str, target: str, data: Any) -> str:
    """Serialize network scan output to standard JSON envelope."""
    vulnerable = False
    if isinstance(data, dict):
        misconfigs = data.get("misconfigurations", [])
        vulnerable = len(misconfigs) > 0
    first_payload = None
    if isinstance(data, dict) and data.get("misconfigurations"):
        first_payload = data["misconfigurations"][0].get("service")
    return json.dumps({
        "tool": tool_name,
        "target": target,
        "vulnerable": vulnerable,
        "payload": first_payload,
        "data": data,
    })


# ── Service probes ────────────────────────────────────────────────────────────


def _tcp_connect(host: str, port: int) -> bool:
    """Check if a TCP port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SOCKET_TIMEOUT)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except (OSError, socket.error):
        return False


def _tcp_recv(host: str, port: int, send_data: bytes | None = None) -> str | None:
    """Connect to TCP port, optionally send data, and read the response banner."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SOCKET_TIMEOUT)
        sock.connect((host, port))
        if send_data:
            sock.sendall(send_data)
        data = sock.recv(2048)
        sock.close()
        return data.decode("utf-8", errors="replace")
    except (OSError, socket.error, socket.timeout):
        return None


def _probe_redis(host: str, port: int = 6379) -> dict | None:
    """Check for unauthenticated Redis access."""
    if not _tcp_connect(host, port):
        return None

    banner = _tcp_recv(host, port, b"INFO server\r\n")
    if banner and ("redis_version" in banner or "# Server" in banner):
        return {
            "service": "Redis",
            "port": port,
            "severity": "critical",
            "title": f"Unauthenticated Redis on port {port}",
            "description": (
                "Redis is accessible without authentication. An attacker can "
                "read/write all cached data, execute Lua scripts, or write "
                "crontab/SSH key files for RCE."
            ),
            "evidence": f"Redis INFO command returned: {banner[:300]}",
            "remediation": (
                "Set 'requirepass' in redis.conf. Bind to 127.0.0.1 or use "
                "firewall rules to restrict access. Disable dangerous commands "
                "via 'rename-command'."
            ),
            "cvss_score": 9.8,
        }
    return None


def _probe_ftp(host: str, port: int = 21) -> dict | None:
    """Check for anonymous FTP access."""
    banner = _tcp_recv(host, port)
    if not banner or "220" not in banner:
        if not _tcp_connect(host, port):
            return None
        # Port open but no banner — still report
        banner = ""

    # Try anonymous login
    anon_resp = _tcp_recv(host, port, b"USER anonymous\r\n")
    if anon_resp and ("230" in anon_resp or "331" in anon_resp):
        return {
            "service": "FTP",
            "port": port,
            "severity": "high",
            "title": f"Anonymous FTP access on port {port}",
            "description": (
                "FTP server allows anonymous login. An attacker may browse, "
                "download, or upload files without authentication."
            ),
            "evidence": (
                f"FTP banner: {banner[:200]}. "
                f"Anonymous USER response: {anon_resp[:200]}"
            ),
            "remediation": (
                "Disable anonymous FTP access. Use SFTP/SCP instead of FTP. "
                "If FTP is required, enforce strong authentication."
            ),
            "cvss_score": 7.5,
        }
    return None


def _probe_smb(host: str, port: int = 445) -> dict | None:
    """Check if SMB port is open (basic detection)."""
    if not _tcp_connect(host, port):
        return None

    return {
        "service": "SMB",
        "port": port,
        "severity": "medium",
        "title": f"SMB service exposed on port {port}",
        "description": (
            "SMB (Server Message Block) service is accessible. If share-level "
            "permissions are misconfigured, an attacker may access files or "
            "exploit known SMB vulnerabilities (EternalBlue, etc.)."
        ),
        "evidence": f"TCP port {port} is open and accepting connections.",
        "remediation": (
            "Block SMB ports (445, 139) at the firewall for external access. "
            "Disable SMBv1. Require SMB signing. Enforce share-level ACLs."
        ),
        "cvss_score": 7.2,
    }


def _probe_mongodb(host: str, port: int = 27017) -> dict | None:
    """Check for unauthenticated MongoDB access."""
    if not _tcp_connect(host, port):
        return None

    # MongoDB wire protocol: send isMaster command
    # A simpler check: try to read the initial handshake
    banner = _tcp_recv(host, port)
    if banner and ("ismaster" in banner.lower() or "mongodb" in banner.lower()):
        return {
            "service": "MongoDB",
            "port": port,
            "severity": "critical",
            "title": f"Unauthenticated MongoDB on port {port}",
            "description": (
                "MongoDB is accessible without authentication. An attacker "
                "can read, modify, or delete any database and collection."
            ),
            "evidence": f"MongoDB responded without auth: {banner[:300]}",
            "remediation": (
                "Enable MongoDB authentication. Bind to 127.0.0.1 or use "
                "firewall rules. Enable TLS. Use SCRAM-SHA-256 auth."
            ),
            "cvss_score": 9.8,
        }

    # Port is open even if banner didn't match — note it
    return {
        "service": "MongoDB (possible)",
        "port": port,
        "severity": "medium",
        "title": f"Port {port} open (common MongoDB port)",
        "description": (
            f"TCP port {port} is open. This is commonly used by MongoDB. "
            "Further investigation needed to confirm the service."
        ),
        "evidence": f"TCP port {port} is open.",
        "remediation": "Verify the service. If MongoDB, enable authentication.",
        "cvss_score": 5.3,
    }


def _probe_mysql(host: str, port: int = 3306) -> dict | None:
    """Check for exposed MySQL."""
    banner = _tcp_recv(host, port)
    if not banner:
        return None

    if "mysql" in banner.lower() or "mariadb" in banner.lower():
        version_info = banner.replace("\x00", "").strip()[:100]
        return {
            "service": "MySQL/MariaDB",
            "port": port,
            "severity": "high",
            "title": f"MySQL/MariaDB exposed on port {port}",
            "description": (
                "MySQL/MariaDB is accessible from the network. If using "
                "weak credentials or remote root access, an attacker can "
                "access all databases."
            ),
            "evidence": f"MySQL banner: {version_info}",
            "remediation": (
                "Bind MySQL to 127.0.0.1. Disable remote root login. "
                "Use strong passwords. Firewall port 3306."
            ),
            "cvss_score": 7.5,
        }
    return None


def _probe_postgresql(host: str, port: int = 5432) -> dict | None:
    """Check for exposed PostgreSQL."""
    if not _tcp_connect(host, port):
        return None

    # PostgreSQL responds to a startup packet
    return {
        "service": "PostgreSQL",
        "port": port,
        "severity": "medium",
        "title": f"PostgreSQL exposed on port {port}",
        "description": (
            "PostgreSQL is accessible from the network. If using weak "
            "authentication (trust/md5 with weak passwords), an attacker "
            "may access databases."
        ),
        "evidence": f"TCP port {port} is open and accepting connections.",
        "remediation": (
            "Bind PostgreSQL to 127.0.0.1. Use pg_hba.conf to restrict "
            "remote access. Enforce scram-sha-256 authentication. "
            "Firewall port 5432."
        ),
        "cvss_score": 6.5,
    }


def _probe_elasticsearch(host: str, port: int = 9200) -> dict | None:
    """Check for unauthenticated Elasticsearch."""
    try:
        import httpx as hx
        resp = hx.get(f"http://{host}:{port}/", timeout=SOCKET_TIMEOUT)
        if resp.status_code == 200:
            body = resp.text
            if "cluster_name" in body or "lucene_version" in body:
                return {
                    "service": "Elasticsearch",
                    "port": port,
                    "severity": "critical",
                    "title": f"Unauthenticated Elasticsearch on port {port}",
                    "description": (
                        "Elasticsearch is accessible without authentication. "
                        "An attacker can read, modify, or delete any index."
                    ),
                    "evidence": f"Elasticsearch root response: {body[:300]}",
                    "remediation": (
                        "Enable Elasticsearch security features (X-Pack). "
                        "Require authentication. Bind to localhost or use "
                        "firewall rules."
                    ),
                    "cvss_score": 9.8,
                }
    except Exception:
        pass
    return None


# ── Main scan tool ────────────────────────────────────────────────────────────


# Service probes: (probe_function, default_port, service_name)
_SERVICE_PROBES = [
    (_probe_redis, 6379, "Redis"),
    (_probe_ftp, 21, "FTP"),
    (_probe_smb, 445, "SMB"),
    (_probe_smb, 139, "SMB/NetBIOS"),
    (_probe_mongodb, 27017, "MongoDB"),
    (_probe_mysql, 3306, "MySQL"),
    (_probe_postgresql, 5432, "PostgreSQL"),
    (_probe_elasticsearch, 9200, "Elasticsearch"),
]


@tool("Network Scanner")
def network_scan_tool(target_url: str) -> str:
    """
    Scan the target host for network-level service misconfigurations.

    Probes common service ports (Redis 6379, FTP 21, SMB 445/139,
    MongoDB 27017, MySQL 3306, PostgreSQL 5432, Elasticsearch 9200)
    for open access, missing authentication, and information disclosure.
    Returns a JSON report with confirmed misconfigurations.
    """
    from urllib.parse import urlparse

    parsed = urlparse(target_url if "://" in target_url else f"http://{target_url}")
    host = parsed.hostname or target_url

    open_ports: list[dict] = []
    misconfigurations: list[dict] = []

    for probe_fn, port, service_name in _SERVICE_PROBES:
        try:
            result = probe_fn(host, port)
            if result:
                result["id"] = str(uuid.uuid4())
                result["agent"] = "NetworkAgent"
                if result.get("severity") in ("critical", "high"):
                    misconfigurations.append(result)
                else:
                    open_ports.append(result)
        except Exception:
            continue

    return _make_result("network_scan", target_url, {
        "host": host,
        "probes_run": len(_SERVICE_PROBES),
        "misconfigurations": misconfigurations,
        "open_services": open_ports,
        "findings": misconfigurations + open_ports,
    })
