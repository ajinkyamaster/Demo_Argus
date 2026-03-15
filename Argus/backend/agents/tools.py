"""
Person 1's agent tools — run_recon, scan_web_vulns, lookup_cves,
check_network_misconfig, and HTTP wrappers for Person 2's verification API.
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from crewai.tools import tool


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

_HTTP_TIMEOUT = 10  # seconds for HTTP probes


def _safe_get(url: str, **kwargs) -> httpx.Response | None:
    try:
        return httpx.get(url, timeout=_HTTP_TIMEOUT, follow_redirects=True, **kwargs)
    except Exception:
        return None


def _safe_post(url: str, **kwargs) -> httpx.Response | None:
    try:
        return httpx.post(url, timeout=_HTTP_TIMEOUT, follow_redirects=True, **kwargs)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Passive recon helpers
# ---------------------------------------------------------------------------

_SECURITY_HEADERS = [
    "X-Frame-Options",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "X-XSS-Protection",
    "Permissions-Policy",
    "Referrer-Policy",
]

_SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "api", "dev", "staging", "test", "admin",
    "beta", "cdn", "docs", "portal", "app", "m", "shop", "blog",
]

_DIR_ENUM_WORDLIST = [
    "/backup", "/backups", "/db", "/database", "/dump", "/dumps",
    "/uploads", "/upload", "/tmp", "/temp", "/logs", "/log",
    "/private", "/secret", "/hidden", "/internal",
    "/api/v1", "/api/v2", "/api/v3", "/api/internal",
    "/phpmyadmin", "/adminer", "/wp-admin", "/wp-login.php",
    "/administrator", "/panel", "/dashboard", "/cpanel", "/control",
    "/cgi-bin", "/server-status", "/server-info",
    "/swagger", "/swagger-ui", "/api-docs", "/openapi.json", "/docs",
    "/graphql", "/graphiql", "/playground",
    "/.htaccess", "/.htpasswd", "/.DS_Store", "/web.config",
    "/sitemap.xml", "/crossdomain.xml", "/.well-known",
    "/status", "/metrics", "/prometheus", "/actuator", "/actuator/health",
    "/test", "/testing", "/staging", "/dev",
    "/old", "/bak", "/archive", "/archived",
]


def _dns_resolve(host: str) -> dict:
    records: dict[str, list[str]] = {}
    try:
        records["A"] = list({r[4][0] for r in socket.getaddrinfo(host, None, socket.AF_INET)})
    except Exception:
        pass
    try:
        records["AAAA"] = list({r[4][0] for r in socket.getaddrinfo(host, None, socket.AF_INET6)})
    except Exception:
        pass
    return records


def _check_security_headers(base_url: str) -> dict:
    resp = _safe_get(base_url)
    if not resp:
        return {"present": [], "missing": _SECURITY_HEADERS}
    present = []
    missing = []
    resp_header_keys = {k.lower() for k in resp.headers.keys()}
    for h in _SECURITY_HEADERS:
        if h.lower() in resp_header_keys:
            present.append(h)
        else:
            missing.append(h)
    return {"present": present, "missing": missing}


def _discover_subdomains(host: str) -> list[str]:
    # Skip subdomain brute for localhost/IPs
    if host in ("localhost", "127.0.0.1") or host.replace(".", "").isdigit():
        return []
    found = []
    for sub in _SUBDOMAIN_WORDLIST:
        fqdn = f"{sub}.{host}"
        try:
            socket.getaddrinfo(fqdn, None, socket.AF_INET)
            found.append(fqdn)
        except socket.gaierror:
            pass
    return found


def _enumerate_directories(base_url: str) -> list[dict]:
    """Brute-force common directories and return those that respond with non-404."""
    found = []
    for path in _DIR_ENUM_WORDLIST:
        url = urljoin(base_url, path)
        resp = _safe_get(url)
        if resp is None:
            continue
        if resp.status_code < 404:
            found.append({
                "path": path,
                "status": resp.status_code,
                "content_type": resp.headers.get("content-type", ""),
                "content_length": len(resp.content),
            })
    return found


def _classify_endpoint(path: str) -> str:
    """Classify an endpoint for context-aware routing."""
    p = path.lower()
    if any(k in p for k in ("login", "auth", "admin", "signin", "register", "password")):
        return "auth"
    if any(k in p for k in ("search", "query", "find", "lookup", "q=")):
        return "search"
    if any(k in p for k in ("file", "download", "read", "path", "include", "load", "open")):
        return "file"
    if any(k in p for k in ("api", "rest", "graphql", "json")):
        return "api"
    return "general"


# ---------------------------------------------------------------------------
# Tool 1: run_recon
# ---------------------------------------------------------------------------


@tool("Network Recon")
def run_recon(target: str) -> str:
    """
    Run network reconnaissance against a target URL or host.

    Executes `nmap -sV -sC` for service/version detection, performs
    a lightweight web crawl to enumerate HTTP endpoints, and brute-forces
    common directories to discover hidden paths.

    Args:
        target: Base URL (e.g. 'http://localhost:5000') or hostname/IP.

    Returns:
        JSON string with keys: host, ports, services, web_endpoints, technologies,
        directory_enumeration.
    """
    parsed = urlparse(target if "://" in target else f"http://{target}")
    host = parsed.hostname or target
    base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else f"http://{host}"

    result: dict[str, Any] = {
        "host": host,
        "base_url": base_url,
        "ports": [],
        "services": [],
        "web_endpoints": [],
        "technologies": [],
        "endpoint_routes": {},
        "directory_enumeration": [],
        "dns": {},
        "security_headers": {},
        "subdomains": [],
        "nmap_error": None,
        "crawl_error": None,
    }

    # ── nmap scan (120 s hard timeout) ──────────────────────────────────────
    try:
        nmap_proc = subprocess.run(
            ["nmap", "-sV", "-sC", "-oX", "-", host],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if nmap_proc.returncode == 0 and nmap_proc.stdout.strip():
            root = ET.fromstring(nmap_proc.stdout)
            for port_el in root.findall(".//port"):
                port_id = port_el.get("portid")
                proto = port_el.get("protocol", "tcp")
                state_el = port_el.find("state")
                state = state_el.get("state") if state_el is not None else "unknown"
                svc_el = port_el.find("service")
                svc_name = svc_el.get("name", "") if svc_el is not None else ""
                svc_product = svc_el.get("product", "") if svc_el is not None else ""
                svc_version = svc_el.get("version", "") if svc_el is not None else ""
                # Collect script output for NSE results
                scripts = {}
                for script_el in port_el.findall("script"):
                    scripts[script_el.get("id", "")] = script_el.get("output", "")

                port_entry = {
                    "port": int(port_id),
                    "protocol": proto,
                    "state": state,
                    "service": svc_name,
                    "product": svc_product,
                    "version": svc_version,
                    "scripts": scripts,
                }
                result["ports"].append(port_entry)
                if state == "open" and svc_name:
                    result["services"].append(
                        f"{svc_product} {svc_version}".strip() or svc_name
                    )
        else:
            result["nmap_error"] = nmap_proc.stderr[:500] if nmap_proc.stderr else "no output"
    except subprocess.TimeoutExpired:
        result["nmap_error"] = "nmap timed out after 120 s"
    except FileNotFoundError:
        result["nmap_error"] = "nmap not found on PATH"
    except Exception as exc:
        result["nmap_error"] = str(exc)

    # ── lightweight web crawl ────────────────────────────────────────────────
    known_paths = [
        "/",
        "/login",
        "/register",
        "/api",
        "/api/login",
        "/api/register",
        "/api/users",
        "/api/search",
        "/admin",
        "/health",
        "/robots.txt",
        "/.env",
        "/config",
        "/debug",
        "/.git/HEAD",
        "/.git/config",
        "/api/debug",
        "/console",
    ]
    found_endpoints: list[str] = []
    tech_hints: set[str] = set()
    try:
        for path in known_paths:
            url = urljoin(base_url, path)
            resp = _safe_get(url)
            if resp is None:
                continue
            if resp.status_code < 404:
                found_endpoints.append(
                    {
                        "path": path,
                        "status": resp.status_code,
                        "content_type": resp.headers.get("content-type", ""),
                    }
                )
            # Technology fingerprinting from headers / body
            server = resp.headers.get("server", "").lower()
            powered_by = resp.headers.get("x-powered-by", "").lower()
            for hint in [server, powered_by]:
                if hint:
                    tech_hints.add(hint)
            body_lower = resp.text[:2000].lower()
            if "flask" in body_lower or "jinja" in body_lower or "werkzeug" in server:
                tech_hints.add("Flask/Jinja2")
            if "django" in body_lower:
                tech_hints.add("Django")
            if "express" in powered_by:
                tech_hints.add("Express.js")
            if "sqlalchemy" in body_lower or "sqlite" in body_lower:
                tech_hints.add("SQLAlchemy/SQLite")

        result["web_endpoints"] = found_endpoints
        result["technologies"] = list(tech_hints)
    except Exception as exc:
        result["crawl_error"] = str(exc)

    # ── endpoint classification (context-aware routing) ─────────────────────
    routes: dict[str, list[str]] = {"auth": [], "search": [], "file": [], "api": [], "general": []}
    for ep in result["web_endpoints"]:
        if isinstance(ep, dict):
            path = ep.get("path", "")
            category = _classify_endpoint(path)
            routes[category].append(path)
            ep["route_category"] = category
    result["endpoint_routes"] = routes

    # ── passive recon: DNS resolution ───────────────────────────────────────
    result["dns"] = _dns_resolve(host)

    # ── passive recon: security headers ─────────────────────────────────────
    result["security_headers"] = _check_security_headers(base_url)

    # ── subdomain discovery ─────────────────────────────────────────────────
    result["subdomains"] = _discover_subdomains(host)

    # ── directory enumeration ─────────────────────────────────────────────
    result["directory_enumeration"] = _enumerate_directories(base_url)

    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# Tool 2: scan_web_vulns
# ---------------------------------------------------------------------------

_SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),
    ("{{7*'7'}}", "7777777"),
    ("${7*7}", "49"),
    ("{7*7}", "49"),
    ("<%= 7*7 %>", "49"),
]

_SQLI_ERROR_PATTERNS = [
    r"sql syntax",
    r"mysql_fetch",
    r"sqlite3",
    r"ORA-\d+",
    r"pg_query",
    r"syntax error.*sql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"you have an error in your sql",
]

_LFI_PAYLOADS = [
    ("../../../etc/passwd", "root:"),
    ("....//....//....//etc/passwd", "root:"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "root:"),
]

_XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><svg/onload=alert(1)>',
    "'><img src=x onerror=alert(1)>",
]


def _test_ssti(base_url: str, endpoints: list) -> list[dict]:
    findings = []
    test_paths = [ep["path"] for ep in endpoints if isinstance(ep, dict)] or ["/search", "/"]
    for path in test_paths:
        url = urljoin(base_url, path)
        for payload, expected in _SSTI_PAYLOADS:
            # GET parameter injection
            try:
                resp = httpx.get(
                    url,
                    params={"q": payload, "search": payload, "name": payload},
                    timeout=_HTTP_TIMEOUT,
                    follow_redirects=True,
                )
                if expected in resp.text:
                    findings.append(
                        {
                            "type": "SSTI",
                            "endpoint": url,
                            "method": "GET",
                            "payload": payload,
                            "evidence": f"Response contained '{expected}' — template evaluation confirmed",
                            "severity": "critical",
                            "cvss_score": 9.8,
                        }
                    )
                    break
            except Exception:
                pass
            # POST body injection
            try:
                resp = httpx.post(
                    url,
                    data={"q": payload, "search": payload, "username": payload},
                    timeout=_HTTP_TIMEOUT,
                    follow_redirects=True,
                )
                if expected in resp.text:
                    findings.append(
                        {
                            "type": "SSTI",
                            "endpoint": url,
                            "method": "POST",
                            "payload": payload,
                            "evidence": f"Response contained '{expected}' — template evaluation confirmed",
                            "severity": "critical",
                            "cvss_score": 9.8,
                        }
                    )
                    break
            except Exception:
                pass
    return findings


def _test_sqli(base_url: str, endpoints: list) -> list[dict]:
    findings = []
    sqli_payloads = ["'", "' OR '1'='1", "1 OR 1=1--", "' OR 1=1--", "admin'--"]
    combined_pattern = re.compile("|".join(_SQLI_ERROR_PATTERNS), re.IGNORECASE)

    login_url = urljoin(base_url, "/api/login")
    search_url = urljoin(base_url, "/api/search")
    test_targets = [
        (login_url, "POST", {"username": None, "password": "x"}),
        (search_url, "GET", {"q": None}),
    ]
    for url, method, param_template in test_targets:
        for payload in sqli_payloads:
            try:
                if method == "POST":
                    body = {k: payload if v is None else v for k, v in param_template.items()}
                    resp = httpx.post(url, json=body, timeout=_HTTP_TIMEOUT, follow_redirects=True)
                else:
                    params = {k: payload if v is None else v for k, v in param_template.items()}
                    resp = httpx.get(url, params=params, timeout=_HTTP_TIMEOUT, follow_redirects=True)

                if combined_pattern.search(resp.text):
                    findings.append(
                        {
                            "type": "SQL_INJECTION",
                            "endpoint": url,
                            "method": method,
                            "payload": payload,
                            "evidence": f"SQL error pattern detected in response (HTTP {resp.status_code})",
                            "severity": "critical",
                            "cvss_score": 9.8,
                        }
                    )
                    break
                # Boolean-based: 200 with suspicious content
                if method == "POST" and resp.status_code == 200 and "token" in resp.text.lower():
                    findings.append(
                        {
                            "type": "SQL_INJECTION",
                            "endpoint": url,
                            "method": method,
                            "payload": payload,
                            "evidence": f"Auth bypass: HTTP 200 with token returned for payload '{payload}'",
                            "severity": "critical",
                            "cvss_score": 9.8,
                        }
                    )
                    break
            except Exception:
                pass
    return findings


def _test_lfi(base_url: str, endpoints: list) -> list[dict]:
    findings = []
    test_paths = ["/api/file", "/file", "/download", "/read"]
    for path in test_paths:
        url = urljoin(base_url, path)
        for payload, indicator in _LFI_PAYLOADS:
            try:
                resp = httpx.get(
                    url,
                    params={"file": payload, "path": payload, "filename": payload},
                    timeout=_HTTP_TIMEOUT,
                    follow_redirects=True,
                )
                if indicator in resp.text and resp.status_code == 200:
                    findings.append(
                        {
                            "type": "PATH_TRAVERSAL",
                            "endpoint": url,
                            "method": "GET",
                            "payload": payload,
                            "evidence": f"'/etc/passwd' content exposed in response",
                            "severity": "high",
                            "cvss_score": 7.5,
                        }
                    )
                    break
            except Exception:
                pass
    return findings


def _test_xss(base_url: str, endpoints: list) -> list[dict]:
    findings = []
    test_paths = [ep["path"] for ep in endpoints if isinstance(ep, dict)] or ["/search"]
    for path in test_paths:
        url = urljoin(base_url, path)
        for payload in _XSS_PAYLOADS:
            try:
                resp = httpx.get(
                    url,
                    params={"q": payload, "search": payload},
                    timeout=_HTTP_TIMEOUT,
                    follow_redirects=True,
                )
                if payload in resp.text and "text/html" in resp.headers.get("content-type", ""):
                    findings.append(
                        {
                            "type": "XSS",
                            "endpoint": url,
                            "method": "GET",
                            "payload": payload,
                            "evidence": f"Payload reflected verbatim in HTML response with content-type text/html",
                            "severity": "high",
                            "cvss_score": 7.2,
                        }
                    )
                    break
            except Exception:
                pass
    return findings


_SENSITIVE_PATHS = {
    "/.env": {
        "type": "SENSITIVE_EXPOSURE",
        "title": "Environment File Exposed",
        "severity": "critical",
        "cvss_score": 9.1,
        "indicators": ["SECRET_KEY", "DATABASE_URL", "API_KEY", "PASSWORD", "TOKEN", "DB_"],
    },
    "/.git/HEAD": {
        "type": "GIT_EXPOSURE",
        "title": "Git Repository Exposed",
        "severity": "high",
        "cvss_score": 7.5,
        "indicators": ["ref:", "HEAD"],
    },
    "/.git/config": {
        "type": "GIT_EXPOSURE",
        "title": "Git Config Exposed",
        "severity": "high",
        "cvss_score": 7.5,
        "indicators": ["[core]", "[remote", "url ="],
    },
    "/debug": {
        "type": "DEBUG_PANEL_EXPOSED",
        "title": "Debug Panel Exposed",
        "severity": "high",
        "cvss_score": 8.0,
        "indicators": ["Traceback", "werkzeug", "debugger", "Interactive Console", "PIN"],
    },
    "/api/debug": {
        "type": "DEBUG_PANEL_EXPOSED",
        "title": "API Debug Endpoint Exposed",
        "severity": "high",
        "cvss_score": 7.5,
        "indicators": ["debug", "env", "config", "secret"],
    },
    "/console": {
        "type": "DEBUG_PANEL_EXPOSED",
        "title": "Interactive Console Exposed",
        "severity": "critical",
        "cvss_score": 9.8,
        "indicators": ["console", "python", ">>", "interactive"],
    },
}


def _check_sensitive_paths(base_url: str) -> list[dict]:
    findings = []
    for path, meta in _SENSITIVE_PATHS.items():
        url = urljoin(base_url, path)
        try:
            resp = httpx.get(url, timeout=_HTTP_TIMEOUT, follow_redirects=False)
            if resp.status_code not in (200, 403):
                continue
            body = resp.text
            matched_indicators = [ind for ind in meta["indicators"] if ind.lower() in body.lower()]
            if resp.status_code == 200 and matched_indicators:
                snippet = body[:300].replace("\n", " ")
                findings.append(
                    {
                        "type": meta["type"],
                        "title": meta["title"],
                        "endpoint": url,
                        "method": "GET",
                        "payload": "Direct GET request",
                        "evidence": (
                            f"HTTP 200 returned for {path}. "
                            f"Matched indicators: {matched_indicators}. "
                            f"Response snippet: {snippet!r}"
                        ),
                        "severity": meta["severity"],
                        "cvss_score": meta["cvss_score"],
                    }
                )
            elif resp.status_code == 403:
                # 403 on .git/HEAD confirms git exists even if blocked — still report
                if path in ("/.git/HEAD", "/.git/config"):
                    findings.append(
                        {
                            "type": meta["type"],
                            "title": meta["title"] + " (Access Restricted but Exists)",
                            "endpoint": url,
                            "method": "GET",
                            "payload": "Direct GET request",
                            "evidence": (
                                f"HTTP 403 on {path} confirms resource exists "
                                "but server blocked direct access. "
                                "Git objects may still be accessible via enumeration."
                            ),
                            "severity": "medium",
                            "cvss_score": 5.3,
                        }
                    )
        except Exception:
            pass
    return findings


@tool("Web Vulnerability Scanner")
def scan_web_vulns(recon_json: str) -> str:
    """
    Perform differential vulnerability testing for SSTI, SQLi, LFI, and XSS.

    Takes the JSON output from run_recon as input. Automatically triggered
    when HTTP/S services are detected.

    Args:
        recon_json: JSON string output from the run_recon tool.

    Returns:
        JSON string with confirmed web vulnerability findings, each with hard
        evidence receipts. Potential-only findings are excluded.
    """
    try:
        recon = json.loads(recon_json)
    except Exception:
        return json.dumps({"error": "Invalid recon_json", "findings": []})

    base_url = recon.get("base_url", "")
    endpoints = recon.get("web_endpoints", [])

    if not base_url:
        return json.dumps({"error": "No base_url in recon data", "findings": []})

    all_findings: list[dict] = []
    errors: list[str] = []

    for test_fn, name in [
        (_test_ssti, "SSTI"),
        (_test_sqli, "SQLi"),
        (_test_lfi, "LFI"),
        (_test_xss, "XSS"),
        (_check_sensitive_paths, "SensitivePaths"),
    ]:
        try:
            if name == "SensitivePaths":
                results = test_fn(base_url)
            else:
                results = test_fn(base_url, endpoints)
            all_findings.extend(results)
        except Exception as exc:
            errors.append(f"{name}: {str(exc)}")

    return json.dumps(
        {
            "target": base_url,
            "findings": all_findings,
            "total_confirmed": len(all_findings),
            "errors": errors,
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# Tool 3: lookup_cves
# ---------------------------------------------------------------------------

_NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def _query_nvd(keyword: str, api_key: str | None = None) -> list[dict]:
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    params = {"keywordSearch": keyword, "resultsPerPage": 5}
    try:
        resp = httpx.get(_NVD_API_BASE, params=params, headers=headers, timeout=20)
        if resp.status_code != 200:
            return []
        data = resp.json()
        results = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
            # Extract CVSS score (v3.1 preferred, fall back to v2)
            metrics = cve.get("metrics", {})
            cvss_score = 0.0
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                metric_list = metrics.get(key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    cvss_score = float(cvss_data.get("baseScore", 0.0))
                    break
            # Scan references for exploit, patch, and Exploit-DB links
            exploit_available = False
            exploit_db_url = None
            patch_url = None
            refs = []
            for ref in cve.get("references", []):
                url = ref.get("url", "")
                tags = [t.lower() for t in ref.get("tags", [])]
                if len(refs) < 5:
                    refs.append(url)
                if any(t in ("exploit", "third party advisory") for t in tags):
                    exploit_available = True
                if "exploit-db.com" in url.lower():
                    exploit_db_url = url
                    exploit_available = True
                if "patch" in tags or "vendor advisory" in tags:
                    patch_url = patch_url or url     # first one wins
            # Construct Exploit-DB search link as fallback
            if not exploit_db_url and cve_id:
                exploit_db_url = f"https://www.exploit-db.com/search?cve={cve_id}"
            # Extract fixed-in-version from configurations if present
            fixed_in_version = None
            for node in cve.get("configurations", []):
                for n in node.get("nodes", []):
                    for match in n.get("cpeMatch", []):
                        vend = match.get("versionEndExcluding")
                        if vend:
                            fixed_in_version = vend
                            break
                    if fixed_in_version:
                        break
                if fixed_in_version:
                    break
            results.append(
                {
                    "cve_id": cve_id,
                    "description": desc[:500],
                    "cvss_score": cvss_score,
                    "severity": _cvss_to_severity(cvss_score),
                    "exploit_available": exploit_available,
                    "exploit_db_url": exploit_db_url,
                    "patch_url": patch_url,
                    "fixed_in_version": fixed_in_version,
                    "references": refs,
                }
            )
        return results
    except Exception:
        return []


@tool("CVE Lookup")
def lookup_cves(services_json: str) -> str:
    """
    Look up known CVEs for discovered services using the NVD API v2.

    Args:
        services_json: JSON string — either the raw output from run_recon
                       or a JSON array/object of service strings, e.g.:
                       '["Flask 2.0.1", "OpenSSH 8.2p1", "nginx 1.18"]'

    Returns:
        JSON string with CVE findings per service including CVSS scores,
        severity, exploit availability, and reference links.
    """
    import os
    api_key = os.getenv("NVD_API_KEY")  # optional — raises rate limit without it

    # Accept either recon JSON or a bare services list
    try:
        data = json.loads(services_json)
    except Exception:
        return json.dumps({"error": "Invalid JSON input", "cve_findings": []})

    if isinstance(data, dict):
        services = data.get("services", [])
        # Also extract from ports
        for p in data.get("ports", []):
            svc = f"{p.get('product', '')} {p.get('version', '')}".strip()
            if svc and svc not in services:
                services.append(svc)
    elif isinstance(data, list):
        services = data
    else:
        services = [str(data)]

    if not services:
        return json.dumps({"message": "No services to look up", "cve_findings": []})

    all_cve_findings: list[dict] = []
    errors: list[str] = []

    for service in services:
        if not service.strip():
            continue
        try:
            cves = _query_nvd(service, api_key)
            for cve in cves:
                cve["service"] = service
                # Parse version from service string (e.g. "nginx 1.18.0" → "1.18.0")
                parts = service.split()
                cve["version"] = parts[-1] if len(parts) > 1 else "unknown"
                all_cve_findings.append(cve)
        except Exception as exc:
            errors.append(f"{service}: {str(exc)}")

    return json.dumps(
        {
            "services_queried": services,
            "total_cves": len(all_cve_findings),
            "cve_findings": all_cve_findings,
            "errors": errors,
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# Tool 4: check_network_misconfig
# ---------------------------------------------------------------------------

_MISCONFIG_CHECKS = {
    "redis": {
        "port": 6379,
        "probe": b"PING\r\n",
        "indicator": b"+PONG",
        "title": "Redis Unauthenticated Access",
        "description": "Redis server accepts connections without authentication. "
                       "An attacker can read/write data, execute Lua scripts, or dump the database.",
        "severity": "critical",
        "cvss_score": 9.8,
        "remediation": "Set a strong password with 'requirepass' in redis.conf and bind to 127.0.0.1.",
    },
    "ftp": {
        "port": 21,
        "probe": None,  # FTP sends banner on connect
        "indicator": b"220",
        "title": "FTP Service Exposed",
        "description": "FTP server is publicly accessible. FTP transmits credentials in cleartext.",
        "severity": "high",
        "cvss_score": 7.5,
        "remediation": "Disable FTP and use SFTP instead. If FTP is required, disable anonymous login.",
    },
    "smb": {
        "port": 445,
        "probe": None,
        "indicator": None,  # connection success = exposed
        "title": "SMB Service Exposed",
        "description": "SMB (port 445) is publicly accessible. May allow share enumeration "
                       "or exploitation of EternalBlue-class vulnerabilities.",
        "severity": "high",
        "cvss_score": 8.1,
        "remediation": "Block port 445 at the firewall. If SMB is required, enforce SMBv3 and authentication.",
    },
    "mysql": {
        "port": 3306,
        "probe": None,
        "indicator": None,
        "title": "MySQL Service Exposed",
        "description": "MySQL server is publicly accessible. May be vulnerable to brute-force "
                       "or authentication bypass attacks.",
        "severity": "high",
        "cvss_score": 7.5,
        "remediation": "Bind MySQL to 127.0.0.1 in my.cnf and use firewall rules to restrict access.",
    },
    "mongodb": {
        "port": 27017,
        "probe": None,
        "indicator": None,
        "title": "MongoDB Unauthenticated Access",
        "description": "MongoDB is publicly accessible and may lack authentication, "
                       "allowing full database read/write.",
        "severity": "critical",
        "cvss_score": 9.8,
        "remediation": "Enable authentication in mongod.conf and bind to 127.0.0.1.",
    },
    "memcached": {
        "port": 11211,
        "probe": b"stats\r\n",
        "indicator": b"STAT",
        "title": "Memcached Exposed",
        "description": "Memcached is publicly accessible without authentication. "
                       "Can be used for data exfiltration or DDoS amplification.",
        "severity": "high",
        "cvss_score": 8.6,
        "remediation": "Bind memcached to 127.0.0.1 and disable UDP (to prevent amplification).",
    },
}

# FTP anonymous login check
_FTP_ANON_USER = b"USER anonymous\r\n"
_FTP_ANON_PASS = b"PASS anonymous@\r\n"


def _check_port(host: str, port: int, probe: bytes | None, timeout: float = 5.0) -> tuple[bool, bytes]:
    """Try to connect to host:port, optionally send a probe, return (open, response_bytes)."""
    import socket as _sock
    try:
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        banner = b""
        try:
            banner = s.recv(1024)
        except _sock.timeout:
            pass
        if probe:
            s.sendall(probe)
            try:
                banner += s.recv(1024)
            except _sock.timeout:
                pass
        s.close()
        return True, banner
    except Exception:
        return False, b""


def _check_ftp_anonymous(host: str, timeout: float = 5.0) -> bool:
    """Check if FTP server allows anonymous login."""
    import socket as _sock
    try:
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, 21))
        s.recv(1024)  # banner
        s.sendall(_FTP_ANON_USER)
        resp = s.recv(1024)
        if b"331" in resp:  # 331 = password required (promising)
            s.sendall(_FTP_ANON_PASS)
            resp = s.recv(1024)
            s.close()
            return b"230" in resp  # 230 = login successful
        s.close()
    except Exception:
        pass
    return False


@tool("Network Misconfig Scanner")
def check_network_misconfig(recon_json: str) -> str:
    """
    Check for network-level misconfigurations on exposed services.

    Probes common dangerous ports (Redis, FTP, SMB, MySQL, MongoDB, Memcached)
    for unauthenticated access and insecure defaults.

    Args:
        recon_json: JSON string output from the run_recon tool.

    Returns:
        JSON string with confirmed network misconfiguration findings.
    """
    try:
        recon = json.loads(recon_json)
    except Exception:
        return json.dumps({"error": "Invalid recon_json", "findings": []})

    host = recon.get("host", "")
    if not host:
        return json.dumps({"error": "No host in recon data", "findings": []})

    # Build set of open ports from recon
    open_ports: set[int] = set()
    for p in recon.get("ports", []):
        if p.get("state") == "open":
            open_ports.add(int(p.get("port", 0)))

    findings: list[dict] = []
    errors: list[str] = []

    for svc_name, check in _MISCONFIG_CHECKS.items():
        port = check["port"]
        # Only probe if nmap found the port open, OR if nmap had an error (probe anyway)
        if port not in open_ports and not recon.get("nmap_error"):
            continue

        try:
            is_open, banner = _check_port(host, port, check["probe"])
            if not is_open:
                continue

            confirmed = False
            evidence_parts = [f"Port {port} is open on {host}."]

            if check["indicator"]:
                if check["indicator"] in banner:
                    confirmed = True
                    evidence_parts.append(
                        f"Service responded with expected indicator: {banner[:200].decode('utf-8', errors='replace')}"
                    )
            else:
                # No specific indicator — connection success alone is the finding
                confirmed = True
                if banner:
                    evidence_parts.append(
                        f"Banner: {banner[:200].decode('utf-8', errors='replace')}"
                    )

            # Extra check: FTP anonymous login
            if svc_name == "ftp" and confirmed:
                if _check_ftp_anonymous(host):
                    evidence_parts.append("Anonymous FTP login SUCCEEDED (230 response).")
                    check_title = "FTP Anonymous Login Allowed"
                    check_severity = "critical"
                    check_cvss = 9.1
                else:
                    check_title = check["title"]
                    check_severity = check["severity"]
                    check_cvss = check["cvss_score"]
            else:
                check_title = check["title"]
                check_severity = check["severity"]
                check_cvss = check["cvss_score"]

            if confirmed:
                findings.append({
                    "type": "NETWORK_MISCONFIG",
                    "title": check_title,
                    "service": svc_name,
                    "port": port,
                    "endpoint": f"{host}:{port}",
                    "method": "TCP",
                    "payload": f"Direct TCP probe to port {port}",
                    "evidence": " ".join(evidence_parts),
                    "severity": check_severity,
                    "cvss_score": check_cvss,
                    "remediation": check["remediation"],
                })
        except Exception as exc:
            errors.append(f"{svc_name}:{port}: {str(exc)}")

    return json.dumps(
        {
            "host": host,
            "findings": findings,
            "total_confirmed": len(findings),
            "ports_checked": sorted(open_ports),
            "errors": errors,
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# Person 2 Verification API — HTTP wrapper tools
# ---------------------------------------------------------------------------
# These tools call Person 2's deterministic verification endpoints via HTTP.
# The agents MUST use these instead of direct function calls — this ensures
# a true service boundary between Person 1 (AI orchestrator) and Person 2
# (deterministic scanner).
# ---------------------------------------------------------------------------

_VERIFY_API_BASE = os.getenv("VERIFY_API_BASE", "http://localhost:8000")
_VERIFY_TIMEOUT = 30  # seconds for verification API calls


def _call_verify_endpoint(route: str, target_url: str) -> str:
    """POST to a Person 2 verification endpoint and return the raw JSON response."""
    try:
        resp = httpx.post(
            f"{_VERIFY_API_BASE}{route}",
            json={"target_url": target_url},
            timeout=_VERIFY_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.text
    except Exception as exc:
        return json.dumps({
            "error": f"Verification API call to {route} failed: {exc}",
            "tool": route,
            "target": target_url,
            "findings": [],
        })


@tool("SQLi Scanner")
def verify_sqli(target_url: str) -> str:
    """
    Verify SQL injection by calling Person 2's verification API.

    POSTs the target URL to /api/verify/sqli and returns the deterministic
    ground-truth response. The response contains a 'findings' array — if empty,
    the hypothesis was a false positive.

    Args:
        target_url: The endpoint URL to verify for SQL injection.

    Returns:
        JSON string with Person 2's verification result including findings array.
    """
    return _call_verify_endpoint("/api/verify/sqli", target_url)


@tool("XSS Scanner")
def verify_xss(target_url: str) -> str:
    """
    Verify Cross-Site Scripting by calling Person 2's verification API.

    POSTs the target URL to /api/verify/xss and returns the deterministic
    ground-truth response.

    Args:
        target_url: The endpoint URL to verify for XSS.

    Returns:
        JSON string with Person 2's verification result including findings array.
    """
    return _call_verify_endpoint("/api/verify/xss", target_url)


@tool("Auth Bypass Probe")
def verify_auth_bypass(target_url: str) -> str:
    """
    Verify authentication bypass by calling Person 2's verification API.

    POSTs the target URL to /api/verify/auth-bypass and returns the deterministic
    ground-truth response.

    Args:
        target_url: The endpoint URL to verify for auth bypass.

    Returns:
        JSON string with Person 2's verification result including findings array.
    """
    return _call_verify_endpoint("/api/verify/auth-bypass", target_url)


@tool("IDOR Probe")
def verify_idor(target_url: str) -> str:
    """
    Verify Insecure Direct Object Reference by calling Person 2's verification API.

    POSTs the target URL to /api/verify/idor and returns the deterministic
    ground-truth response.

    Args:
        target_url: The endpoint URL to verify for IDOR.

    Returns:
        JSON string with Person 2's verification result including findings array.
    """
    return _call_verify_endpoint("/api/verify/idor", target_url)


@tool("SSTI Scanner")
def verify_ssti(target_url: str) -> str:
    """
    Verify Server-Side Template Injection by calling Person 2's verification API.

    POSTs the target URL to /api/verify/ssti and returns the deterministic
    ground-truth response. The response contains a 'findings' array — if empty,
    the hypothesis was a false positive.

    Args:
        target_url: The endpoint URL to verify for SSTI.

    Returns:
        JSON string with Person 2's verification result including findings array.
    """
    return _call_verify_endpoint("/api/verify/ssti", target_url)


@tool("LFI Scanner")
def verify_lfi(target_url: str) -> str:
    """
    Verify Local File Inclusion by calling Person 2's verification API.

    POSTs the target URL to /api/verify/lfi and returns the deterministic
    ground-truth response. The response contains a 'findings' array — if empty,
    the hypothesis was a false positive.

    Args:
        target_url: The endpoint URL to verify for LFI.

    Returns:
        JSON string with Person 2's verification result including findings array.
    """
    return _call_verify_endpoint("/api/verify/lfi", target_url)
