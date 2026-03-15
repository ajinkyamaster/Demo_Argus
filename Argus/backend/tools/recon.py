"""
Reconnaissance tools — Person 2 (Toolsmith).

Provides deterministic recon capabilities for Person 1's Recon Scout agent:
  - nmap_scan_tool   — service/version discovery via nmap
  - web_scraper_tool — endpoint & input-field mapping via httpx + BeautifulSoup
  - subdomain_scan_tool — wordlist-based subdomain enumeration via DNS
"""

import json
import re
import socket
import subprocess
import uuid
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from crewai.tools import tool

TIMEOUT = 10.0


def _make_result(tool_name: str, target: str, data: Any) -> str:
    """Serialize recon output to standard JSON envelope."""
    return json.dumps({
        "tool": tool_name,
        "target": target,
        "data": data,
    })


# ── Tool 1 — Nmap Service Discovery ──────────────────────────────────────────


@tool("Nmap Scanner")
def nmap_scan_tool(target_url: str) -> str:
    """
    Run nmap service/version scan against the target host.

    Executes ``nmap -sV -sC`` on the target, parses the output, and returns
    a structured JSON map of open ports, services, versions, and script
    results.  Requires nmap to be installed on the system.
    """
    parsed = urlparse(target_url if "://" in target_url else f"http://{target_url}")
    host = parsed.hostname or target_url
    port = parsed.port

    try:
        # Build nmap command
        cmd = ["nmap", "-sV", "-sC", "--open", "-T4"]
        if port:
            cmd.extend(["-p", str(port)])
        else:
            cmd.extend(["-p", "1-1024,3000,3306,5000,5432,6379,8000,8080,8443,27017"])
        cmd.append(host)

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )

        raw_output = result.stdout
        services = _parse_nmap_output(raw_output)

        return _make_result("nmap_scan", target_url, {
            "host": host,
            "services": services,
            "raw_output": raw_output[:3000],
        })

    except FileNotFoundError:
        return _make_result("nmap_scan", target_url, {
            "error": "nmap is not installed. Install with: sudo apt install nmap",
            "host": host,
            "services": [],
        })
    except subprocess.TimeoutExpired:
        return _make_result("nmap_scan", target_url, {
            "error": "nmap scan timed out after 120 seconds",
            "host": host,
            "services": [],
        })
    except Exception as exc:
        return _make_result("nmap_scan", target_url, {
            "error": str(exc),
            "host": host,
            "services": [],
        })


def _parse_nmap_output(raw: str) -> list[dict]:
    """Parse nmap text output into structured service dicts."""
    services = []
    # Match lines like: 5000/tcp open  http    Werkzeug httpd 3.0.1 (Python 3.12.3)
    port_re = re.compile(
        r"(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)\s*(.*)"
    )
    for line in raw.splitlines():
        m = port_re.match(line.strip())
        if m:
            port_num, proto, state, service, version = m.groups()
            services.append({
                "port": int(port_num),
                "protocol": proto,
                "state": state,
                "service": service,
                "version": version.strip() or None,
            })
    return services


# ── Tool 2 — Web Endpoint Scraper ────────────────────────────────────────────


@tool("Web Scraper")
def web_scraper_tool(target_url: str) -> str:
    """
    Crawl the target website to discover endpoints, forms, and input fields.

    Uses httpx to fetch pages and BeautifulSoup to parse HTML structure.
    Returns a structured JSON map of discovered endpoints categorised by
    function (Auth, Search, File Handling, API, etc.), including forms,
    input fields, and link targets.
    """
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        return _make_result("web_scraper", target_url, {
            "error": "beautifulsoup4 not installed. Run: pip install beautifulsoup4",
        })

    base = target_url.rstrip("/")
    parsed_base = urlparse(base)
    visited: set[str] = set()
    endpoints: list[dict] = []
    forms: list[dict] = []
    links_to_visit: list[str] = [base]

    # Common paths to probe
    common_paths = [
        "/", "/login", "/register", "/signup", "/admin", "/dashboard",
        "/search", "/api", "/api/login", "/api/users", "/api/search",
        "/api/v1", "/api/v2", "/upload", "/file", "/download",
        "/profile", "/settings", "/robots.txt", "/sitemap.xml",
        "/.env", "/config", "/api/config",
        # Legacy / corporate paths
        "/corp", "/legacy", "/portal",
        # Admin sub-paths
        "/admin/disputes", "/admin/disputes/search",
        "/admin/users", "/admin/settings",
        # API versioned paths
        "/api/v1/users", "/api/v1/vault",
        # Auth variants
        "/auth", "/sso", "/oauth", "/logout",
        # Common framework paths
        "/swagger", "/openapi.json", "/docs", "/health", "/status",
        "/.git/config", "/debug", "/trace",
    ]
    for path in common_paths:
        links_to_visit.append(f"{base}{path}")

    try:
        client = httpx.Client(timeout=TIMEOUT, follow_redirects=True)

        for url in links_to_visit:
            # Normalise: strip trailing slash for dedup (except bare domain)
            norm = url.rstrip("/") if url.rstrip("/") else url
            if norm in visited:
                continue
            visited.add(norm)

            try:
                resp = client.get(url)
            except httpx.HTTPError:
                continue

            path = urlparse(url).path or "/"
            endpoint_info: dict = {
                "url": url,
                "path": path,
                "status_code": resp.status_code,
                "content_type": resp.headers.get("content-type", ""),
                "category": _categorise_endpoint(path, resp),
            }

            # Parse HTML for forms and links
            if "text/html" in resp.headers.get("content-type", ""):
                soup = BeautifulSoup(resp.text, "html.parser")

                # Extract forms
                for form in soup.find_all("form"):
                    form_data = {
                        "action": form.get("action", ""),
                        "method": (form.get("method") or "GET").upper(),
                        "page": path,
                        "inputs": [],
                    }
                    for inp in form.find_all(["input", "textarea", "select"]):
                        form_data["inputs"].append({
                            "name": inp.get("name", ""),
                            "type": inp.get("type", "text"),
                            "id": inp.get("id", ""),
                        })
                    forms.append(form_data)

                # Extract links for further crawling
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"]
                    full_url = urljoin(url, href)
                    full_norm = full_url.rstrip("/") if full_url.rstrip("/") else full_url
                    if urlparse(full_url).hostname == parsed_base.hostname:
                        if full_norm not in visited and len(visited) < 100:
                            links_to_visit.append(full_url)

            endpoints.append(endpoint_info)

        client.close()

        # Build categorised summary
        categories: dict[str, list] = {}
        for ep in endpoints:
            cat = ep.get("category", "Other")
            categories.setdefault(cat, []).append({
                "path": ep["path"],
                "status": ep["status_code"],
                "content_type": ep["content_type"],
            })

        return _make_result("web_scraper", target_url, {
            "endpoints_discovered": len(endpoints),
            "forms_discovered": len(forms),
            "categories": categories,
            "forms": forms,
            "all_endpoints": [
                {"path": ep["path"], "status": ep["status_code"], "category": ep["category"]}
                for ep in endpoints
            ],
        })

    except Exception as exc:
        return _make_result("web_scraper", target_url, {
            "error": f"Scraping failed: {exc}",
        })


def _categorise_endpoint(path: str, resp: httpx.Response) -> str:
    """Assign a functional category to an endpoint path."""
    p = path.lower()
    if any(kw in p for kw in ("/login", "/auth", "/signin", "/signup", "/register",
                               "-auth", "legacy-auth", "/sso", "/oauth")):
        return "Auth"
    if any(kw in p for kw in ("/search", "/find", "/query", "/dispute")):
        return "Search"
    if any(kw in p for kw in ("/upload", "/file", "/download", "/media", "/asset",
                               "/export", "/import")):
        return "File Handling"
    if any(kw in p for kw in ("/admin", "/dashboard", "/manage", "/panel",
                               "/console")):
        return "Admin"
    if any(kw in p for kw in ("/user", "/profile", "/account", "/settings",
                               "/receipt", "/vault")):
        return "User Management"
    if "/api" in p:
        return "API"
    if any(kw in p for kw in ("/robots.txt", "/sitemap", "/.env", "/config",
                               "/.git", "/swagger", "/openapi")):
        return "Configuration / Meta"
    return "Other"


# ── Tool 3 — Subdomain Discovery ─────────────────────────────────────────────


# Common subdomains wordlist (compact but effective)
_SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "dns", "api", "dev", "staging", "test", "beta", "admin", "portal", "vpn",
    "remote", "server", "cloud", "app", "web", "blog", "shop", "store",
    "cdn", "static", "media", "assets", "img", "images", "files",
    "docs", "help", "support", "status", "monitor", "grafana", "kibana",
    "jenkins", "ci", "git", "gitlab", "bitbucket", "jira", "confluence",
    "wiki", "forum", "community", "internal", "intranet", "proxy",
    "gateway", "lb", "load", "backup", "db", "database", "mysql", "postgres",
    "redis", "mongo", "elastic", "elasticsearch", "rabbitmq", "kafka",
    "mq", "queue", "worker", "cron", "scheduler", "auth", "sso", "oauth",
    "login", "id", "identity", "accounts", "payments", "billing",
    "dashboard", "panel", "console", "management", "uat", "qa", "sandbox",
    "demo", "preview", "secure", "ssl", "vpn2", "mx", "mx1", "mx2",
    "ns3", "ns4", "dns1", "dns2", "api2", "api-v2", "v1", "v2",
    "m", "mobile", "search", "analytics", "tracking", "log", "logs",
]


@tool("Subdomain Scanner")
def subdomain_scan_tool(target_url: str) -> str:
    """
    Perform wordlist-based subdomain enumeration on the target domain.

    Resolves common subdomain prefixes against the target domain via DNS
    to discover additional attack surface.  Returns a list of discovered
    subdomains with their resolved IP addresses.
    """
    parsed = urlparse(target_url if "://" in target_url else f"http://{target_url}")
    domain = parsed.hostname or target_url

    # Skip subdomain enumeration for IPs and localhost
    if _is_ip(domain) or domain in ("localhost", "127.0.0.1", "::1"):
        return _make_result("subdomain_scan", target_url, {
            "domain": domain,
            "note": "Subdomain enumeration skipped for IP/localhost targets",
            "discovered": [],
        })

    discovered: list[dict] = []

    for prefix in _SUBDOMAIN_WORDLIST:
        fqdn = f"{prefix}.{domain}"
        try:
            ips = socket.getaddrinfo(fqdn, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            resolved_ips = list({addr[4][0] for addr in ips})
            if resolved_ips:
                discovered.append({
                    "subdomain": fqdn,
                    "ips": resolved_ips,
                })
        except (socket.gaierror, socket.herror, OSError):
            continue

    return _make_result("subdomain_scan", target_url, {
        "domain": domain,
        "wordlist_size": len(_SUBDOMAIN_WORDLIST),
        "discovered_count": len(discovered),
        "discovered": discovered,
    })


def _is_ip(host: str) -> bool:
    """Check if a host string is an IP address."""
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except OSError:
        return False
