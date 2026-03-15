import type { ScanResult } from '../types';

export const SCAN_RESULT: ScanResult = {
  scan_id: "a3f8c2d1-9e4b-4a2f-b8d7-1c5e9f3a7b2e",
  target: "https://demo.acme-corp.com",
  timestamp: "2024-01-15T14:22:35Z",
  status: "complete",
  summary: {
    total_findings: 7,
    critical_count: 2,
    high_count: 2,
    medium_count: 2,
    low_count: 1,
    scan_duration: "00:32",
    max_cvss: 9.8,
  },
  vulnerabilities: [
    {
      id: "vuln-001",
      title: "Server-Side Template Injection via Search Parameter",
      severity: "CRITICAL",
      cvss_score: 9.8,
      cve_ids: ["CVE-2024-3094"],
      affected_component: "/search?q=",
      description:
        "Jinja2 template engine renders user input directly. Payload {{7*7}} returns 49.",
      patch_code: {
        vulnerable_snippet:
          "return render_template_string(f'Results for: {query}')",
        fixed_snippet:
          "return render_template_string('Results for: {{ query }}', query=query)",
        language: "python",
        file_path: "app/routes/search.py",
      },
    },
    {
      id: "vuln-002",
      title: "SQL Injection in User Authentication Endpoint",
      severity: "CRITICAL",
      cvss_score: 9.1,
      cve_ids: ["CVE-2024-1337"],
      affected_component: "/api/auth/login",
      description:
        "Unsanitized user input concatenated directly into SQL query. Full DB dump possible.",
      patch_code: {
        vulnerable_snippet:
          'query = f"SELECT * FROM users WHERE email=\'{email}\' AND pass=\'{pwd}\'"',
        fixed_snippet:
          'query = "SELECT * FROM users WHERE email=? AND password=?"\ncursor.execute(query, (email, pwd))',
        language: "python",
        file_path: "app/routes/auth.py",
      },
    },
    {
      id: "vuln-003",
      title: "Cross-Site Request Forgery on Password Reset",
      severity: "HIGH",
      cvss_score: 8.1,
      cve_ids: [],
      affected_component: "/account/reset-password",
      description:
        "Password reset form lacks CSRF token. Attacker can trigger reset for any account.",
      patch_code: null,
    },
    {
      id: "vuln-004",
      title: "Exposed Admin Panel Without Authentication",
      severity: "HIGH",
      cvss_score: 7.5,
      cve_ids: [],
      affected_component: "/admin",
      description:
        "Admin panel accessible without credentials from public internet. No rate limiting.",
      patch_code: null,
    },
    {
      id: "vuln-005",
      title: "Outdated jQuery 1.9.1 with Known XSS Vectors",
      severity: "MEDIUM",
      cvss_score: 6.1,
      cve_ids: ["CVE-2019-11358"],
      affected_component: "CDN: jquery-1.9.1.min.js",
      description:
        "jQuery version 1.9.1 contains prototype pollution vulnerability.",
      patch_code: null,
    },
    {
      id: "vuln-006",
      title: "Missing HTTP Security Headers",
      severity: "MEDIUM",
      cvss_score: 5.3,
      cve_ids: [],
      affected_component: "Global HTTP responses",
      description:
        "X-Frame-Options, CSP, and HSTS headers absent. Enables clickjacking.",
      patch_code: null,
    },
    {
      id: "vuln-007",
      title: "Directory Listing Enabled on /static/",
      severity: "LOW",
      cvss_score: 3.1,
      cve_ids: [],
      affected_component: "/static/",
      description:
        "Web server lists directory contents. Internal file structure exposed.",
      patch_code: null,
    },
  ],
  agent_logs: [
    // ── Batch 0: Recon phase (indices 0-3) ──
    {
      agent: "Master",
      message: "PRIORITY ALPHA. All units stand by. Commencing full reconnaissance of target demo.acme-corp.com. Recon, you have point.",
      timestamp: "14:22:35",
    },
    {
      agent: "Recon",
      message: "Copy, Master. Deploying port sweep across all 65535 ports. Simultaneous subdomain enumeration running against DNS records.",
      timestamp: "14:22:36",
    },
    {
      agent: "Recon",
      message: "Contact. Ports 80, 443, 8080, 5432 responding. That 5432 is PostgreSQL — wide open, no firewall. Found 3 subdomains: api., staging., admin.",
      timestamp: "14:22:38",
    },
    {
      agent: "Recon",
      message: "Tech fingerprint complete. Target running Python/Flask 2.1 behind Nginx 1.18. Database is PostgreSQL 13.2. Handing off target map to Web Exploiter and Net Exploiter.",
      timestamp: "14:22:41",
    },
    // ── Batch 1: Web Exploiter phase (indices 4-8) ──
    {
      agent: "Master",
      message: "Good work, Recon. Web Exploiter — that /search endpoint looks soft. Hit it first. Net Exploiter — that exposed Postgres needs immediate attention.",
      timestamp: "14:22:42",
    },
    {
      agent: "Web Exploiter",
      message: "Roger. Loading injection payloads — SSTI, SQLi, XSS, LFI vectors queued. Starting with the search parameter. Sending {{7*7}} probe...",
      timestamp: "14:22:45",
    },
    {
      agent: "Web Exploiter",
      message: "We have a hit. Response body contains '49' — Jinja2 template engine is processing raw input. This is Server-Side Template Injection. Full RCE possible. This is bad.",
      timestamp: "14:22:49",
    },
    {
      agent: "Web Exploiter",
      message: "Moving to auth endpoints. Sending union-based payload to /api/auth/login... email parameter is injectable. I can dump the entire users table from here.",
      timestamp: "14:22:52",
    },
    {
      agent: "Web Exploiter",
      message: "Also found: /account/reset-password has no CSRF token, and /admin panel is publicly accessible with zero auth. These people are running naked out here.",
      timestamp: "14:22:54",
    },
    // ── Batch 2: Net Exploiter phase (indices 9-11) ──
    {
      agent: "Net Exploiter",
      message: "Copy that. Running nmap service scan on port 5432. Banner grab says PostgreSQL 13.2 — no ACL, no SSL, accepting connections from 0.0.0.0.",
      timestamp: "14:22:56",
    },
    {
      agent: "Net Exploiter",
      message: "Web Exploiter, heads up — if you chain that SQLi with this exposed DB port, an attacker could pivot from web to direct database access. Two entry points to the same crown jewels.",
      timestamp: "14:22:58",
    },
    {
      agent: "Web Exploiter",
      message: "Confirmed. The Flask app has DATABASE_URL in its environment config. SSTI → read env → get DB creds → direct Postgres connection. Game over for this target.",
      timestamp: "14:23:00",
    },
    // ── Batch 3: CVE Engine phase (indices 12-15) ──
    {
      agent: "Master",
      message: "CVE Engine — cross-reference everything they found. I need CVE IDs and CVSS scores for the report.",
      timestamp: "14:23:01",
    },
    {
      agent: "CVE Engine",
      message: "On it. Querying NVD database... The SSTI vulnerability maps to CVE-2024-3094. CVSS 9.8 CRITICAL. Public proof-of-concept exploit exists on GitHub. This is actively exploited in the wild.",
      timestamp: "14:23:03",
    },
    {
      agent: "CVE Engine",
      message: "Also flagging: target loads jQuery 1.9.1 from CDN. That maps to CVE-2019-11358 — prototype pollution, CVSS 6.1. And the missing security headers enable CVE-2022-31629 clickjacking vectors.",
      timestamp: "14:23:05",
    },
    {
      agent: "CVE Engine",
      message: "Score card: 2 CRITICAL (9.8, 9.1), 2 HIGH (8.1, 7.5), 2 MEDIUM (6.1, 5.3), 1 LOW (3.1). Max CVSS is 9.8. Recommending immediate remediation for the top two.",
      timestamp: "14:23:07",
    },
    // ── Batch 4: Chainer phase (indices 16-18) ──
    {
      agent: "Chainer",
      message: "Running chain_engine against all findings. Building attack graph from 7 nodes...",
      timestamp: "14:23:08",
    },
    {
      agent: "Chainer",
      message: "Found viable kill chain: SSTI on /search → RCE via Jinja2 sandbox escape → read Flask config → extract DATABASE_URL → pivot to PostgreSQL on :5432 → full database dump. 5-step chain, zero authentication required.",
      timestamp: "14:23:10",
    },
    {
      agent: "Chainer",
      message: "Secondary chain: SQLi on /api/auth/login → credential dump → admin panel access via /admin (no auth anyway, but stolen creds enable deeper persistence). Master, these chains are catastrophic.",
      timestamp: "14:23:12",
    },
    // ── Batch 5: Report phase (indices 19-22) ──
    {
      agent: "Master",
      message: "Understood. Report — generate patches for the two criticals immediately. Include the attack chains in the executive summary. This client needs to act today.",
      timestamp: "14:23:13",
    },
    {
      agent: "Report",
      message: "Generating remediation for SSTI: replacing render_template_string(f-string) with parameterized template rendering. Sandboxed Jinja2 environment recommended.",
      timestamp: "14:23:15",
    },
    {
      agent: "Report",
      message: "SQLi patch ready: converting string concatenation to parameterized queries with cursor.execute(). Also recommending ORM migration to SQLAlchemy to prevent future injection vectors.",
      timestamp: "14:23:17",
    },
    {
      agent: "Master",
      message: "All units, stand down. Scan complete. 7 findings catalogued, 2 critical patches generated, 2 attack chains documented. Anchoring full report hash to blockchain. Mission accomplished.",
      timestamp: "14:23:19",
    },
  ],
  blockchain: {
    tx_hash:
      "0x8f3a2c9d1e4b7a0f2c6d8e1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d2e4f6a8b9",
    block_number: 18847293,
    timestamp: "2024-01-15T14:23:07Z",
    report_hash:
      "sha256:a3f8c2d1e4b5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
  },
};
