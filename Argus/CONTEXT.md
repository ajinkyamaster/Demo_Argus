# Project Argus — Full Implementation Context

> This file captures all implementation details for Person 2 (Toolsmith).
> Hand this to a new Claude session for full continuity.

---

## 1. Project Overview

**Project Argus** is a multi-agent AI pentesting tool with **4 persons**:

| Person | Role | LLM | Owns |
|--------|------|-----|------|
| **1 — Orchestrator** | Dispatches agents, verifies results | Gemini 2.5 Flash | `backend/agents/` |
| **2 — Toolsmith** | Builds all scanner/recon/intel tools | Dual: Gemini (cloud) / WhiteRabbitNeo + Foundation-Sec (local) | `backend/tools/` |
| **3 — Target Builder** | Builds the intentionally vulnerable app | N/A | `target/` |
| **4 — Documentation** | Docs and reporting | N/A | `docs/` |

Person 1's Orchestrator calls Person 2's `@tool`-decorated functions. Every tool returns:
```json
{"tool": "...", "target": "...", "vulnerable": true, "payload": "...", "findings": [...]}
```

Person 1's "Hallucination-Killer" verification loop:
```
AI hypothesis → call Person 2's @tool → read vulnerable: bool → discard if false
```

---

## 2. All 11 Tools (Person 2)

### File: `backend/tools/scanner.py` — 6 vulnerability scanners

| Tool Name (decorator) | Function | Endpoint (hardcoded) | Vuln Type |
|----------------------|----------|---------------------|-----------|
| `SQLi Scanner` | `sqli_scan_tool` | `/api/login` | SQL_INJECTION |
| `XSS Scanner` | `xss_scan_tool` | `/api/search` | XSS |
| `Auth Bypass Probe` | `auth_bypass_tool` | `/api/login` | AUTH_BYPASS |
| `IDOR Probe` | `idor_probe_tool` | `/api/users/:id` | IDOR |
| `SSTI Scanner` | `ssti_scan_tool` | `/api/search` (default) | SSTI |
| `LFI Scanner` | `lfi_scan_tool` | `/api/file` (default) | LFI |

**IMPORTANT**: The hardcoded endpoints above are defaults. Person 1's Orchestrator
should pass the correct `target_url` including the right path. The target app's
actual vulnerable endpoints are different (see Section 4).

Each tool: tries sub-crew first → falls back to deterministic httpx scan.

### File: `backend/tools/recon.py` — 3 reconnaissance tools

| Tool Name | Function | Description |
|-----------|----------|-------------|
| `Nmap Scanner` | `nmap_scan_tool` | Runs `nmap -sV -sC --open -T4`, parses into structured JSON |
| `Web Scraper` | `web_scraper_tool` | Crawls target with httpx+BeautifulSoup, discovers endpoints/forms/links. Probes ~40 common paths |
| `Subdomain Scanner` | `subdomain_scan_tool` | DNS-based enumeration with 100+ prefixes. Skips for IP/localhost |

### File: `backend/tools/intel.py` — 1 intelligence tool

| Tool Name | Function | Description |
|-----------|----------|-------------|
| `CVE Lookup` | `cve_lookup_tool` | Queries NVD API v2.0. Returns CVE IDs, CVSS scores, patches, affected versions. Supports `NVD_API_KEY` env var |

### File: `backend/tools/network.py` — 1 network tool

| Tool Name | Function | Description |
|-----------|----------|-------------|
| `Network Scanner` | `network_scan_tool` | Probes 8 service ports: Redis(6379), FTP(21), SMB(445/139), MongoDB(27017), MySQL(3306), PostgreSQL(5432), Elasticsearch(9200). Individual probe functions per service |

---

## 3. Architecture: Dual Execution Paths

### File: `backend/tools/_crew_factory.py` — Core engine

```
_resolve_llm_model() priority:
  1. SCANNER_LLM_MODEL env var (explicit override)
  2. GOOGLE_API_KEY     → gemini/gemini-2.5-flash
  3. OPENAI_API_KEY     → gpt-4.1-mini
  4. ANTHROPIC_API_KEY  → claude-sonnet-4-20250514
  5. OPENROUTER_API_KEY → openrouter/auto
  6. No key set         → Ollama local (dual-model)
```

### PRIMARY path (cloud API)

Full 3-agent Crew per iteration: **Crafter → Tester (with HTTP tool) → Analyst**.
All agents use the same cloud LLM. The Analyst's JSON verdict drives the loop.

```
_run_cloud_feedback_loop()
  └─ Crafter agent (proposes payload JSON)
  └─ Tester agent (calls http_request_tool, returns raw response)
  └─ Analyst agent (returns JSON verdict: confirmed/dead_end/try_again)
```

### LOCAL path (Ollama — dual-model)

Two specialised local models:

| Role | Model | Ollama Name | Purpose |
|------|-------|-------------|---------|
| **Crafter** | WhiteRabbitNeo 8B v2.0 | `ollama/lazarevtill/Llama-3-WhiteRabbitNeo-8B-v2.0` | Offensive payload crafting |
| **Analyst** | Foundation-Sec 8B | `ollama/hf.co/mradermacher/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M` | CVE reasoning, verdict |

Override via env vars: `LOCAL_CRAFTER_MODEL` / `LOCAL_ANALYST_MODEL`

```
_run_local_feedback_loop()
  └─ Crafter crew (WhiteRabbitNeo, seeds as fallback)
  └─ Python httpx (direct HTTP execution, no Tester agent)
  └─ _python_detect_evidence() ← AUTHORITATIVE confirmation gate
  └─ Analyst crew (Foundation-Sec, try_again as fallback)
       NOTE: Analyst CANNOT confirm vulnerabilities in local path.
       Only _python_detect_evidence() can confirm.
```

### Deterministic fallback (scanner.py level)

If the sub-crew raises any exception, scanner.py's `_deterministic_*_scan()` functions
run pure httpx probes with seed payloads. No LLM involved.

---

## 4. Target Application (Person 3)

### File: `target/app.py` — "Capsule Trust & Savings"

Flask app on port 5000 with intentional vulnerabilities:

| Vuln | Route | Method | Injection Point | Key Detail |
|------|-------|--------|-----------------|------------|
| **SQLi** | `/corp/legacy-auth` | POST (form-encoded) | `username` field | Uses f-string SQL: `f"SELECT * FROM users WHERE username = '{username}'"`. Returns `db_error` on syntax error, `CORE_BANKING_ACCESS_TOKEN` on bypass |
| **IDOR** | `/api/v1/vault/receipt/<tx_id>` | GET | Path param `tx_id` | Requires `session_user` cookie. Returns PII (SSN, salary, email) for any tx_id without ownership check |
| **XSS** | `/admin/disputes/search` | GET | Query param `merchant` | Requires `session_user` cookie. Template uses `{{ merchant \| safe }}` (escaping disabled). Injection point is `merchant` param |

**Critical notes for testing**:
- The `/login` endpoint (safe) uses parameterised queries. The SQLi is only on `/corp/legacy-auth`.
- IDOR and XSS endpoints require a valid `session_user` cookie. Login first via safe `/login` or set cookie manually.
- SQLi endpoint uses form-encoded POST (`application/x-www-form-urlencoded`), NOT JSON.
- There is NO SSTI vulnerability (f-string HTML, not `render_template_string()`).
- There is NO LFI vulnerability.

### Database: `target/database.py` → `target/capsule.db`

Tables: `users` (id, username, password, email, ssn, salary), `transactions` (tx_id, user_id, amount, recipient_account, routing_number, is_private)

---

## 5. Supporting Files

### `backend/tools/_payloads.py`

- **SEED_PAYLOADS**: Dict of seed payloads per vuln type (SQL_INJECTION, XSS, AUTH_BYPASS, IDOR, SSTI, LFI)
- **CRAFTER_PROMPT**: Cloud path crafter prompt template
- **TESTER_PROMPT**: Cloud path tester prompt template
- **ANALYST_PROMPT**: Cloud path analyst prompt template
- **IDOR_CRAFTER_PROMPT**: Cloud path IDOR crafter prompt
- **IDOR_TESTER_PROMPT**: Cloud path IDOR tester prompt
- **LOCAL_CRAFTER_PROMPT**: Local path crafter prompt (shorter, imperative — optimised for WhiteRabbitNeo)
- **LOCAL_ANALYST_PROMPT**: Local path analyst prompt (includes http_response field, CWE references — optimised for Foundation-Sec)
- **LOCAL_IDOR_CRAFTER_PROMPT**: Local path IDOR crafter prompt

### `backend/tools/_http_tool.py`

CrewAI tool `http_request_tool` with `result_as_answer=True`. Used by the Tester agent in the cloud path only.

### `backend/tools/_schemas.py`

Pydantic models: `PayloadProposal`, `ExecutionReport`, `AnalysisVerdict`.

---

### Gemini free tier rate limits (discovered during testing)
Free tier Gemini API keys are too restrictive for the 3-agent crew:
- `gemini-2.5-flash`: 5 RPM, low daily cap
- `gemini-2.0-flash`: 15 RPM but very low daily cap
- Each iteration = 3+ API calls (Crafter + Tester + Analyst + CrewAI internals)
- 5 iterations = 15+ calls → burns through free tier quota immediately

**Solutions**:
- Use a paid Gemini plan (removes limits)
- Use OpenAI/Anthropic/OpenRouter instead
- Use the local dual-model path (slow but unlimited)
- Add retry-with-backoff for 429 errors in `_run_cloud_feedback_loop()`

### SQLi endpoint content type mismatch
The target `/corp/legacy-auth` expects `application/x-www-form-urlencoded` POST.
The `_execute_http()` function sends `application/json`. The cloud path's Tester
agent uses `http_request_tool` which also sends JSON. Both need form-encoding support.

---

## 6. Key Code Patterns

### JSON extraction (`_crew_factory.py:127`)

```python
def _extract_json(text: str) -> dict | None:
    # Tier 1: json.loads(raw) — if LLM outputs pure JSON
    # Tier 2: regex for ```json...``` markdown fences
    # Tier 3: find first balanced {…} brace block in free text
    # Returns None if all fail → triggers seed fallback
```

### Python evidence detector (`_crew_factory.py:224`)

String-matching function that confirms exploitation from raw HTTP responses:
- **SQL_INJECTION/AUTH_BYPASS**: db errors (sqlite3.OperationalError, syntax error), or HTTP 200 + token
- **XSS**: payload reflected unescaped in body, or `<script` + `alert` present
- **IDOR**: HTTP 200 with username/email in body without auth
- **SSTI**: math result (50337) present WITHOUT raw expression (7*7191), or config/class leaks
- **LFI**: /etc/passwd markers, Windows file markers, base64-encoded content

### Seed cycling fix

```python
seed = seeds[(iteration - 1) % len(seeds)]  # iteration 1 → index 0
```

### Result format for Person 1

```python
def _make_result(tool_name, target, findings):
    real_findings = [f for f in findings if "error" not in f]
    return json.dumps({
        "tool": tool_name, "target": target,
        "vulnerable": len(real_findings) > 0,
        "payload": real_findings[0].get("payload") if real_findings else None,
        "findings": findings,
    })
```

---

## 7. Environment Setup

```bash
# Virtual environment
cd /home/fivetimesfourteen/Argus
source .venv/bin/activate

# Required packages (already installed)
pip install crewai crewai[google-genai] httpx beautifulsoup4

# Ollama models (already pulled)
# ollama pull lazarevtill/Llama-3-WhiteRabbitNeo-8B-v2.0
# ollama pull hf.co/mradermacher/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M

# Start target app
cd target && python app.py  # runs on :5000

# API key priority for cloud path
export GOOGLE_API_KEY="..."       # → gemini/gemini-2.5-flash (primary)
# OR
export OPENAI_API_KEY="..."       # → gpt-4.1-mini
# OR
export ANTHROPIC_API_KEY="..."    # → claude-sonnet-4-20250514
# OR unset all → local Ollama dual-model
```

---

## 8. Known Issues & Pending Work

### Endpoint mismatch
The scanner tools in `scanner.py` hardcode endpoints (`/api/login`, `/api/search`, `/api/users/:id`) that don't match the target app's actual routes (`/corp/legacy-auth`, `/admin/disputes/search?merchant=`, `/api/v1/vault/receipt/<tx_id>`). Person 1 must pass the correct `target_url` including the right endpoint path.

### Target auth requirements
IDOR (`/api/v1/vault/receipt/<tx_id>`) and XSS (`/admin/disputes/search`) endpoints require a `session_user` cookie. The scanner tools don't currently handle cookie-based auth. The `_execute_http()` function and `http_request_tool` need cookie support added.

### XSS injection point
The XSS param is `merchant` (not `q`). The scanner defaults to `q` as injection point. Person 1 should pass the right target URL + param.

### SQLi content type
Target expects form-encoded POST, but `_execute_http()` sends JSON. This needs a content-type toggle for form-encoded endpoints.

### Gemini cloud path
`crewai[google-genai]` has been installed. Gemini 2.5 Flash cloud path test was initiated but result pending at time of context export.

### Local model speed
Local 8B models take ~120s per iteration (5 iterations = ~600s per scan). Acceptable for fallback but not primary use.

### Not tested
- Nmap tool (requires nmap binary installed)
- SSTI/LFI against actually vulnerable targets (the demo app has neither)
- Full Person 1 ↔ Person 2 integration test

---

## 9. File Tree

```
backend/tools/
├── __init__.py
├── scanner.py          # 6 vuln scanner @tool functions
├── recon.py            # 3 recon @tool functions (nmap, web scraper, subdomain)
├── intel.py            # 1 CVE lookup @tool function
├── network.py          # 1 network scanner @tool function
├── _crew_factory.py    # Core: dual-path engine, sub-crew loops, evidence detector
├── _http_tool.py       # HTTP executor tool for cloud Tester agent
├── _payloads.py        # Seed payloads + all prompt templates
└── _schemas.py         # Pydantic models (PayloadProposal, AnalysisVerdict, etc.)

target/
├── app.py              # Flask app — 3 vulns (SQLi, IDOR, XSS)
├── database.py         # SQLite init + seed data
├── capsule.db          # Runtime database
├── requirements.txt
└── templates/
    ├── index.html
    ├── login.html
    ├── dashboard.html
    ├── legacy_auth.html
    └── disputes.html
```

---

## 10. Gemini API Keys (for testing only — rotate after use)

```
GOOGLE_API_KEY=AIzaSyBZuRQ-fWf-GohaWFeZImcEBEUoDXO7mhA
# backup: AIzaSyAsapN-mYnc6SS2rPRqhK77K_fLvbhV9-k
```

**Rotate these keys immediately after testing is complete.**
