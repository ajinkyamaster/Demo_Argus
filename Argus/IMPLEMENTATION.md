# IMPLEMENTATION.md — Project Argus Technical Guide

> **This document is the single source of truth for the data contract.**
> Person 1 (Backend) and Person 4 (Frontend) must implement exactly these schemas.
> Do not negotiate over field names mid-hackathon.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│  Browser (localhost:3000)                                       │
│  /frontend  ── Next.js + Tailwind CSS + Shadcn UI              │
└──────────────────────┬──────────────────────────────────────────┘
                       │  POST /api/scan  (JSON body)
                       │  ◄── ScanReport (JSON)
┌──────────────────────▼──────────────────────────────────────────┐
│  FastAPI + CrewAI  (localhost:8000)                             │
│  /backend/main1.py  ──  /backend/agents/crew1.py                │
│                     ──  /backend/tools/scanner1.py               │
└──────────────────────┬──────────────────────────────────────────┘
                       │  HTTP probes + Firecrawl
┌──────────────────────▼──────────────────────────────────────────┐
│  Vulnerable Flask App  (localhost:5000)                        │
│  /target/app.py                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Rules:**
- All data transfer is **strict JSON**. No form data. No URL query parameters for inputs.
- The frontend sends exactly one request: `POST /api/scan`.
- The backend returns exactly one response: the `ScanReport` object.
- Agents decide autonomously what to test. The frontend does not direct the scan.

---

## Division of Labour

| Person | Owns | Never touches |
|--------|------|---------------|
| 1 — Backend Orchestrator | `/backend/agents/`, `/backend/main1.py`, `/backend/models1.py` | Everything else |
| 2 — Toolsmith | `/backend/tools/` | Everything else |
| 3 — Target Architect | `/target/` | Everything else |
| 4 — Frontend Illusionist | `/frontend/` | Everything else |

### Agent Responsibilities

The backend runs exactly three agents. There are no others. Do not invent new ones.

| Agent | Role | Primary Tool |
|-------|------|--------------|
| `ReconAgent` | Maps the full attack surface of the target. Discovers all endpoints, parameters, forms, and authentication boundaries. | Firecrawl |
| `ExploitationAgent` | Receives the attack surface from `ReconAgent` and fires payloads against every viable vector. Owns all Python exploit tools in `/backend/tools/`. | Custom scanner tools |
| `ReportingAgent` | Receives raw findings from `ExploitationAgent` and synthesises them into the final `ScanReport` JSON. Does not perform any probing. | None - synthesis only |

---

## API Endpoint

```
POST http://localhost:8000/api/scan
Content-Type: application/json
```

---

## Request Schema — `ScanRequest`

This is the exact JSON body the frontend must POST. The frontend's only job is to provide a target. It does not instruct the agents on what to scan, which modules to run, or what mode to use. That is the crew's decision.

```json
{
  "target_url": "http://localhost:5000",
  "options": {
    "timeout": 30,
    "verbose": false
  }
}
```

### Field Reference

| Field | Type | Required | Values / Constraints |
|-------|------|----------|----------------------|
| `target_url` | `string` | YES | Base URL of the target. Must be `http://localhost:5000` for the local target. |
| `options.timeout` | `integer` | NO | Default `30`. Range: `5–120`. Seconds per agent action. |
| `options.verbose` | `boolean` | NO | Default `false`. Set `true` to populate full agent logs. |

**Deleted fields:** `scan_mode` and `modules` have been intentionally removed. They do not exist. If you find them in old code, delete them.

---

## Response Schema — `ScanReport`

This is the exact JSON object the backend will return and the frontend must render.

```json
{
  "scan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "timestamp": "2026-03-14T12:00:00.000Z",
  "target": "http://localhost:5000",
  "status": "complete",
  "summary": {
    "total_vulnerabilities": 2,
    "critical": 1,
    "high": 1,
    "medium": 0,
    "low": 0,
    "info": 0
  },
  "vulnerabilities": [
    {
      "id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
      "type": "SQL_INJECTION",
      "severity": "critical",
      "title": "SQL Injection in /api/login",
      "description": "The 'username' parameter is interpolated directly into a raw SQL query without sanitisation.",
      "endpoint": "/api/login",
      "method": "POST",
      "payload": "' OR '1'='1",
      "evidence": "Raw database error returned: 'sqlite3.OperationalError: near \"OR\": syntax error' followed by HTTP 200 with admin JWT on second attempt with valid bypass string.",
      "remediation": "Replace raw string interpolation with parameterised queries.",
      "cvss_score": 9.8,
      "agent": "ExploitationAgent"
    },
    {
      "id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
      "type": "IDOR",
      "severity": "high",
      "title": "Insecure Direct Object Reference on /api/users/:id",
      "description": "Endpoint returns any user record without verifying that the requesting user is the owner.",
      "endpoint": "/api/users/2",
      "method": "GET",
      "payload": null,
      "evidence": "Authenticated as user ID 1 (token: eyJ...). GET /api/users/2 returned full record: {\"id\": 2, \"username\": \"bob\", \"email\": \"bob@example.com\", \"password_hash\": \"...\"}. No 403 issued.",
      "remediation": "Add server-side ownership validation before returning any record.",
      "cvss_score": 7.5,
      "agent": "ExploitationAgent"
    }
  ],
  "agent_logs": [
    {
      "agent": "ReconAgent",
      "timestamp": "2026-03-14T12:00:00.500Z",
      "action": "Firecrawl surface mapping",
      "result": "Discovered 4 endpoints: /api/login (POST, params: username, password), /api/users/:id (GET, auth required), /api/search (GET, params: q), /api/characters (GET)"
    },
    {
      "agent": "ReconAgent",
      "timestamp": "2026-03-14T12:00:02.100Z",
      "action": "Parameter analysis",
      "result": "Identified 3 injectable parameters: username at /api/login, q at /api/search, id at /api/users/:id"
    },
    {
      "agent": "ExploitationAgent",
      "timestamp": "2026-03-14T12:00:03.800Z",
      "action": "SQLi probe on /api/login:username",
      "result": "Payload \\\"' OR '1'='1\\\" triggered sqlite3.OperationalError. Confirmed exploitable."
    },
    {
      "agent": "ExploitationAgent",
      "timestamp": "2026-03-14T12:00:05.400Z",
      "action": "IDOR probe on /api/users/:id",
      "result": "Cross-user record retrieval confirmed. User ID 1 token returned full PII for user ID 2 with HTTP 200."
    },
    {
      "agent": "ReportingAgent",
      "timestamp": "2026-03-14T12:00:06.100Z",
      "action": "Report synthesis",
      "result": "Compiled 2 confirmed vulnerabilities into final ScanReport. 0 unconfirmed findings dropped."
    }
  ]
}
```

### `ScanReport` Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `scan_id` | `string` (UUID4) | Unique identifier for this scan run. |
| `timestamp` | `string` (ISO 8601 UTC) | When the scan completed. |
| `target` | `string` | The URL that was scanned. |
| `status` | `string` | `"complete"` · `"running"` · `"failed"` |
| `summary` | `object` | Aggregated counts by severity. |
| `vulnerabilities` | `Vulnerability[]` | Ordered by `cvss_score` descending. |
| `agent_logs` | `AgentLog[]` | Chronological agent activity trace. |

### `Vulnerability` Field Reference

| Field | Type | Nullable | Description |
|-------|------|----------|-------------|
| `id` | `string` (UUID4) | No | Unique finding identifier. |
| `type` | `string` | No | Canonical type: `SQL_INJECTION`, `XSS`, `IDOR`, `AUTH_BYPASS`, `CSRF`, `PATH_TRAVERSAL` |
| `severity` | `string` | No | `critical` · `high` · `medium` · `low` · `info` |
| `title` | `string` | No | Short, human-readable title. |
| `description` | `string` | No | Full technical description. |
| `endpoint` | `string` | No | The vulnerable path, e.g. `/api/login`. |
| `method` | `string` | No | HTTP method: `GET`, `POST`, etc. |
| `payload` | `string` | Yes | The exploit payload used, or `null` if not applicable. |
| `evidence` | `string` | **NO. THIS FIELD IS NEVER NULL.** | See the Evidence Contract below. |
| `remediation` | `string` | No | Concrete fix recommendation. |
| `cvss_score` | `float` | No | CVSS v3 base score. Range: `0.0–10.0`. |
| `agent` | `string` | No | Always `"ExploitationAgent"`. There is no other agent that finds vulnerabilities. |

### The Evidence Contract

This rule has no exceptions. Read it once and implement it correctly.

The `ExploitationAgent` **must** populate `evidence` with one of the following before a finding is recorded:

- A raw server error string (e.g., a database exception, a stack trace, a verbose error page snippet)
- A verbatim snippet of data that should not be accessible (e.g., another user's PII record, a file read via path traversal, a deserialized object)
- A concrete, unreproducible-by-chance HTTP response differential that proves the injection worked (e.g., "200 returned only when payload is applied, 401 returned for all benign inputs")

**If the `ExploitationAgent` cannot provide one of the above, the finding is a false positive. Drop it. Do not include it in the `vulnerabilities` array. Do not include it as a low-confidence finding. Do not add a disclaimer. Drop it.**

A generic statement like "the endpoint may be vulnerable" or "response time was slightly elevated" does not qualify as evidence. Hunches are not findings. This is a Red Team, not a risk register.

---

## Running the Stack

### 1. Target (Person 3)
```bash
cd target
pip install -r requirements.txt
python app.py
# Listening on http://localhost:5000
```

### 2. Backend (Person 1 & 2)
```bash
cd backend
pip install -r requirements.txt
uvicorn backend.main1:app --reload --port 8000
# Listening on http://localhost:8000
```

### 3. Frontend (Person 4)
```bash
cd frontend
npm install
npm run dev
# Listening on http://localhost:3000
```

---

## Stub Data for Frontend Development

`/frontend/app/page.tsx` ships with a `STUB_REPORT` constant and a **"Use stub data"** checkbox.
**Person 4: check that box and build the entire UI before the backend is ready.**
Swap it off when Person 1 merges a working `/api/scan` endpoint.

The stub data in your frontend must match the schema above exactly: `agent` set to `"ExploitationAgent"`, no `scan_mode`, no `modules`, and a non-null `evidence` string on every finding.

---

## Severity — CVSS Mapping Convention

| Severity | CVSS Range |
|----------|------------|
| Critical | 9.0 – 10.0 |
| High | 7.0 – 8.9 |
| Medium | 4.0 – 6.9 |
| Low | 0.1 – 3.9 |
| Info | 0.0 |
