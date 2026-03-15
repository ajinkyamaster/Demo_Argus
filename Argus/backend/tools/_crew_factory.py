"""
Sub-agent crew factories — the feedback-loop core.

Two execution paths, selected automatically based on the resolved LLM:

PRIMARY  (cloud API: OpenAI / Anthropic / OpenRouter / Gemini)
  Full 3-agent Crew per iteration: Crafter → Tester (with HTTP tool) → Analyst.
  All reasoning is LLM-driven.  The Analyst's JSON verdict drives the loop.

LOCAL  (Ollama — dual-model architecture, no cloud key set)
  Uses two specialised local models:

  • WhiteRabbitNeo  — offensive executor, generates payloads / exploit PoC.
    Purpose-built uncensored model trained for adversarial tasks.
    Drives the Crafter agent.

  • Foundation-Sec-8B-Instruct — CVE reasoning brain, analyses responses.
    Surpasses 70B models on CVE root-cause mapping.
    Drives the Analyst agent.

  Execution path: Crafter crew (WhiteRabbitNeo, seeds as fallback) →
  direct Python httpx → Python evidence detector →
  Analyst crew (Foundation-Sec, try_again as fallback).
  The Python detector confirms exploitation from raw HTTP strings; the Analyst
  provides supplementary reasoning when the detector is inconclusive.

DETERMINISTIC FALLBACK (scanner.py level)
  If the entire sub-crew raises an exception, scanner.py falls back to
  deterministic httpx probes.  This is NOT handled here.
"""

from __future__ import annotations

import json
import os
import re
import time
import uuid
from typing import Any

import httpx
from crewai import Agent, Crew, LLM, Process, Task

from backend.tools._http_tool import http_request_tool
from backend.tools._payloads import (
    ANALYST_PROMPT,
    CRAFTER_PROMPT,
    IDOR_CRAFTER_PROMPT,
    IDOR_TESTER_PROMPT,
    LOCAL_ANALYST_PROMPT,
    LOCAL_CRAFTER_PROMPT,
    LOCAL_IDOR_CRAFTER_PROMPT,
    SEED_PAYLOADS,
    TESTER_PROMPT,
)
from backend.tools._schemas import AnalysisVerdict

MAX_ITERATIONS = 5
HTTP_TIMEOUT = 10.0
RATE_LIMIT_MAX_RETRIES = 3
RATE_LIMIT_BASE_DELAY = 60.0    # seconds — Gemini free tier asks for ~50s

# ── Local model defaults ─────────────────────────────────────────────────────
# Dual-model architecture for the local (Ollama) fallback path.
#
# CRAFTER model: WhiteRabbitNeo — uncensored offensive executor.
#   Trained end-to-end for adversarial tasks (payload writing, exploit PoC,
#   reverse shells).  Unlike abliterated models, it was trained offensive
#   from day one.
#
# ANALYST model: Foundation-Sec-8B-Instruct — CVE reasoning brain.
#   Surpasses Llama-3.1-70B and WhiteRabbitNeo-V2-70B on CVE root-cause
#   mapping benchmarks.  Best-in-class at 8B for understanding what a
#   vulnerability is and why it works.
#
# Override via env vars:  LOCAL_CRAFTER_MODEL / LOCAL_ANALYST_MODEL

LOCAL_CRAFTER_MODEL = os.environ.get(
    "LOCAL_CRAFTER_MODEL",
    "ollama/lazarevtill/Llama-3-WhiteRabbitNeo-8B-v2.0",  # WhiteRabbitNeo 8B
)
LOCAL_ANALYST_MODEL = os.environ.get(
    "LOCAL_ANALYST_MODEL",
    "ollama/hf.co/mradermacher/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M",  # Foundation-Sec-8B
)


# ── LLM resolution ────────────────────────────────────────────────────────────


def _resolve_llm_model() -> str:
    """Pick the right LLM model string for CrewAI sub-agents.

    Priority:
    1. ``SCANNER_LLM_MODEL`` env var (explicit override)
    2. ``GOOGLE_API_KEY``     → ``gemini/gemini-2.5-flash``  (Person 1 primary)
    3. ``OPENAI_API_KEY``     → ``gpt-4.1-mini``
    4. ``ANTHROPIC_API_KEY``  → ``claude-sonnet-4-20250514``
    5. ``OPENROUTER_API_KEY`` → ``openrouter/auto``
    6. Local Ollama fallback  → dual-model (returns crafter model as default)
    """
    explicit = os.environ.get("SCANNER_LLM_MODEL")
    if explicit:
        return explicit
    if os.environ.get("GOOGLE_API_KEY"):
        return "gemini/gemini-2.5-flash"
    if os.environ.get("OPENAI_API_KEY"):
        return "gpt-4.1-mini"
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "claude-sonnet-4-20250514"
    if os.environ.get("OPENROUTER_API_KEY"):
        return "openrouter/auto"
    return LOCAL_CRAFTER_MODEL          # Ollama fallback


def _get_llm() -> LLM:
    """Build a CrewAI LLM instance for cloud path (resolved at call time)."""
    return LLM(model=_resolve_llm_model())


def _get_local_crafter_llm() -> LLM:
    """Build a CrewAI LLM instance for the LOCAL Crafter (WhiteRabbitNeo)."""
    return LLM(model=LOCAL_CRAFTER_MODEL)


def _get_local_analyst_llm() -> LLM:
    """Build a CrewAI LLM instance for the LOCAL Analyst (Foundation-Sec)."""
    return LLM(model=LOCAL_ANALYST_MODEL)


def _is_local_model() -> bool:
    """True when no cloud API key is present and Ollama is the active model."""
    return _resolve_llm_model().startswith("ollama/")


def _crew_kickoff_with_retry(crew: Crew) -> Any:
    """Run ``crew.kickoff()`` with retry on rate-limit (429) errors.

    Cloud APIs (especially Gemini free tier) return 429 when the RPM or
    daily quota is exceeded.  This wrapper catches those errors and retries
    with exponential backoff so a scan doesn't crash mid-loop.
    """
    for attempt in range(1, RATE_LIMIT_MAX_RETRIES + 1):
        try:
            return crew.kickoff()
        except Exception as exc:
            err_str = str(exc).lower()
            is_rate_limit = (
                "429" in err_str
                or "resource_exhausted" in err_str
                or "rate" in err_str and "limit" in err_str
                or "quota" in err_str
            )
            if is_rate_limit and attempt < RATE_LIMIT_MAX_RETRIES:
                delay = RATE_LIMIT_BASE_DELAY * attempt
                time.sleep(delay)
                continue
            raise


# ── JSON extraction helpers ───────────────────────────────────────────────────

_JSON_BLOCK_RE = re.compile(r"```(?:json)?\s*\n?(.*?)\n?```", re.DOTALL)


def _extract_json(text: str) -> dict | None:
    """Extract the first JSON object from LLM raw text output.

    Handles raw JSON, JSON inside markdown code fences, and embedded {…}.
    """
    if not text:
        return None
    try:
        return json.loads(text.strip())
    except (json.JSONDecodeError, TypeError):
        pass
    match = _JSON_BLOCK_RE.search(text)
    if match:
        try:
            return json.loads(match.group(1).strip())
        except (json.JSONDecodeError, TypeError):
            pass
    start = text.find("{")
    if start != -1:
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start : i + 1])
                    except (json.JSONDecodeError, TypeError):
                        break
    return None


# ── Verdict parsing ───────────────────────────────────────────────────────────


def _parse_verdict(crew_result: Any, analyze_task: Task) -> AnalysisVerdict:
    """Extract ``AnalysisVerdict`` from analyst crew output.

    Falls back to ``try_again=True`` on any parse failure so the loop
    continues safely rather than silently terminating.
    """
    raw_sources: list[str] = []
    if analyze_task.output and hasattr(analyze_task.output, "raw"):
        raw_sources.append(analyze_task.output.raw or "")
    if hasattr(crew_result, "raw"):
        raw_sources.append(crew_result.raw or "")
    for raw in raw_sources:
        d = _extract_json(raw)
        if d:
            try:
                return AnalysisVerdict(**d)
            except Exception:
                continue
    return AnalysisVerdict(
        confirmed=False,
        dead_end=False,
        try_again=True,
        reasoning="Failed to parse analyst output; retrying with new payload.",
        failure_reason="Sub-agent output parsing error",
    )


# ── Agent builders ────────────────────────────────────────────────────────────


def _make_crafter(vuln_type: str, endpoint: str, *, llm: LLM | None = None) -> Agent:
    return Agent(
        role=f"{vuln_type} Payload Crafter",
        goal=(
            f"Output a JSON object with a {vuln_type} exploit payload for "
            f"{endpoint}. Output ONLY JSON, nothing else."
        ),
        backstory=(
            f"You are a {vuln_type} exploit specialist. You craft real, "
            "offensive payloads — not theoretical descriptions. You know "
            "every bypass technique, encoding trick, and language-specific "
            "injection vector. You output structured JSON payloads only. "
            "Never output explanations, markdown, or commentary — "
            "only raw JSON objects."
        ),
        verbose=False,
        max_iter=3,
        allow_delegation=False,
        llm=llm or _get_llm(),
    )


def _make_tester() -> Agent:
    """Tester agent — used by the PRIMARY (cloud) path only."""
    return Agent(
        role="Payload Tester",
        goal=(
            "Call the 'HTTP Request Executor' tool with the payload from the "
            "Crafter. Return the raw HTTP response. Do not interpret it."
        ),
        backstory=(
            "You execute HTTP requests exactly as instructed by the Crafter. "
            "You never modify payloads. You always call the HTTP Request "
            "Executor tool and return its output verbatim."
        ),
        tools=[http_request_tool],
        verbose=False,
        max_iter=3,
        allow_delegation=False,
        llm=_get_llm(),
    )


def _make_analyst(vuln_type: str, *, llm: LLM | None = None) -> Agent:
    return Agent(
        role="Vulnerability Analyst",
        goal=(
            "Output a JSON verdict: confirmed, dead_end, or try_again. "
            "Output ONLY JSON, nothing else."
        ),
        backstory=(
            f"You are a vulnerability analyst specialising in {vuln_type}. "
            "You apply CVE root-cause analysis, MITRE ATT&CK mapping, and "
            "evidence-based reasoning to HTTP responses. "
            "You output ONLY a JSON object with keys: "
            "confirmed, dead_end, try_again, evidence, failure_reason, reasoning. "
            "You never output explanations — only raw JSON."
        ),
        verbose=False,
        max_iter=3,
        allow_delegation=False,
        llm=llm or _get_llm(),
    )


# ── Python evidence detector (LOCAL path only) ────────────────────────────────


def _python_detect_evidence(vuln_type: str, payload: str, http_response_json: str) -> str | None:
    """Detect exploitation evidence from raw HTTP response strings.

    Used by the LOCAL path so that string-level proof is never missed when
    local models fail to reason about the response correctly.  Not used in
    the PRIMARY (cloud) path — the cloud Analyst handles confirmation.

    In the dual-model local architecture, this detector sits between
    WhiteRabbitNeo (crafter) and Foundation-Sec (analyst) and acts as the
    authoritative confirmation gate — neither local LLM's "confirmed"
    verdict is trusted without matching evidence from this function.
    """
    try:
        resp = json.loads(http_response_json)
    except (json.JSONDecodeError, TypeError):
        return None

    body: str = resp.get("body", "")
    status: int = resp.get("status_code", 0)

    if vuln_type in ("SQL_INJECTION", "AUTH_BYPASS"):
        db_errors = [
            "sqlite3.OperationalError",
            "OperationalError",
            "sqlite3",
            "syntax error",
            "unrecognized token",
            "db_error",
        ]
        for marker in db_errors:
            if marker.lower() in body.lower():
                return f"Database error in response body: {body[:300]}"
        # Auth bypass detection — broadened to match real-world login responses
        if status == 200 and vuln_type == "AUTH_BYPASS":
            bypass_markers = [
                "token", "access_token", "session", "authenticated",
                "CORE_BANKING_ACCESS_TOKEN", "INTERNAL_VAULT_KEY",
                "jwt", "bearer", "auth_token",
            ]
            for marker in bypass_markers:
                if marker.lower() in body.lower():
                    return (
                        f"HTTP 200 with auth indicator '{marker}' returned for "
                        f"injected credentials. payload={payload!r}. body={body[:300]}"
                    )

    elif vuln_type == "XSS":
        if payload and payload in body:
            return (
                f"Payload reflected unescaped in HTML body. "
                f"payload={payload!r} found in: {body[:300]}"
            )
        if "<script" in body.lower() and "alert" in body.lower():
            return f"Unescaped script tag reflected in body: {body[:300]}"

    elif vuln_type == "IDOR":
        if status == 200 and ("username" in body.lower() or "email" in body.lower()):
            return f"User PII returned unauthenticated (HTTP {status}): {body[:300]}"

    elif vuln_type == "SSTI":
        # Check for evaluated math expression results
        # We use unique products (7*7191=50337) to avoid false positives
        ssti_markers = [
            ("50337", "7*7191"),   # primary canary
            ("49", "7*7"),         # common variant
        ]
        for result_str, expr in ssti_markers:
            if result_str in body and expr not in body:
                # The computed result is in the body but not the raw expression
                return (
                    f"SSTI confirmed: expression {expr} was evaluated by the server. "
                    f"Result '{result_str}' found in body: {body[:300]}"
                )
        # Config/class leaks from Jinja2
        config_markers = [
            ("SECRET_KEY", "Flask config object leaked"),
            ("__class__", "Python class hierarchy leaked"),
            ("__mro__", "Python MRO chain leaked"),
            ("__subclasses__", "Python subclasses list leaked"),
            ("__globals__", "Python globals leaked"),
        ]
        for marker, desc in config_markers:
            if marker in body:
                return f"SSTI confirmed: {desc}. body={body[:300]}"

    elif vuln_type == "LFI":
        # /etc/passwd markers
        passwd_markers = [
            "root:x:0:0",
            "root:x:0:",
            "/bin/bash",
            "/bin/sh",
            "daemon:x:",
            "nobody:x:",
        ]
        for marker in passwd_markers:
            if marker in body:
                return f"LFI confirmed: system file contents in response ({marker}). body={body[:300]}"
        # Windows markers
        win_markers = [
            "# Copyright (c) 1993-",   # Windows hosts file header
            "[boot loader]",            # Windows boot.ini
            "[extensions]",             # Windows win.ini
        ]
        for marker in win_markers:
            if marker.lower() in body.lower():
                return f"LFI confirmed: Windows system file in response ({marker}). body={body[:300]}"
        # Base64 encoded file (PHP wrappers)
        # /etc/passwd base64 starts with "cm9vd" (for "root:")
        if "cm9vd" in body:
            return f"LFI confirmed: base64-encoded /etc/passwd detected. body={body[:200]}"

    return None


# ── Direct HTTP execution (LOCAL path only) ───────────────────────────────────


def _execute_http(proposal: dict, target_url: str, cookies: dict | None = None) -> str:
    """Fire the HTTP request described by a Crafter JSON proposal.

    Returns a compact JSON string so the Analyst can read it directly.
    Used by the LOCAL path only.

    Supports both ``application/json`` and ``application/x-www-form-urlencoded``
    POST bodies.  If ``content_type`` is ``form`` in the proposal (or the body
    is a flat dict with no nesting), sends as form data.
    """
    base = target_url.rstrip("/")
    method = (proposal.get("method") or "GET").upper()
    url_path = proposal.get("url_path", "")
    url = f"{base}{url_path}" if url_path else base

    try:
        if method == "POST":
            body_str = proposal.get("body_template") or proposal.get("body", "{}")
            try:
                body_data = json.loads(body_str) if isinstance(body_str, str) else body_str
            except json.JSONDecodeError:
                body_data = body_str

            # Decide form vs JSON encoding.
            # Prefer form-encoded when the proposal says so, or when the body is
            # a flat dict (login forms, auth endpoints, etc.).
            use_form = proposal.get("content_type", "").lower() in ("form", "form-urlencoded")
            if not use_form and isinstance(body_data, dict):
                # Heuristic: flat dicts with string-only values → form-encoded
                use_form = all(isinstance(v, (str, int, float, bool)) for v in body_data.values())

            if use_form and isinstance(body_data, dict):
                resp = httpx.post(url, data=body_data, cookies=cookies, timeout=HTTP_TIMEOUT)
            else:
                resp = httpx.post(url, json=body_data, cookies=cookies, timeout=HTTP_TIMEOUT)
        else:
            params_str = proposal.get("query_params") or proposal.get("params", "{}")
            try:
                params = json.loads(params_str) if isinstance(params_str, str) else params_str
            except json.JSONDecodeError:
                params = {}
            resp = httpx.get(url, params=params, cookies=cookies, timeout=HTTP_TIMEOUT)

        return json.dumps({
            "status_code": resp.status_code,
            "content_type": resp.headers.get("content-type", ""),
            "body": resp.text[:3000],
            "url": str(resp.url),
        })
    except httpx.HTTPError as exc:
        return json.dumps({"error": str(exc), "url": url})


# ── Seed proposal builder ─────────────────────────────────────────────────────


def _seed_proposal(vuln_type: str, endpoint: str, method: str, iteration: int) -> dict:
    """Build a deterministic seed proposal when the Crafter LLM fails."""
    seeds = SEED_PAYLOADS.get(vuln_type, [])
    if not seeds:
        return {}
    seed = seeds[(iteration - 1) % len(seeds)]   # start at index 0 on iteration 1
    if method == "POST":
        return {
            "payload": seed["payload"],
            "injection_point": "username",
            "method": "POST",
            "url_path": endpoint,
            "body_template": json.dumps({"username": seed["payload"], "password": "x"}),
        }
    return {
        "payload": seed["payload"],
        "injection_point": "q",
        "method": "GET",
        "url_path": endpoint,
        "query_params": json.dumps({"q": seed["payload"]}),
    }


# ── PRIMARY path: full 3-agent Crew (cloud LLMs) ─────────────────────────────


def _run_cloud_feedback_loop(
    *,
    vuln_type: str,
    target_url: str,
    endpoint: str,
    method: str,
    crafter_prompt: str,
    tester_prompt: str,
    finding_template: dict,
) -> dict:
    """Full 3-agent Crew per iteration: Crafter → Tester → Analyst.

    Used when a cloud API key is present.  All reasoning is LLM-driven.
    """
    base = target_url.rstrip("/")
    full_url = f"{base}{endpoint}"
    previous_attempts: list[dict] = []
    seeds_json = json.dumps(SEED_PAYLOADS.get(vuln_type, []), indent=2)

    for iteration in range(1, MAX_ITERATIONS + 1):
        prev_json = (
            json.dumps(previous_attempts, indent=2)
            if previous_attempts
            else "None — this is the first attempt."
        )

        crafter = _make_crafter(vuln_type, endpoint)
        tester = _make_tester()
        analyst = _make_analyst(vuln_type)

        craft_task = Task(
            description=crafter_prompt.format(
                vuln_type=vuln_type,
                target_url=full_url,
                endpoint=endpoint,
                method=method,
                seed_payloads=seeds_json,
                previous_attempts=prev_json,
                attempt_number=iteration,
                max_attempts=MAX_ITERATIONS,
            ),
            expected_output=(
                'ONLY a JSON object like: '
                '{"payload": "...", "injection_point": "...", "method": "...", '
                '"url_path": "...", "body_template": "...", "rationale": "..."}'
            ),
            agent=crafter,
        )
        test_task = Task(
            description=tester_prompt.format(
                target_url=full_url,
                endpoint=endpoint,
                method=method,
            ),
            expected_output=(
                "The raw JSON response from the HTTP Request Executor tool: "
                "status_code, content_type, body, url."
            ),
            agent=tester,
            context=[craft_task],
        )
        analyze_task = Task(
            description=ANALYST_PROMPT.format(
                vuln_type=vuln_type,
                endpoint=endpoint,
                attempt_number=iteration,
                max_attempts=MAX_ITERATIONS,
                previous_attempts=prev_json,
            ),
            expected_output=(
                'ONLY a JSON object like: '
                '{"confirmed": false, "dead_end": false, "try_again": true, '
                '"evidence": null, "failure_reason": "...", "reasoning": "..."}'
            ),
            agent=analyst,
            context=[craft_task, test_task],
        )

        crew = Crew(
            agents=[crafter, tester, analyst],
            tasks=[craft_task, test_task, analyze_task],
            process=Process.sequential,
            verbose=False,
        )
        result = _crew_kickoff_with_retry(crew)

        verdict = _parse_verdict(result, analyze_task)

        # Extract payload string best-effort
        crafter_raw = (craft_task.output.raw or "") if craft_task.output else ""
        proposal = _extract_json(crafter_raw) or {}
        payload_str = proposal.get("payload") or "<unknown>"

        if verdict.confirmed and verdict.evidence:
            return {
                "findings": [{
                    **finding_template,
                    "id": str(uuid.uuid4()),
                    "payload": payload_str,
                    "evidence": verdict.evidence,
                }],
                "iterations_used": iteration,
            }

        if verdict.dead_end:
            return {"findings": [], "iterations_used": iteration}

        previous_attempts.append({
            "iteration": iteration,
            "payload": payload_str,
            "failure_reason": verdict.failure_reason or "Unknown",
            "reasoning": verdict.reasoning,
        })

    return {"findings": [], "iterations_used": MAX_ITERATIONS}


# ── LOCAL path: Crafter LLM + Python httpx + Python detector + Analyst LLM ───


def _run_local_feedback_loop(
    *,
    vuln_type: str,
    target_url: str,
    endpoint: str,
    method: str,
    crafter_prompt: str,
    finding_template: dict,
) -> dict:
    """Dual-model hybrid loop for local Ollama.

    Crafter crew (WhiteRabbitNeo — offensive payload generation) →
    Python httpx fires the request →
    Python evidence detector checks for hard proof →
    Analyst crew (Foundation-Sec — CVE reasoning / verdict) when detector
    is inconclusive.
    """
    base = target_url.rstrip("/")
    full_url = f"{base}{endpoint}"
    previous_attempts: list[dict] = []
    seeds_json = json.dumps(SEED_PAYLOADS.get(vuln_type, []), indent=2)

    # Resolve the two local models once per loop
    crafter_llm = _get_local_crafter_llm()
    analyst_llm = _get_local_analyst_llm()

    for iteration in range(1, MAX_ITERATIONS + 1):
        prev_json = (
            json.dumps(previous_attempts, indent=2)
            if previous_attempts
            else "None — this is the first attempt."
        )

        # ── Step 1: Crafter crew (WhiteRabbitNeo) ────────────────────
        crafter = _make_crafter(vuln_type, endpoint, llm=crafter_llm)
        craft_task = Task(
            description=crafter_prompt.format(
                vuln_type=vuln_type,
                target_url=full_url,
                endpoint=endpoint,
                method=method,
                seed_payloads=seeds_json,
                previous_attempts=prev_json,
                attempt_number=iteration,
                max_attempts=MAX_ITERATIONS,
            ),
            expected_output=(
                'ONLY a JSON object like: '
                '{"payload": "...", "injection_point": "...", "method": "...", '
                '"url_path": "...", "body_template": "...", "rationale": "..."}'
            ),
            agent=crafter,
        )
        craft_crew = Crew(
            agents=[crafter],
            tasks=[craft_task],
            process=Process.sequential,
            verbose=False,
        )
        craft_result = _crew_kickoff_with_retry(craft_crew)

        crafter_raw = ""
        if craft_task.output and hasattr(craft_task.output, "raw"):
            crafter_raw = craft_task.output.raw or ""
        if not crafter_raw and hasattr(craft_result, "raw"):
            crafter_raw = craft_result.raw or ""

        proposal = _extract_json(crafter_raw) or {}
        if not proposal.get("payload"):
            # LLM produced no valid JSON — cycle through seeds
            proposal = _seed_proposal(vuln_type, endpoint, method, iteration)
        if not proposal:
            previous_attempts.append({
                "iteration": iteration,
                "payload": "<unknown>",
                "failure_reason": "Crafter produced no proposal; no seeds available",
                "reasoning": "No output",
            })
            continue

        payload_str = proposal.get("payload", "<unknown>")

        # ── Step 2: Direct Python HTTP execution ─────────────────────
        http_response_json = _execute_http(proposal, target_url)

        # ── Step 2a: Python evidence detector (primary confirmation) ──
        python_evidence = _python_detect_evidence(vuln_type, payload_str, http_response_json)
        if python_evidence:
            return {
                "findings": [{
                    **finding_template,
                    "id": str(uuid.uuid4()),
                    "payload": payload_str,
                    "evidence": python_evidence,
                }],
                "iterations_used": iteration,
            }

        # ── Step 3: Analyst crew (Foundation-Sec — CVE reasoning) ───
        analyst = _make_analyst(vuln_type, llm=analyst_llm)
        analyze_task = Task(
            description=LOCAL_ANALYST_PROMPT.format(
                vuln_type=vuln_type,
                endpoint=endpoint,
                attempt_number=iteration,
                max_attempts=MAX_ITERATIONS,
                previous_attempts=prev_json,
                http_response=http_response_json,
            ),
            expected_output=(
                'ONLY a JSON object like: '
                '{"confirmed": false, "dead_end": false, "try_again": true, '
                '"evidence": null, "failure_reason": "...", "reasoning": "..."}'
            ),
            agent=analyst,
        )
        analyst_crew = Crew(
            agents=[analyst],
            tasks=[analyze_task],
            process=Process.sequential,
            verbose=False,
        )
        analyze_result = _crew_kickoff_with_retry(analyst_crew)

        verdict = _parse_verdict(analyze_result, analyze_task)

        # In the LOCAL path, only _python_detect_evidence() can confirm a
        # vulnerability.  The 8B Analyst's "confirmed" verdict is ignored
        # because it frequently hallucinates evidence.  The Analyst only
        # gates dead_end vs try_again here.

        if verdict.dead_end:
            return {"findings": [], "iterations_used": iteration}

        previous_attempts.append({
            "iteration": iteration,
            "payload": payload_str,
            "failure_reason": verdict.failure_reason or "Unknown",
            "reasoning": verdict.reasoning,
        })

    return {"findings": [], "iterations_used": MAX_ITERATIONS}


# ── Generic dispatcher ────────────────────────────────────────────────────────


def _run_feedback_loop(
    *,
    vuln_type: str,
    target_url: str,
    endpoint: str,
    method: str,
    crafter_prompt: str,
    finding_template: dict,
) -> dict:
    """Dispatch to cloud or local feedback loop based on active LLM."""
    if _is_local_model():
        return _run_local_feedback_loop(
            vuln_type=vuln_type,
            target_url=target_url,
            endpoint=endpoint,
            method=method,
            crafter_prompt=LOCAL_CRAFTER_PROMPT,
            finding_template=finding_template,
        )
    return _run_cloud_feedback_loop(
        vuln_type=vuln_type,
        target_url=target_url,
        endpoint=endpoint,
        method=method,
        crafter_prompt=crafter_prompt,
        tester_prompt=TESTER_PROMPT,
        finding_template=finding_template,
    )


# ── IDOR loops ────────────────────────────────────────────────────────────────


def _run_cloud_idor_loop(target_url: str, finding_template: dict) -> dict:
    """Cloud IDOR: full 3-agent Crew — Crafter → Tester (multi-call tool) → Analyst."""
    base = target_url.rstrip("/")
    previous_attempts: list[dict] = []

    for iteration in range(1, MAX_ITERATIONS + 1):
        prev_json = (
            json.dumps(previous_attempts, indent=2)
            if previous_attempts
            else "None — this is the first attempt."
        )

        crafter = _make_crafter("IDOR", "/api/users/")
        tester = _make_tester()
        analyst = _make_analyst("IDOR")

        craft_task = Task(
            description=IDOR_CRAFTER_PROMPT.format(
                target_url=base,
                previous_attempts=prev_json,
                attempt_number=iteration,
                max_attempts=MAX_ITERATIONS,
            ),
            expected_output=(
                'ONLY a JSON object like: '
                '{"payload": "1,2,3", "injection_point": "path_segment", '
                '"method": "GET", "url_path": "/api/users/", "rationale": "..."}'
            ),
            agent=crafter,
        )
        test_task = Task(
            description=IDOR_TESTER_PROMPT.format(target_url=base),
            expected_output="Summary of HTTP responses for each user ID tested.",
            agent=tester,
            context=[craft_task],
        )
        analyze_task = Task(
            description=ANALYST_PROMPT.format(
                vuln_type="IDOR",
                endpoint="/api/users/:id",
                attempt_number=iteration,
                max_attempts=MAX_ITERATIONS,
                previous_attempts=prev_json,
            ),
            expected_output=(
                'ONLY a JSON object like: '
                '{"confirmed": false, "dead_end": false, "try_again": true, '
                '"evidence": null, "failure_reason": "...", "reasoning": "..."}'
            ),
            agent=analyst,
            context=[craft_task, test_task],
        )

        crew = Crew(
            agents=[crafter, tester, analyst],
            tasks=[craft_task, test_task, analyze_task],
            process=Process.sequential,
            verbose=False,
        )
        result = _crew_kickoff_with_retry(crew)

        verdict = _parse_verdict(result, analyze_task)

        crafter_raw = (craft_task.output.raw or "") if craft_task.output else ""
        proposal = _extract_json(crafter_raw) or {}
        ids_str = proposal.get("payload", "1,2,3")

        if verdict.confirmed and verdict.evidence:
            return {
                "findings": [{
                    **finding_template,
                    "id": str(uuid.uuid4()),
                    "payload": ids_str,
                    "evidence": verdict.evidence,
                }],
                "iterations_used": iteration,
            }

        if verdict.dead_end:
            return {"findings": [], "iterations_used": iteration}

        previous_attempts.append({
            "iteration": iteration,
            "payload": ids_str,
            "failure_reason": verdict.failure_reason or "Unknown",
            "reasoning": verdict.reasoning,
        })

    return {"findings": [], "iterations_used": MAX_ITERATIONS}


def _run_local_idor_loop(target_url: str, finding_template: dict) -> dict:
    """Local IDOR: Crafter (WhiteRabbitNeo) → Python httpx → Python detector → Analyst (Foundation-Sec)."""
    base = target_url.rstrip("/")
    previous_attempts: list[dict] = []

    # Resolve dual models once
    crafter_llm = _get_local_crafter_llm()
    analyst_llm = _get_local_analyst_llm()

    for iteration in range(1, MAX_ITERATIONS + 1):
        prev_json = (
            json.dumps(previous_attempts, indent=2)
            if previous_attempts
            else "None — this is the first attempt."
        )

        # Crafter: pick IDs (WhiteRabbitNeo)
        crafter = _make_crafter("IDOR", "/api/users/", llm=crafter_llm)
        craft_task = Task(
            description=LOCAL_IDOR_CRAFTER_PROMPT.format(
                target_url=base,
                previous_attempts=prev_json,
                attempt_number=iteration,
                max_attempts=MAX_ITERATIONS,
            ),
            expected_output=(
                'ONLY a JSON object like: '
                '{"payload": "1,2,3", "injection_point": "path_segment", '
                '"method": "GET", "url_path": "/api/users/", "rationale": "..."}'
            ),
            agent=crafter,
        )
        craft_crew = Crew(
            agents=[crafter],
            tasks=[craft_task],
            process=Process.sequential,
            verbose=False,
        )
        craft_result = _crew_kickoff_with_retry(craft_crew)

        crafter_raw = ""
        if craft_task.output and hasattr(craft_task.output, "raw"):
            crafter_raw = craft_task.output.raw or ""
        if not crafter_raw and hasattr(craft_result, "raw"):
            crafter_raw = craft_result.raw or ""

        proposal = _extract_json(crafter_raw) or {}
        ids_str = proposal.get("payload", "1,2,3")
        ids = [i.strip() for i in ids_str.split(",") if i.strip()] or ["1", "2", "3"]

        # Direct Python enumeration
        responses: list[dict] = []
        for user_id in ids:
            url = f"{base}/api/users/{user_id}"
            try:
                resp = httpx.get(url, timeout=HTTP_TIMEOUT)
                responses.append({
                    "id": user_id,
                    "status_code": resp.status_code,
                    "body": resp.text[:500],
                    "url": str(resp.url),
                })
            except httpx.HTTPError as exc:
                responses.append({"id": user_id, "error": str(exc)})

        # Python evidence check across all IDs
        for r in responses:
            evidence = _python_detect_evidence("IDOR", ids_str, json.dumps(r))
            if evidence:
                return {
                    "findings": [{
                        **finding_template,
                        "id": str(uuid.uuid4()),
                        "payload": ids_str,
                        "evidence": evidence,
                    }],
                    "iterations_used": iteration,
                }

        # Analyst crew (Foundation-Sec — CVE reasoning)
        http_summary = json.dumps(responses, indent=2)
        analyst = _make_analyst("IDOR", llm=analyst_llm)
        analyze_task = Task(
            description=LOCAL_ANALYST_PROMPT.format(
                vuln_type="IDOR",
                endpoint="/api/users/:id",
                attempt_number=iteration,
                max_attempts=MAX_ITERATIONS,
                previous_attempts=prev_json,
                http_response=http_summary,
            ),
            expected_output=(
                'ONLY a JSON object like: '
                '{"confirmed": false, "dead_end": false, "try_again": true, '
                '"evidence": null, "failure_reason": "...", "reasoning": "..."}'
            ),
            agent=analyst,
        )
        analyst_crew = Crew(
            agents=[analyst],
            tasks=[analyze_task],
            process=Process.sequential,
            verbose=False,
        )
        analyze_result = _crew_kickoff_with_retry(analyst_crew)
        verdict = _parse_verdict(analyze_result, analyze_task)

        # In the LOCAL path, only _python_detect_evidence() can confirm.
        # Foundation-Sec is used here only for dead_end vs try_again gating.

        if verdict.dead_end:
            return {"findings": [], "iterations_used": iteration}

        previous_attempts.append({
            "iteration": iteration,
            "payload": ids_str,
            "failure_reason": verdict.failure_reason or "Unknown",
            "reasoning": verdict.reasoning,
        })

    return {"findings": [], "iterations_used": MAX_ITERATIONS}


def _run_idor_feedback_loop(target_url: str, finding_template: dict) -> dict:
    """Dispatch to cloud or local IDOR loop based on active LLM."""
    if _is_local_model():
        return _run_local_idor_loop(target_url, finding_template)
    return _run_cloud_idor_loop(target_url, finding_template)


# ── Public factory functions ──────────────────────────────────────────────────


def run_sqli_subcrew(target_url: str) -> dict:
    """Spawn a sub-crew to test for SQL injection at /api/login."""
    return _run_feedback_loop(
        vuln_type="SQL_INJECTION",
        target_url=target_url,
        endpoint="/api/login",
        method="POST",
        crafter_prompt=CRAFTER_PROMPT,
        finding_template={
            "type": "SQL_INJECTION",
            "severity": "critical",
            "title": "SQL Injection in /api/login",
            "agent": "ExploitationAgent",
            "description": (
                "The 'username' parameter is interpolated directly into a "
                "raw SQL query without sanitisation, allowing authentication "
                "bypass and potential data exfiltration."
            ),
            "endpoint": "/api/login",
            "method": "POST",
            "remediation": (
                "Replace raw string interpolation with parameterised queries "
                "(use ? placeholders with sqlite3)."
            ),
            "cvss_score": 9.8,
        },
    )


def run_xss_subcrew(target_url: str) -> dict:
    """Spawn a sub-crew to test for reflected XSS at /api/search."""
    return _run_feedback_loop(
        vuln_type="XSS",
        target_url=target_url,
        endpoint="/api/search",
        method="GET",
        crafter_prompt=CRAFTER_PROMPT,
        finding_template={
            "type": "XSS",
            "severity": "medium",
            "title": "Reflected XSS in /api/search",
            "agent": "ExploitationAgent",
            "description": (
                "The 'q' query parameter is echoed directly into an HTML "
                "response without encoding, allowing arbitrary script "
                "injection in the context of the page."
            ),
            "endpoint": "/api/search",
            "method": "GET",
            "remediation": (
                "HTML-encode all user-controlled output before rendering "
                "in HTML context. Use a templating engine with auto-escaping."
            ),
            "cvss_score": 6.1,
        },
    )


def run_auth_bypass_subcrew(target_url: str) -> dict:
    """Spawn a sub-crew to test for auth bypass at /api/login."""
    return _run_feedback_loop(
        vuln_type="AUTH_BYPASS",
        target_url=target_url,
        endpoint="/api/login",
        method="POST",
        crafter_prompt=CRAFTER_PROMPT,
        finding_template={
            "type": "AUTH_BYPASS",
            "severity": "critical",
            "title": "Authentication Bypass via SQL Injection on /api/login",
            "agent": "ExploitationAgent",
            "description": (
                "SQL injection in the login endpoint allows complete "
                "authentication bypass, granting access without valid "
                "credentials."
            ),
            "endpoint": "/api/login",
            "method": "POST",
            "remediation": (
                "Use parameterised queries for authentication. Implement "
                "proper session tokens (JWT with signing and expiry)."
            ),
            "cvss_score": 9.0,
        },
    )


def run_idor_subcrew(target_url: str) -> dict:
    """Spawn a sub-crew to test for IDOR at /api/users/:id."""
    return _run_idor_feedback_loop(
        target_url=target_url,
        finding_template={
            "type": "IDOR",
            "severity": "high",
            "title": "Insecure Direct Object Reference on /api/users/:id",
            "agent": "ExploitationAgent",
            "description": (
                "User records are accessible by sequential ID enumeration "
                "without any authentication or authorisation check. Any "
                "client can retrieve any user's PII."
            ),
            "endpoint": "/api/users/:id",
            "method": "GET",
            "remediation": (
                "Require authentication on user endpoints. Validate that "
                "the requesting user owns or has permission to access the "
                "requested record. Return 403 for unauthorised access."
            ),
            "cvss_score": 7.5,
        },
    )


def run_ssti_subcrew(target_url: str, endpoint: str = "/api/search", method: str = "GET") -> dict:
    """Spawn a sub-crew to test for Server-Side Template Injection."""
    return _run_feedback_loop(
        vuln_type="SSTI",
        target_url=target_url,
        endpoint=endpoint,
        method=method,
        crafter_prompt=CRAFTER_PROMPT,
        finding_template={
            "type": "SSTI",
            "severity": "critical",
            "title": f"Server-Side Template Injection in {endpoint}",
            "agent": "ExploitationAgent",
            "description": (
                "User input is passed directly into a server-side template "
                "engine (e.g. Jinja2, Twig, Freemarker) without sanitisation. "
                "An attacker can inject template expressions that are evaluated "
                "on the server, leading to information disclosure or remote "
                "code execution."
            ),
            "endpoint": endpoint,
            "method": method,
            "remediation": (
                "Never pass raw user input to render_template_string() or "
                "equivalent. Use render_template() with auto-escaping. "
                "Sandbox the template engine and restrict built-in access."
            ),
            "cvss_score": 9.8,
        },
    )


def run_lfi_subcrew(target_url: str, endpoint: str = "/api/file", method: str = "GET") -> dict:
    """Spawn a sub-crew to test for Local File Inclusion."""
    return _run_feedback_loop(
        vuln_type="LFI",
        target_url=target_url,
        endpoint=endpoint,
        method=method,
        crafter_prompt=CRAFTER_PROMPT,
        finding_template={
            "type": "LFI",
            "severity": "high",
            "title": f"Local File Inclusion via {endpoint}",
            "agent": "ExploitationAgent",
            "description": (
                "A parameter is used to construct a file path on the server "
                "without adequate validation. Path traversal sequences "
                "(../) allow an attacker to read arbitrary files outside "
                "the intended directory, including /etc/passwd and "
                "application configuration files."
            ),
            "endpoint": endpoint,
            "method": method,
            "remediation": (
                "Use an allow-list of permitted filenames instead of "
                "passing user input directly to file-system operations. "
                "Strip or reject path traversal sequences. Use "
                "os.path.realpath() and verify the resolved path starts "
                "within the intended directory."
            ),
            "cvss_score": 7.5,
        },
    )
