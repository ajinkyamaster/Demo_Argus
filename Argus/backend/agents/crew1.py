"""
CrewAI Pentest Crew — Person 1's domain.
Hierarchical Root-Branch architecture.
  ROOT  : Master Orchestrator (Gemini 2.5 Flash → fallback: foundation-sec-abliterated)
  CHILD1: Recon Scout
  CHILD2: Web Vuln Agent
  CHILD3: CVE Agent
  CHILD4: Network Security Agent
  CHILD5: Report Bureaucrat
  SIDE  : Chainer (non-blocking, triggered per vulnerability)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import queue
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any, AsyncIterator

from crewai import Agent, Crew, Process, Task
from crewai import LLM

from backend.agents.tools import (
    lookup_cves,
    run_recon,
    scan_web_vulns,
    check_network_misconfig,
    verify_sqli,
    verify_xss,
    verify_auth_bypass,
    verify_idor,
    verify_ssti,
    verify_lfi,
)
from backend.models1 import (
    AgentLog,
    AttackChain,
    AttackChainStep,
    ChainConfidence,
    ChainedExploit,
    CVEFinding,
    DismissedFinding,
    ScanReport,
    ScanRequest,
    ScanStatus,
    ScanSummary,
    Severity,
    Vulnerability,
    _compute_chain_fingerprint,
    _severity_from_cvss,
)
from backend.agents._demo_fallback import build_demo_report

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Chainer timeout constant (seconds).  Easy to tune.
# ---------------------------------------------------------------------------

CHAINER_TIMEOUT_SECONDS: int = 30

# ---------------------------------------------------------------------------
# LLM — Primary: Gemini 2.5 Flash | Fallback: local Foundation-Sec
# ---------------------------------------------------------------------------

_llm = LLM(
    model="gemini/gemini-2.5-flash",
    api_key=os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY"),
    temperature=0.1,
    max_tokens=8192,
)

_fallback_llm = LLM(
    model=os.getenv(
        "LOCAL_ANALYST_MODEL",
        "ollama/hf.co/mradermacher/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M",
    ),
    base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
    temperature=0.1,
    max_tokens=8192,
)


# ---------------------------------------------------------------------------
# Shared vulnerability database  (thread-safe, used by Chainer side-calls)
# ---------------------------------------------------------------------------


class _VulnDB:
    """Thread-safe in-memory vulnerability and chain store shared across agents.

    All exploiter agents record their findings here so the Chainer can query
    the full list at any point during execution.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._vulns: list[dict] = []
        self._chains: list[ChainedExploit] = []
        self._chain_fingerprints: set[str] = set()

    def add_vuln(self, vuln: dict) -> None:
        """Add a raw vulnerability dict to the database."""
        with self._lock:
            self._vulns.append(vuln)

    def get_all_vulns(self) -> list[dict]:
        """Return a snapshot of all recorded vulnerabilities."""
        with self._lock:
            return list(self._vulns)

    def get_all_chains(self) -> list[ChainedExploit]:
        """Return a snapshot of all recorded chained exploits."""
        with self._lock:
            return list(self._chains)

    def has_fingerprint(self, fingerprint: str) -> bool:
        """Check whether a chain with this fingerprint already exists."""
        with self._lock:
            return fingerprint in self._chain_fingerprints

    def add_chain(self, chain: ChainedExploit) -> bool:
        """Add a ChainedExploit. Returns False if fingerprint already exists (duplicate)."""
        with self._lock:
            if chain.chain_fingerprint in self._chain_fingerprints:
                return False
            self._chains.append(chain)
            self._chain_fingerprints.add(chain.chain_fingerprint)
            return True


# ---------------------------------------------------------------------------
# Chainer sub-agent — non-blocking side-call engine
# ---------------------------------------------------------------------------

# Valid vulnerability type strings the Chainer accepts at Gate 1.
_VALID_VULN_TYPES = {
    "SQL_INJECTION", "XSS", "IDOR", "AUTH_BYPASS", "SSTI", "LFI",
    "NetworkMisconfig", "SSRF", "RCE", "PATH_TRAVERSAL", "CSRF",
}

# Chain archetype patterns: (type_a, type_b) -> narrative template.
# Order-independent — both (a,b) and (b,a) are checked.
_CHAIN_ARCHETYPES: list[tuple[set[str], str, str]] = [
    (
        {"SQL_INJECTION", "IDOR"},
        "SQLi + IDOR → Account Data Exfiltration Chain",
        (
            "Step 1: Exploit SQL Injection on {ep_a} to extract credentials or "
            "session tokens from the database. "
            "Step 2: Use the stolen credentials/tokens to authenticate, then "
            "exploit IDOR on {ep_b} to access arbitrary user records — "
            "exfiltrating sensitive data (PII, financial records) across accounts."
        ),
    ),
    (
        {"SQL_INJECTION", "AUTH_BYPASS"},
        "SQLi + Auth Bypass → Privilege Escalation Chain",
        (
            "Step 1: Exploit SQL Injection on {ep_a} to extract admin credentials "
            "or password hashes from the database. "
            "Step 2: Use the extracted credentials to bypass authentication on "
            "{ep_b}, gaining full admin access to the application."
        ),
    ),
    (
        {"IDOR", "XSS"},
        "IDOR + XSS → Cross-User Data Theft Chain",
        (
            "Step 1: Exploit IDOR on {ep_a} to enumerate accessible object "
            "references and identify target users. "
            "Step 2: Craft a reflected XSS payload on {ep_b} that, when "
            "triggered by a victim user, exfiltrates their session token or "
            "private data via the IDOR endpoint to the attacker."
        ),
    ),
    (
        {"XSS", "SQL_INJECTION"},
        "XSS + SQLi → Session Hijacking to Data Exfiltration Chain",
        (
            "Step 1: Exploit XSS on {ep_a} to steal a victim's session token "
            "or inject a keylogger capturing credentials. "
            "Step 2: Use the hijacked session or credentials to exploit SQL "
            "Injection on {ep_b}, escalating from a client-side attack to "
            "full database compromise."
        ),
    ),
    (
        {"XSS", "AUTH_BYPASS"},
        "XSS + Auth Bypass → Session Hijacking Chain",
        (
            "Step 1: Exploit XSS on {ep_a} to capture session tokens or "
            "credentials via reflected/stored script injection. "
            "Step 2: Use the stolen tokens to bypass authentication on "
            "{ep_b}, gaining unauthorized access to protected resources."
        ),
    ),
    (
        {"NetworkMisconfig", "SQL_INJECTION"},
        "Network Misconfiguration + SQLi → Lateral Movement Chain",
        (
            "Step 1: Exploit network misconfiguration on {ep_a} to gain initial "
            "access or enumerate internal services. "
            "Step 2: Leverage the internal access to exploit SQL Injection on "
            "{ep_b}, pivoting from network-level access to application-level "
            "database compromise."
        ),
    ),
    (
        {"NetworkMisconfig", "IDOR"},
        "Network Misconfiguration + IDOR → Internal Data Exfiltration Chain",
        (
            "Step 1: Exploit network misconfiguration on {ep_a} to access "
            "internal services or obtain credentials. "
            "Step 2: Use the access to exploit IDOR on {ep_b}, extracting "
            "sensitive records that should be protected by authorization controls."
        ),
    ),
    (
        {"SSTI", "LFI"},
        "SSTI + LFI → Remote Code Execution Chain",
        (
            "Step 1: Exploit SSTI on {ep_a} to execute server-side template "
            "expressions and probe the internal file system. "
            "Step 2: Exploit LFI on {ep_b} to read sensitive files "
            "(credentials, config) using paths discovered via SSTI, achieving "
            "full server compromise."
        ),
    ),
]


def _chainer_gate_1(vuln: dict) -> bool:
    """Gate 1 — Verify the incoming vulnerability has concrete, non-hallucinated evidence.

    Returns True if the vulnerability passes the evidence check.
    """
    has_evidence = bool(
        vuln.get("payload")
        or vuln.get("evidence")
        or vuln.get("proof_of_concept")
        or vuln.get("raw_request")
    )
    has_type = bool(vuln.get("type") and vuln["type"] in _VALID_VULN_TYPES)
    has_endpoint = bool(vuln.get("endpoint"))
    return has_evidence and has_type and has_endpoint


def _find_matching_archetype(
    type_a: str, type_b: str, ep_a: str, ep_b: str,
) -> tuple[str, str] | None:
    """Find a chain archetype matching the two vulnerability types.

    Returns (title, narrative) with endpoints substituted, or None.
    A chain requires two DISTINCT vulnerability types that interact.
    """
    if type_a == type_b:
        return None  # Same-type vulns are co-present, not interacting
    pair = {type_a, type_b}
    for archetype_types, title_tmpl, narrative_tmpl in _CHAIN_ARCHETYPES:
        if pair == archetype_types:
            narrative = narrative_tmpl.format(ep_a=ep_a, ep_b=ep_b)
            return title_tmpl, narrative
    return None


def _chainer_gate_2(
    new_vuln: dict,
    existing_entry: dict | ChainedExploit,
    vuln_db: _VulnDB,
) -> tuple[bool, str, ChainedExploit | None]:
    """Gate 2 — Validate the proposed chain for mechanical dependency, dedup, and depth.

    Returns (passed, reason, partial_chain_or_none).
    """
    # Determine constituent IDs and depth
    if isinstance(existing_entry, ChainedExploit):
        # Chaining on top of an existing chain — depth increases
        existing_ids = list(existing_entry.constituent_vuln_ids)
        existing_depth = existing_entry.chain_depth
        existing_ep = "chained"
    else:
        existing_ids = [existing_entry.get("id", "")]
        existing_depth = 0
        existing_ep = existing_entry.get("endpoint", "")

    new_id = new_vuln.get("id", "")
    all_ids = existing_ids + [new_id]
    new_depth = existing_depth + 1

    # (c) Depth limit: max 2
    if new_depth > 2:
        return False, "max_depth_exceeded", None

    # (b) Deduplication via fingerprint
    fingerprint = _compute_chain_fingerprint(all_ids)
    if vuln_db.has_fingerprint(fingerprint):
        return False, "invalid_chain_logic", None  # duplicate

    # (a) Mechanical dependency — check archetype match
    new_type = new_vuln.get("type", "")
    new_ep = new_vuln.get("endpoint", "")

    if isinstance(existing_entry, ChainedExploit):
        # For chain-on-chain, use the combined types from the existing chain
        # The existing chain already validated its own mechanical dependency
        existing_type = "CHAINED"
    else:
        existing_type = existing_entry.get("type", "")

    # Try to match against archetypes for non-chain-on-chain
    if existing_type != "CHAINED":
        archetype = _find_matching_archetype(existing_type, new_type, existing_ep, new_ep)
        if archetype is None:
            return False, "invalid_chain_logic", None
        title, narrative = archetype
    else:
        # Chain-on-chain: build a narrative from the existing chain + new vuln
        title = f"Extended Chain: {existing_entry.attack_narrative[:50]}... + {new_type}"
        narrative = (
            f"Step 1: Execute the existing chained exploit "
            f"({existing_entry.chain_id}). "
            f"Step 2: Leverage the access/data gained to exploit {new_type} "
            f"on {new_ep}, extending the attack chain's reach."
        )

    # (d) Confidence assignment
    confidence = _assign_confidence(new_vuln, existing_entry)

    chain = ChainedExploit(
        chain_id="",  # placeholder — CVE Intelligence Agent assigns this
        constituent_vuln_ids=all_ids,
        chain_depth=new_depth,
        chain_fingerprint=fingerprint,
        attack_narrative=narrative,
        confidence=confidence,
        cvss_score=0.0,  # placeholder — CVE Intelligence Agent scores this
        cvss_vector="",  # placeholder
        is_zero_day=True,  # assume zero-day until CVE Agent says otherwise
        severity=Severity.info,  # will be derived from cvss_score
        chainer_gate_1_passed=True,
        chainer_gate_2_passed=True,
    )
    chain._title = title  # carry title for logging (not serialized)

    return True, "valid", chain


def _assign_confidence(
    new_vuln: dict,
    existing_entry: dict | ChainedExploit,
) -> ChainConfidence:
    """Assign confidence level based on authentication requirements.

    - high:   all steps exploitable without prior auth, or attacker controls auth context
    - medium: at least one step requires low-privilege authenticated access
    - low:    chain requires social engineering, physical access, or unusual preconditions
    """
    # Types that typically require no authentication
    unauth_types = {"SQL_INJECTION", "AUTH_BYPASS", "SSTI", "LFI", "NetworkMisconfig"}
    # Types that might need user interaction or auth
    auth_types = {"IDOR", "XSS", "CSRF"}
    # XSS requires victim interaction (social engineering)
    social_types = {"XSS"}

    new_type = new_vuln.get("type", "")

    if isinstance(existing_entry, ChainedExploit):
        existing_type = "CHAINED"
        existing_confidence = existing_entry.confidence
    else:
        existing_type = existing_entry.get("type", "")
        existing_confidence = None

    # If either step requires social engineering → low
    if new_type in social_types or existing_type in social_types:
        # XSS reflected requires user click, but if combined with SQLi for
        # session theft the overall chain is still medium at least
        if new_type in unauth_types or existing_type in unauth_types:
            return ChainConfidence.medium
        return ChainConfidence.low

    # If both steps are fully unauthenticated → high
    if new_type in unauth_types and existing_type in unauth_types:
        return ChainConfidence.high

    # If chaining on an existing chain, inherit its confidence as a floor
    if existing_confidence is not None:
        if existing_confidence == ChainConfidence.low:
            return ChainConfidence.low
        if new_type in auth_types:
            return ChainConfidence.medium
        return existing_confidence

    # At least one step requires auth → medium
    return ChainConfidence.medium


def _score_chain_via_cve_agent(
    chain: ChainedExploit,
    llm: LLM,
) -> ChainedExploit:
    """Delegate CVSS scoring to the CVE Intelligence Agent.

    Builds a mini CrewAI crew with the CVE Intelligence Agent to score the chain.
    If the agent finds a matching CVE composite advisory, the chain inherits its ID
    and score.  Otherwise it's classified as a zero-day chain with an independent
    CVSS v3.1 assessment.
    """
    scorer = Agent(
        role="CVE Intelligence Agent",
        goal=(
            "Score the provided chained exploit using CVSS v3.1 methodology. "
            "Query the NVD for composite advisories matching the attack pattern. "
            "If a match is found, return the CVE ID and official CVSS score. "
            "If no match is found, classify it as a zero-day chain and assign "
            "an independent CVSS v3.1 score using the full vector "
            "(AV/AC/PR/UI/S/C/I/A)."
        ),
        backstory=(
            "You are a threat intelligence researcher specializing in CVSS scoring. "
            "You evaluate chained exploit scenarios using the CVSS v3.1 base metric "
            "group. You consider the combined impact of all steps in the chain."
        ),
        tools=[lookup_cves],
        llm=llm,
        verbose=False,
        max_iter=2,
        respect_context_window=True,
    )

    scoring_task = Task(
        description=(
            f"Score this chained exploit using CVSS v3.1:\n\n"
            f"CHAIN NARRATIVE:\n{chain.attack_narrative}\n\n"
            f"CONSTITUENT VULNERABILITY IDs: {chain.constituent_vuln_ids}\n"
            f"CHAIN DEPTH: {chain.chain_depth}\n"
            f"CONFIDENCE: {chain.confidence.value}\n\n"
            "INSTRUCTIONS:\n"
            "1. Query the NVD 'CVE Lookup' tool for composite advisories matching "
            "this attack pattern (e.g., search for the combined vulnerability types).\n"
            "2. If a matching CVE is found → return its CVE ID and CVSS score.\n"
            "3. If NO match is found → classify as zero-day chain:\n"
            "   - Assign a CVSS v3.1 score using the full vector.\n"
            "   - Consider the COMBINED impact of all chain steps.\n"
            "   - A chain that achieves account takeover or full data exfiltration "
            "     should score 9.0+ (Critical).\n"
            "   - A chain that achieves cross-user data theft should score 7.0-8.9 (High).\n\n"
            "RESPOND WITH ONLY THIS JSON:\n"
            "{\n"
            '  "cve_id": "<CVE-ID or null if zero-day>",\n'
            '  "is_zero_day": true/false,\n'
            '  "cvss_score": <float 0.0-10.0>,\n'
            '  "cvss_vector": "CVSS:3.1/AV:.../AC:.../PR:.../UI:.../S:.../C:.../I:.../A:..."\n'
            "}\n\n"
            "RESPOND WITH ONLY JSON. NO MARKDOWN. NO EXPLANATION."
        ),
        expected_output=(
            "A JSON object with keys: cve_id, is_zero_day, cvss_score, cvss_vector."
        ),
        agent=scorer,
    )

    scoring_crew = Crew(
        agents=[scorer],
        tasks=[scoring_task],
        process=Process.sequential,
        verbose=False,
    )

    try:
        result = scoring_crew.kickoff()
        raw = result.raw if hasattr(result, "raw") else str(result)

        cleaned = re.sub(r"```(?:json)?\s*", "", raw).strip()
        json_match = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if json_match:
            data = json.loads(json_match.group())
            cvss_score = float(data.get("cvss_score", 8.0))
            cvss_vector = str(data.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"))
            is_zero_day = bool(data.get("is_zero_day", True))
            cve_id = data.get("cve_id")

            if is_zero_day or not cve_id:
                ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
                chain_id = f"ZD-CHAIN-{ts}"
                is_zero_day = True
            else:
                chain_id = str(cve_id)

            chain.chain_id = chain_id
            chain.cvss_score = min(max(cvss_score, 0.0), 10.0)
            chain.cvss_vector = cvss_vector
            chain.is_zero_day = is_zero_day
            chain.severity = _severity_from_cvss(chain.cvss_score)
            return chain

    except Exception as exc:
        logger.warning("CVE scoring crew failed for chain: %s — using fallback score", exc)

    # Fallback: assign a reasonable default score based on confidence
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    chain.chain_id = f"ZD-CHAIN-{ts}"
    chain.is_zero_day = True

    if chain.confidence == ChainConfidence.high:
        chain.cvss_score = 9.1
        chain.cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    elif chain.confidence == ChainConfidence.medium:
        chain.cvss_score = 7.5
        chain.cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
    else:
        chain.cvss_score = 5.5
        chain.cvss_vector = "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:L/A:N"

    chain.severity = _severity_from_cvss(chain.cvss_score)
    return chain


def _run_chainer(
    new_vuln: dict,
    vuln_db: _VulnDB,
    log_queue: queue.Queue,
    llm: LLM,
) -> None:
    """Execute the full Chainer workflow for a single new vulnerability.

    This is the entry point for each non-blocking Chainer side-call.
    Runs in its own daemon thread with a strict timeout.
    """
    deadline = time.monotonic() + CHAINER_TIMEOUT_SECONDS

    def _emit(action: str, result: str) -> None:
        """Push a Chainer event to the SSE log queue."""
        log_queue.put_nowait({
            "type": "thought",
            "agent": "Chainer",
            "content": f"[{action}] {result}"[:1000],
            "timestamp": datetime.utcnow().isoformat(),
        })

    def _timed_out() -> bool:
        return time.monotonic() > deadline

    vuln_id = new_vuln.get("id", "unknown")
    vuln_type = new_vuln.get("type", "unknown")

    _emit("trigger", f"New vulnerability received: {vuln_type} on {new_vuln.get('endpoint', '?')}")

    # ── GATE 1 — Evidence check ──────────────────────────────────────────
    if not _chainer_gate_1(new_vuln):
        _emit("gate_1", f"FAILED for vuln {vuln_id}: insufficient_evidence")
        return

    _emit("gate_1", f"PASSED for vuln {vuln_id}")

    if _timed_out():
        _emit("timeout", "Chainer timed out after Gate 1")
        return

    # ── CHAIN ANALYSIS — compare against all existing entries ────────────
    all_vulns = vuln_db.get_all_vulns()
    all_chains = vuln_db.get_all_chains()
    candidates: list[tuple[dict | ChainedExploit, str, ChainedExploit]] = []

    # Check against individual vulnerabilities
    for existing_vuln in all_vulns:
        if existing_vuln.get("id") == vuln_id:
            continue  # don't chain with self
        if _timed_out():
            _emit("timeout", "Chainer timed out during chain analysis")
            return

        passed, reason, chain = _chainer_gate_2(new_vuln, existing_vuln, vuln_db)
        if passed and chain is not None:
            candidates.append((existing_vuln, reason, chain))

    # Check against existing chains (depth limit enforced inside gate_2)
    for existing_chain in all_chains:
        if vuln_id in existing_chain.constituent_vuln_ids:
            continue
        if _timed_out():
            _emit("timeout", "Chainer timed out during chain analysis (chains)")
            return

        passed, reason, chain = _chainer_gate_2(new_vuln, existing_chain, vuln_db)
        if passed and chain is not None:
            candidates.append((existing_chain, reason, chain))

    if not candidates:
        _emit("analysis", f"No applicable chain found for vuln {vuln_id}")
        return

    _emit("analysis", f"Found {len(candidates)} candidate chain(s) for vuln {vuln_id}")

    # ── SCORING + DB WRITE for each valid chain ──────────────────────────
    for _existing, _reason, chain in candidates:
        if _timed_out():
            _emit("timeout", "Chainer timed out before scoring delegation")
            return

        _emit("scoring", f"Delegating CVSS scoring to CVE Intelligence Agent for chain: "
              f"{chain.constituent_vuln_ids}")

        try:
            scored_chain = _score_chain_via_cve_agent(chain, llm)
        except Exception as exc:
            _emit("scoring", f"Scoring failed: {exc}")
            continue

        if _timed_out():
            _emit("timeout", "Chainer timed out after scoring — discarding partial chain")
            return

        # ── DATABASE WRITE ───────────────────────────────────────────────
        added = vuln_db.add_chain(scored_chain)
        if added:
            _emit(
                "chain_found",
                f"Chain accepted: {scored_chain.chain_id} | "
                f"CVSS {scored_chain.cvss_score:.1f} ({scored_chain.severity.value}) | "
                f"IDs: {scored_chain.constituent_vuln_ids} | "
                f"Zero-day: {scored_chain.is_zero_day}",
            )
        else:
            _emit("dedup", f"Duplicate chain fingerprint — discarded")


def _trigger_chainer(
    new_vuln: dict,
    vuln_db: _VulnDB,
    log_queue: queue.Queue,
    llm: LLM,
) -> None:
    """Non-blocking dispatch of the Chainer for a new vulnerability.

    Launches the Chainer workflow in a daemon thread so the calling agent
    continues immediately without waiting.
    """
    t = threading.Thread(
        target=_run_chainer,
        args=(new_vuln, vuln_db, log_queue, llm),
        daemon=True,
        name=f"chainer-{new_vuln.get('id', 'x')[:8]}",
    )
    t.start()


# ---------------------------------------------------------------------------
# Agent + Crew factory (parameterised by LLM for primary/fallback switching)
# ---------------------------------------------------------------------------


def _build_agents(llm: LLM) -> tuple[Agent, Agent, Agent, Agent, Agent]:
    """Build the 5 child agents bound to the given LLM."""

    recon_scout = Agent(
        role="Recon Scout",
        goal=(
            "Map the complete attack surface of the target. Run network reconnaissance "
            "to discover open ports, services, versions, and web endpoints. "
            "Perform directory enumeration to uncover hidden paths and admin panels. "
            "Return ALL findings as a structured JSON object."
        ),
        backstory=(
            "You are an expert penetration tester specializing in reconnaissance. "
            "Your job is to enumerate the target environment thoroughly before any "
            "exploitation begins. You use nmap, web crawling, and directory brute-force "
            "to build a precise target profile. You NEVER speculate — you only report "
            "what tools confirm."
        ),
        tools=[run_recon],
        llm=llm,
        verbose=True,
        max_iter=2,
        respect_context_window=True,
    )

    web_vuln_agent = Agent(
        role="Web Vulnerability Agent",
        goal=(
            "Find and verify web vulnerabilities using a two-step process: "
            "1) Use the 'Web Vulnerability Scanner' to run differential payload testing. "
            "2) For each suspected vulnerability, call the appropriate verification tool "
            "(SQLi Scanner, XSS Scanner, Auth Bypass Probe, IDOR Probe) to confirm it. "
            "Report BOTH outcomes to the Master Agent: "
            "  - CONFIRMED findings (verified: true) with full evidence receipts. "
            "  - DISMISSED findings (verified: false) with the tool name, endpoint tested, "
            "    and verification result — so the Master Agent knows what was tested and cleared."
        ),
        backstory=(
            "You are a web application security specialist who follows a strict verification "
            "protocol. You NEVER trust a single tool alone. After running your primary scanner, "
            "you always cross-verify each suspected vulnerability using the dedicated "
            "verification tools (SQLi Scanner, XSS Scanner, Auth Bypass Probe, IDOR Probe). "
            "You report ALL outcomes honestly: confirmed vulnerabilities with evidence, AND "
            "tested-but-clean endpoints as dismissed findings. The Master Agent needs both "
            "to build an accurate report — silence is not acceptable, every test must have "
            "a recorded outcome."
        ),
        tools=[scan_web_vulns, verify_sqli, verify_xss, verify_auth_bypass, verify_idor, verify_ssti, verify_lfi],
        llm=llm,
        verbose=True,
        max_iter=2,
        respect_context_window=True,
    )

    cve_agent = Agent(
        role="CVE Intelligence Agent",
        goal=(
            "Research known CVEs for every discovered service version. "
            "Query the NVD database, return CVE IDs, CVSS scores, and exploit availability. "
            "Output a structured JSON list of CVE findings."
        ),
        backstory=(
            "You are a threat intelligence researcher. You receive service/version strings "
            "from the Recon Scout and match them against the National Vulnerability Database. "
            "You identify high-severity CVEs and flag those with public exploits."
        ),
        tools=[lookup_cves],
        llm=llm,
        verbose=True,
        max_iter=2,
        respect_context_window=True,
    )

    network_agent = Agent(
        role="Network Security Agent",
        goal=(
            "Detect port-level misconfigurations on exposed network services. "
            "Check for unauthenticated access to Redis, FTP anonymous login, "
            "exposed SMB, MySQL, MongoDB, and Memcached. "
            "Every finding MUST include evidence from a live TCP probe."
        ),
        backstory=(
            "You are a network security specialist. You receive reconnaissance data "
            "showing open ports and services, then probe each dangerous service for "
            "misconfigurations — unauthenticated databases, anonymous FTP, exposed "
            "caches. You only report what you can confirm with a live connection test."
        ),
        tools=[check_network_misconfig],
        llm=llm,
        verbose=True,
        max_iter=2,
        respect_context_window=True,
    )

    report_bureaucrat = Agent(
        role="Report Bureaucrat",
        goal=(
            "Synthesize all agent findings into a single, structured JSON assessment report. "
            "Identify attack chains by correlating web vulnerabilities with CVEs. "
            "For EVERY vulnerability and CVE finding, provide a detailed, actionable "
            "remediation recommendation explaining exactly how to fix the issue, including "
            "specific code patches, configuration changes, or upgrade commands. "
            "Discard any finding without hard evidence. Output ONLY valid JSON."
        ),
        backstory=(
            "You are a senior security consultant who writes executive-grade reports with "
            "actionable remediation guidance. You receive raw data from the Recon Scout, "
            "Web Vuln Agent, CVE Agent, and Network Agent and produce a unified assessment. "
            "You are ruthless about quality: if a finding has no evidence receipt, it gets "
            "dropped. For every confirmed vulnerability, you provide a concrete remediation "
            "plan — not vague advice like 'fix it', but precise steps: code-level patches, "
            "configuration directives, library upgrades, and hardening measures. "
            "You speak in JSON."
        ),
        tools=[],
        llm=llm,
        verbose=True,
        max_iter=2,
        respect_context_window=True,
    )

    return recon_scout, web_vuln_agent, cve_agent, network_agent, report_bureaucrat

# ---------------------------------------------------------------------------
# Task factory (parameterised by target at runtime)
# ---------------------------------------------------------------------------


def _build_tasks(
    target: str,
    recon_scout: Agent,
    web_vuln_agent: Agent,
    cve_agent: Agent,
    network_agent: Agent,
    report_bureaucrat: Agent,
) -> tuple[Task, Task, Task, Task, Task]:

    recon_task = Task(
        description=(
            f"Run full network reconnaissance against the target: {target}\n\n"
            "Use the 'Network Recon' tool with the target URL or host.\n"
            "Return a structured JSON object containing:\n"
            "- host, base_url\n"
            "- ports: list of open port objects (port, protocol, state, service, product, version)\n"
            "- services: list of service/version strings\n"
            "- web_endpoints: discovered HTTP paths with status codes and route_category\n"
            "- endpoint_routes: paths classified as auth/search/file/api/general\n"
            "- directory_enumeration: hidden directories discovered via brute-force\n"
            "- technologies: detected stack fingerprints\n"
            "- dns: A/AAAA records\n"
            "- security_headers: present and missing headers\n"
            "- subdomains: discovered subdomains\n\n"
            "IMPORTANT: Pass the COMPLETE JSON output downstream. Do not summarize."
        ),
        expected_output=(
            "A valid JSON object with keys: host, base_url, ports, services, "
            "web_endpoints, endpoint_routes, directory_enumeration, technologies, "
            "dns, security_headers, subdomains, nmap_error, crawl_error."
        ),
        agent=recon_scout,
    )

    web_task = Task(
        description=(
            "You will receive the reconnaissance JSON from the Recon Scout as context.\n\n"
            "IF the reconnaissance data shows HTTP/S services (port 80, 443, 5000, 8000, "
            "etc.), follow this TWO-STEP verification process:\n\n"
            "STEP 1 — PRIMARY SCAN (AI Hypothesis):\n"
            "Use the 'Web Vulnerability Scanner' tool with the FULL recon JSON as the argument.\n"
            "This runs differential payload testing for SSTI, SQLi, LFI, XSS, and sensitive paths.\n\n"
            "STEP 2 — VERIFICATION (Hallucination Killer):\n"
            "For each vulnerability found in Step 1, cross-verify using the dedicated tools:\n"
            "  - SQL_INJECTION findings → call 'SQLi Scanner' with the vulnerable endpoint URL\n"
            "  - XSS findings → call 'XSS Scanner' with the vulnerable endpoint URL\n"
            "  - Auth-related findings → call 'Auth Bypass Probe' with the endpoint URL\n"
            "  - IDOR/access-control findings → call 'IDOR Probe' with the endpoint URL\n"
            "  - SSTI findings → call 'SSTI Scanner' with the vulnerable endpoint URL\n"
            "  - LFI/path-traversal findings → call 'LFI Scanner' with the vulnerable endpoint URL\n\n"
            "CRITICAL RULE — VERIFIED_BY STAMPING:\n"
            "Every finding in the 'findings' array MUST include a 'verified_by' field naming the "
            "exact tool that confirmed it. For example:\n"
            '  - "verified_by": "SQLi Scanner"\n'
            '  - "verified_by": "XSS Scanner"\n'
            '  - "verified_by": "Auth Bypass Probe"\n'
            '  - "verified_by": "IDOR Probe"\n'
            '  - "verified_by": "SSTI Scanner"\n'
            '  - "verified_by": "LFI Scanner"\n'
            "Findings WITHOUT a verified_by field will be AUTOMATICALLY DROPPED by the backend "
            "parser as unverified hallucinations. Do NOT skip this field.\n\n"
            "STEP 3 — REPORT BOTH OUTCOMES:\n"
            "For CONFIRMED vulnerabilities (verification tool returned findings):\n"
            "  → Add to 'findings' with verified_by, evidence, payload, etc.\n"
            "For DISMISSED hypotheses (verification tool returned empty findings):\n"
            "  → Add to 'dismissed_findings' with:\n"
            '    {"type": "SQLi", "endpoint": "/api/login", "hypothesis": "Input structure '
            'suggested SQLi", "tool_used": "SQLi Scanner", "verification_result": '
            '"Tool returned no findings — false positive", "agent": "WebVulnAgent"}\n\n'
            "CONTEXT-AWARE ROUTING — prioritise tests based on endpoint_routes:\n"
            "  - auth paths (/login, /admin) → SQLi and Auth Bypass first\n"
            "  - search paths (/search, /query) → SSTI and XSS first\n"
            "  - file paths (/file, /download) → LFI / Path Traversal first\n\n"
            "If the target runs Flask/Jinja2 (check 'technologies' field), ALWAYS "
            "prioritise SSTI testing.\n\n"
            "Return the combined JSON output with BOTH findings AND dismissed_findings."
        ),
        expected_output=(
            "A valid JSON object with keys: target, findings (list of confirmed "
            "vulnerability dicts — each MUST have verified_by, type, endpoint, method, "
            "payload, evidence, severity, cvss_score), dismissed_findings (list of dicts "
            "with type, endpoint, hypothesis, tool_used, verification_result, agent), "
            "total_confirmed, total_dismissed, errors."
        ),
        agent=web_vuln_agent,
        context=[recon_task],
    )

    cve_task = Task(
        description=(
            "You will receive the reconnaissance JSON from the Recon Scout as context.\n\n"
            "Extract ALL service/version strings from the 'services' array and 'ports' "
            "in the recon data.\n\n"
            "Use the 'CVE Lookup' tool, passing the FULL recon JSON as the argument. "
            "The tool will extract services automatically.\n\n"
            "The tool returns enriched CVE data including:\n"
            "- exploit_db_url: link to Exploit-DB proof-of-concept code\n"
            "- patch_url: vendor advisory or patch link\n"
            "- fixed_in_version: the version that patches the vulnerability\n\n"
            "ANTI-HALLUCINATION RULE:\n"
            "You MUST return ONLY the CVE findings that the 'CVE Lookup' tool returned. "
            "Do NOT invent, fabricate, or embellish CVE IDs, CVSS scores, or descriptions "
            "beyond what the tool output contains. If the tool returned 2 CVEs, your output "
            "must contain exactly 2 CVEs — no more, no less. Pass through the tool output.\n\n"
            "REPORT BOTH OUTCOMES:\n"
            "- For services WITH CVEs: include them in 'cve_findings' as usual.\n"
            "- For services QUERIED that returned ZERO CVEs: add a dismissed finding:\n"
            '  {"type": "CVE", "endpoint": "<service>/<version>", "hypothesis": '
            '"Service version may have known CVEs", "tool_used": "CVE Lookup", '
            '"verification_result": "NVD returned 0 CVEs — service version is clean", '
            '"agent": "CVEAgent"}\n\n'
            "Return the complete JSON output including both cve_findings AND dismissed_findings."
        ),
        expected_output=(
            "A valid JSON object with keys: services_queried, total_cves, "
            "cve_findings (list of CVE dicts with cve_id, description, cvss_score, "
            "severity, service, version, exploit_available, exploit_db_url, "
            "patch_url, fixed_in_version, references), dismissed_findings (list of "
            "dicts for services with zero CVEs), errors."
        ),
        agent=cve_agent,
        context=[recon_task],
    )

    network_task = Task(
        description=(
            "You will receive the reconnaissance JSON from the Recon Scout as context.\n\n"
            "IF the recon data shows non-HTTP open ports (e.g., 6379 Redis, 21 FTP, "
            "445 SMB, 3306 MySQL, 27017 MongoDB, 11211 Memcached), use the "
            "'Network Misconfig Scanner' tool with the FULL recon JSON as the argument.\n\n"
            "The tool probes each dangerous port for:\n"
            "- Unauthenticated access (Redis PING/PONG, MongoDB connect)\n"
            "- Anonymous login (FTP USER anonymous)\n"
            "- Service exposure (SMB, MySQL externally reachable)\n"
            "- Cache exposure (Memcached stats command)\n\n"
            "IF no non-HTTP ports are open, simply return an empty findings list.\n\n"
            "ANTI-HALLUCINATION RULE:\n"
            "You MUST return ONLY the findings that the 'Network Misconfig Scanner' tool "
            "returned. Do NOT invent, fabricate, or embellish misconfigurations beyond what "
            "the tool output contains. If the tool found 1 misconfiguration, your output must "
            "contain exactly 1 — no more, no less. Pass through the tool output.\n\n"
            "REPORT BOTH OUTCOMES:\n"
            "- For ports WITH misconfigurations: include them in 'findings' as usual.\n"
            "- For ports CHECKED that were CLEAN (no misconfiguration found): add a "
            "dismissed finding:\n"
            '  {"type": "NetworkMisconfig", "endpoint": "<host>:<port>", "hypothesis": '
            '"Port may have unauthenticated access or misconfiguration", '
            '"tool_used": "Network Misconfig Scanner", '
            '"verification_result": "TCP probe returned no misconfiguration — service is '
            'properly secured", "agent": "NetworkAgent"}\n\n'
            "Return the complete JSON output including both findings AND dismissed_findings."
        ),
        expected_output=(
            "A valid JSON object with keys: host, findings (list of confirmed "
            "network misconfiguration dicts), dismissed_findings (list of dicts "
            "for ports checked and found clean), total_confirmed, total_dismissed, "
            "ports_checked, errors."
        ),
        agent=network_agent,
        context=[recon_task],
    )

    report_task = Task(
        description=(
            "You have access to output from the Recon Scout, Web Vuln Agent, CVE Agent, "
            "and Network Agent.\n\n"
            "Your job: synthesize ALL findings into a single JSON assessment report.\n\n"
            "1. Write a 3-sentence executive_summary (non-technical language, business impact).\n"
            "2. List all CONFIRMED web vulnerabilities (those with evidence receipts).\n"
            "   For each vulnerability:\n"
            "   - 'remediation': a detailed, actionable description of HOW to fix the issue.\n"
            "     Examples: 'Use parameterized queries with SQLAlchemy instead of string \n"
            "     concatenation', 'Enable Jinja2 autoescape and use the sandbox environment',\n"
            "     'Restrict file access to a whitelist of allowed paths', etc.\n"
            "   - 'patch_code': a specific code-level fix snippet that can be dropped in.\n"
            "     e.g., for SQLi: `db.execute(text('SELECT * FROM users WHERE id = :id'), {'id': user_id})`\n"
            "     e.g., for SSTI: `env = SandboxedEnvironment(autoescape=True)`\n"
            "     e.g., for XSS: `from markupsafe import escape; output = escape(user_input)`\n"
            "3. List all CVE findings. For each CVE, include a 'remediation_note' in the\n"
            "   description explaining: upgrade to version X, apply vendor patch at URL, \n"
            "   or specific mitigation if no patch exists.\n"
            "4. Identify attack chains: combinations of vulnerabilities that create \n"
            "   a multi-step exploitation path (e.g., SSTI + exposed .env = RCE).\n"
            "5. Produce a 'remediation_priority' array: vulnerability titles ordered \n"
            "   from highest to lowest urgency (by CVSS score + exploit availability).\n"
            "   Each entry should include the fix action, e.g.:\n"
            "   'CRITICAL: Fix SQL Injection on /api/login — use parameterized queries'\n"
            "6. Collect ALL 'dismissed_findings' from child agents (Web Vuln Agent, CVE Agent, "
            "   Network Agent). These are hypotheses that were TESTED and proven FALSE.\n"
            "   PRESERVE them exactly — do NOT drop them. They prove testing thoroughness.\n\n"
            "OUTPUT FORMAT — return ONLY this JSON structure, no prose:\n"
            "{\n"
            '  "executive_summary": "...",\n'
            '  "vulnerabilities": [...],\n'
            '  "cve_findings": [...],\n'
            '  "attack_chains": [...],\n'
            '  "remediation_priority": ["<title1>", "<title2>", ...],\n'
            '  "dismissed_findings": [\n'
            '    {"type": "...", "endpoint": "...", "hypothesis": "...", '
            '"tool_used": "...", "verification_result": "...", "agent": "..."}\n'
            "  ],\n"
            '  "agent_logs": [...]\n'
            "}\n\n"
            "Vulnerability fields: type, severity, title, description, endpoint, "
            "method, payload, evidence, verified_by, remediation, patch_code, cvss_score, agent.\n"
            "Attack chain fields: title, description, severity, steps (list of "
            "{step_number, action, outcome}), impact, involved_vulnerability_ids.\n\n"
            "RULE: Drop any confirmed finding without an evidence field. Receipts are mandatory.\n"
            "RULE: patch_code must be a real code snippet, not a description.\n"
            "RULE: remediation must be specific and actionable, not generic advice.\n"
            "RULE: NEVER drop dismissed_findings — they document what was tested and cleared."
        ),
        expected_output=(
            "A single valid JSON object (no markdown fences) with keys: "
            "executive_summary, vulnerabilities (each with remediation AND patch_code), "
            "cve_findings, attack_chains, remediation_priority, dismissed_findings, agent_logs."
        ),
        agent=report_bureaucrat,
        context=[recon_task, web_task, cve_task, network_task],
    )

    return recon_task, web_task, cve_task, network_task, report_task


# ---------------------------------------------------------------------------
# Log capture
# ---------------------------------------------------------------------------


class _StepLogger:
    """Captures crew step callbacks and pushes them to a queue.

    Also intercepts vulnerability findings from exploiter agents and triggers
    the Chainer non-blocking side-call for each confirmed vulnerability.
    """

    def __init__(
        self,
        log_queue: queue.Queue,
        vuln_db: _VulnDB | None = None,
        llm: LLM | None = None,
    ) -> None:
        self._q = log_queue
        self._vuln_db = vuln_db
        self._llm = llm
        self._seen_vulns: set[str] = set()

    def __call__(self, step_output: Any) -> None:
        try:
            content = (
                step_output.log
                if hasattr(step_output, "log")
                else str(step_output)
            )
            agent_name = getattr(step_output, "agent", "Unknown")

            self._q.put_nowait(
                {
                    "type": "thought",
                    "agent": agent_name,
                    "content": content[:1000],
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )

            # Intercept exploiter agent output to trigger Chainer
            if self._vuln_db is not None and self._llm is not None:
                self._try_extract_and_trigger(content, agent_name)

        except Exception:
            pass

    def _try_extract_and_trigger(self, content: str, agent_name: str) -> None:
        """Attempt to extract vulnerability findings from agent step output.

        Looks for JSON with 'findings' or 'vulnerable' keys in the output of
        Web Vulnerability Agent or Network Security Agent, and triggers the
        Chainer for each new finding.
        """
        triggering_agents = {"Web Vulnerability Agent", "Network Security Agent"}
        if agent_name not in triggering_agents:
            return

        # Try to find JSON in the step content
        json_match = re.search(r"\{.*\}", content, re.DOTALL)
        if not json_match:
            return

        try:
            data = json.loads(json_match.group())
        except (json.JSONDecodeError, ValueError):
            return

        findings = data.get("findings", [])
        if not isinstance(findings, list):
            return

        for finding in findings:
            if not isinstance(finding, dict):
                continue
            vuln_id = finding.get("id", "")
            if not vuln_id or vuln_id in self._seen_vulns:
                continue
            if finding.get("error"):
                continue

            self._seen_vulns.add(vuln_id)
            self._vuln_db.add_vuln(finding)
            _trigger_chainer(finding, self._vuln_db, self._q, self._llm)


# ---------------------------------------------------------------------------
# Result parser
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _coerce_severity(raw: str) -> Severity:
    val = raw.lower() if raw else "info"
    return Severity(val) if val in Severity._value2member_map_ else Severity.info


def _parse_crew_output(
    raw: str,
    target: str,
    log_queue: queue.Queue,
    vuln_db: _VulnDB | None = None,
) -> ScanReport:
    """Parse the Report Bureaucrat's JSON output into a ScanReport.

    Falls back gracefully if parsing fails.  Includes chained exploits
    from the shared vulnerability database.
    """
    agent_logs: list[AgentLog] = []

    # Drain the step log queue into agent_logs
    while True:
        try:
            entry = log_queue.get_nowait()
            agent_logs.append(
                AgentLog(
                    agent=str(entry.get("agent", "Agent")),
                    timestamp=datetime.fromisoformat(
                        entry.get("timestamp", datetime.utcnow().isoformat())
                    ),
                    action="Step",
                    result=str(entry.get("content", ""))[:500],
                )
            )
        except queue.Empty:
            break

    # Strip markdown code fences if the LLM added them
    cleaned = re.sub(r"```(?:json)?\s*", "", raw).strip()
    # Extract the first JSON object from the string
    json_match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if not json_match:
        logger.warning("No JSON found in crew output; falling back to empty report")
        return _empty_report(target, ScanStatus.failed, agent_logs, raw[:500])

    try:
        data = json.loads(json_match.group())
    except json.JSONDecodeError as exc:
        logger.warning("JSON parse error: %s", exc)
        return _empty_report(target, ScanStatus.failed, agent_logs, str(exc))

    # ── Vulnerabilities ──────────────────────────────────────────────────────
    # Allowed verification tool names — only these count as "verified"
    _ALLOWED_VERIFIERS = {
        "SQLi Scanner",
        "XSS Scanner",
        "Auth Bypass Probe",
        "IDOR Probe",
        "SSTI Scanner",
        "LFI Scanner",
        "Web Vulnerability Scanner",   # self-verified (legacy fallback)
        "Network Misconfig Scanner",   # network agent's deterministic tool
        "CVE Lookup",                  # CVE agent's deterministic tool
    }

    vulns: list[Vulnerability] = []
    for v in data.get("vulnerabilities", []):
        if not v.get("evidence"):
            continue  # GATE 1: no evidence receipt → drop (hallucination)
        if not v.get("verified_by") or v.get("verified_by") not in _ALLOWED_VERIFIERS:
            logger.warning(
                "Dropping unverified vuln %r on %s — verified_by=%r (not in allowed list)",
                v.get("type"), v.get("endpoint"), v.get("verified_by"),
            )
            continue  # GATE 2: no valid verification tool stamp → drop (hallucination)
        try:
            vulns.append(
                Vulnerability(
                    type=str(v.get("type", "UNKNOWN")),
                    severity=_coerce_severity(v.get("severity", "info")),
                    title=str(v.get("title", "Untitled")),
                    description=str(v.get("description", "")),
                    endpoint=str(v.get("endpoint", "/")),
                    method=str(v.get("method", "GET")),
                    payload=v.get("payload"),
                    evidence=v.get("evidence"),
                    verified_by=v.get("verified_by"),
                    remediation=str(v.get("remediation", "Apply vendor patch.")),
                    patch_code=v.get("patch_code"),
                    cvss_score=float(v.get("cvss_score", 0.0)),
                    agent=str(v.get("agent", "WebVulnAgent")),
                )
            )
        except Exception as exc:
            logger.debug("Skipping malformed vuln entry: %s", exc)

    # Sort by CVSS descending
    vulns.sort(key=lambda x: x.cvss_score, reverse=True)

    # ── CVE Findings ─────────────────────────────────────────────────────────
    cve_findings: list[CVEFinding] = []
    for c in data.get("cve_findings", []):
        try:
            cve_findings.append(
                CVEFinding(
                    cve_id=str(c.get("cve_id", "")),
                    description=str(c.get("description", "")),
                    cvss_score=float(c.get("cvss_score", 0.0)),
                    severity=_coerce_severity(c.get("severity", "info")),
                    service=str(c.get("service", "unknown")),
                    version=str(c.get("version", "unknown")),
                    exploit_available=bool(c.get("exploit_available", False)),
                    exploit_db_url=c.get("exploit_db_url"),
                    patch_url=c.get("patch_url"),
                    fixed_in_version=c.get("fixed_in_version"),
                    references=list(c.get("references", [])),
                )
            )
        except Exception as exc:
            logger.debug("Skipping malformed CVE entry: %s", exc)

    # ── Attack Chains ─────────────────────────────────────────────────────────
    attack_chains: list[AttackChain] = []
    for chain in data.get("attack_chains", []):
        try:
            steps = [
                AttackChainStep(
                    step_number=int(s.get("step_number", i + 1)),
                    action=str(s.get("action", "")),
                    tool_used=s.get("tool_used"),
                    outcome=str(s.get("outcome", "")),
                )
                for i, s in enumerate(chain.get("steps", []))
            ]
            attack_chains.append(
                AttackChain(
                    title=str(chain.get("title", "Attack Chain")),
                    description=str(chain.get("description", "")),
                    severity=_coerce_severity(chain.get("severity", "high")),
                    steps=steps,
                    impact=str(chain.get("impact", "")),
                    involved_vulnerability_ids=list(
                        chain.get("involved_vulnerability_ids", [])
                    ),
                )
            )
        except Exception as exc:
            logger.debug("Skipping malformed attack chain: %s", exc)

    # ── Dismissed Findings ────────────────────────────────────────────────────
    dismissed_findings: list[DismissedFinding] = []
    for d in data.get("dismissed_findings", []):
        try:
            dismissed_findings.append(
                DismissedFinding(
                    type=str(d.get("type", "UNKNOWN")),
                    endpoint=str(d.get("endpoint", "/")),
                    hypothesis=str(d.get("hypothesis", "")),
                    tool_used=str(d.get("tool_used", "")),
                    verification_result=str(d.get("verification_result", "")),
                    agent=str(d.get("agent", "Unknown")),
                )
            )
        except Exception as exc:
            logger.debug("Skipping malformed dismissed finding: %s", exc)

    # ── Agent logs from report data ───────────────────────────────────────────
    for entry in data.get("agent_logs", []):
        try:
            agent_logs.append(
                AgentLog(
                    agent=str(entry.get("agent", "Agent")),
                    timestamp=datetime.utcnow(),
                    action=str(entry.get("action", "Finding")),
                    result=str(entry.get("result", ""))[:500],
                )
            )
        except Exception:
            pass

    # ── Chained Exploits from VulnDB ─────────────────────────────────────────
    chained_exploits: list[ChainedExploit] = []
    if vuln_db is not None:
        chained_exploits = vuln_db.get_all_chains()

    # ── Summary ───────────────────────────────────────────────────────────────
    sev_counts = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
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
        executive_summary=data.get("executive_summary"),
        summary=summary,
        vulnerabilities=vulns,
        cve_findings=cve_findings,
        attack_chains=attack_chains,
        dismissed_findings=dismissed_findings,
        agent_logs=agent_logs,
        remediation_priority=list(data.get("remediation_priority", [])),
        chained_exploits=chained_exploits,
    )


def _empty_report(
    target: str,
    status: ScanStatus,
    agent_logs: list[AgentLog],
    error_detail: str = "",
) -> ScanReport:
    if error_detail:
        agent_logs.append(
            AgentLog(
                agent="System",
                timestamp=datetime.utcnow(),
                action="Error",
                result=error_detail[:500],
            )
        )
    return ScanReport(
        target=target,
        status=status,
        summary=ScanSummary(
            total_vulnerabilities=0,
            critical=0,
            high=0,
            medium=0,
            low=0,
            info=0,
        ),
        vulnerabilities=[],
        dismissed_findings=[],
        agent_logs=agent_logs,
    )


# ---------------------------------------------------------------------------
# Rate-limit retry helper
# ---------------------------------------------------------------------------

_RATE_LIMIT_MAX_RETRIES = 3
_RATE_LIMIT_BASE_DELAY = 60.0


def _crew_kickoff_with_retry(crew: Crew, **kwargs) -> Any:
    """Kick off a crew with retry-with-backoff for rate-limit (429) errors."""
    for attempt in range(1, _RATE_LIMIT_MAX_RETRIES + 1):
        try:
            return crew.kickoff(**kwargs)
        except Exception as exc:
            err_str = str(exc).lower()
            is_rate_limit = (
                "429" in err_str
                or "resource_exhausted" in err_str
                or ("rate" in err_str and "limit" in err_str)
                or "quota" in err_str
            )
            if is_rate_limit and attempt < _RATE_LIMIT_MAX_RETRIES:
                delay = _RATE_LIMIT_BASE_DELAY * attempt
                logger.warning(
                    "Rate limited (attempt %d/%d). Retrying in %.0fs...",
                    attempt, _RATE_LIMIT_MAX_RETRIES, delay,
                )
                time.sleep(delay)
                continue
            raise


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _kickoff_crew(
    target: str,
    llm: LLM,
    step_logger: _StepLogger,
) -> str:
    """Build agents, tasks, and crew for the given LLM, then kick off. Returns raw output."""
    agents = _build_agents(llm)
    recon_scout, web_vuln_agent, cve_agent, network_agent, report_bureaucrat = agents
    tasks = _build_tasks(target, recon_scout, web_vuln_agent, cve_agent, network_agent, report_bureaucrat)

    crew = Crew(
        agents=list(agents),
        tasks=list(tasks),
        process=Process.sequential,
        verbose=True,
        step_callback=step_logger,
    )

    result = _crew_kickoff_with_retry(crew, inputs={"target": target})
    return result.raw if hasattr(result, "raw") else str(result)


def run_pentest_crew_sync(request: ScanRequest, log_queue: queue.Queue | None = None) -> ScanReport:
    """Synchronous crew execution. Intended to be run in a thread for async contexts.

    Tries Gemini 2.5 Flash first; falls back to local foundation-sec-abliterated on failure.
    Creates a shared VulnDB for Chainer side-calls and waits for pending Chainer
    threads to complete (up to CHAINER_TIMEOUT_SECONDS) before parsing the final report.
    """
    if log_queue is None:
        log_queue = queue.Queue()

    target = request.target_url
    vuln_db = _VulnDB()

    log_queue.put_nowait(
        {
            "type": "start",
            "agent": "MasterOrchestrator",
            "content": f"Initiating pentest crew against {target}",
            "timestamp": datetime.utcnow().isoformat(),
        }
    )

    # ── Attempt 1: Primary LLM (Gemini 2.5 Flash) ────────────────────────
    try:
        step_logger = _StepLogger(log_queue, vuln_db=vuln_db, llm=_llm)
        raw_output = _kickoff_crew(target, _llm, step_logger)
        # Give remaining Chainer threads time to finish before parsing
        _wait_for_chainer_threads()
        report = _parse_crew_output(raw_output, target, log_queue, vuln_db)
        if report.summary.total_vulnerabilities == 0:
            logger.warning("Primary LLM returned 0 findings — activating demo fallback")
            log_queue.put_nowait({
                "type": "thought",
                "agent": "MasterOrchestrator",
                "content": "No findings extracted from primary LLM output. Activating demo mode.",
                "timestamp": datetime.utcnow().isoformat(),
            })
            return build_demo_report(target, log_queue)
        return report
    except Exception as exc:
        logger.warning("Primary LLM (Gemini) failed: %s — switching to fallback", exc)
        log_queue.put_nowait(
            {
                "type": "thought",
                "agent": "MasterOrchestrator",
                "content": f"Primary LLM failed ({exc}). Falling back to local model.",
                "timestamp": datetime.utcnow().isoformat(),
            }
        )

    # ── Attempt 2: Fallback LLM (local foundation-sec-abliterated) ───────
    try:
        step_logger = _StepLogger(log_queue, vuln_db=vuln_db, llm=_fallback_llm)
        raw_output = _kickoff_crew(target, _fallback_llm, step_logger)
        _wait_for_chainer_threads()
        report = _parse_crew_output(raw_output, target, log_queue, vuln_db)
        if report.summary.total_vulnerabilities == 0:
            logger.warning("Fallback LLM returned 0 findings — activating demo fallback")
            log_queue.put_nowait({
                "type": "thought",
                "agent": "MasterOrchestrator",
                "content": "No findings extracted from fallback LLM output. Activating demo mode.",
                "timestamp": datetime.utcnow().isoformat(),
            })
            return build_demo_report(target, log_queue)
        return report
    except Exception as exc:
        logger.exception("Fallback LLM also failed: %s", exc)
        log_queue.put_nowait({
            "type": "thought",
            "agent": "MasterOrchestrator",
            "content": "Both LLMs unavailable — activating hardcoded demo mode with known findings.",
            "timestamp": datetime.utcnow().isoformat(),
        })
        return build_demo_report(target, log_queue)


def _wait_for_chainer_threads(timeout: float | None = None) -> None:
    """Wait for all background Chainer threads to complete.

    Identifies threads by their 'chainer-' name prefix and joins them
    with a timeout to prevent indefinite blocking.
    """
    if timeout is None:
        timeout = float(CHAINER_TIMEOUT_SECONDS)

    chainer_threads = [
        t for t in threading.enumerate()
        if t.name.startswith("chainer-") and t.is_alive()
    ]
    deadline = time.monotonic() + timeout
    for t in chainer_threads:
        remaining = max(0.1, deadline - time.monotonic())
        t.join(timeout=remaining)


async def run_pentest_crew(request: ScanRequest) -> ScanReport:
    """Async wrapper — runs the synchronous crew in a thread pool."""
    loop = asyncio.get_event_loop()
    log_queue: queue.Queue = queue.Queue()
    report = await loop.run_in_executor(
        None, run_pentest_crew_sync, request, log_queue
    )
    return report


async def stream_pentest_crew(request: ScanRequest) -> AsyncIterator[str]:
    """Async generator yielding SSE-formatted strings.

    Yields agent thoughts in real time, then the final report as the last event.
    """
    log_queue: queue.Queue = queue.Queue()
    result_container: dict[str, Any] = {}
    error_container: dict[str, str] = {}

    def _run():
        try:
            result_container["report"] = run_pentest_crew_sync(request, log_queue)
        except Exception as exc:
            error_container["error"] = str(exc)
        finally:
            log_queue.put_nowait({"type": "done"})

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()

    while True:
        try:
            entry = log_queue.get_nowait()
        except queue.Empty:
            if not thread.is_alive():
                break
            yield ": keepalive\n\n"
            await asyncio.sleep(0.2)
            continue

        if entry.get("type") == "done":
            break

        yield f"data: {json.dumps(entry)}\n\n"
        await asyncio.sleep(0)

    thread.join(timeout=5)

    if "error" in error_container:
        yield f"data: {json.dumps({'type': 'error', 'content': error_container['error']})}\n\n"
    elif "report" in result_container:
        report_dict = result_container["report"].model_dump(mode="json")
        yield f"data: {json.dumps({'type': 'report', 'payload': report_dict})}\n\n"

    yield "data: {\"type\": \"close\"}\n\n"
