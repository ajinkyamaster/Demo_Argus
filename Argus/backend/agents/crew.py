"""
CrewAI Pentest Crew — Person 1's domain.
Define agents and tasks here. Wire in tools from backend/tools/.
"""

from __future__ import annotations

from datetime import datetime

from crewai import Agent, Crew, Task

from backend.models import (
    AgentLog,
    ScanReport,
    ScanRequest,
    ScanStatus,
    ScanSummary,
    Vulnerability,
)
from backend.tools.scanner import (
    auth_bypass_tool,
    idor_probe_tool,
    sqli_scan_tool,
    xss_scan_tool,
)


# ---------------------------------------------------------------------------
# Agent definitions
# ---------------------------------------------------------------------------

recon_agent = Agent(
    role="Recon Specialist",
    goal="Map the attack surface of the target application.",
    backstory=(
        "You are an expert in passive and active reconnaissance. "
        "You enumerate endpoints, identify technologies, and build a "
        "comprehensive target profile before any exploitation begins."
    ),
    tools=[],
    verbose=True,
)

sqli_agent = Agent(
    role="SQL Injection Hunter",
    goal="Identify and verify SQL injection vulnerabilities.",
    backstory=(
        "You specialize in finding SQL injection flaws — blind, error-based, "
        "and time-based. You craft payloads and verify exploitability."
    ),
    tools=[sqli_scan_tool],
    verbose=True,
)

xss_agent = Agent(
    role="XSS Specialist",
    goal="Find stored, reflected, and DOM-based XSS vulnerabilities.",
    backstory=(
        "You hunt cross-site scripting vectors across all user-controlled "
        "inputs. You prove exploitability with minimal payloads."
    ),
    tools=[xss_scan_tool],
    verbose=True,
)

auth_agent = Agent(
    role="Authentication Auditor",
    goal="Break authentication and session management controls.",
    backstory=(
        "You test for weak credentials, insecure session tokens, "
        "auth bypass, and broken access control patterns."
    ),
    tools=[auth_bypass_tool, idor_probe_tool],
    verbose=True,
)

report_agent = Agent(
    role="Report Compiler",
    goal="Aggregate findings and produce a clean, structured vulnerability report.",
    backstory=(
        "You synthesize raw findings from other agents into a concise, "
        "actionable report prioritised by CVSS score."
    ),
    tools=[],
    verbose=True,
)


# ---------------------------------------------------------------------------
# Crew assembly
# ---------------------------------------------------------------------------


async def run_pentest_crew(request: ScanRequest) -> ScanReport:
    """
    Orchestrates the pentest crew against request.target_url.
    Returns a ScanReport conforming to the agreed JSON contract.

    TODO: Replace stub return with real CrewAI .kickoff() results.
    """

    # ── Stub — replace with real crew execution ──────────────────────────
    stub_vulns: list[Vulnerability] = []
    stub_logs: list[AgentLog] = [
        AgentLog(
            agent="ReconAgent",
            timestamp=datetime.utcnow(),
            action="Endpoint enumeration",
            result=f"Mapped target: {request.target_url}",
        )
    ]

    summary = ScanSummary(
        total_vulnerabilities=0,
        critical=0,
        high=0,
        medium=0,
        low=0,
        info=0,
    )

    return ScanReport(
        target=request.target_url,
        status=ScanStatus.complete,
        summary=summary,
        vulnerabilities=stub_vulns,
        agent_logs=stub_logs,
    )
    # ── End stub ──────────────────────────────────────────────────────────
