"""
Pydantic models — the single source of truth for the JSON contract.
Both Person 1 and Person 4 live and die by these schemas.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class ScanMode(str, Enum):
    quick = "quick"
    full = "full"
    focused = "focused"


class Module(str, Enum):
    sqli = "sqli"
    xss = "xss"
    auth = "auth"
    idor = "idor"
    csrf = "csrf"
    path_traversal = "path_traversal"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class ScanStatus(str, Enum):
    complete = "complete"
    running = "running"
    failed = "failed"


class ChainConfidence(str, Enum):
    """Confidence level for a chained exploit."""
    high = "high"
    medium = "medium"
    low = "low"


# ---------------------------------------------------------------------------
# Request schema  (Frontend → Backend)
# ---------------------------------------------------------------------------


class ScanOptions(BaseModel):
    depth: int = Field(default=3, ge=1, le=10)
    timeout: int = Field(default=30, ge=5, le=120)
    verbose: bool = False


class VerifyRequest(BaseModel):
    """Request body for Person 2's verification API endpoints."""
    target_url: str = Field(
        ...,
        description="URL of the endpoint to verify for a specific vulnerability.",
    )


class ScanRequest(BaseModel):
    target_url: str = Field(
        ...,
        examples=["http://localhost:5000"],
        description="Base URL of the target application.",
    )
    scan_mode: ScanMode = ScanMode.full
    modules: List[Module] = Field(
        default=[Module.sqli, Module.xss, Module.auth, Module.idor]
    )
    options: ScanOptions = ScanOptions()


# ---------------------------------------------------------------------------
# Response schema  (Backend → Frontend)
# ---------------------------------------------------------------------------


class AgentLog(BaseModel):
    agent: str
    timestamp: datetime
    action: str
    result: str


class Vulnerability(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: str
    severity: Severity
    title: str
    description: str
    endpoint: str
    method: str
    payload: Optional[str] = None
    evidence: Optional[str] = None
    verified_by: Optional[str] = Field(
        default=None,
        description="Name of the Person 2 verification tool that confirmed this finding. "
                    "Web vulns without this field are treated as unverified hallucinations.",
    )
    remediation: str
    patch_code: Optional[str] = None
    cvss_score: float = Field(ge=0.0, le=10.0)
    agent: str


class ScanSummary(BaseModel):
    total_vulnerabilities: int
    critical: int
    high: int
    medium: int
    low: int
    info: int


class CVEFinding(BaseModel):
    cve_id: str
    description: str
    cvss_score: float = Field(ge=0.0, le=10.0)
    severity: Severity
    service: str
    version: str
    exploit_available: bool = False
    exploit_db_url: Optional[str] = None
    patch_url: Optional[str] = None
    fixed_in_version: Optional[str] = None
    references: List[str] = Field(default_factory=list)


class AttackChainStep(BaseModel):
    step_number: int
    action: str
    tool_used: Optional[str] = None
    outcome: str


class DismissedFinding(BaseModel):
    """A vulnerability hypothesis that was tested and proven FALSE."""
    type: str
    endpoint: str
    hypothesis: str
    tool_used: str
    verification_result: str
    agent: str


class AttackChain(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    severity: Severity
    steps: List[AttackChainStep]
    impact: str
    involved_vulnerability_ids: List[str] = Field(default_factory=list)


class ScanStartResponse(BaseModel):
    scan_id: str
    status: str = "running"


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str
    active_agent: str
    agents_done: List[str]
    percent: int
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Chained Exploit model (Chainer sub-agent output)
# ---------------------------------------------------------------------------


def _compute_chain_fingerprint(vuln_ids: List[str]) -> str:
    """Compute a deterministic fingerprint from sorted constituent vulnerability IDs."""
    canonical = ",".join(sorted(vuln_ids))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _severity_from_cvss(score: float) -> Severity:
    """Derive CVSS v3.1 severity band from a numeric score."""
    if score >= 9.0:
        return Severity.critical
    if score >= 7.0:
        return Severity.high
    if score >= 4.0:
        return Severity.medium
    if score >= 0.1:
        return Severity.low
    return Severity.info


class ChainedExploit(BaseModel):
    """A multi-step exploit chain composed of two or more individual vulnerabilities."""

    chain_id: str = Field(
        description="Unique identifier — 'ZD-CHAIN-<timestamp>' for zero-days, or the matched CVE ID.",
    )
    constituent_vuln_ids: List[str] = Field(
        description="IDs of the vulnerabilities that form this chain.",
        min_length=2,
    )
    chain_depth: int = Field(
        ge=1, le=2,
        description="Nesting depth of this chain. Max 2 (one previously chained finding allowed).",
    )
    chain_fingerprint: str = Field(
        description="SHA-256 hash of sorted constituent_vuln_ids — used for deduplication.",
    )
    attack_narrative: str = Field(
        description="Step-by-step description of the full chained attack.",
    )
    confidence: ChainConfidence = Field(
        description="Chainer-assigned confidence level: high, medium, or low.",
    )
    cvss_score: float = Field(
        ge=0.0, le=10.0,
        description="CVSS v3.1 score assigned by the CVE Intelligence Agent.",
    )
    cvss_vector: str = Field(
        description="Full CVSS v3.1 vector string (e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N).",
    )
    is_zero_day: bool = Field(
        description="True if no matching NVD CVE was found — classified as a zero-day chain.",
    )
    severity: Severity = Field(
        description="Derived from cvss_score using standard CVSS severity bands.",
    )
    discovered_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of chain discovery.",
    )
    chainer_gate_1_passed: bool = Field(
        description="True if Gate 1 (evidence check) passed — audit trail.",
    )
    chainer_gate_2_passed: bool = Field(
        description="True if Gate 2 (logical validity check) passed — audit trail.",
    )

    @field_validator("chain_fingerprint", mode="before")
    @classmethod
    def _validate_fingerprint(cls, v: str, info) -> str:
        """Ensure fingerprint matches the constituent IDs if both are provided."""
        vuln_ids = info.data.get("constituent_vuln_ids")
        if vuln_ids:
            expected = _compute_chain_fingerprint(vuln_ids)
            if v != expected:
                return expected
        return v

    @field_validator("severity", mode="before")
    @classmethod
    def _derive_severity(cls, v, info) -> Severity | str:
        """Auto-derive severity from cvss_score when not explicitly set."""
        score = info.data.get("cvss_score")
        if score is not None:
            return _severity_from_cvss(float(score))
        if isinstance(v, str):
            return Severity(v.lower()) if v.lower() in Severity._value2member_map_ else Severity.info
        return v


class ScanReport(BaseModel):
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    target: str
    status: ScanStatus
    # Existing required fields (frontend contract)
    summary: ScanSummary
    vulnerabilities: List[Vulnerability]
    agent_logs: List[AgentLog]
    # Extended fields from Master Directive (optional for backward compat)
    executive_summary: Optional[str] = None
    cve_findings: List[CVEFinding] = Field(default_factory=list)
    attack_chains: List[AttackChain] = Field(default_factory=list)
    raw_recon: Optional[Dict] = None
    remediation_priority: List[str] = Field(default_factory=list)
    dismissed_findings: List[DismissedFinding] = Field(default_factory=list)
    chained_exploits: List[ChainedExploit] = Field(default_factory=list)


class AnchorResponse(BaseModel):
    """Response from the blockchain anchoring endpoint."""
    pdf_hash: str
    tx_hash: str
    block_number: int
    block_timestamp: int
    etherscan_url: str
