"""
Pydantic models — the single source of truth for the JSON contract.
Both Person 1 and Person 4 live and die by these schemas.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


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


# ---------------------------------------------------------------------------
# Request schema  (Frontend → Backend)
# ---------------------------------------------------------------------------


class ScanOptions(BaseModel):
    depth: int = Field(default=3, ge=1, le=10)
    timeout: int = Field(default=30, ge=5, le=120)
    verbose: bool = False


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
    remediation: str
    cvss_score: float = Field(ge=0.0, le=10.0)
    agent: str


class ScanSummary(BaseModel):
    total_vulnerabilities: int
    critical: int
    high: int
    medium: int
    low: int
    info: int


class ScanReport(BaseModel):
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    target: str
    status: ScanStatus
    summary: ScanSummary
    vulnerabilities: List[Vulnerability]
    agent_logs: List[AgentLog]
