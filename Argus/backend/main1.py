"""
Project Argus — FastAPI Entry Point
Person 1 owns this file.
"""

import asyncio
import json
import queue
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, StreamingResponse

from backend.agents.crew1 import run_pentest_crew_sync, stream_pentest_crew
from backend.agents.pdf_engine import generate_pdf
from backend.blockchain import anchor_hash, verify_hash_on_chain
from backend.models1 import (
    AnchorResponse,
    ScanReport,
    ScanRequest,
    ScanStartResponse,
    ScanStatusResponse,
    VerifyRequest,
)
from backend.tools.scanner import (
    sqli_scan_tool,
    xss_scan_tool,
    auth_bypass_tool,
    idor_probe_tool,
    _deterministic_sqli_scan,
    _deterministic_xss_scan,
    _deterministic_auth_bypass,
    _deterministic_idor_probe,
    _deterministic_ssti_scan,
    _deterministic_lfi_scan,
)

app = FastAPI(title="Project Argus", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Accept"],
    allow_credentials=False,
)

# ---------------------------------------------------------------------------
# In-memory scan store
# ---------------------------------------------------------------------------


@dataclass
class ScanState:
    scan_id: str
    request: ScanRequest
    status: str = "running"            # "running" | "complete" | "failed"
    log_events: list = field(default_factory=list)  # all events, for SSE replay
    report: Optional[ScanReport] = None
    error: Optional[str] = None


class _EventQueue(queue.Queue):
    """
    Queue sub-class that mirrors every item into ScanState.log_events
    so late-connecting SSE clients can replay the full event history.
    """

    def __init__(self, state: ScanState) -> None:
        super().__init__()
        self._state = state

    def put_nowait(self, item) -> None:          # type: ignore[override]
        self._state.log_events.append(item)
        super().put_nowait(item)


_scans: dict[str, ScanState] = {}

# Agent role names as CrewAI reports them (used for percent calculation)
_AGENT_ROLES = {
    "Recon Scout",
    "Web Vulnerability Agent",
    "CVE Intelligence Agent",
    "Network Security Agent",
    "Report Bureaucrat",
}


def _run_scan_in_thread(state: ScanState) -> None:
    """Blocking crew execution — runs in a dedicated daemon thread."""
    log_queue = _EventQueue(state)
    try:
        report = run_pentest_crew_sync(state.request, log_queue)
        state.report = report
        state.status = report.status.value          # "complete" or "failed"
    except Exception as exc:
        state.status = "failed"
        state.error = str(exc)
        log_queue.put_nowait(
            {"type": "error", "content": str(exc), "timestamp": datetime.utcnow().isoformat()}
        )
    finally:
        log_queue.put_nowait({"type": "done", "timestamp": datetime.utcnow().isoformat()})


# ---------------------------------------------------------------------------
# POST /api/scan  — non-blocking, returns scan_id immediately
# POST /api/v1/scan — alias
# ---------------------------------------------------------------------------


@app.post("/api/scan", response_model=ScanStartResponse)
async def run_scan(payload: ScanRequest) -> ScanStartResponse:
    """
    Start a pentest scan. Returns a scan_id immediately.
    Track progress via GET /api/scan/{id}/stream or /api/scan/{id}/status.
    Retrieve the full report via GET /api/scan/{id}/report once complete.
    """
    scan_id = str(uuid.uuid4())
    state = ScanState(scan_id=scan_id, request=payload)
    _scans[scan_id] = state
    threading.Thread(target=_run_scan_in_thread, args=(state,), daemon=True).start()
    return ScanStartResponse(scan_id=scan_id, status="running")


@app.post("/api/v1/scan", response_model=ScanStartResponse)
async def run_scan_v1(payload: ScanRequest) -> ScanStartResponse:
    """Alias for POST /api/scan."""
    return await run_scan(payload)


# ---------------------------------------------------------------------------
# GET /api/scan/{scan_id}/stream  — SSE, replays history then streams live
# ---------------------------------------------------------------------------


async def _sse_generator(state: ScanState):
    sent_idx = 0

    while True:
        # Drain buffered events (handles late-connecting clients via replay)
        while sent_idx < len(state.log_events):
            event = state.log_events[sent_idx]
            sent_idx += 1

            if event.get("type") == "done":
                if state.report:
                    payload = state.report.model_dump(mode="json")
                    yield f"data: {json.dumps({'type': 'report', 'payload': payload})}\n\n"
                elif state.error:
                    yield f"data: {json.dumps({'type': 'error', 'content': state.error})}\n\n"
                yield 'data: {"type": "close"}\n\n'
                return

            yield f"data: {json.dumps(event)}\n\n"

        # Scan finished but "done" event not yet seen — check and exit
        if state.status != "running" and sent_idx >= len(state.log_events):
            if state.report:
                payload = state.report.model_dump(mode="json")
                yield f"data: {json.dumps({'type': 'report', 'payload': payload})}\n\n"
            yield 'data: {"type": "close"}\n\n'
            return

        yield ": keepalive\n\n"
        await asyncio.sleep(0.2)


@app.get("/api/scan/{scan_id}/stream")
async def stream_scan(scan_id: str) -> StreamingResponse:
    """
    SSE stream for a running or completed scan.
    Replays all past events first, then streams new ones live.
    Compatible with the browser's native EventSource API.
    """
    state = _scans.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    return StreamingResponse(
        _sse_generator(state),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ---------------------------------------------------------------------------
# GET /api/scan/{scan_id}/status  — polling fallback for agent stepper
# ---------------------------------------------------------------------------


@app.get("/api/scan/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str) -> ScanStatusResponse:
    """
    Returns current scan progress. Poll every 2 s as an EventSource fallback.
    Drives the agent stepper and progress bar on the frontend.
    """
    state = _scans.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")

    active_agent = "MasterOrchestrator"
    agents_seen: set[str] = set()

    for event in state.log_events:
        if event.get("type") == "thought":
            agent = str(event.get("agent", ""))
            if agent and agent not in ("Unknown", ""):
                agents_seen.add(agent)
                active_agent = agent        # last one wins

    agents_done = list(agents_seen & _AGENT_ROLES)
    percent = (
        100
        if state.status != "running"
        else min(int(len(agents_done) / 5 * 100), 99)
    )

    return ScanStatusResponse(
        scan_id=scan_id,
        status=state.status,
        active_agent=active_agent,
        agents_done=agents_done,
        percent=percent,
        error=state.error,
    )


# ---------------------------------------------------------------------------
# GET /api/scan/{scan_id}/report  — final report retrieval
# ---------------------------------------------------------------------------


@app.get("/api/scan/{scan_id}/report", response_model=ScanReport)
async def get_scan_report(scan_id: str) -> ScanReport:
    """
    Returns the completed ScanReport. Call after status.percent == 100
    or after receiving a 'report' SSE event.
    Returns HTTP 202 if the scan is still running.
    """
    state = _scans.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    if state.status == "running":
        raise HTTPException(status_code=202, detail="Scan still in progress")
    if not state.report:
        raise HTTPException(
            status_code=500, detail=state.error or "Scan failed with no report"
        )
    return state.report


# ---------------------------------------------------------------------------
# GET /api/scan/{scan_id}/report/pdf  — downloadable PDF advisory
# ---------------------------------------------------------------------------


@app.get("/api/scan/{scan_id}/report/pdf")
async def get_scan_report_pdf(scan_id: str) -> Response:
    """
    Returns a professional PDF security advisory.
    Includes executive summary, risk matrix, detailed findings with evidence,
    CVE intelligence with Exploit-DB links, attack chains, and remediation.
    """
    state = _scans.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    if state.status == "running":
        raise HTTPException(status_code=202, detail="Scan still in progress")
    if not state.report:
        raise HTTPException(
            status_code=500, detail=state.error or "Scan failed with no report"
        )
    pdf_bytes = generate_pdf(state.report)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=argus-{scan_id[:8]}.pdf",
        },
    )


# ---------------------------------------------------------------------------
# POST /api/scan/{scan_id}/report/anchor  — anchor PDF hash on Sepolia
# ---------------------------------------------------------------------------


@app.post("/api/scan/{scan_id}/report/anchor", response_model=AnchorResponse)
async def anchor_report(scan_id: str) -> AnchorResponse:
    """
    Generate PDF, hash it, store the hash on Sepolia, return tx details.
    Takes ~15 seconds (Sepolia block time).
    """
    state = _scans.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    if state.status == "running":
        raise HTTPException(status_code=202, detail="Scan still in progress")
    if not state.report:
        raise HTTPException(
            status_code=500, detail=state.error or "Scan failed with no report"
        )
    pdf_bytes = generate_pdf(state.report)
    result = await asyncio.to_thread(anchor_hash, pdf_bytes)
    return AnchorResponse(
        pdf_hash=result.pdf_hash,
        tx_hash=result.tx_hash,
        block_number=result.block_number,
        block_timestamp=result.block_timestamp,
        etherscan_url=result.etherscan_url,
    )


# ---------------------------------------------------------------------------
# GET /api/verify/{pdf_hash}  — check if a hash exists on-chain
# ---------------------------------------------------------------------------


@app.get("/api/verify/{pdf_hash}")
async def verify_report_hash(pdf_hash: str):
    """Check if a report hash has been anchored on-chain."""
    result = await asyncio.to_thread(verify_hash_on_chain, pdf_hash)
    return result


# ---------------------------------------------------------------------------
# POST /api/v1/scan/stream  — inline SSE (fire-and-stream, no scan_id needed)
# Kept for backward compat / alternative integration pattern.
# ---------------------------------------------------------------------------


@app.post("/api/v1/scan/stream")
async def run_scan_stream_inline(payload: ScanRequest) -> StreamingResponse:
    """
    Starts scan and streams results in the same HTTP connection.
    No scan_id. Alternative to the POST → GET /stream pattern.
    """
    return StreamingResponse(
        stream_pentest_crew(payload),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ---------------------------------------------------------------------------
# Person 2 — Verification API endpoints
# Child agents POST here to get deterministic ground-truth verification.
# Each route wraps Person 2's tool and returns its JSON response.
# ---------------------------------------------------------------------------


@app.post("/api/verify/sqli")
async def verify_sqli(req: VerifyRequest):
    """Person 2's SQL Injection verification. Deterministic — no LLM needed."""
    raw = _deterministic_sqli_scan(req.target_url)
    return json.loads(raw)


@app.post("/api/verify/xss")
async def verify_xss(req: VerifyRequest):
    """Person 2's XSS verification. Deterministic — no LLM needed."""
    raw = _deterministic_xss_scan(req.target_url)
    return json.loads(raw)


@app.post("/api/verify/auth-bypass")
async def verify_auth_bypass(req: VerifyRequest):
    """Person 2's Auth Bypass verification. Deterministic — no LLM needed."""
    raw = _deterministic_auth_bypass(req.target_url)
    return json.loads(raw)


@app.post("/api/verify/idor")
async def verify_idor(req: VerifyRequest):
    """Person 2's IDOR verification. Deterministic — no LLM needed."""
    raw = _deterministic_idor_probe(req.target_url)
    return json.loads(raw)


@app.post("/api/verify/ssti")
async def verify_ssti(req: VerifyRequest):
    """Person 2's SSTI verification. Deterministic — no LLM needed."""
    raw = _deterministic_ssti_scan(req.target_url)
    return json.loads(raw)


@app.post("/api/verify/lfi")
async def verify_lfi(req: VerifyRequest):
    """Person 2's LFI verification. Deterministic — no LLM needed."""
    raw = _deterministic_lfi_scan(req.target_url)
    return json.loads(raw)


# ---------------------------------------------------------------------------
# GET /api/health
# ---------------------------------------------------------------------------


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}
