"""
Project Argus — FastAPI Entry Point
Person 1 owns this file.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.models import ScanRequest, ScanReport
from backend.agents.crew import run_pentest_crew

app = FastAPI(title="Project Argus", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["POST"],
    allow_headers=["Content-Type"],
)


@app.post("/api/scan", response_model=ScanReport)
async def run_scan(payload: ScanRequest) -> ScanReport:
    """
    Accepts a ScanRequest JSON body, kicks off the CrewAI pentest pipeline,
    and returns a structured ScanReport.
    """
    return await run_pentest_crew(payload)


@app.get("/api/health")
async def health():
    return {"status": "ok"}
