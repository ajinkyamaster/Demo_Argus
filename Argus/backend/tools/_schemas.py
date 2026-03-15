"""
Pydantic models for structured sub-agent output.

These models are used as `output_json` on CrewAI Task objects to force
the LLM to return parseable, validated JSON rather than free-form text.
"""

from typing import Optional

from pydantic import BaseModel, Field


class PayloadProposal(BaseModel):
    """Structured output of the Payload Crafter agent."""

    payload: str = Field(
        description="The raw exploit payload string to inject"
    )
    injection_point: str = Field(
        description=(
            "Parameter or field to inject into, "
            "e.g. 'username', 'q', 'path_segment'"
        )
    )
    method: str = Field(description="HTTP method: GET or POST")
    url_path: str = Field(
        description="Endpoint path, e.g. '/api/login'"
    )
    body_template: Optional[str] = Field(
        default=None,
        description=(
            "JSON body as a string with payload inserted, for POST requests"
        ),
    )
    query_params: Optional[str] = Field(
        default=None,
        description=(
            "Query parameters as a JSON dict string, for GET requests"
        ),
    )
    rationale: str = Field(
        description=(
            "Brief explanation of why this payload should trigger "
            "the vulnerability"
        )
    )


class ExecutionReport(BaseModel):
    """Structured output of the Payload Tester agent."""

    status_code: int = Field(description="HTTP response status code")
    response_body: str = Field(
        description="Response body, truncated to 1000 chars"
    )
    content_type: str = Field(
        description="Response Content-Type header value"
    )
    payload_used: str = Field(description="Exact payload that was sent")
    full_request: str = Field(
        description=(
            "Description of the full request: method, URL, headers, body"
        )
    )


class AnalysisVerdict(BaseModel):
    """Structured output of the Analyst agent.  Drives the feedback loop."""

    confirmed: bool = Field(
        description=(
            "True ONLY if concrete evidence proves the vulnerability exists"
        )
    )
    dead_end: bool = Field(
        description=(
            "True if the vulnerability almost certainly does NOT exist "
            "at this endpoint"
        )
    )
    try_again: bool = Field(
        description=(
            "True if a different payload might succeed — the vulnerability "
            "may exist but this particular payload did not trigger it"
        )
    )
    evidence: Optional[str] = Field(
        default=None,
        description=(
            "If confirmed=True: concrete proof — raw DB error, leaked data, "
            "or HTTP response differential.  Must never be null when "
            "confirmed is True."
        ),
    )
    failure_reason: Optional[str] = Field(
        default=None,
        description=(
            "If try_again=True: analysis of WHY the payload failed and "
            "what to try next"
        ),
    )
    reasoning: str = Field(
        description="Full chain-of-thought analysis"
    )
