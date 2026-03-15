"""
HTTP Request Executor tool for sub-agents.

This is the ONLY tool that performs real I/O inside the sub-agent system.
The Payload Tester agent calls this to fire payloads against the target.

``result_as_answer=True`` makes the raw HTTP response the agent's final
answer, preventing the LLM from interpreting or mangling response data.
"""

import json

import httpx
from crewai.tools import tool

_TIMEOUT = 10.0


@tool("HTTP Request Executor", result_as_answer=True)
def http_request_tool(
    method: str,
    url: str,
    body_json: str = "{}",
    query_params_json: str = "{}",
    content_type: str = "auto",
    cookies_json: str = "{}",
) -> str:
    """
    Execute a single HTTP request and return the raw response.

    Args:
        method: HTTP method — GET or POST.
        url: Full URL including scheme and host,
             e.g. http://localhost:5000/corp/legacy-auth
        body_json: JSON string of the request body (for POST).
                   Default: empty object.
        query_params_json: JSON string of query parameters (for GET).
                           Default: empty object.
        content_type: How to encode the POST body. Options:
                      "json" — send as application/json (default for nested objects).
                      "form" — send as application/x-www-form-urlencoded.
                      "auto" — auto-detect: flat dicts → form, nested → json.
        cookies_json: JSON string of cookies to include, e.g.
                      {"session_user": "admin"}.  Default: empty.

    Returns:
        JSON string with status_code, headers (selected), body, and url.
    """
    try:
        body = json.loads(body_json)
        params = json.loads(query_params_json)
        cookies = json.loads(cookies_json) or None
    except json.JSONDecodeError as exc:
        return json.dumps({"error": f"Invalid JSON input: {exc}"})

    try:
        if method.upper() == "POST":
            # Decide form vs JSON encoding
            use_form = False
            if content_type.lower() == "form":
                use_form = True
            elif content_type.lower() == "auto" and isinstance(body, dict):
                # Flat dicts with simple values → form-encoded (login forms, etc.)
                use_form = all(isinstance(v, (str, int, float, bool)) for v in body.values())

            if use_form and isinstance(body, dict):
                resp = httpx.post(url, data=body, cookies=cookies, timeout=_TIMEOUT)
            else:
                resp = httpx.post(url, json=body, cookies=cookies, timeout=_TIMEOUT)
        else:
            resp = httpx.get(url, params=params or None, cookies=cookies, timeout=_TIMEOUT)

        return json.dumps({
            "status_code": resp.status_code,
            "content_type": resp.headers.get("content-type", "unknown"),
            "body": resp.text[:2000],
            "url": str(resp.url),
        })
    except httpx.HTTPError as exc:
        return json.dumps({"error": f"HTTP request failed: {exc}"})
