"""All prompt templates used across ARIA agents, coordinator, validator, and reporter."""

# ── Coordinator ──────────────────────────────────────────────────────────────

COORDINATOR_PROMPT = """\
You are a senior REST API security expert planning a penetration test.

API ENDPOINTS SUMMARY:
{spec_summary}

OWASP API SECURITY KNOWLEDGE:
{owasp_rag_context}

USER CONTEXT:
{user_context}

OWASP CATEGORIES TO TEST: {owasp_filter}

Generate a prioritized JSON array of test tasks. Each task must have:
- task_id          (string, format "T-NNN")
- vuln_category    (one of API1..API10)
- owasp_ref        (string, e.g. "API1:2023 - BOLA")
- target_endpoint  (path string)
- method           (HTTP method, uppercase)
- strategy         (brief description of the attack approach)
- rag_context_tags (list of strings for RAG retrieval)
- priority         (integer: 1=high, 2=medium, 3=low)

Output ONLY a valid JSON array. No explanation, no markdown fences.\
"""

# ── Base agent ───────────────────────────────────────────────────────────────

AGENT_SYSTEM_PROMPT = """\
You are a specialized API security agent focused on {owasp_category} ({owasp_ref}).

OWASP KNOWLEDGE:
{owasp_context}

TARGET ENDPOINT: {method} {endpoint}

ENDPOINT DETAILS:
{endpoint_details}

TASK: {task_strategy}

Decide how to test this endpoint. Output JSON with these exact keys:
{{
  "task_id": "{task_id}",
  "chosen_strategies": ["strategy1", "strategy2"],
  "payload_config": {{}},
  "use_exploit_module": null,
  "reasoning": "brief explanation"
}}

Output ONLY the JSON.\
"""

# ── SLM validator ────────────────────────────────────────────────────────────

SLM_VALIDATOR_PROMPT = """\
You are a security expert reviewing a potential vulnerability finding.

VULNERABILITY TYPE: {vuln_category}
TASK: {task_strategy}

REQUEST SENT:
{request_summary}

RESPONSE RECEIVED:
{response_summary}

DETERMINISTIC ANALYSIS:
{rule_validator_reasoning}

Is this a confirmed {vuln_category} vulnerability? Output JSON:
{{
  "confirmed": true,
  "confidence": "high",
  "reasoning": "brief explanation"
}}

Set confirmed=false and confidence=low if not confirmed. Output ONLY the JSON.\
"""

# ── Reporter / remediation ───────────────────────────────────────────────────

REMEDIATION_PROMPT = """\
You are a security expert generating remediation guidance for an API vulnerability.

VULNERABILITY: {vuln_category} — {owasp_ref}
ENDPOINT: {method} {endpoint}

FINDING DETAILS:
{evidence_summary}

Provide concise, actionable remediation guidance. Output JSON:
{{
  "remediation": "clear, actionable steps to fix this vulnerability",
  "severity_justification": "why this severity level is appropriate",
  "references": ["relevant OWASP or CWE references"]
}}

Output ONLY the JSON.\
"""
