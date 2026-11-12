"""Ollama client and the analyst prompt.

Uses Ollama's native /api/chat endpoint with `format` set to a JSON schema,
so the model is constrained to emit JSON that matches LLMAnalysis.
"""
from __future__ import annotations

import json

import requests
from pydantic import ValidationError

from . import config
from pydantic import BaseModel

from .models import Finding, LLMAnalysis, LLMExplanation

SYSTEM_PROMPT = """You are a careful Tier-2 SOC analyst. You get ONE finding from \
deterministic detection rules plus enrichment context. The facts in it are correct; \
never change or invent facts, and only cite context fields that are actually present \
with the value you claim.

Work in this order: reasoning -> verdict -> severity.

Severity table. Go top to bottom and use the FIRST row that matches:
1. login_succeeded=true AND privileged account AND source_ip_type=external AND rule \
is brute_force_success -> CRITICAL, likely_malicious
2. login_succeeded=true AND rule is brute_force_success or password_spray -> HIGH, \
likely_malicious
3. service account AND regular_interval=true AND login_succeeded=false -> LOW, \
likely_benign (misconfigured service retrying a stale password)
4. rule is failed_then_success AND source_ip_type=internal -> LOW, likely_benign \
(user mistyped password)
5. rule is off_hours_privileged_login AND source_ip_type=internal -> LOW, likely_benign
6. rule is brute_force or password_spray AND login_succeeded=false -> MEDIUM, suspicious
7. rule is external_privileged_login -> MEDIUM, suspicious
8. anything else -> keep baseline_severity_from_rules

Verdict and severity must agree: likely_benign -> LOW, suspicious -> MEDIUM, \
likely_malicious -> HIGH or CRITICAL.

Other guidance:
- Name the table row you used in the first reasoning bullet, e.g. "Row 4: ...".
- An internal source is not automatically safe: a burst from an internal host can mean \
that host is compromised. Mention it in alternative_explanations when relevant.
- nonexistent_account_attempts > 0 means the attacker is guessing usernames.
- confidence: 0.9 when a row matches cleanly, lower when the evidence is mixed.
- recommended_action: 2-4 concrete steps, most important first.
- summary: 2-3 sentences."""


class OllamaError(RuntimeError):
    pass


def check_ollama(model: str = config.MODEL) -> tuple[bool, str]:
    try:
        r = requests.get(f"{config.OLLAMA_URL}/api/tags", timeout=5)
        r.raise_for_status()
    except requests.RequestException as exc:
        return False, (
            f"Cannot reach Ollama at {config.OLLAMA_URL} ({exc.__class__.__name__}). "
            "Is it running? Try: ollama serve"
        )
    names = [m["name"] for m in r.json().get("models", [])]
    if not any(n == model or n.split(":")[0] == model or n == f"{model}:latest" for n in names):
        return False, (
            f"Model '{model}' not installed. Installed: {', '.join(names) or 'none'}. "
            f"Run: ollama pull {model}  (or pass --model <one of the above>)"
        )
    return True, f"Ollama OK at {config.OLLAMA_URL}, model '{model}' available."


def _finding_payload(f: Finding) -> str:
    data = f.model_dump(mode="json", exclude={"rule_severity"})
    data["baseline_severity_from_rules"] = f.rule_severity
    return json.dumps(data, indent=2)


def _chat(model: str, messages: list[dict], schema: type[BaseModel]) -> str:
    try:
        r = requests.post(
            f"{config.OLLAMA_URL}/api/chat",
            json={
                "model": model,
                "messages": messages,
                "stream": False,
                "format": schema.model_json_schema(),
                "keep_alive": config.LLM_KEEP_ALIVE,
                "options": {
                    "temperature": config.LLM_TEMPERATURE,
                    "num_predict": config.LLM_NUM_PREDICT,
                },
            },
            timeout=config.LLM_TIMEOUT_S,
        )
        r.raise_for_status()
    except requests.RequestException as exc:
        raise OllamaError(f"Ollama request failed: {exc}") from exc
    return r.json()["message"]["content"]


def _ask(model: str, messages: list[dict], schema: type[BaseModel], retries: int = 1):
    last_err: Exception | None = None
    for _ in range(retries + 1):
        content = _chat(model, messages, schema)
        try:
            return schema.model_validate_json(content)
        except ValidationError as exc:
            last_err = exc
            # Feed the validation error back once so the model can fix it.
            messages = messages + [
                {"role": "assistant", "content": content},
                {
                    "role": "user",
                    "content": f"That JSON was invalid: {exc.errors()[:3]}. "
                    "Return corrected JSON only.",
                },
            ]
    raise OllamaError(f"Model returned invalid JSON after {retries + 1} attempts: {last_err}")


def analyze_finding(f: Finding, model: str = config.MODEL) -> LLMAnalysis:
    """LLM decides severity and verdict (severity_by=llm)."""
    return _ask(model, [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Analyze this finding:\n{_finding_payload(f)}"},
    ], LLMAnalysis)


EXPLAIN_PROMPT = """You are a careful Tier-2 SOC analyst writing up ONE finding. \
Severity and verdict are already decided by policy and are final; do not argue with \
them. Explain the finding to an on-call engineer.

Rules:
- Use only facts present in the finding and its context. Do not claim anything the \
context contradicts (e.g. do not call an internal IP external, do not mention a service \
account unless service_accounts is non-empty, do not claim a regular interval unless \
regular_interval is true).
- reasoning: 2-4 bullets, each citing a specific evidence line or context field.
- alternative_explanations: 1-3 plausible other explanations. An internal source can \
also mean that internal host is compromised.
- recommended_action: 2-4 concrete steps, most important first, proportionate to the \
severity (LOW = verify, not incident response).
- summary: 2-3 sentences."""


def explain_finding(f: Finding, severity: str, verdict: str, reason: str,
                    model: str = config.MODEL) -> LLMExplanation:
    """Code decided severity (severity_by=code); LLM writes the explanation."""
    payload = json.loads(_finding_payload(f))
    payload.pop("baseline_severity_from_rules", None)
    payload["final_severity"] = severity
    payload["final_verdict"] = verdict
    payload["policy_reason"] = reason
    return _ask(model, [
        {"role": "system", "content": EXPLAIN_PROMPT},
        {"role": "user", "content": f"Write up this finding:\n{json.dumps(payload, indent=2)}"},
    ], LLMExplanation)
