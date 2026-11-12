"""Rule-only analysis. Used with --no-llm, as the eval baseline, and when
Ollama fails, so the pipeline always produces a report."""
from __future__ import annotations

from .models import Finding, LLMAnalysis

_VERDICT = {"LOW": "likely_benign", "MEDIUM": "suspicious", "HIGH": "likely_malicious",
            "CRITICAL": "likely_malicious"}

_ACTIONS = {
    "brute_force": [
        "Block or rate-limit the source IP",
        "Confirm the account is locked out or protected by MFA",
    ],
    "brute_force_success": [
        "Contact the account owner to confirm the login",
        "Reset the password and revoke active sessions if not confirmed",
        "Review activity after the successful login",
    ],
    "failed_then_success": [
        "Confirm with the account owner that they mistyped their password",
    ],
    "password_spray": [
        "Block the source IP",
        "Check every targeted account for successful logins",
        "Enforce MFA and lockout policy",
    ],
    "external_privileged_login": [
        "Verify the login with the administrator",
        "Restrict privileged access to VPN or bastion hosts",
    ],
    "off_hours_privileged_login": [
        "Verify the login with the administrator or change calendar",
    ],
}

_ALTERNATIVES = {
    "brute_force": ["misconfigured client or service with a stale password"],
    "brute_force_success": ["legitimate user who forgot the password, then remembered it"],
    "failed_then_success": ["user mistyped password"],
    "password_spray": ["misconfigured application iterating over accounts"],
    "external_privileged_login": ["administrator working remotely"],
    "off_hours_privileged_login": ["scheduled maintenance or on-call work"],
}


def rule_based_analysis(f: Finding) -> LLMAnalysis:
    sev = f.rule_severity
    ip = f.src_ip or "an unknown source"
    return LLMAnalysis(
        severity=sev,
        confidence=0.5,
        verdict=_VERDICT[sev],
        summary=f"{f.title} for {', '.join(f.users[:5])} from {ip} "
        f"({f.context.get('source_ip_type', 'unknown')}). Severity from rules only.",
        reasoning=list(f.evidence[:3]),
        alternative_explanations=_ALTERNATIVES.get(f.rule, []),
        recommended_action=_ACTIONS.get(f.rule, ["Investigate manually"]),
    )
