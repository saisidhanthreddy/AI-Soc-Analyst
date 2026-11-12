"""Deterministic severity decision table.

The 7B-model eval showed the LLM could not reliably apply an ordered rubric
(it skipped matching rows and escalated anything mentioning "admin"), so
severity and verdict are decided here and the LLM only explains them.
First matching row wins.
"""
from __future__ import annotations

from .models import Finding

# (row id, description, predicate, severity, verdict)
_ROWS = [
    ("R1", "privileged account brute forced from an external IP and the login succeeded",
     lambda f, c: f.rule == "brute_force_success" and c["login_succeeded"]
     and c["privileged_accounts"] and c["source_ip_type"] == "external",
     "CRITICAL", "likely_malicious"),
    ("R2", "brute force or password spray followed by a successful login",
     lambda f, c: f.rule in ("brute_force_success", "password_spray") and c["login_succeeded"],
     "HIGH", "likely_malicious"),
    ("R3", "service account retrying at a regular interval with no success (stale password)",
     lambda f, c: c["service_accounts"] and c.get("regular_interval") and not c["login_succeeded"],
     "LOW", "likely_benign"),
    ("R4", "a few failed logins then success from an internal IP (mistyped password)",
     lambda f, c: f.rule == "failed_then_success" and c["source_ip_type"] == "internal",
     "LOW", "likely_benign"),
    ("R5", "privileged login outside business hours from an internal IP",
     lambda f, c: f.rule == "off_hours_privileged_login" and c["source_ip_type"] == "internal",
     "LOW", "likely_benign"),
    ("R6", "brute force or password spray with no successful login",
     lambda f, c: f.rule in ("brute_force", "password_spray") and not c["login_succeeded"],
     "MEDIUM", "suspicious"),
    ("R7", "privileged login from an external IP",
     lambda f, c: f.rule == "external_privileged_login",
     "MEDIUM", "suspicious"),
]

_DEFAULT_VERDICT = {"LOW": "likely_benign", "MEDIUM": "suspicious",
                    "HIGH": "likely_malicious", "CRITICAL": "likely_malicious"}


def classify(f: Finding) -> tuple[str, str, str, float]:
    """Return (severity, verdict, reason, confidence) for an enriched finding."""
    for row_id, desc, pred, sev, verdict in _ROWS:
        if pred(f, f.context):
            return sev, verdict, f"{row_id}: {desc}", 0.9
    return f.rule_severity, _DEFAULT_VERDICT[f.rule_severity], "R8: no row matched, kept rule baseline", 0.6
