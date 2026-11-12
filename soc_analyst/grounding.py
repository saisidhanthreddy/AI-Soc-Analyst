"""Cheap hallucination checks on the LLM's text.

Each check looks for a claim in the explanation that the enrichment context
contradicts, e.g. calling an internal IP external or blaming a service
account when none is involved. Keyword-based, so it catches the common
failures, not all of them.
"""
from __future__ import annotations

import re

from .models import Finding


def _text(parts: list[str]) -> str:
    return " ".join(parts).lower()


def check(f: Finding, summary: str, reasoning: list[str]) -> list[str]:
    """Return a list of contradictions between the LLM's claims and the facts."""
    c = f.context
    # Only the summary and reasoning state facts; alternative explanations may
    # legitimately raise possibilities.
    t = _text([summary, *reasoning])
    issues: list[str] = []

    def says(pattern: str) -> bool:
        return re.search(pattern, t) is not None

    neg = r"(no|not|without|isn't|is not|wasn't|never)\W+(\w+\W+){0,3}"
    if c["source_ip_type"] == "internal" and says(r"\bexternal (ip|source|address|host)") \
            and not says(neg + r"external"):
        issues.append("calls an internal IP external")
    if c["source_ip_type"] == "external" and says(r"\binternal (ip|source|address|host)") \
            and not says(neg + r"internal"):
        issues.append("calls an external IP internal")
    if not c["service_accounts"] and says(r"\bservice account") and not says(neg + r"service account"):
        issues.append("mentions a service account but none is involved")
    if not c.get("regular_interval") and says(r"\bregular (interval|timing|cadence)|regularly spaced|"
                                                 r"interval\w*\W+(\w+\W+){0,4}(is|are|was|were)\s+regular") \
            and not says(neg + r"regular"):
        issues.append("claims a regular interval but timing is irregular")
    if not c["login_succeeded"] and says(r"\b(login|logon|attempt) (succeeded|was successful)|successful (login|logon)") \
            and not says(neg + r"(successful|succeed)"):
        issues.append("claims a successful login but none occurred")
    if c["login_succeeded"] and says(r"\bno successful (login|logon)|never succeeded|did not succeed"):
        issues.append("claims no success but the login succeeded")
    if c.get("nonexistent_account_attempts", 0) == 0 \
            and says(r"non-?existent (user|account)|invalid user") \
            and not says(neg + r"(non-?existent|invalid)"):
        issues.append("claims username guessing but all accounts exist")
    return issues
