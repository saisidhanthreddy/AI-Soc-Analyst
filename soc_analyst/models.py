"""Data models shared across the pipeline."""
from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
Verdict = Literal["likely_malicious", "suspicious", "likely_benign"]
SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class Event(BaseModel):
    """One normalized authentication event, whatever the log source."""

    timestamp: datetime  # always timezone-aware UTC
    outcome: Literal["success", "failure"]
    user: str
    src_ip: Optional[str] = None
    host: Optional[str] = None
    source: str  # linux_auth | windows_security | simple | wazuh
    invalid_user: bool = False  # sshd "invalid user" = account does not exist
    raw: str = ""


class Finding(BaseModel):
    """Output of a deterministic detection rule. Facts only, no opinions."""

    rule: str
    title: str
    mitre_technique: str
    users: list[str]
    src_ip: Optional[str] = None
    start: datetime
    end: datetime
    failed_count: int = 0
    success_count: int = 0
    evidence: list[str]
    rule_severity: Severity
    context: dict = Field(default_factory=dict)  # filled by the enrich step


class LLMAnalysis(BaseModel):
    """The part of the report the LLM is allowed to write.

    Facts (users, IPs, times, counts) come from code, never from the model,
    so the model cannot hallucinate evidence.

    Field order matters: the model generates JSON top to bottom, so it writes
    its reasoning first, then commits to a verdict, then picks a severity that
    matches the verdict.
    """

    reasoning: list[str] = Field(description="2-4 short bullets, each citing evidence or context")
    alternative_explanations: list[str]
    verdict: Verdict
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str = Field(description="2-3 sentences: what happened and why it matters")
    recommended_action: list[str]


class LLMExplanation(BaseModel):
    """Used when severity is decided in code: the LLM only explains."""

    reasoning: list[str] = Field(description="2-4 short bullets, each citing evidence or context")
    alternative_explanations: list[str]
    summary: str = Field(description="2-3 sentences: what happened and why it matters")
    recommended_action: list[str]


class TimeWindow(BaseModel):
    start: datetime
    end: datetime


class IncidentReport(BaseModel):
    incident: str
    rule: str
    severity: Severity
    confidence: float
    verdict: Verdict
    affected_users: list[str]
    source_ip: Optional[str]
    source_type: str
    time_window: TimeWindow
    evidence: list[str]
    mitre_technique: str
    summary: str
    reasoning: list[str]
    alternative_explanations: list[str]
    recommended_action: list[str]
    rule_severity: Severity
    severity_by: str  # code | llm | baseline
    severity_reason: str
    analyzed_by: str
    analysis_error: Optional[str] = None
    warnings: list[str] = Field(default_factory=list)
    grounding_issues: list[str] = Field(default_factory=list)
