"""LangGraph pipeline:

    parse -> detect --(no findings)--> report
                    \\-> enrich -> analyze -> report
"""
from __future__ import annotations

import time
from typing import Optional, TypedDict

from langgraph.graph import END, START, StateGraph

from . import config, detectors, parsers
from .enrich import enrich
from .fallback import rule_based_analysis
from .grounding import check as grounding_check
from .llm import OllamaError, analyze_finding, explain_finding
from .severity import classify
from .models import SEVERITY_ORDER, Event, Finding, IncidentReport, LLMAnalysis, TimeWindow

_VERDICT_SEVERITIES = {
    "likely_benign": {"LOW"},
    "suspicious": {"MEDIUM"},
    "likely_malicious": {"HIGH", "CRITICAL"},
}


def apply_guardrails(f: Finding, a: LLMAnalysis) -> tuple[LLMAnalysis, list[str]]:
    """Checks on LLM output that code can enforce.

    1. Severity may move at most LLM_MAX_SEVERITY_SHIFT levels from the rule baseline.
    2. Verdict/severity disagreement is recorded as a warning (not silently fixed).
    """
    warnings: list[str] = []
    base = SEVERITY_ORDER.index(f.rule_severity)
    got = SEVERITY_ORDER.index(a.severity)
    shift = config.LLM_MAX_SEVERITY_SHIFT
    if abs(got - base) > shift:
        clamped = SEVERITY_ORDER[max(0, min(len(SEVERITY_ORDER) - 1, base + (shift if got > base else -shift)))]
        warnings.append(f"severity clamped {a.severity} -> {clamped} (baseline {f.rule_severity})")
        a = a.model_copy(update={"severity": clamped})
    if a.severity not in _VERDICT_SEVERITIES[a.verdict]:
        warnings.append(f"verdict {a.verdict} does not match severity {a.severity}")
    return a, warnings


class SOCState(TypedDict, total=False):
    # inputs
    path: str
    fmt: str
    use_llm: bool
    model: str
    severity_by: str  # code (default) | llm | baseline
    # produced along the way
    detected_format: str
    events: list[Event]
    findings: list[Finding]
    incidents: list[IncidentReport]
    llm_seconds: float
    errors: list[str]


def parse_node(state: SOCState) -> SOCState:
    fmt, events = parsers.parse_file(state["path"], state.get("fmt", "auto"))
    return {"detected_format": fmt, "events": events}


def detect_node(state: SOCState) -> SOCState:
    return {"findings": detectors.run_all(state["events"])}


def enrich_node(state: SOCState) -> SOCState:
    return {"findings": enrich(state["findings"], state["events"])}


def _decide(f: Finding, severity_by: str) -> tuple[str, str, str, float]:
    if severity_by == "code":
        return classify(f)
    base = rule_based_analysis(f)
    return base.severity, base.verdict, "baseline severity from the detection rule", base.confidence


def analyze_node(state: SOCState) -> SOCState:
    model = state.get("model") or config.MODEL
    use_llm = state.get("use_llm", True)
    severity_by = state.get("severity_by") or config.SEVERITY_BY
    if severity_by == "llm" and not use_llm:
        severity_by = "baseline"
    incidents: list[IncidentReport] = []
    errors: list[str] = list(state.get("errors", []))
    t0 = time.perf_counter()

    for f in state["findings"]:
        error: Optional[str] = None
        warnings: list[str] = []
        text = rule_based_analysis(f)  # template text, replaced by LLM text when available
        analyzed_by = f"ollama:{model}" if use_llm else "rules"

        if severity_by == "llm":
            reason = "decided by LLM"
            try:
                text, warnings = apply_guardrails(f, analyze_finding(f, model=model))
                sev, verdict, conf = text.severity, text.verdict, text.confidence
            except OllamaError as exc:
                error, analyzed_by = str(exc), "rules (LLM failed)"
                sev, verdict, reason, conf = _decide(f, "code")
        else:
            sev, verdict, reason, conf = _decide(f, severity_by)
            if use_llm:
                try:
                    text = explain_finding(f, sev, verdict, reason, model=model)
                except OllamaError as exc:
                    error, analyzed_by = str(exc), "rules (LLM failed)"
        if error:
            errors.append(error)

        grounding = grounding_check(f, text.summary, text.reasoning) if use_llm and not error else []
        incidents.append(
            IncidentReport(
                incident=f.title,
                rule=f.rule,
                severity=sev,
                confidence=conf,
                verdict=verdict,
                affected_users=f.users,
                source_ip=f.src_ip,
                source_type=f.context.get("source_ip_type", "unknown"),
                time_window=TimeWindow(start=f.start, end=f.end),
                evidence=f.evidence,
                mitre_technique=f.mitre_technique,
                summary=text.summary,
                reasoning=text.reasoning,
                alternative_explanations=text.alternative_explanations,
                recommended_action=text.recommended_action,
                rule_severity=f.rule_severity,
                severity_by=severity_by,
                severity_reason=reason,
                analyzed_by=analyzed_by,
                analysis_error=error,
                warnings=warnings,
                grounding_issues=grounding,
            )
        )
    return {
        "incidents": incidents,
        "errors": errors,
        "llm_seconds": round(time.perf_counter() - t0, 2),
    }


def report_node(state: SOCState) -> SOCState:
    # Most severe first.
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    incidents = sorted(state.get("incidents", []), key=lambda i: order[i.severity])
    return {"incidents": incidents}


def _route_after_detect(state: SOCState) -> str:
    return "enrich" if state["findings"] else "report"


def build_graph():
    g = StateGraph(SOCState)
    g.add_node("parse", parse_node)
    g.add_node("detect", detect_node)
    g.add_node("enrich", enrich_node)
    g.add_node("analyze", analyze_node)
    g.add_node("report", report_node)
    g.add_edge(START, "parse")
    g.add_edge("parse", "detect")
    g.add_conditional_edges("detect", _route_after_detect, {"enrich": "enrich", "report": "report"})
    g.add_edge("enrich", "analyze")
    g.add_edge("analyze", "report")
    g.add_edge("report", END)
    return g.compile()


def run(path: str, fmt: str = "auto", use_llm: bool = True, model: str | None = None,
        severity_by: str | None = None) -> SOCState:
    return build_graph().invoke({
        "path": path, "fmt": fmt, "use_llm": use_llm, "model": model or config.MODEL,
        "severity_by": severity_by or config.SEVERITY_BY,
    })
