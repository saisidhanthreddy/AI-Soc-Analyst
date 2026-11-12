"""Command line entrypoint.

    python -m soc_analyst check
    python -m soc_analyst analyze data/samples/linux_auth.log
    python -m soc_analyst analyze data/samples/windows_security.json --no-llm
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import config
from .graph import run
from .llm import check_ollama
from .parsers import FORMATS

_COLORS = {"CRITICAL": "\033[95m", "HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[92m"}
_RESET = "\033[0m"


def _cmd_check(args) -> int:
    ok, msg = check_ollama(args.model)
    print(("OK   " if ok else "FAIL ") + msg)
    return 0 if ok else 1


def _cmd_analyze(args) -> int:
    use_llm = not args.no_llm
    if use_llm:
        ok, msg = check_ollama(args.model)
        if not ok:
            print(f"FAIL {msg}\nTip: add --no-llm to run with rules only.", file=sys.stderr)
            return 1

    state = run(args.file, fmt=args.format, use_llm=use_llm, model=args.model,
                severity_by=args.severity_by)
    incidents = state.get("incidents", [])
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "input_file": str(args.file),
        "format": state["detected_format"],
        "events_parsed": len(state["events"]),
        "incident_count": len(incidents),
        "analysis_seconds": state.get("llm_seconds", 0),
        "incidents": [i.model_dump(mode="json") for i in incidents],
    }

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"report_{Path(args.file).stem}_{datetime.now():%Y%m%d_%H%M%S}.json"
    out_file.write_text(json.dumps(report, indent=2), encoding="utf-8")

    if args.json:
        print(json.dumps(report, indent=2))
        return 0

    color = sys.stdout.isatty() and not args.no_color
    print(
        f"\nParsed {report['events_parsed']} events ({report['format']}) "
        f"-> {len(incidents)} incident(s)\n"
    )
    for i in incidents:
        sev = f"{_COLORS[i.severity]}{i.severity}{_RESET}" if color else i.severity
        print(f"[{sev}] {i.incident}  (rule: {i.rule}, baseline {i.rule_severity})")
        print(f"   users: {', '.join(i.affected_users[:5])}   ip: {i.source_ip} ({i.source_type})")
        print(f"   verdict: {i.verdict}  confidence: {i.confidence:.2f}  severity by: {i.severity_by}"
              f"  text by: {i.analyzed_by}")
        print(f"   why: {i.severity_reason}")
        print(f"   {i.summary}")
        for w in i.warnings:
            print(f"   ! {w}")
        for g in i.grounding_issues:
            print(f"   ! grounding: {g}")
        for a in i.recommended_action[:3]:
            print(f"   -> {a}")
        print()
    if state.get("errors"):
        print(f"{len(state['errors'])} LLM error(s); those incidents used rule-based analysis.")
    print(f"Full JSON report: {out_file}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="soc_analyst", description="AI SOC Analyst (local Ollama)")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="verify Ollama is running and the model is installed")
    c.add_argument("--model", default=config.MODEL)
    c.set_defaults(func=_cmd_check)

    a = sub.add_parser("analyze", help="analyze a log file")
    a.add_argument("file")
    a.add_argument("--format", default="auto", choices=FORMATS)
    a.add_argument("--model", default=config.MODEL)
    a.add_argument("--no-llm", action="store_true", help="rules only, no Ollama")
    a.add_argument("--severity-by", choices=["code", "llm", "baseline"], default=config.SEVERITY_BY,
                   help="who decides severity (default: code)")
    a.add_argument("--out", default="reports", help="directory for JSON reports")
    a.add_argument("--json", action="store_true", help="print the JSON report to stdout")
    a.add_argument("--no-color", action="store_true")
    a.set_defaults(func=_cmd_analyze)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
