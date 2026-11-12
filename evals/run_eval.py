"""Score the pipeline against evals/labels.json.

    python evals/run_eval.py --no-llm                    # raw detection-rule baseline
    python evals/run_eval.py                             # code decides severity, LLM explains
    python evals/run_eval.py --severity-by llm           # LLM decides severity (experiment)
    python evals/run_eval.py --both                      # baseline vs the selected LLM mode
    python evals/run_eval.py --only 05 12 13             # subset of scenarios

Metrics
  detection precision / recall  - did the rules fire the expected findings (deterministic)
  severity exact / within-one   - does the final severity match the analyst label
  over / under escalation       - direction of severity mistakes
  llm errors                    - findings where the model failed and rules were used
  grounding issues              - claims in the LLM's text that the facts contradict
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from soc_analyst import config  # noqa: E402
from soc_analyst.graph import run  # noqa: E402
from soc_analyst.llm import check_ollama  # noqa: E402
from soc_analyst.models import SEVERITY_ORDER  # noqa: E402

RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


def evaluate(use_llm: bool, model: str, severity_by: str, verbose: bool = True,
             only: list[str] | None = None) -> dict:
    labels = json.loads((ROOT / "evals" / "labels.json").read_text(encoding="utf-8"))
    if only:
        labels = [c for c in labels if any(Path(c["file"]).name.startswith(o) for o in only)]
    tp = fp = fn = 0
    exact = within_one = over = under = llm_errors = warnings = grounding = 0
    rows = []
    t0 = time.perf_counter()

    for case in labels:
        state = run(str(ROOT / "evals" / case["file"]), use_llm=use_llm, model=model,
                    severity_by=severity_by)
        incidents = list(state.get("incidents", []))
        remaining = list(incidents)
        case_rows = []
        for exp in case["expected"]:
            match = next((i for i in remaining if i.rule == exp["rule"]), None)
            if not match:
                fn += 1
                case_rows.append(("MISSED", exp["rule"], exp["severity"], "-"))
                continue
            remaining.remove(match)
            tp += 1
            llm_errors += bool(match.analysis_error)
            warnings += len(match.warnings)
            grounding += len(match.grounding_issues)
            for g in match.grounding_issues:
                case_rows.append(("GROUND", exp["rule"], "-", g))
            d = RANK[match.severity] - RANK[exp["severity"]]
            exact += d == 0
            within_one += abs(d) <= 1
            over += d > 0
            under += d < 0
            status = "ok" if d == 0 else ("OVER" if d > 0 else "UNDER")
            case_rows.append((status, exp["rule"], exp["severity"], match.severity))
        for extra in remaining:
            fp += 1
            case_rows.append(("FALSE+", extra.rule, "-", extra.severity))
        rows.append({"file": case["file"], "description": case["description"], "results": case_rows})

    n = max(tp, 1)
    metrics = {
        "mode": f"severity={severity_by}, text=" + (f"ollama:{model}" if use_llm else "rules"),
        "scenarios": len(labels),
        "detection_precision": round(tp / max(tp + fp, 1), 3),
        "detection_recall": round(tp / max(tp + fn, 1), 3),
        "severity_exact": round(exact / n, 3),
        "severity_within_one": round(within_one / n, 3),
        "over_escalations": over,
        "under_escalations": under,
        "llm_errors": llm_errors,
        "guardrail_warnings": warnings,
        "grounding_issues": grounding,
        "seconds": round(time.perf_counter() - t0, 1),
    }

    if verbose:
        print(f"\n=== {metrics['mode']} ===")
        for r in rows:
            for status, rule, exp, got in r["results"]:
                if status != "ok":
                    if status == "GROUND":
                        print(f"  {status:<7} {Path(r['file']).name:<34} {rule:<27} {got}")
                    else:
                        print(f"  {status:<7} {Path(r['file']).name:<34} {rule:<27} expected {exp:<8} got {got}")
        print()
        for k, v in metrics.items():
            print(f"  {k:<22} {v}")

    out = ROOT / "evals" / "results"
    out.mkdir(exist_ok=True)
    tag = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in metrics["mode"])
    (out / f"{tag}_{datetime.now():%Y%m%d_%H%M%S}.json").write_text(
        json.dumps({"metrics": metrics, "cases": rows}, indent=2), encoding="utf-8"
    )
    return metrics


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--model", default=config.MODEL)
    p.add_argument("--no-llm", action="store_true")
    p.add_argument("--severity-by", choices=["code", "llm", "baseline"], default=config.SEVERITY_BY)
    p.add_argument("--both", action="store_true", help="run rules baseline and LLM")
    p.add_argument("--only", nargs="+", metavar="PREFIX",
                   help="run only scenarios whose file name starts with these, e.g. --only 05 12 13")
    args = p.parse_args()

    if not args.no_llm:
        ok, msg = check_ollama(args.model)
        if not ok:
            print(f"FAIL {msg}", file=sys.stderr)
            return 1

    if args.both:
        base = evaluate(False, args.model, "baseline", only=args.only)
        llm = evaluate(True, args.model, args.severity_by, only=args.only)
        print(f"\n{'metric':<22} {'baseline':>10} {args.severity_by + '+llm':>10}")
        for k in ("severity_exact", "severity_within_one", "over_escalations",
                  "under_escalations", "llm_errors", "guardrail_warnings", "grounding_issues", "seconds"):
            print(f"{k:<22} {base[k]:>10} {llm[k]:>10}")
    else:
        mode = "baseline" if args.no_llm and args.severity_by == "llm" else args.severity_by
        evaluate(not args.no_llm, args.model, mode, only=args.only)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
