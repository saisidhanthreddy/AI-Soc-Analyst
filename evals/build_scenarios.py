"""Build the labeled eval set: evals/scenarios/*.log|json + evals/labels.json.

    python evals/build_scenarios.py

Two variants of each scenario type (different seeds), every third one
rendered as Windows Security JSON instead of Linux auth.log.
Edit labels.json by hand if you disagree with a label: the labels are the
analyst rubric the LLM is being measured against.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from soc_analyst.simulate import SCENARIOS, build_scenario, render_linux, render_windows  # noqa: E402

VARIANTS = 2


def main() -> None:
    out = ROOT / "evals" / "scenarios"
    out.mkdir(parents=True, exist_ok=True)
    for old in out.glob("*"):
        old.unlink()
    day = datetime.now(timezone.utc).replace(month=11, day=4, hour=0, minute=0, second=0, microsecond=0)

    labels, idx = [], 0
    for fn in SCENARIOS:
        for v in range(VARIANTS):
            idx += 1
            evs, expected, desc = build_scenario(fn, seed=1000 + idx, day=day)
            name = fn.__name__.removeprefix("sc_")
            if idx % 3 == 0:
                fname, text = f"{idx:02d}_{name}.json", render_windows(evs)
            else:
                fname, text = f"{idx:02d}_{name}.log", render_linux(evs)
            (out / fname).write_text(text, encoding="utf-8")
            labels.append({
                "file": f"scenarios/{fname}",
                "scenario": name,
                "description": desc,
                "expected": [{"rule": r, "severity": s} for r, s in expected],
            })
    (ROOT / "evals" / "labels.json").write_text(json.dumps(labels, indent=2), encoding="utf-8")
    print(f"Wrote {len(labels)} scenarios to {out}")


if __name__ == "__main__":
    main()
