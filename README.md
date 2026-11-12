# AI SOC Analyst (local, Ollama + LangGraph)

Reads Linux/Windows authentication logs, detects brute force, password spraying and
suspicious privileged logins, then uses a local LLM to judge severity, explain the
finding and recommend actions. Output is a JSON incident report. No API keys, no cloud.

```
parse ─► detect ─┬─(nothing found)──────────────► report
                 └─► enrich ─► analyze (Ollama) ─► report (JSON)
```

**Design rule: code finds facts, the LLM makes judgments.** Counting, time windows and
IP classification are deterministic Python. The model only writes severity, verdict,
confidence, reasoning and actions, and cannot change users, IPs, times or counts. Its
output is constrained to a JSON schema (Ollama `format`), validated with Pydantic,
retried once on bad JSON, and replaced with a rule-based analysis if it still fails.

## Setup (Windows, PowerShell)

```powershell
cd "$HOME\Downloads\AI-Soc-Analyst"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

ollama pull qwen2.5:7b        # default model; any tool/JSON-capable model works
python -m soc_analyst check   # confirms Ollama is up and the model is installed
```

Use a different model with `--model llama3.1:8b`, or set it once:
`$env:SOC_MODEL = "llama3.1:8b"`.

## Run it

```powershell
# The brief's example: 4 failures then success from 192.168.1.50
python -m soc_analyst analyze data\samples\simple_example.log

# Busy Linux server: brute force, root compromise, username guessing, stale service account
python -m soc_analyst analyze data\samples\linux_auth.log

# Windows workstation: password spray with a success, admin login at night
python -m soc_analyst analyze data\samples\windows_security.json

# Rules only (no Ollama), print the JSON report
python -m soc_analyst analyze data\samples\linux_auth.log --no-llm --json
```

Every run writes `reports\report_<file>_<timestamp>.json`.

### Your own Windows logs

From an **Administrator** PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\export_windows_events.ps1 -Hours 24
python -m soc_analyst analyze data\windows_security_live.json
```

A normal PC usually produces zero or a few LOW findings. That's the expected result.

### Linux logs

Copy `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL) and run `analyze` on it.
Syslog lines have no year, so the current year is assumed. Times are treated as UTC.

## Detection rules (`soc_analyst/detectors.py`)

| Rule | Fires when | Baseline severity |
|---|---|---|
| `brute_force` | ≥5 failures, same IP+user, gaps ≤10 min, no success | MEDIUM |
| `brute_force_success` | same, then a success within 30 min | HIGH |
| `failed_then_success` | 3–4 failures then success | LOW |
| `password_spray` | one IP fails against ≥5 accounts in 30 min | MEDIUM (HIGH with a success) |
| `external_privileged_login` | admin/root success from a public IP | MEDIUM |
| `off_hours_privileged_login` | admin/root success outside 07:00–20:00 UTC | LOW |

Thresholds live in `soc_analyst/config.py` and can be overridden with env vars.

Enrichment (`enrich.py`) adds: internal vs external IP, privileged/service account,
non-existent-username attempts, attempts per minute, **regular interval** (a script or
service retrying), other IPs the user logged in from, and off-hours timing. The LLM uses
this context to move severity up or down from the baseline.

## Evals

26 labeled scenarios (13 types × 2 variants, mixed Linux/Windows) in `evals/`.

```powershell
python evals\run_eval.py --no-llm   # rules baseline
python evals\run_eval.py            # with Ollama
python evals\run_eval.py --both     # side-by-side comparison
python evals\run_eval.py --model llama3.1:8b
```

Iterate on the failing cases only (much faster than all 26):

```powershell
python evals\run_eval.py --both --only 05 06 12 13 14
```

Guardrails on LLM output (`graph.py`): severity can move at most one level from the rule
baseline (`SOC_LLM_MAX_SHIFT`), and a verdict that disagrees with severity is logged as a
warning and counted in the eval as `guardrail_warnings`.

Metrics: detection precision/recall, severity exact and within-one, over/under-escalation
counts, LLM failures and runtime. Results are saved to `evals\results\`.

The rules baseline scores 0.833 severity-exact. It misses on purpose in two places only
context can fix:
- **Root brute-forced from the internet, then success** → should be CRITICAL, rules say HIGH.
- **Service account retrying a stale password every 60s** → should be LOW, rules say MEDIUM.

That gap is what the LLM has to close without breaking the rest. Labels are in
`evals\labels.json`; edit them if your rubric differs. Regenerate data with
`python evals\build_scenarios.py` and `python -m soc_analyst.simulate`.

## Tests

```powershell
python -m pytest -q
```

## Project layout

```
soc_analyst/
  parsers.py    linux auth.log, Windows 4624/4625 JSON, Wazuh alerts.json, simple format
  detectors.py  deterministic rules -> Finding
  enrich.py     IP type, account type, timing stats
  llm.py        Ollama client, analyst prompt, JSON schema, retry
  fallback.py   rule-only analysis (baseline and safety net)
  graph.py      LangGraph pipeline
  simulate.py   synthetic log generator
  __main__.py   CLI
evals/          labeled scenarios, builder, scorer
scripts/        export_windows_events.ps1
data/samples/   demo logs
```

## Next steps

1. **Wazuh (Phase 2).** The parser already reads `alerts.json`
   (`--format wazuh`). Point it at `/var/ossec/logs/alerts/alerts.json` from a Wazuh
   Docker install, or add a node that polls the Wazuh indexer API.
2. **Baseline rule:** "new source IP for this user" against a stored history.
3. **Human-in-the-loop:** a LangGraph `interrupt` before the report for CRITICAL incidents.
4. **MCP server:** expose `analyze_log(path)` as an MCP tool so other agents can call it.
5. **Threat intel enrichment:** AbuseIPDB / GreyNoise community APIs (free keys) behind an
   optional flag.
