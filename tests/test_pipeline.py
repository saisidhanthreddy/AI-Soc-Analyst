"""Fast tests that need no Ollama:  python -m pytest -q"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from soc_analyst import detectors, parsers  # noqa: E402
from soc_analyst.enrich import enrich, ip_type  # noqa: E402
from soc_analyst.graph import run  # noqa: E402

LINUX = """\
Nov 10 10:00:01 web01 sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2
Nov 10 10:00:03 web01 sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2
Nov 10 10:00:05 web01 sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2
Nov 10 10:00:07 web01 sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2
Nov 10 10:00:09 web01 sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2
Nov 10 10:00:12 web01 sshd[1]: Accepted password for root from 203.0.113.9 port 1 ssh2
Nov 10 10:05:00 web01 sshd[2]: Invalid user oracle from 198.51.100.4 port 2
Nov 10 10:05:00 web01 sshd[2]: Failed password for invalid user oracle from 198.51.100.4 port 2 ssh2
"""


def test_linux_parser():
    evs = parsers.parse_linux_auth(LINUX, year=2026)
    assert len(evs) == 7  # "Invalid user" line is not double counted
    assert evs[-1].invalid_user and evs[-1].user == "oracle"
    assert sum(e.outcome == "success" for e in evs) == 1


def test_brute_force_success_detected():
    evs = parsers.parse_linux_auth(LINUX, year=2026)
    findings = enrich(detectors.run_all(evs), evs)
    assert [f.rule for f in findings] == ["brute_force_success"]
    f = findings[0]
    assert f.failed_count == 5 and f.context["source_ip_type"] == "external"
    assert f.context["privileged_accounts"] == ["root"]
    json.dumps(f.model_dump(mode="json"))  # must be serializable for the LLM


def test_windows_parser_skips_machine_accounts():
    recs = [
        {"EventID": 4625, "TimeCreated": "2026-11-10T10:00:00.1234567Z", "TargetUserName": "bob", "IpAddress": "10.0.0.5"},
        {"EventID": 4624, "TimeCreated": "2026-11-10T10:00:05Z", "TargetUserName": "WS01$", "IpAddress": "-"},
    ]
    evs = parsers.parse_windows_security(recs)
    assert len(evs) == 1 and evs[0].outcome == "failure"


def test_wazuh_parser():
    rec = {
        "timestamp": "2026-11-10T10:00:00.000+0000",
        "rule": {"id": "5760", "groups": ["syslog", "sshd", "authentication_failed"]},
        "agent": {"name": "web01"},
        "data": {"srcip": "203.0.113.7", "dstuser": "admin"},
        "full_log": "Failed password for admin",
    }
    evs = parsers.parse_wazuh_alerts([rec])
    assert evs[0].user == "admin" and evs[0].outcome == "failure"
    assert parsers.detect_format(json.dumps(rec)) == "wazuh"


def test_ip_type():
    assert ip_type("192.168.1.50") == "internal"
    assert ip_type("203.0.113.5") == "external"
    assert ip_type("8.8.8.8") == "external"
    assert ip_type(None) == "unknown"


def test_simple_example_end_to_end(tmp_path):
    p = ROOT / "data" / "samples" / "simple_example.log"
    state = run(str(p), use_llm=False)
    [inc] = state["incidents"]
    assert inc.rule == "failed_then_success" and inc.severity == "LOW"
    assert inc.source_type == "internal"


def test_no_findings_path(tmp_path):
    p = tmp_path / "quiet.log"
    p.write_text("Nov 10 10:00:00 h sshd[1]: Accepted publickey for alice from 10.0.0.2 port 1 ssh2\n")
    state = run(str(p), use_llm=False)
    assert state["incidents"] == []


def test_few_failures_never_regular_interval():
    """Regression: 3-4 evenly spaced typos must not look like a scripted retry."""
    p = ROOT / "data" / "samples" / "simple_example.log"
    evs = parsers.parse_file(p)[1]
    [f] = enrich(detectors.run_all(evs), evs)
    assert f.context["regular_interval"] is False
    assert f.context["login_succeeded"] is True


def test_guardrails_clamp_and_warn():
    from soc_analyst.graph import apply_guardrails
    from soc_analyst.models import LLMAnalysis

    evs = parsers.parse_file(ROOT / "data" / "samples" / "simple_example.log")[1]
    [f] = enrich(detectors.run_all(evs), evs)  # baseline LOW
    a = LLMAnalysis(reasoning=["x"], alternative_explanations=[], verdict="likely_benign",
                    severity="CRITICAL", confidence=0.9, summary="s", recommended_action=["a"])
    fixed, warnings = apply_guardrails(f, a)
    assert fixed.severity == "MEDIUM"  # LOW + 1
    assert any("clamped" in w for w in warnings)
    assert any("does not match" in w for w in warnings)


def _simple_finding():
    evs = parsers.parse_file(ROOT / "data" / "samples" / "simple_example.log")[1]
    [f] = enrich(detectors.run_all(evs), evs)
    return f


def test_grounding_flags_real_qwen_hallucination():
    """The exact text qwen2.5:7b produced for simple_example.log on the first run."""
    from soc_analyst.grounding import check
    f = _simple_finding()
    summary = ("The admin account experienced repeated failed logins followed by a successful "
               "login from an internal IP. While suspicious, the context suggests this is likely "
               "a benign scenario, possibly due to a misconfiguration or a service account "
               "retrying a stale password.")
    reasoning = ["The user did not attempt to log in with a nonexistent account, and the interval "
                 "between failures is regular, which is typical of service account behavior."]
    issues = check(f, summary, reasoning)
    assert "mentions a service account but none is involved" in issues
    assert "claims a regular interval but timing is irregular" in issues


def test_grounding_accepts_faithful_text():
    from soc_analyst.grounding import check
    f = _simple_finding()
    assert check(f, "Four failed logins from internal IP 192.168.1.50, then success 30s later.",
                 ["Internal source, irregular timing, consistent with a mistyped password."]) == []


def test_severity_table_matches_all_eval_labels():
    """Code-decided severity must agree with every eval label (no LLM needed)."""
    labels = json.loads((ROOT / "evals" / "labels.json").read_text())
    for case in labels:
        state = run(str(ROOT / "evals" / case["file"]), use_llm=False, severity_by="code")
        got = sorted((i.rule, i.severity) for i in state["incidents"])
        exp = sorted((e["rule"], e["severity"]) for e in case["expected"])
        assert got == exp, case["file"]


def test_grounding_ignores_negated_claims():
    """Regression: qwen2.5:7b wrote a correct negative statement that was flagged."""
    from soc_analyst.grounding import check
    f = _simple_finding()
    reasoning = ["There are no attempts on nonexistent accounts, and the source IP has a low "
                 "number of total failures and successes in the log, indicating a one-off event."]
    assert check(f, "Failed logins then success from an internal IP.", reasoning) == []
