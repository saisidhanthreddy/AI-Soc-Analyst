"""Central configuration. Override any value with an environment variable."""
import os


def _env_int(name: str, default: int) -> int:
    return int(os.getenv(name, default))


# --- Ollama ---------------------------------------------------------------
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
MODEL = os.getenv("SOC_MODEL", "qwen2.5:7b")
LLM_TIMEOUT_S = _env_int("SOC_LLM_TIMEOUT", 180)  # first call also loads the model
LLM_TEMPERATURE = float(os.getenv("SOC_LLM_TEMPERATURE", "0"))
LLM_NUM_PREDICT = _env_int("SOC_LLM_NUM_PREDICT", 400)  # cap output tokens (speed)
LLM_KEEP_ALIVE = os.getenv("SOC_LLM_KEEP_ALIVE", "30m")  # keep model loaded between calls
# Who decides severity: "code" (decision table in severity.py, LLM explains),
# "llm" (LLM decides, guardrails apply) or "baseline" (raw detection rule).
SEVERITY_BY = os.getenv("SOC_SEVERITY_BY", "code")
# The LLM may move severity at most this many levels away from the rule baseline.
LLM_MAX_SEVERITY_SHIFT = _env_int("SOC_LLM_MAX_SHIFT", 1)

# --- Detection thresholds -------------------------------------------------
# Failures from the same (IP, user) closer together than this belong to one burst.
BURST_GAP_MIN = _env_int("SOC_BURST_GAP_MIN", 10)
# Failures in a burst needed to call it brute force.
BRUTE_FORCE_MIN_FAILURES = _env_int("SOC_BRUTE_MIN_FAILS", 5)
# Fewer failures than that, but at least this many followed by a success,
# is reported as a low-severity "failed then success" finding.
FAILED_THEN_SUCCESS_MIN = _env_int("SOC_FTS_MIN_FAILS", 3)
# How long after a burst a success still counts as "the attack worked".
SUCCESS_LOOKAHEAD_MIN = _env_int("SOC_SUCCESS_LOOKAHEAD_MIN", 30)

# Password spraying: one IP failing against many distinct users.
SPRAY_WINDOW_MIN = _env_int("SOC_SPRAY_WINDOW_MIN", 30)
SPRAY_MIN_USERS = _env_int("SOC_SPRAY_MIN_USERS", 5)

# Business hours (UTC, 24h clock) used by the off-hours rule.
BUSINESS_HOUR_START = _env_int("SOC_BUSINESS_START", 7)
BUSINESS_HOUR_END = _env_int("SOC_BUSINESS_END", 20)

# --- Enrichment -----------------------------------------------------------
PRIVILEGED_USERS = {
    u.strip().lower()
    for u in os.getenv(
        "SOC_PRIVILEGED_USERS", "root,admin,administrator,sysadmin,domain admin"
    ).split(",")
    if u.strip()
}
SERVICE_ACCOUNT_PREFIXES = ("svc_", "svc-", "service_", "sa_")
