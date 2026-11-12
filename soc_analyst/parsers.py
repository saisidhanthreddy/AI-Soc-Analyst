"""Turn raw log files into normalized Event objects.

Supported formats:
  linux_auth       /var/log/auth.log or /var/log/secure (sshd lines)
  windows_security JSON exported by scripts/export_windows_events.ps1 (4624/4625)
  wazuh            Wazuh alerts.json (one JSON alert per line)
  simple           "Failed login - user: admin - IP: 1.2.3.4" (optional ISO timestamp prefix)
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .models import Event

# ---------------------------------------------------------------- helpers


def _to_utc(dt: datetime) -> datetime:
    """Naive timestamps are assumed to be UTC."""
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _parse_iso(value: str) -> datetime:
    value = value.strip().replace("Z", "+00:00")
    # Windows/.NET can emit 7 fractional digits; Python accepts at most 6.
    value = re.sub(r"(\.\d{6})\d+", r"\1", value)
    # Wazuh uses +0000 instead of +00:00
    value = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", value)
    return _to_utc(datetime.fromisoformat(value))


def _clean_ip(ip: str | None) -> str | None:
    if not ip or ip.strip() in {"-", ""}:
        return None
    return ip.strip().removeprefix("::ffff:")


# ---------------------------------------------------------------- linux

_SYSLOG_TS = r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})"
_ISO_TS = r"(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
_LINUX_PREFIX = rf"^(?:{_SYSLOG_TS}|{_ISO_TS})\s+(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+"
_LINUX_FAIL = re.compile(
    _LINUX_PREFIX
    + r"Failed (?:password|publickey|keyboard-interactive/pam) for (?P<invalid>invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\S+)"
)
_LINUX_OK = re.compile(
    _LINUX_PREFIX + r"Accepted (?:password|publickey|keyboard-interactive/pam) for "
    r"(?P<user>\S+) from (?P<ip>\S+)"
)
_LINUX_INVALID = re.compile(_LINUX_PREFIX + r"Invalid user (?P<user>\S+) from (?P<ip>\S+)")


def parse_linux_auth(text: str, year: int | None = None) -> list[Event]:
    year = year or datetime.now(timezone.utc).year
    events: list[Event] = []
    for line in text.splitlines():
        m = _LINUX_FAIL.search(line)
        outcome = "failure"
        if not m:
            m = _LINUX_OK.search(line)
            outcome = "success"
        if not m:
            # "Invalid user x from ip" is always followed by a "Failed password
            # for invalid user" line, so skip it to avoid double counting.
            continue
        if m.group("iso"):
            ts = _parse_iso(m.group("iso"))
        else:
            ts = _to_utc(datetime.strptime(f"{year} {m.group('ts')}", "%Y %b %d %H:%M:%S"))
        events.append(
            Event(
                timestamp=ts,
                outcome=outcome,
                user=m.group("user"),
                src_ip=_clean_ip(m.group("ip")),
                host=m.group("host"),
                source="linux_auth",
                invalid_user=bool(m.groupdict().get("invalid")),
                raw=line.strip(),
            )
        )
    return events


# ---------------------------------------------------------------- windows

_SKIP_WINDOWS_USERS = {"-", "system", "anonymous logon", "local service", "network service"}


def parse_windows_security(records: list[dict]) -> list[Event]:
    events: list[Event] = []
    for r in records:
        event_id = int(r.get("EventID") or r.get("Id") or 0)
        if event_id not in (4624, 4625):
            continue
        user = (r.get("TargetUserName") or "").strip()
        # Skip machine accounts (HOST$) and built-in service logons: pure noise.
        if not user or user.endswith("$") or user.lower() in _SKIP_WINDOWS_USERS:
            continue
        if event_id == 4624 and str(r.get("LogonType")) == "5":  # service logon
            continue
        events.append(
            Event(
                timestamp=_parse_iso(str(r.get("TimeCreated"))),
                outcome="success" if event_id == 4624 else "failure",
                user=user,
                src_ip=_clean_ip(r.get("IpAddress")),
                host=r.get("Computer") or r.get("WorkstationName"),
                source="windows_security",
                raw=json.dumps(r, default=str)[:500],
            )
        )
    return events


# ---------------------------------------------------------------- wazuh


def parse_wazuh_alerts(records: list[dict]) -> list[Event]:
    events: list[Event] = []
    for r in records:
        groups = set(r.get("rule", {}).get("groups", []))
        if groups & {"authentication_failed", "authentication_failures", "invalid_login"}:
            outcome = "failure"
        elif "authentication_success" in groups:
            outcome = "success"
        else:
            continue
        data = r.get("data", {})
        win = data.get("win", {}).get("eventdata", {})
        user = data.get("dstuser") or data.get("srcuser") or win.get("targetUserName")
        ip = data.get("srcip") or win.get("ipAddress")
        if not user:
            continue
        events.append(
            Event(
                timestamp=_parse_iso(r["timestamp"]),
                outcome=outcome,
                user=user,
                src_ip=_clean_ip(ip),
                host=r.get("agent", {}).get("name"),
                source="wazuh",
                raw=r.get("full_log", "")[:500],
            )
        )
    return events


# ---------------------------------------------------------------- simple

_SIMPLE = re.compile(
    r"^(?:(?P<iso>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*)\s+)?"
    r"(?P<outcome>Failed|Successful) login\s*-\s*user:\s*(?P<user>\S+)\s*-\s*IP:\s*(?P<ip>\S+)",
    re.IGNORECASE,
)


def parse_simple(text: str) -> list[Event]:
    """Lines without a timestamp get synthetic ones, 10 seconds apart."""
    events: list[Event] = []
    base = datetime.now(timezone.utc).replace(microsecond=0)
    for i, line in enumerate(l for l in text.splitlines() if l.strip()):
        m = _SIMPLE.search(line.strip())
        if not m:
            continue
        ts = _parse_iso(m.group("iso")) if m.group("iso") else base + timedelta(seconds=10 * i)
        events.append(
            Event(
                timestamp=ts,
                outcome="failure" if m.group("outcome").lower() == "failed" else "success",
                user=m.group("user"),
                src_ip=_clean_ip(m.group("ip")),
                source="simple",
                raw=line.strip(),
            )
        )
    return events


# ---------------------------------------------------------------- entrypoint

FORMATS = ("auto", "linux_auth", "windows_security", "wazuh", "simple")


def _load_json_records(text: str) -> list[dict]:
    text = text.strip()
    if text.startswith("["):
        return json.loads(text)
    if text.startswith("{"):
        try:  # a single JSON object (PowerShell does this for 1 event)
            obj = json.loads(text)
            return [obj]
        except json.JSONDecodeError:  # JSON lines
            return [json.loads(l) for l in text.splitlines() if l.strip()]
    raise ValueError("not JSON")


def detect_format(text: str) -> str:
    head = text.lstrip()[:2000]
    if head.startswith(("[", "{")):
        first = _load_json_records(text)[:1]
        if first and "rule" in first[0]:
            return "wazuh"
        return "windows_security"
    if _SIMPLE.search(head.splitlines()[0] if head else ""):
        return "simple"
    return "linux_auth"


def parse_file(path: str | Path, fmt: str = "auto") -> tuple[str, list[Event]]:
    # utf-8-sig strips the BOM that Windows PowerShell 5.1 writes.
    text = Path(path).read_text(encoding="utf-8-sig", errors="replace")
    if fmt == "auto":
        fmt = detect_format(text)
    if fmt == "linux_auth":
        events = parse_linux_auth(text)
    elif fmt == "simple":
        events = parse_simple(text)
    elif fmt == "windows_security":
        events = parse_windows_security(_load_json_records(text))
    elif fmt == "wazuh":
        events = parse_wazuh_alerts(_load_json_records(text))
    else:
        raise ValueError(f"Unknown format {fmt!r}; choose from {FORMATS}")
    return fmt, sorted(events, key=lambda e: e.timestamp)
