"""Deterministic detection rules.

Counting and time-window math happens here, in code. The LLM never counts.
Each rule returns Finding objects with a coarse baseline severity; the LLM
step later refines severity using the enrichment context.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta

from . import config
from .enrich import ip_type, is_privileged
from .models import Event, Finding


def _fmt(e: Event) -> str:
    return f"{e.timestamp:%Y-%m-%d %H:%M:%S}Z {e.outcome} user={e.user} ip={e.src_ip or '-'}"


def _split_bursts(fails: list[Event], gap: timedelta) -> list[list[Event]]:
    bursts: list[list[Event]] = []
    for e in fails:
        if bursts and e.timestamp - bursts[-1][-1].timestamp <= gap:
            bursts[-1].append(e)
        else:
            bursts.append([e])
    return bursts


def _evidence(fails: list[Event], success: Event | None) -> list[str]:
    span = (fails[-1].timestamp - fails[0].timestamp).total_seconds()
    ev = [f"{len(fails)} failed logins in {span / 60:.1f} min"]
    ev.append(f"first failure: {_fmt(fails[0])}")
    ev.append(f"last failure: {_fmt(fails[-1])}")
    if success:
        delay = (success.timestamp - fails[-1].timestamp).total_seconds()
        ev.append(f"success {delay:.0f}s after last failure: {_fmt(success)}")
    return ev


# ------------------------------------------------------------- rule 1: bursts


def detect_login_bursts(events: list[Event], covered: set[int]) -> list[Finding]:
    """Repeated failures for one (IP, user), optionally followed by a success."""
    gap = timedelta(minutes=config.BURST_GAP_MIN)
    lookahead = timedelta(minutes=config.SUCCESS_LOOKAHEAD_MIN)
    by_key: dict[tuple, list[Event]] = defaultdict(list)
    for e in events:
        by_key[(e.src_ip, e.user.lower())].append(e)

    findings: list[Finding] = []
    for (ip, _), evs in by_key.items():
        fails = [e for e in evs if e.outcome == "failure"]
        successes = [e for e in evs if e.outcome == "success"]
        for burst in _split_bursts(fails, gap):
            n = len(burst)
            if n < config.FAILED_THEN_SUCCESS_MIN:
                continue
            start, end = burst[0].timestamp, burst[-1].timestamp
            success = next(
                (s for s in successes if start <= s.timestamp <= end + lookahead), None
            )
            if n >= config.BRUTE_FORCE_MIN_FAILURES and success:
                rule, title, sev = (
                    "brute_force_success",
                    "Possible brute-force attack followed by successful login",
                    "HIGH",
                )
                mitre = "T1110 - Brute Force; T1078 - Valid Accounts"
            elif n >= config.BRUTE_FORCE_MIN_FAILURES:
                rule, title, sev = "brute_force", "Possible brute-force attempt", "MEDIUM"
                mitre = "T1110.001 - Brute Force: Password Guessing"
            elif success:
                rule, title, sev = (
                    "failed_then_success",
                    "Repeated failed logins followed by success",
                    "LOW",
                )
                mitre = "T1110 - Brute Force (unconfirmed)"
            else:
                continue
            if success:
                covered.add(id(success))
            findings.append(
                Finding(
                    rule=rule,
                    title=title,
                    mitre_technique=mitre,
                    users=[burst[0].user],
                    src_ip=ip,
                    start=start,
                    end=success.timestamp if success else end,
                    failed_count=n,
                    success_count=1 if success else 0,
                    evidence=_evidence(burst, success),
                    rule_severity=sev,
                    context={"_failures": burst, "_success": success},
                )
            )
    return findings


# ------------------------------------------------------------- rule 2: spray


def detect_password_spray(events: list[Event], covered: set[int]) -> list[Finding]:
    """One source IP failing against many distinct accounts in a short window."""
    window = timedelta(minutes=config.SPRAY_WINDOW_MIN)
    lookahead = timedelta(minutes=config.SUCCESS_LOOKAHEAD_MIN)
    by_ip: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.src_ip:
            by_ip[e.src_ip].append(e)

    findings: list[Finding] = []
    for ip, evs in by_ip.items():
        fails = [e for e in evs if e.outcome == "failure"]
        best: tuple[int, int, int] = (0, 0, -1)  # (distinct users, left, right)
        left = 0
        in_window: Counter[str] = Counter()
        for right in range(len(fails)):
            in_window[fails[right].user.lower()] += 1
            while fails[right].timestamp - fails[left].timestamp > window:
                key = fails[left].user.lower()
                in_window[key] -= 1
                if not in_window[key]:
                    del in_window[key]
                left += 1
            distinct = len(in_window)
            if distinct > best[0]:
                best = (distinct, left, right)
        distinct, lo, hi = best
        if distinct < config.SPRAY_MIN_USERS:
            continue
        burst = fails[lo : hi + 1]
        users = sorted({e.user for e in burst})
        start, end = burst[0].timestamp, burst[-1].timestamp
        hits = [
            e
            for e in evs
            if e.outcome == "success"
            and e.user.lower() in {u.lower() for u in users}
            and start <= e.timestamp <= end + lookahead
        ]
        for h in hits:
            covered.add(id(h))
        evidence = [
            f"{len(burst)} failed logins against {distinct} distinct accounts "
            f"in {(end - start).total_seconds() / 60:.1f} min from {ip}",
            f"accounts tried: {', '.join(users[:15])}{' ...' if len(users) > 15 else ''}",
        ] + [f"successful login during/after spray: {_fmt(h)}" for h in hits]
        findings.append(
            Finding(
                rule="password_spray",
                title="Possible password spraying"
                + (" with successful login" if hits else ""),
                mitre_technique="T1110.003 - Brute Force: Password Spraying",
                users=users,
                src_ip=ip,
                start=start,
                end=max([end] + [h.timestamp for h in hits]),
                failed_count=len(burst),
                success_count=len(hits),
                evidence=evidence,
                rule_severity="HIGH" if hits else "MEDIUM",
                context={"_failures": burst, "_success": hits[0] if hits else None},
            )
        )
    return findings


# ------------------------------------------------------------- rule 3: privileged logins


def detect_privileged_logins(events: list[Event], covered: set[int]) -> list[Finding]:
    """Successful privileged logins from outside the network or outside business hours.

    Successes already explained by a brute-force/spray finding are skipped.
    """
    groups: dict[tuple, list[Event]] = defaultdict(list)
    for e in events:
        if e.outcome != "success" or id(e) in covered or not is_privileged(e.user):
            continue
        external = ip_type(e.src_ip) == "external"
        off_hours = not (
            config.BUSINESS_HOUR_START <= e.timestamp.hour < config.BUSINESS_HOUR_END
        )
        if external:
            groups[("external_privileged_login", e.user, e.src_ip, e.timestamp.date())].append(e)
        elif off_hours:
            groups[("off_hours_privileged_login", e.user, e.src_ip, e.timestamp.date())].append(e)

    findings: list[Finding] = []
    for (rule, user, ip, _), evs in groups.items():
        external = rule == "external_privileged_login"
        findings.append(
            Finding(
                rule=rule,
                title=(
                    "Privileged account login from external IP"
                    if external
                    else "Privileged account login outside business hours"
                ),
                mitre_technique="T1078 - Valid Accounts",
                users=[user],
                src_ip=ip,
                start=evs[0].timestamp,
                end=evs[-1].timestamp,
                success_count=len(evs),
                evidence=[f"{len(evs)} successful login(s)"] + [_fmt(e) for e in evs[:5]],
                rule_severity="MEDIUM" if external else "LOW",
                context={"_failures": [], "_success": evs[0]},
            )
        )
    return findings


def run_all(events: list[Event]) -> list[Finding]:
    covered: set[int] = set()
    findings = detect_login_bursts(events, covered)
    findings += detect_password_spray(events, covered)
    findings += detect_privileged_logins(events, covered)
    return sorted(findings, key=lambda f: f.start)
