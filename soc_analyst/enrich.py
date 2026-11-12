"""Add context to findings so the LLM can reason about them.

Everything here is computed from the log itself or from config, with no
network calls, so it runs fully offline.
"""
from __future__ import annotations

import ipaddress
import statistics
from collections import defaultdict

from . import config
from .models import Event, Finding


def ip_type(ip: str | None) -> str:
    if not ip:
        return "unknown"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if addr.is_loopback:
        return "loopback"
    # Documentation ranges (203.0.113.0/24 etc.) count as external so the
    # sample data behaves like real internet traffic.
    if addr.is_private and not any(
        addr in ipaddress.ip_network(n)
        for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
    ):
        return "internal"
    return "external"


def is_privileged(user: str) -> bool:
    u = user.lower().split("\\")[-1]
    return u in config.PRIVILEGED_USERS or "admin" in u


def is_service_account(user: str) -> bool:
    u = user.lower().split("\\")[-1]
    return u.startswith(config.SERVICE_ACCOUNT_PREFIXES) or u.endswith("$")


def _interval_stats(fails: list[Event]) -> dict:
    if len(fails) < 3:
        return {}
    gaps = [
        (b.timestamp - a.timestamp).total_seconds() for a, b in zip(fails, fails[1:])
    ]
    mean = statistics.mean(gaps)
    stdev = statistics.pstdev(gaps)
    span_min = max((fails[-1].timestamp - fails[0].timestamp).total_seconds() / 60, 1 / 60)
    return {
        "mean_seconds_between_failures": round(mean, 1),
        "stdev_seconds_between_failures": round(stdev, 1),
        # Near-identical gaps usually mean a script or a service retrying, not a human.
        # Needs enough samples: 3-4 gaps can look regular by pure chance.
        "regular_interval": len(fails) >= 8 and mean > 0 and stdev / mean < 0.10,
        "attempts_per_minute": round(len(fails) / span_min, 1),
    }


def enrich(findings: list[Finding], events: list[Event]) -> list[Finding]:
    ip_fail_count: dict[str, int] = defaultdict(int)
    ip_success_count: dict[str, int] = defaultdict(int)
    ip_users: dict[str, set] = defaultdict(set)
    user_success_ips: dict[str, set] = defaultdict(set)
    for e in events:
        if e.src_ip:
            ip_users[e.src_ip].add(e.user.lower())
            if e.outcome == "failure":
                ip_fail_count[e.src_ip] += 1
            else:
                ip_success_count[e.src_ip] += 1
        if e.outcome == "success":
            user_success_ips[e.user.lower()].add(e.src_ip)

    for f in findings:
        fails: list[Event] = f.context.pop("_failures", [])
        success: Event | None = f.context.pop("_success", None)
        ctx = {
            "login_succeeded": success is not None,
            "source_ip_type": ip_type(f.src_ip),
            "privileged_accounts": [u for u in f.users if is_privileged(u)],
            "service_accounts": [u for u in f.users if is_service_account(u)],
            "nonexistent_account_attempts": sum(1 for e in fails if e.invalid_user),
            "source_ip_total_failures_in_log": ip_fail_count.get(f.src_ip, 0),
            "source_ip_total_successes_in_log": ip_success_count.get(f.src_ip, 0),
            "source_ip_distinct_users_in_log": len(ip_users.get(f.src_ip, ())),
            "log_sources": sorted({e.source for e in fails} | ({success.source} if success else set())),
        }
        ctx.update(_interval_stats(fails))
        if success:
            ctx["success_time_utc"] = success.timestamp.strftime("%H:%M")
            ctx["success_outside_business_hours"] = not (
                config.BUSINESS_HOUR_START <= success.timestamp.hour < config.BUSINESS_HOUR_END
            )
            others = user_success_ips.get(success.user.lower(), set()) - {success.src_ip}
            ctx["user_other_successful_source_ips"] = sorted(i for i in others if i)
        f.context = ctx
    return findings
