"""Synthetic auth-log generator for demos and evals.

    python -m soc_analyst.simulate            # writes data/samples/*
    python evals/build_scenarios.py           # writes the labeled eval set

All attack IPs use the 203.0.113.0/24 and 198.51.100.0/24 documentation
ranges, which enrich.py treats as external. Nothing here touches a network.
"""
from __future__ import annotations

import json
import random
import zlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

NORMAL_USERS = ["alice", "bob", "carol", "dave", "erin"]
INTERNAL_HOSTS = [f"10.0.{i}.{j}" for i in (1, 2) for j in range(10, 40)]


@dataclass
class Ev:
    ts: datetime
    outcome: str  # success | failure
    user: str
    ip: str
    invalid: bool = False


def ext_ip(rng: random.Random) -> str:
    return f"{rng.choice(['203.0.113', '198.51.100'])}.{rng.randint(2, 250)}"


def int_ip(rng: random.Random) -> str:
    return rng.choice(INTERNAL_HOSTS)


# ------------------------------------------------------------------ building blocks


def background(rng: random.Random, day: datetime, n: int = 12) -> list[Ev]:
    """Normal users logging in during business hours; at most one typo each."""
    evs: list[Ev] = []
    for user in rng.sample(NORMAL_USERS, k=min(len(NORMAL_USERS), 4)):
        ip = int_ip(rng)
        for _ in range(max(1, n // 4)):
            t = day.replace(hour=rng.randint(8, 18), minute=rng.randint(0, 59), second=rng.randint(0, 59))
            if rng.random() < 0.2:
                evs.append(Ev(t - timedelta(seconds=8), "failure", user, ip))
            evs.append(Ev(t, "success", user, ip))
    return evs


def burst(start: datetime, user: str, ip: str, n: int, rng: random.Random,
          gap: tuple[float, float] = (1.5, 6.0), invalid: bool = False) -> list[Ev]:
    evs, t = [], start
    for _ in range(n):
        evs.append(Ev(t, "failure", user, ip, invalid))
        t += timedelta(seconds=rng.uniform(*gap))
    return evs


def at(day: datetime, hour: int, minute: int = 0) -> datetime:
    return day.replace(hour=hour, minute=minute, second=0)


# ------------------------------------------------------------------ scenarios
# Each returns (events, expected findings, description).


def sc_ext_brute_force(rng, day):
    ip, user = ext_ip(rng), rng.choice(["admin", "root", "deploy"])
    evs = burst(at(day, rng.randint(1, 23), 5), user, ip, rng.randint(10, 40), rng)
    return evs, [("brute_force", "MEDIUM")], f"External brute force on {user}, no success"


def sc_int_brute_force(rng, day):
    ip, user = int_ip(rng), rng.choice(["admin", "carol", "backup"])
    evs = burst(at(day, rng.randint(9, 17), 15), user, ip, rng.randint(8, 15), rng)
    return evs, [("brute_force", "MEDIUM")], f"Internal host brute forcing {user}, no success"


def sc_ext_brute_success_priv(rng, day):
    ip, user = ext_ip(rng), rng.choice(["root", "admin"])
    evs = burst(at(day, rng.randint(0, 23), 20), user, ip, rng.randint(15, 60), rng)
    evs.append(Ev(evs[-1].ts + timedelta(seconds=4), "success", user, ip))
    return evs, [("brute_force_success", "CRITICAL")], f"External brute force then success on {user}"


def sc_ext_brute_success_user(rng, day):
    ip, user = ext_ip(rng), rng.choice(["dev01", "jsmith", "intern"])
    evs = burst(at(day, rng.randint(9, 17), 30), user, ip, rng.randint(10, 30), rng)
    evs.append(Ev(evs[-1].ts + timedelta(seconds=3), "success", user, ip))
    return evs, [("brute_force_success", "HIGH")], f"External brute force then success on normal user {user}"


def sc_int_brute_success_priv(rng, day):
    ip, user = int_ip(rng), "admin"
    evs = burst(at(day, rng.randint(9, 17), 40), user, ip, rng.randint(8, 20), rng)
    evs.append(Ev(evs[-1].ts + timedelta(seconds=5), "success", user, ip))
    return evs, [("brute_force_success", "HIGH")], "Internal host brute forced admin then succeeded"


def sc_typo(rng, day):
    ip, user = int_ip(rng), rng.choice(["admin", "bob", "erin"])
    n = rng.randint(3, 4)
    evs = burst(at(day, rng.randint(9, 16), 10), user, ip, n, rng, gap=(8, 25))
    evs.append(Ev(evs[-1].ts + timedelta(seconds=rng.randint(10, 30)), "success", user, ip))
    return evs, [("failed_then_success", "LOW")], f"{user} mistyped password {n}x then logged in (internal)"


def sc_service_stale_password(rng, day):
    ip, user = int_ip(rng), rng.choice(["svc_backup", "svc_reporting"])
    start = at(day, rng.randint(1, 5), 0)
    evs = [Ev(start + timedelta(seconds=60 * i), "failure", user, ip) for i in range(rng.randint(15, 30))]
    return evs, [("brute_force", "LOW")], f"{user} retrying a stale password every 60s (misconfig)"


def sc_spray(rng, day):
    ip = ext_ip(rng)
    users = rng.sample(NORMAL_USERS + ["frank", "grace", "heidi", "ivan", "judy", "mallory"], k=rng.randint(7, 11))
    t, evs = at(day, rng.randint(0, 23), 10), []
    for u in users:
        evs.append(Ev(t, "failure", u, ip))
        t += timedelta(seconds=rng.uniform(20, 90))
    return evs, [("password_spray", "MEDIUM")], f"External password spray over {len(users)} accounts, no success"


def sc_spray_username_guessing(rng, day):
    ip = ext_ip(rng)
    users = rng.sample(["test", "oracle", "ubuntu", "pi", "git", "postgres", "ftpuser", "guest", "user1"], k=8)
    t, evs = at(day, rng.randint(0, 23), 30), []
    for u in users:
        for _ in range(rng.randint(1, 2)):
            evs.append(Ev(t, "failure", u, ip, invalid=True))
            t += timedelta(seconds=rng.uniform(2, 10))
    return evs, [("password_spray", "MEDIUM")], "Internet scanner guessing non-existent usernames"


def sc_spray_success(rng, day):
    ip = ext_ip(rng)
    users = rng.sample(NORMAL_USERS + ["frank", "grace", "heidi", "ivan"], k=8)
    t, evs = at(day, rng.randint(9, 17), 5), []
    for u in users:
        evs.append(Ev(t, "failure", u, ip))
        t += timedelta(seconds=rng.uniform(15, 60))
    victim = users[-1]
    evs.append(Ev(t + timedelta(minutes=2), "success", victim, ip))
    return evs, [("password_spray", "HIGH")], f"Password spray with successful login as {victim}"


def sc_offhours_admin(rng, day):
    ip = int_ip(rng)
    evs = [Ev(at(day, rng.choice([1, 2, 3, 22, 23]), rng.randint(0, 59)), "success", "admin", ip)]
    return evs, [("off_hours_privileged_login", "LOW")], "Admin login at night from internal IP, no failures"


def sc_ext_admin_login(rng, day):
    ip = ext_ip(rng)
    evs = [Ev(at(day, rng.randint(9, 17), rng.randint(0, 59)), "success", rng.choice(["admin", "root"]), ip)]
    return evs, [("external_privileged_login", "MEDIUM")], "Privileged login from external IP, no failures"


def sc_normal(rng, day):
    return [], [], "Normal business-hours activity only"


SCENARIOS = [
    sc_ext_brute_force, sc_int_brute_force, sc_ext_brute_success_priv, sc_ext_brute_success_user,
    sc_int_brute_success_priv, sc_typo, sc_service_stale_password, sc_spray,
    sc_spray_username_guessing, sc_spray_success, sc_offhours_admin, sc_ext_admin_login, sc_normal,
]


# ------------------------------------------------------------------ renderers


def render_linux(evs: list[Ev], host: str = "web01") -> str:
    lines = []
    for e in sorted(evs, key=lambda e: e.ts):
        ts = f"{e.ts:%b} {e.ts.day:>2} {e.ts:%H:%M:%S}"
        pid = 1000 + zlib.crc32(f"{e.ip}{e.user}".encode()) % 8000
        port = 40000 + int(e.ts.timestamp()) % 20000
        if e.outcome == "failure":
            inv = "invalid user " if e.invalid else ""
            if e.invalid:
                lines.append(f"{ts} {host} sshd[{pid}]: Invalid user {e.user} from {e.ip} port {port}")
            lines.append(f"{ts} {host} sshd[{pid}]: Failed password for {inv}{e.user} from {e.ip} port {port} ssh2")
        else:
            lines.append(f"{ts} {host} sshd[{pid}]: Accepted password for {e.user} from {e.ip} port {port} ssh2")
            lines.append(f"{ts} {host} sshd[{pid}]: pam_unix(sshd:session): session opened for user {e.user}(uid=1000) by (uid=0)")
    return "\n".join(lines) + "\n"


def render_windows(evs: list[Ev], computer: str = "WS-FIN-07") -> str:
    recs = []
    for e in sorted(evs, key=lambda e: e.ts):
        recs.append({
            "EventID": 4624 if e.outcome == "success" else 4625,
            "TimeCreated": e.ts.isoformat().replace("+00:00", "Z"),
            "TargetUserName": e.user,
            "IpAddress": e.ip,
            "LogonType": 10 if not e.ip.startswith("10.") else 3,
            "WorkstationName": "-",
            "Computer": computer,
        })
    # A machine-account logon that the parser should ignore.
    if recs:
        recs.append({**recs[0], "TargetUserName": f"{computer}$", "EventID": 4624, "LogonType": 3})
    return json.dumps(recs, indent=2)


def build_scenario(fn, seed: int, day: datetime):
    rng = random.Random(seed)
    attack, expected, desc = fn(rng, day)
    return attack + background(rng, day), expected, desc


def write_samples(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    day = datetime.now(timezone.utc).replace(month=11, day=3, hour=0, minute=0, second=0, microsecond=0)
    rng = random.Random(7)

    # One busy Linux server with several things going on.
    evs = background(rng, day, n=40)
    for i, fn in enumerate([sc_ext_brute_force, sc_typo, sc_ext_brute_success_priv,
                            sc_spray_username_guessing, sc_service_stale_password]):
        evs += fn(random.Random(100 + i), day)[0]
    (out_dir / "linux_auth.log").write_text(render_linux(evs), encoding="utf-8")

    # A Windows workstation.
    wevs = background(rng, day, n=20)
    wevs += sc_spray_success(random.Random(200), day)[0]
    wevs += sc_offhours_admin(random.Random(201), day)[0]
    (out_dir / "windows_security.json").write_text(render_windows(wevs), encoding="utf-8")

    # The exact example from the project brief.
    (out_dir / "simple_example.log").write_text(
        "2026-11-10T10:01:00Z Failed login - user: admin - IP: 192.168.1.50\n"
        "2026-11-10T10:01:20Z Failed login - user: admin - IP: 192.168.1.50\n"
        "2026-11-10T10:01:45Z Failed login - user: admin - IP: 192.168.1.50\n"
        "2026-11-10T10:02:10Z Failed login - user: admin - IP: 192.168.1.50\n"
        "2026-11-10T10:02:40Z Successful login - user: admin - IP: 192.168.1.50\n",
        encoding="utf-8",
    )
    print(f"Wrote samples to {out_dir}")


if __name__ == "__main__":
    write_samples(Path(__file__).resolve().parent.parent / "data" / "samples")
