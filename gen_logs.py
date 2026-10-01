#!/usr/bin/env python3
"""Generate realistic JSON-lines security logs for the SIEM triage demo.

Writes:
    sample_logs.jsonl  - one JSON object per line
    known_ips.txt      - baseline of "known" source IPs

Event types: ``auth_success``, ``auth_failure``, ``firewall_deny``.

Four attack patterns are planted for the analyzer to find:
    1. SSH brute force from 203.0.113.45   (12 failures in ~8 minutes)
    2. Port scan from 198.51.100.23        (30 denied ports in ~4 minutes)
    3. Successful login outside business hours (jdoe, 02:14)
    4. Successful login from a new IP (asmith from 192.0.2.99)

Usage:
    python gen_logs.py --count 1500 --output sample_logs.jsonl --seed 42
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta

BASE_DATE = datetime(2026, 9, 29, 0, 0, 0)

USERS = ["jdoe", "asmith", "bwayne", "ckent", "dprince", "pparker", "srogers"]
INTERNAL_IPS = ["10.0.1.21", "10.0.1.22", "10.0.1.35", "10.0.1.40", "10.0.2.15"]
SERVICES = [("ssh", 22), ("rdp", 3389), ("vpn", 443), ("webmail", 443)]

BRUTE_IP = "203.0.113.45"
SCAN_IP = "198.51.100.23"
NEW_IP = "192.0.2.99"

SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 1433,
              1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9000,
              9090, 9200, 11211, 27017, 50000, 50070]


def fmt(dt: datetime) -> str:
    """Format a datetime as an ISO-like timestamp string."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


def background_events(rng: random.Random, count: int) -> list[dict]:
    """Normal daily noise.

    Successful logins stay inside business hours (08:00-18:00) so the
    planted off-hours login stands out; failures happen at any time.
    """
    events: list[dict] = []
    for _ in range(count):
        user = rng.choice(USERS)
        ip = rng.choice(INTERNAL_IPS)
        service, port = rng.choice(SERVICES)
        if rng.random() < 0.08:
            # Failed login (typos, expired passwords) - any time of day.
            dt = BASE_DATE + timedelta(minutes=rng.randint(0, 1439))
            events.append({
                "timestamp": fmt(dt),
                "event": "auth_failure",
                "username": user,
                "src_ip": ip,
                "service": service,
                "dst_port": port,
                "reason": rng.choice(["bad password", "unknown user",
                                      "account locked"]),
            })
        else:
            # Successful login - business hours only.
            dt = BASE_DATE + timedelta(minutes=rng.randint(8 * 60, 18 * 60 - 1))
            events.append({
                "timestamp": fmt(dt),
                "event": "auth_success",
                "username": user,
                "src_ip": ip,
                "service": service,
                "dst_port": port,
            })
        if rng.random() < 0.05:
            # Occasional background firewall noise.
            dt = BASE_DATE + timedelta(minutes=rng.randint(0, 1439))
            events.append({
                "timestamp": fmt(dt),
                "event": "firewall_deny",
                "src_ip": f"198.51.100.{rng.randint(2, 250)}",
                "dst_ip": "10.0.1.10",
                "dst_port": rng.choice([22, 23, 80, 443, 445, 3389, 8080]),
                "protocol": "tcp",
            })
    return events


def attack_events(rng: random.Random) -> list[dict]:
    """The four planted attack patterns."""
    events: list[dict] = []

    # 1. SSH brute force: 12 failures from one IP inside ~8 minutes.
    start = BASE_DATE + timedelta(hours=3, minutes=2)
    for i in range(12):
        dt = start + timedelta(seconds=i * 40 + rng.randint(0, 15))
        events.append({
            "timestamp": fmt(dt),
            "event": "auth_failure",
            "username": ["admin", "root", "test", "administrator"][i % 4],
            "src_ip": BRUTE_IP,
            "service": "ssh",
            "dst_port": 22,
            "reason": "bad password",
        })

    # 2. Port scan: 30 denied ports from one IP inside ~4 minutes.
    start = BASE_DATE + timedelta(hours=4, minutes=30)
    for i, port in enumerate(SCAN_PORTS):
        dt = start + timedelta(seconds=i * 8)
        events.append({
            "timestamp": fmt(dt),
            "event": "firewall_deny",
            "src_ip": SCAN_IP,
            "dst_ip": "10.0.1.10",
            "dst_port": port,
            "protocol": "tcp",
        })

    # 3. Successful login outside business hours.
    events.append({
        "timestamp": fmt(BASE_DATE + timedelta(hours=2, minutes=14)),
        "event": "auth_success",
        "username": "jdoe",
        "src_ip": "10.0.1.21",
        "service": "vpn",
        "dst_port": 443,
    })

    # 4. Successful login from a previously unseen IP (inside business hours,
    #    so only the new-IP rule fires).
    events.append({
        "timestamp": fmt(BASE_DATE + timedelta(hours=10, minutes=30)),
        "event": "auth_success",
        "username": "asmith",
        "src_ip": NEW_IP,
        "service": "webmail",
        "dst_port": 443,
    })
    return events


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate sample security logs (JSON lines).")
    parser.add_argument("--count", type=int, default=1500,
                        help="number of background events (default: 1500)")
    parser.add_argument("--output", default="sample_logs.jsonl",
                        help="output JSON-lines file")
    parser.add_argument("--known-ips", default="known_ips.txt",
                        help="output baseline file of known source IPs")
    parser.add_argument("--seed", type=int, default=42,
                        help="random seed for reproducibility")
    args = parser.parse_args()

    rng = random.Random(args.seed)
    events = background_events(rng, args.count) + attack_events(rng)
    events.sort(key=lambda e: e["timestamp"])

    with open(args.output, "w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")

    with open(args.known_ips, "w", encoding="utf-8") as f:
        f.write("\n".join(INTERNAL_IPS) + "\n")

    print(f"Wrote {len(events)} events to {args.output}")
    print(f"Wrote {len(INTERNAL_IPS)} known IPs to {args.known_ips}")


if __name__ == "__main__":
    main()
