#!/usr/bin/env python3
"""SIEM-style log triage analyzer.

Reads JSON-lines security logs (see ``gen_logs.py``) and detects:

    * Brute-force logins  - N auth failures from one IP within T minutes
    * Port scans           - one IP touching many denied ports in a window
    * Off-hours logins     - successful auth outside business hours
    * New-IP logins        - successful auth from an IP outside the baseline

Prints a severity-ranked console summary and writes a Markdown threat
report. All detection thresholds are configurable via CLI flags.

Usage:
    python analyze.py sample_logs.jsonl --known-ips known_ips.txt
    python analyze.py sample_logs.jsonl --brute-threshold 5 --brute-window 10 \\
        --scan-threshold 15 --scan-window 5 --report threat_report.md
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def parse_ts(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S")


def load_events(path: str) -> list[dict]:
    events = []
    with open(path, encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                print(f"Warning: skipping malformed line {line_no}: {exc}")
    return events


def load_known_ips(path: str | None) -> set[str] | None:
    if path is None:
        return None
    with open(path, encoding="utf-8") as f:
        return {line.strip() for line in f if line.strip()}


def detect_brute_force(events: list[dict], threshold: int,
                       window_min: int) -> list[dict]:
    """Sliding-window count of auth failures per source IP."""
    failures: dict[str, list[tuple[datetime, dict]]] = defaultdict(list)
    for event in events:
        if event.get("event") == "auth_failure" and "src_ip" in event:
            failures[event["src_ip"]].append((parse_ts(event["timestamp"]),
                                              event))

    findings = []
    window = timedelta(minutes=window_min)
    for ip, items in failures.items():
        items.sort(key=lambda item: item[0])
        best: list[tuple[datetime, dict]] = []
        left = 0
        for right in range(len(items)):
            while items[right][0] - items[left][0] > window:
                left += 1
            if right - left + 1 >= threshold and right - left + 1 > len(best):
                best = items[left:right + 1]
        if best:
            users = sorted({e["username"] for _, e in best if "username" in e})
            span_min = int((best[-1][0] - best[0][0]).total_seconds() // 60)
            findings.append({
                "type": "Brute-force login attempt",
                "severity": "HIGH",
                "src_ip": ip,
                "detail": (f"{len(best)} failed logins in {span_min} min "
                           f"({best[0][0]:%H:%M}-{best[-1][0]:%H:%M})"),
                "extra": f"targeted accounts: {', '.join(users)}",
            })
    return findings


def detect_port_scans(events: list[dict], port_threshold: int,
                      window_min: int) -> list[dict]:
    """Sliding-window count of *distinct* denied ports per source IP."""
    denies: dict[str, list[tuple[datetime, int]]] = defaultdict(list)
    for event in events:
        if event.get("event") == "firewall_deny" and "src_ip" in event:
            denies[event["src_ip"]].append((parse_ts(event["timestamp"]),
                                            event.get("dst_port")))

    findings = []
    window = timedelta(minutes=window_min)
    for ip, items in denies.items():
        items.sort(key=lambda item: item[0])
        best_ports: set[int] = set()
        left = 0
        for right in range(len(items)):
            while items[right][0] - items[left][0] > window:
                left += 1
            ports = {port for _, port in items[left:right + 1]
                     if port is not None}
            if len(ports) >= port_threshold and len(ports) > len(best_ports):
                best_ports = ports
        if best_ports:
            sample = sorted(best_ports)[:10]
            findings.append({
                "type": "Port scan detected",
                "severity": "MEDIUM",
                "src_ip": ip,
                "detail": (f"{len(best_ports)} distinct ports probed "
                           f"(e.g. {', '.join(map(str, sample))}...)"),
                "extra": "reconnaissance - check for follow-up exploitation",
            })
    return findings


def detect_off_hours(events: list[dict], start: int, end: int) -> list[dict]:
    """Successful logins outside the business-hours window."""
    findings = []
    for event in events:
        if event.get("event") != "auth_success":
            continue
        hour = parse_ts(event["timestamp"]).hour
        if hour < start or hour >= end:
            findings.append({
                "type": "Off-hours login",
                "severity": "MEDIUM",
                "src_ip": event.get("src_ip", "?"),
                "detail": (f"{event.get('username', '?')} authenticated at "
                           f"{event['timestamp'][11:16]} via "
                           f"{event.get('service', '?')}"),
                "extra": "verify with the user - possible compromised account",
            })
    return findings


def detect_new_ips(events: list[dict],
                   known: set[str] | None) -> list[dict]:
    """Successful logins from IPs absent from the known baseline."""
    if known is None:
        return []
    findings = []
    for event in events:
        if event.get("event") != "auth_success":
            continue
        ip = event.get("src_ip", "")
        if ip and ip not in known:
            findings.append({
                "type": "Login from new IP",
                "severity": "LOW",
                "src_ip": ip,
                "detail": (f"{event.get('username', '?')} authenticated from "
                           f"previously unseen IP {ip}"),
                "extra": "confirm travel / new device with the user",
            })
    return findings


def rank(findings: list[dict]) -> list[dict]:
    return sorted(findings,
                  key=lambda f: (SEVERITY_ORDER[f["severity"]], f["src_ip"]))


def print_summary(events: list[dict], findings: list[dict]) -> None:
    counts = Counter(e.get("event", "?") for e in events)
    print(f"\nSIEM Triage Summary - {len(events)} events analyzed")
    print("  " + " | ".join(f"{k}: {v}" for k, v in sorted(counts.items())))
    print(f"\nFindings ({len(findings)}), ranked by severity:\n")
    if not findings:
        print("  No findings - all clear.")
        return
    for i, f in enumerate(findings, 1):
        print(f"  {i}. [{f['severity']}] {f['type']} - {f['src_ip']}")
        print(f"     {f['detail']}")
        print(f"     -> {f['extra']}")


def write_report(path: str, events: list[dict], findings: list[dict],
                 args: argparse.Namespace) -> None:
    counts = Counter(e.get("event", "?") for e in events)
    lines = [
        "# Threat Triage Report",
        "",
        f"Generated: {datetime.now():%Y-%m-%d %H:%M}",
        f"Log file: `{args.logfile}` ({len(events)} events)",
        "",
        "## Detection thresholds",
        "",
        f"- Brute force: >= {args.brute_threshold} failures / "
        f"{args.brute_window} min",
        f"- Port scan: >= {args.scan_threshold} ports / {args.scan_window} min",
        f"- Business hours: {args.business_start:02d}:00-"
        f"{args.business_end:02d}:00",
        "",
        "## Event counts",
        "",
        "| Event | Count |",
        "|---|---|",
    ]
    lines += [f"| {k} | {v} |" for k, v in sorted(counts.items())]
    lines += ["", "## Findings (severity-ranked)", ""]
    if not findings:
        lines.append("No findings - all clear.")
    for i, f in enumerate(findings, 1):
        lines += [
            f"### {i}. [{f['severity']}] {f['type']} - `{f['src_ip']}`",
            "",
            f"- **Detail:** {f['detail']}",
            f"- **Recommended next step:** {f['extra']}",
            "",
        ]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    print(f"\nMarkdown report written to {path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SIEM-style log triage: detect brute force, port scans, "
                    "off-hours and new-IP logins.")
    parser.add_argument("logfile", help="JSON-lines log file to analyze")
    parser.add_argument("--known-ips", default=None,
                        help="baseline file of known source IPs")
    parser.add_argument("--brute-threshold", type=int, default=5,
                        help="failures that flag brute force (default: 5)")
    parser.add_argument("--brute-window", type=int, default=10,
                        help="brute-force window in minutes (default: 10)")
    parser.add_argument("--scan-threshold", type=int, default=15,
                        help="distinct ports that flag a scan (default: 15)")
    parser.add_argument("--scan-window", type=int, default=5,
                        help="port-scan window in minutes (default: 5)")
    parser.add_argument("--business-start", type=int, default=8,
                        help="business-hours start (default: 8)")
    parser.add_argument("--business-end", type=int, default=18,
                        help="business-hours end (default: 18)")
    parser.add_argument("--report", default="threat_report.md",
                        help="Markdown report output path")
    args = parser.parse_args()

    events = load_events(args.logfile)
    known = load_known_ips(args.known_ips)

    findings = rank(
        detect_brute_force(events, args.brute_threshold, args.brute_window)
        + detect_port_scans(events, args.scan_threshold, args.scan_window)
        + detect_off_hours(events, args.business_start, args.business_end)
        + detect_new_ips(events, known)
    )

    print_summary(events, findings)
    write_report(args.report, events, findings, args)


if __name__ == "__main__":
    main()
