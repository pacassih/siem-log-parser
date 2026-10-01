# siem-log-parser

A SIEM-style log triage tool: it ingests JSON-lines security logs and flags
suspicious activity the way a Tier-1 SOC analyst would — then writes it up as
a severity-ranked threat report.

## What it does

`analyze.py` detects four patterns, all with configurable thresholds:

| Detection | Default rule | Severity |
|---|---|---|
| Brute-force logins | ≥ 5 auth failures from one IP within 10 min | HIGH |
| Port scans | ≥ 15 distinct denied ports from one IP within 5 min | MEDIUM |
| Off-hours logins | successful auth outside 08:00–18:00 | MEDIUM |
| New-IP logins | successful auth from an IP outside the known baseline | LOW |

`gen_logs.py` creates a realistic 24-hour dataset (1,600+ events: auth
successes/failures, firewall denies) with four attack patterns planted, so you
can demo the full pipeline without real log data.

## How to run

```bash
# 1. Generate the sample dataset (logs + known-IP baseline)
python gen_logs.py

# 2. Run the triage
python analyze.py sample_logs.jsonl --known-ips known_ips.txt
```

Tune the detections:

```bash
python analyze.py sample_logs.jsonl --known-ips known_ips.txt \
    --brute-threshold 5 --brute-window 10 \
    --scan-threshold 15 --scan-window 5 \
    --business-start 8 --business-end 18 \
    --report threat_report.md
```

## Example output

```
SIEM Triage Summary - 1617 events analyzed
  auth_failure: 129 | auth_success: 1385 | firewall_deny: 103

Findings (4), ranked by severity:

  1. [HIGH] Brute-force login attempt - 203.0.113.45
     12 failed logins in 7 min (03:02-03:09)
     -> targeted accounts: admin, administrator, root, test
  2. [MEDIUM] Off-hours login - 10.0.1.21
     jdoe authenticated at 02:14 via vpn
     -> verify with the user - possible compromised account
  3. [MEDIUM] Port scan detected - 198.51.100.23
     30 distinct ports probed (e.g. 21, 22, 23, 25, 53, 80, 110, 135, 139, 143...)
     -> reconnaissance - check for follow-up exploitation
  4. [LOW] Login from new IP - 192.0.2.99
     asmith authenticated from previously unseen IP 192.0.2.99
     -> confirm travel / new device with the user

Markdown report written to threat_report.md
```

## Skills demonstrated

- Security log parsing and normalization (JSON-lines)
- Sliding-window correlation for brute-force and scan detection
- Baseline/deviation analysis (known-IP allowlist)
- Alert prioritization by severity with recommended next steps
- Automated Markdown reporting for SOC handoff

## Files

| File | Purpose |
|---|---|
| `gen_logs.py` | Sample log generator (background noise + planted attacks) |
| `analyze.py` | The triage analyzer (CLI, configurable thresholds) |
| `sample_logs.jsonl` | Generated demo dataset |
| `known_ips.txt` | Generated baseline of known source IPs |
| `threat_report.md` | Example analyzer output |

Requirements: Python 3.10+, standard library only — no dependencies to install.
