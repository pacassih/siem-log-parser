# Threat Triage Report

Generated: 2026-10-01 04:34
Log file: `sample_logs.jsonl` (1617 events)

## Detection thresholds

- Brute force: >= 5 failures / 10 min
- Port scan: >= 15 ports / 5 min
- Business hours: 08:00-18:00

## Event counts

| Event | Count |
|---|---|
| auth_failure | 129 |
| auth_success | 1385 |
| firewall_deny | 103 |

## Findings (severity-ranked)

### 1. [HIGH] Brute-force login attempt - `203.0.113.45`

- **Detail:** 12 failed logins in 7 min (03:02-03:09)
- **Recommended next step:** targeted accounts: admin, administrator, root, test

### 2. [MEDIUM] Off-hours login - `10.0.1.21`

- **Detail:** jdoe authenticated at 02:14 via vpn
- **Recommended next step:** verify with the user - possible compromised account

### 3. [MEDIUM] Port scan detected - `198.51.100.23`

- **Detail:** 30 distinct ports probed (e.g. 21, 22, 23, 25, 53, 80, 110, 135, 139, 143...)
- **Recommended next step:** reconnaissance - check for follow-up exploitation

### 4. [LOW] Login from new IP - `192.0.2.99`

- **Detail:** asmith authenticated from previously unseen IP 192.0.2.99
- **Recommended next step:** confirm travel / new device with the user
