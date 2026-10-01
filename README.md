# vuln-prioritizer

Takes a Qualys-style CSV export of vulnerability findings and turns it into a
risk-ranked remediation queue — because raw CVSS alone will tell you to patch
the lab printer before the production database.

## The scoring model

```
priority = severity_weight × asset_weight × age_factor × exploit_factor
```

| Factor | Values | Why |
|---|---|---|
| `severity_weight` | Critical=4, High=3, Medium=2, Low=1 | scanner severity, normalized |
| `asset_weight` | critical=1.5, high=1.25, medium=1.0, low=0.75 (from `assets.json`) | a bug on prod matters more than the same bug on a printer |
| `age_factor` | >180d=1.5, >90d=1.3, >30d=1.15, else 1.0 | old findings are neglected findings |
| `exploit_factor` | 1.5 if a public exploit exists, else 1.0 | exploitability beats theoretical severity |

Every finding's console output includes its score breakdown
(e.g. `4 x 1.5 x 1.5 x 1.5`), so the ranking is fully explainable — no black
box. SLA targets per severity band: **Critical 15 days, High 30 days, Medium
90 days, Low 180 days**, with overdue items flagged.

## How to run

```bash
python prioritize.py sample_findings.csv --assets assets.json
```

Options: `--as-of YYYY-MM-DD` (reference date for age math, default: today),
`--top N` (show only the top N), `--report FILE` (Markdown report path).

Bring your own data — any CSV with these columns works:

```
ip,hostname,title,cve,severity,cvss,port,protocol,first_seen,last_seen,exploit_available
```

## Example output

```
Remediation Queue - 12 findings ranked by priority

 Rk  Score Sev      IP            Host          CVE               Age Status         Title
------------------------------------------------------------------------------------------
  1  13.50 Critical 10.0.1.10     web-prod-01   CVE-2019-19781    181d due 2026-10-13 Citrix ADC path traversal RCE
  2  11.70 Critical 10.0.1.10     web-prod-01   CVE-2021-44228    110d due 2026-10-13 Apache Log4j remote code execution
  3  11.70 Critical 10.0.1.11     web-prod-02   CVE-2022-22965     91d due 2026-10-13 Spring Framework remote code execution
  ...
  6  10.12 High     10.0.1.10     web-prod-01   CVE-2017-0144     228d due 2026-10-28 SMB remote code execution (EternalBlue)
  ...
  9   6.00 Critical 10.0.2.15     wkst-042      CVE-2019-0708      29d due 2026-10-13 Windows RDP remote code execution (BlueKeep)

Top 5 - score breakdown (sev x asset x age x exploit):
   13.50 = 4 x 1.5 x 1.5 x 1.5    10.0.1.10 Citrix ADC path traversal RCE
   11.70 = 4 x 1.5 x 1.3 x 1.5    10.0.1.10 Apache Log4j remote code execution
```

Note rank 6 vs rank 9: a *High* (EternalBlue) on a production web server
outranks a *Critical* (BlueKeep) on a single workstation — asset context and
exposure time correctly beat the raw severity label. That's the whole point of
the model, and a good interview talking point.

## Skills demonstrated

- Vulnerability management workflow (ingest → prioritize → SLA tracking)
- Risk-based prioritization beyond raw CVSS scores
- Asset criticality modeling from a configurable inventory file
- Explainable scoring — every rank shows its math
- CSV data processing and Markdown reporting for stakeholder handoff

## Files

| File | Purpose |
|---|---|
| `prioritize.py` | The prioritizer (CLI, configurable reference date) |
| `sample_findings.csv` | 40 realistic findings across 8 hosts (Qualys-style columns) |
| `assets.json` | Asset criticality tiers (IP → critical/high/medium/low) |
| `remediation_plan.md` | Example analyzer output |

Requirements: Python 3.10+, standard library only — no dependencies to install.
