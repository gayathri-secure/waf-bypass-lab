# Phase 3 — Baseline: Automated Tools vs CRS

## Setup
- Target: DVWA (security level low, auth disabled) behind ModSecurity v2.9.15 + OWASP CRS 4.30.0
- WAF mode: blocking (MODSEC_RULE_ENGINE=On), paranoia level 1, inbound threshold 5

## Results
| Test | Target | Result | Rule(s) |
|---|---|---|---|
| sqlmap (default UA) | http://192.168.3.86/ | Blocked (403) — not injectable | 913100 |
| sqlmap (--random-agent) | http://192.168.3.86/ | Blocked (403) — not injectable | 942100 |
| sqlmap (--dbs) | http://192.168.3.86:8081/ (no WAF) | VULNERABLE — databases enumerated | — |

## Key finding
CRS blocks automated tooling at two independent layers:
1. Tool fingerprinting (913100 — scanner User-Agent)
2. Payload inspection (942100 — libinjection SQLi detection)

A successful bypass must defeat both.

## Evidence
- evidence/screenshots/phase3-01-sqlmap-blocked-default.png
- evidence/screenshots/phase3-02-waf-log-913100-scanner-ua.png
- evidence/screenshots/phase3-03-sqlmap-blocked-random-agent.png
- evidence/screenshots/phase3-04-waf-log-942100-payloads.png
- evidence/screenshots/phase3-05-sqlmap-direct-no-waf-success.png

## Control test
The same tool succeeds against the app directly (port 8081), proving the app is
exploitable and the WAF is the only obstacle.
