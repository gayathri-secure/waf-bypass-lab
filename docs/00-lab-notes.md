# WAF & Signature Bypass Lab — Working Notes

Running notebook. Newest work is at the bottom of the session log.
Screenshots: `evidence/screenshots/`. Log extracts: `evidence/logs/`.

---

## Lab facts

| Item | Value |
|---|---|
| Project folder | `D:\CyberLab\waf-lab` |
| Attacker | Kali VM, **bridged** networking (NAT declined) |
| Windows host IP | **changes every session** (bridged DHCP) |
| IPs seen so far | 192.168.3.86 → 192.168.106.86 → 192.168.31.86 |
| Kali IP | 192.168.31.70 (last known) |
| WAF | ModSecurity 2.9.15 + OWASP CRS 4.30.0 on Apache 2.4.68 |
| WAF mode | blocking (`SecRuleEngine On`), paranoia level 1, inbound threshold 5 |
| Target | DVWA, security level `low`, authentication disabled |
| Port 80 | through the WAF |
| Port 8081 | direct to DVWA, bound to `127.0.0.1` only (control path, host-only) |

**Run `ipconfig` before every session.** Early "failures" were mostly curl hitting a
stale IP (HTTP `000`).

---

## Architecture

```
Kali (attacker)
      │  :80
      ▼
[ waf ]  Apache 2.4.68 + ModSecurity 2.9.15 + CRS 4.30.0
      │  :80
      ▼
[ dvwa ]  PHP 8 / Apache  — intentionally vulnerable
      │
      ▼
[ mariadb 10.11 ]

control path (no WAF): Windows host 127.0.0.1:8081 ──▶ [ dvwa ]
```

The control path exists to prove *which* layer failed. If an attack works on 80 and
on 8081, the application is at fault; if it is blocked on 80 and works on 8081, the
WAF is the only difference.

---

## Rule map (quick reference)

| Rule | Meaning | Seen in |
|---|---|---|
| 913100 | scanner / tool user-agent (sqlmap) | Phase 3 |
| 920181 | Content-Length **and** Transfer-Encoding present (**inert here** — see Phase 6) | inspected |
| 920350 | Host header is a numeric IP address (+3 noise) | every IP-based test |
| 921110 | HTTP request smuggling (method inside body) | inspected |
| 932130 | command substitution `$(...)` | Phase 5 |
| 932160 | Unix command names (`cat` etc.) | Phase 5 |
| 932235 / 932260 | shell obfuscation patterns | Phase 5 |
| 932380 | Unix command keyword list (`whoami` etc.) | Phase 5 |
| 942100 | **libinjection** — SQL grammar parser | Phase 3/4 (22/22) |
| 942151 | SQL function names | Phase 4 |
| 942160 | time-based SQLi (`SLEEP`) | Phase 4 |
| 942190 / 942360 | SQL comment / tautology patterns | Phase 4 |
| 942230 | conditional statements (`CASE WHEN`) | Phase 4 |
| 942500 | MySQL versioned comment `/*!50000*/` | Phase 4 |
| 949110 | blocking evaluation (score ≥ 5 → 403) | all blocks |
| 980170 | anomaly score report (not a block) | all requests |
| **1000001** | **custom: allow-list on the `ip` parameter** | Phase 7 |
| **1000002** | **custom: reject any `Transfer-Encoding`** | Phase 7 |

---

## Session log

### 2026-11-14 — Phases 0–2: build and baseline

- Installed Docker Desktop; built 3 containers (`waf`, `dvwa`, `db`); initialised the
  DVWA database via `http://localhost:8081/setup.php`.
- Verified the WAF blocks: SQLi, XSS and command injection → all `403`.
- A lone single quote `'` returned `200` (score 3, below the threshold of 5) — this is
  how the anomaly-scoring model was confirmed.
- Screenshots: `phase2-01` … `phase2-07`.

### 2026-11-16 — Phase 3: sqlmap baseline

- `sqlmap` through the WAF: blocked by **913100** (scanner user-agent).
- `sqlmap --random-agent`: still blocked, by **942100** (libinjection on the payload).
- Same run against `127.0.0.1:8081` (no WAF): successful — injection confirmed and the
  database enumerated.
- Lesson: the WAF blocks the tool twice, once on identity and once on payload. Removing
  the user-agent signature does not help, because detection does not depend on it.
- Screenshots: `phase3-01` … `phase3-05`.

### 2026-11-16 — Phase 4 batch 1: cosmetic SQLi obfuscation

- 12 payloads: OR tautology, comment insertion, `UNION SELECT`, `/*!50000*/`, hex `0x31`,
  scientific `1e0`, `CHAR()`, case mixing, hash comment, `SLEEP()`.
- Result: **12/12 → 403**.
- Rules observed:
  - **942100 (libinjection) on 12/12** ← primary control
  - 942190 + 942360 on UNION payloads
  - 942500 on MySQL in-line comment
  - 942160 on `SLEEP` (time-based)
  - 949110 blocking, 920350 numeric-host noise, 980170 score report
- Lesson: CRS normalises input and parses SQL grammar, so cosmetic obfuscation is dead
  at PL1.
- Screenshots: `phase4-01`, `phase4-02`.

### 2026-11-16 — Phase 4 batch 2: grammar SQLi + HPP

- 10 payloads: `LIKE`, `BETWEEN`, `IN`, `GREATEST`, `IF`, `CASE WHEN`, `ASCII`,
  `STRCMP`, `<=>` and a quoted-comparison variant.
- HPP test: `?id=1&id=1' OR 1=1-- -`.
- Result: **10/10 → 403**, HPP → **403**.
- Rules: 942100 on **22/22 total attempts**; extras 942151 (functions), 942230
  (conditional), 942190/942360, 942500, 942160.
- Conclusion: CRS PL1 SQLi defence is robust; libinjection is the control.
- Implication: any bypass must come from a different layer — command-injection regexes
  or protocol parsing.
- Screenshots: `phase4-03`, `phase4-04`, `phase4-05`.

### 2026-11-16 — Phase 5 (a): GET vs POST mistake

- I first tested `/vulnerabilities/exec/` with **GET**. Every payload returned `200`
  but with no command output.
- Cause: DVWA reads `$_POST['ip']`. A GET request only re-renders the form — nothing
  executes.
- Proof: re-sent the same value as POST and `uid=33(www-data)` appeared immediately.
- Lesson: `200 | none` is not "bypass"; it may be "the app never ran anything". Always
  define the success criterion first (here: `uid=` in the response body).

### 2026-11-16 — Phase 5 (b): 4 confirmed command-injection bypasses

Endpoint: `POST /vulnerabilities/exec/`, parameter `ip`.

| # | Payload (`ip=`) | Status | Output | Rules |
|---|---|---|---|---|
| 1 | `127.0.0.1;id` | **200** | `uid=33(www-data)` | 920350, 980170 |
| 2 | `127.0.0.1\|id` | **200** | `uid=33(www-data)` | 920350, 980170 |
| 3 | `127.0.0.1&&id` | **200** | `uid=33(www-data)` | 920350, 980170 |
| 4 | `127.0.0.1` + newline + `id` | **200** | `uid=33(www-data)` | 920350, 980170 |
| 5 | `127.0.0.1;cat /etc/passwd` | 403 | — | 930120, 932160 |
| 6 | `127.0.0.1;cat$IFS/etc/passwd` | 403 | — | 930120, 932160 |
| 7 | `127.0.0.1;cat</etc/passwd` | 403 | — | 930120, 932160 |
| 8 | `127.0.0.1;c\at /etc/passwd` | 403 | — | 930120, 932160 |
| 9 | `127.0.0.1;/bin/c?t /etc/passwd` | 403 | — | 930120, 932160 |
| 10 | `127.0.0.1;echo <b64>\|base64 -d\|sh` | 403 | — | 932235, 932260 |
| 11 | `127.0.0.1;$(id)` | 403 | — | 932130 |
| 12 | ``127.0.0.1;echo `whoami` `` | 403 | — | 932235, 932260, 932380 |

- Reproduced identically on `127.0.0.1:8081` (no WAF) → the defect is the application's.
- Rows 1–4: HTTP 200, shell output in the body, and **no 93xxxx rule in the audit
  log** — the request was not merely allowed, it was never scored.
- Backtick case: `ip=127.0.0.1;` + backtick + `id` returned `200` with no output. The
  shell substituted `id` into the command line (`ping ...;uid=33(www-data)`), so the
  command ran but produced no clean output. Detection miss, execution inconclusive —
  recorded as such, not claimed as a clean bypass.
- `%0a` written literally was double-encoded by `--data-urlencode` (`%250a`), so PHP
  received the text `%0a` and nothing executed. Fixed by building a real newline with
  `$'...\n...'`.
- Key insight: detection is a **command-name list**. `id` is absent at PL1, so the
  separator (`;`, `|`, `&&`, newline) is irrelevant to detection. `cat` and `whoami`
  are present, so they are caught however they are spelled.
- Screenshots: `phase5-01` … `phase5-05`.

### 2026-11-16 — Phase 6: HTTP request smuggling

Probes (raw TCP, `Host: lab.local`): `payloads/smuggling.py`.

| Probe | Result |
|---|---|
| CL+TE classic | `HTTP/1.1 200 OK`, no rule fired |
| TE.CL chunked | no HTTP response; Apache logged "Error reading request body" (400) |
| TE space-before-colon | `HTTP/1.1 400 Bad Request` (rejected at header parsing) |

- Control test: identical body with **only** `Content-Length: 6` → the WAF logged
  `Content-Length: 6` and body `0\r\n\r\nG`. This isolates the cause.
- Root cause: Apache 2.4.68 discards `Content-Length` when `Transfer-Encoding` is
  present (RFC 7230 §3.3.3) **before** ModSecurity phase 1 runs. The WAF logged
  `Host, Transfer-Encoding, Connection` and an empty body, with no `Content-Length`.
- Consequence: CRS **920181** ("Content-Length and Transfer-Encoding headers present",
  PL1, +3) is loaded but structurally unable to fire in this topology.
- No desynchronisation observed: at most one backend request, never a smuggled response.
- Mitigation came from HTTP message framing (normalisation), not WAF detection.
- Caveat: single-request probes with `Connection: close`; a definitive desync PoC needs
  pipelined requests on a persistent connection.
- Implication for Phase 7: detection is impossible after normalisation, so the custom
  rule must be **policy** based (reject `Transfer-Encoding` outright).
- Screenshots: `phase6-01`, `phase6-02`, `phase6-03`.

### 2026-11-16 — Phase 7: custom rules close both gaps

`rules/custom-cmdi.conf`, mounted at `/opt/owasp-crs/plugins/custom-after.conf`.

| Payload | Before | After | Rule |
|---|---|---|---|
| `127.0.0.1;id` | 200 + `uid=33` | **403** | 1000001 |
| `127.0.0.1\|id` | 200 + `uid=33` | **403** | 1000001 |
| `127.0.0.1&&id` | 200 + `uid=33` | **403** | 1000001 |
| newline + `id` | 200 + `uid=33` | **403** | 1000001 |
| ``;`id` `` | 200 (no output) | **403** | 1000001 |
| `127.0.0.1`, `8.8.8.8`, `localhost` | 200 | **200** | — (no false positives) |
| CL+TE smuggling probe | 200 | **403** | 1000002 |

- **1000001** (phase 2, allow-list): `ip` must match `^[0-9a-zA-Z.:-]+$`. It blocks every
  separator, not just the four that were tested — a positive model, not a keyword list.
- **1000002** (phase 1, policy): any `Transfer-Encoding` header → 403, compensating for
  920181 being unreachable after Apache's normalisation.
- Screenshots: `phase7-01` … `phase7-04`.
- Log extract: `evidence/logs/custom-rule-hits.log`
  (8 transactions: 5× 1000001, 3× 1000002).

### 2026-11-16 — Phase 8: report and repository

- Wrote `README.md` (result summary, architecture, rebuild steps, screenshot gallery),
  `docs/04-attack-results.md`, `docs/05-conclusion.md`.
- Added `payloads/sqli.txt`, `payloads/cmdi.txt`, `payloads/smuggling.py`, `.gitignore`.
- Dumped WAF audit log to `evidence/logs/` for quotable evidence.
- Published to GitHub.

---

## Answered questions

- **Does HPP bypass CRS?** No. `?id=1&id=<payload>` → 403, 942100. Both values are
  inspected (Phase 4).
- **Is cosmetic obfuscation worth trying?** No, not against libinjection. Grammar-based
  payloads fail too, for the same reason (Phase 4).
- **Why did `200 | none` appear in Phase 5?** GET against a POST-only form (Phase 5a).
- **Why no 921110 on the smuggling probes?** 921110 matches an HTTP method embedded in
  a body (`GET / HTTP/1.1` inside a parameter), not a CL/TE header conflict. The header
  conflict rule is 920181, and Apache strips `Content-Length` first (Phase 6).
- **Does the WAF see my real IP?** No. Docker NAT presents every client as
  `172.18.0.1`. Per-client attribution was therefore out of scope.

## Open questions / future work

- Double-encoding (`%2527` on the SQLi page) — not yet tested.
- Paranoia level 2 and 3: how much of the command-injection gap closes, and at what
  false-positive cost?
- False-positive testing beyond three benign inputs — a realistic benign corpus and a
  crawl of normal DVWA pages.
- Other attack classes: LFI, XXE, SSRF, unrestricted file upload.
- A proper desynchronisation PoC with pipelined requests on one persistent connection.
- Outbound (response) rules were never exercised.

---

## Mistakes I made (and what they taught me)

1. **Tested a POST form with GET.** Cost a full round of misleading `200`s. Lesson:
   confirm the request contract (method + parameter) before interpreting results.
2. **Trusted a stale IP.** `000` responses after DHCP changed the address. Lesson:
   `ipconfig` first.
3. **Double-encoded my own payload** with `--data-urlencode` (`%0a` → `%250a`). Lesson:
   check what actually arrived, not what I intended to send.
4. **Wrote to `/root/` as user `kali`.** Lesson: know your privilege boundary.
5. **Forgot zsh history expansion** — `!` in `/*!50000*/` triggered
   `zsh: no such event`. Fix: `setopt no_bang_hist` before running those payloads.
6. **Assumed "blocked" meant "blocked correctly".** The rule map showed several blocks
   carried `920350` (+3 numeric-Host noise). Always confirm *which* rule fired.
7. **Assumed a rule that exists must be able to fire.** Rule 920181 is loaded but cannot
   evaluate after Apache's header normalisation. Presence ≠ coverage.

---

## Evidence index

| Phase | Screenshots | Demonstrates |
|---|---|---|
| 2 — build & baseline | `phase2-01` … `phase2-07` | 3 containers healthy; DVWA via WAF and directly; SQLi/XSS/cmdi → 403 |
| 3 — sqlmap | `phase3-01` … `phase3-05` | blocked by 913100 and 942100; same payloads succeed on 8081 |
| 4 — SQLi obfuscation | `phase4-01` … `phase4-05` | 22/22 blocked; 942100 every time; HPP blocked |
| 5 — command injection | `phase5-01` … `phase5-05` | 4 bypasses execute; rule map shows no detection rule |
| 6 — smuggling | `phase6-01` … `phase6-03` | CL/TE normalised; `Content-Length` stripped pre-inspection |
| 7 — custom rules | `phase7-01` … `phase7-04` | bypasses → 403; no false positives; smuggling → 403 |

Log extracts: `phase2-sqli-942100.txt`, `all-transactions.jsonl`,
`custom-rule-hits.log`, `phase7-transactions.jsonl`.
