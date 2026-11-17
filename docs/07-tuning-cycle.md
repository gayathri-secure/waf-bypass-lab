# 07 — The tuning cycle

A WAF rule is not finished when it blocks the payload that motivated it. This document
records the cycle used to test rule `1000001` beyond the four bypasses that produced it:
coverage of the attack class, a regression of the full payload set, and the false-positive
cost of the change.

Evidence: `evidence/screenshots/phase9-01` … `phase9-07`.
Raw results: `evidence/logs/phase9-regression.csv`.

---

## 1. Why a second round was needed

Phase 7 showed that `1000001` blocks the four payloads that bypassed CRS. On its own that
is a weak claim: **a rule that blocks exactly the payloads used to write it has
demonstrated nothing.** The questions worth asking are:

| Question | Answered in |
|---|---|
| Does it block commands it has never seen? | §3 |
| Is the block attributable to this rule, not to CRS? | §3 |
| Does anything that used to be blocked now pass? | §4 |
| Does it break legitimate input or ordinary pages? | §5 |

---

## 2. Method — switching the rule off safely

The cycle needs a "before" measurement, so `1000001` must be disabled without editing
the rule itself and without leaving the WAF half-configured. ModSecurity reads its
configuration top to bottom and honours removal directives at load time, so one line is
appended to the end of `rules/custom-cmdi.conf`:

```
SecRuleRemoveById 1000001
```

then:

```powershell
docker restart waf
```

The rule is still defined above; it is removed after definition. Restoring it is a
one-line delete. The state is verified rather than assumed — `ip=127.0.0.1;id` returns
`200` when the rule is off and `403` when it is on.

Renaming the mounted file also works, but risks the container reading a half-written
file during the restart window. Config-order removal has no such window.

---

## 3. Coverage of the class

With CRS alone and `1000001` disabled, nine commands and separators that appear nowhere
in the 37-payload set were sent to `/vulnerabilities/exec/`.

| Command or separator | CRS alone | With `1000001` | Rule logged on the blocked request |
|---|---|---|---|
| `;ls` | 403 | 403 | 932125, 932340 |
| `;pwd` | **200** | **403** | **1000001 only** |
| `;uname -a` | 403 | 403 | 932235, 932260 |
| `;hostname` | 403 | 403 | 932235, 932340, 932380 |
| `;ps aux` | **200** | **403** | **1000001 only** |
| `;env` | 403 | 403 | 932340 |
| `;date` | **200** | **403** | **1000001 only** |
| `\|\|id` | **200** | **403** | **1000001 only** |
| `&id` | **200** | **403** | **1000001 only** |

Five of nine were invisible to CRS at paranoia level 1.

Before the rule was re-enabled, execution was confirmed for the four that ran — the
`200` responses were not merely allowed, they produced shell output:

```
127.0.0.1;pwd        -> /var/www/html/vulnerabilities/exec
127.0.0.1;ps aux     -> www-data
127.0.0.1;date       -> 2026
127.0.0.1||id        -> NO OUTPUT
127.0.0.1&id         -> uid=33
```

`||id` produced no output because `||` short-circuits when its left operand succeeds:
`ping 127.0.0.1` works, so `id` never runs. That is a property of the operator, not of
the WAF, and it is recorded as such rather than claimed as an execution.

**Interpretation.** Two predictions were wrong: `;hostname` and `;env` were blocked, so
CRS's list is wider than expected. The separators are the more useful result — `||` and
`&` had never been tested in Phase 5, and neither is scored at PL1. The model enumerates
command names and does not model shell grammar at all, so both dimensions have gaps.

---

## 4. Regression of the complete payload set

With both custom rules armed, all 37 payloads were replayed from the archived set
(`payloads/sqli.txt`, `payloads/cmdi.txt`, `payloads/smuggling.py`) using
`scripts/regression.ps1`.

| Set | Payloads | Refused | Bypassed |
|---|---|---|---|
| SQL injection | 22 | 22 | 0 |
| Command injection | 12 | 12 | 0 |
| Request smuggling | 3 | 3 | 0 |
| **Total** | **37** | **37** | **0** |

Thirty-six returned `403`. The space-before-colon `Transfer-Encoding` probe returned
`400`, refused during header parsing before ModSecurity phase 1 — refused, but by the
HTTP server rather than by a rule. Recorded precisely rather than rounded up.

---

## 5. False positives

| Check | Result |
|---|---|
| `127.0.0.1`, `8.8.8.8`, `localhost` | 200 |
| `::1`, `2001:4860:4860::8888` | 200 |
| `scanme.nmap.org` | 200 |
| `/`, `/vulnerabilities/sqli/?id=1&Submit=Submit`, `/vulnerabilities/brute/` | 200 |
| `/instructions.php` | **403** — see §6 |

Six of six legitimate parameter values pass, including both IPv6 forms. The allow-list
was written to admit them and does.

---

## 6. An outbound false positive

`/instructions.php` is `403` through the WAF and `200` on the control path
(`127.0.0.1:8081`). The request is clean — **inbound score 0** — so the block is
response-side:

```
GET /instructions.php -> rules: 951230,951250,953100,953110,959100,980170
outbound score = 18   threshold = 4   status = 403
```

| Rule | Matched |
|---|---|
| 951230 mysql SQL information leakage | `ERROR 1045 (28000)` — quoted in DVWA's own README |
| 951250 sqlite SQL information leakage | a `Warning` string containing `SQLite` |
| 953100 PHP information leakage | `Cannot modify header information - headers already sent` |
| 953110 PHP source code leakage | `fopen` — quoted in the README text |
| 959100 outbound blocking evaluation | total 18 ≥ threshold 4 |

Two things are true at once:

1. **Content misclassified.** The page documents SQL errors and PHP functions, so it
   contains those strings. Response inspection classifies content, not intent.
2. **A real leak.** The page genuinely emits
   `Cannot modify header information - headers already sent` from `instructions.php:5`,
   which discloses internal paths.

The remedy is therefore not a blanket exclusion: fix the PHP warning, then narrow the
outbound rules for the documentation path only. This is ordinary tuning work — the
point is that response rules need their own false-positive pass, exactly as request
rules do.

---

## 7. What the cycle establishes

- The rule blocks **the class**, not the payloads it was written for: five unseen
  commands and separators, including two the original test never used.
- The block is attributable to `1000001` and not to CRS: the audit log for each of the
  five contains `1000001` and **no** `93xxxx` rule.
- Nothing regressed: 37 of 37 payloads refused.
- Legitimate input still works: 6 of 6 values, 3 of 3 ordinary pages.
- The single failure is on the response side, is documented, and has a specific remedy.

## 8. Reproducing it

```powershell
# 1. disable the rule
#    append  SecRuleRemoveById 1000001  to rules\custom-cmdi.conf
docker restart waf

# 2. verify it is off (expect 200)
curl.exe -s -o NUL -w "%{http_code}" --data "ip=127.0.0.1%3Bid" --data "Submit=Submit" "http://localhost/vulnerabilities/exec/"

# 3. delete the line, restart, verify 403, then replay everything
powershell -ExecutionPolicy Bypass -File scripts\regression.ps1
```

Smuggling probes (raw sockets, from the attacker host):

```zsh
python3 smuggling.py <windows-ip>
```

## 9. What would change in production

1. Run the coverage map against a sample of **the application's own parameters**, not
   generic commands, before enabling a deny rule.
2. Replace `^[0-9a-zA-Z.:-]+$` with a context-aware IPv4/IPv6 alternation, which also
   closes option injection (`ip=-f`), permitted by the current character class.
3. Give outbound rules their own false-positive pass, excluding a documentation path
   only after the underlying PHP warning is fixed.
4. Keep `scripts/regression.ps1` in CI: any rule change re-runs all 37 payloads plus the
   benign corpus.
