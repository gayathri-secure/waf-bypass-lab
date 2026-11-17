# 04 — Attack results

All traffic originates from Kali Linux. `WAF` = `http://<host>:80` (through
ModSecurity/CRS). `DIRECT` = `http://<host>:8081` (DVWA without the WAF, control
path). DVWA security level `low` throughout.

Measurement caveat: requests sent with a numeric `Host:` header (e.g.
`Host: 192.168.31.86`) additionally trigger **920350** ("Host header is a numeric
IP address", +3, PL1). Requests sent with `Host: lab.local` do not. This affects
the anomaly score but does not change any conclusion below, because the payloads
that were blocked were blocked by rules that each score 5 or more on their own.

---

## Phase 3 — Baseline: sqlmap against the WAF

| Run | Target | Result |
|---|---|---|
| `sqlmap -u ".../sqli/?id=1"` default UA | WAF | blocked, **913100** (scanner user-agent) |
| `sqlmap --random-agent` | WAF | blocked, **942100** (libinjection) on payload |
| `sqlmap` | DIRECT :8081 | successful — injection confirmed, database enumerated |

**Conclusion:** the WAF blocks the tool twice over — once on the tool's identity,
once on the payload's structure. Removing the UA signature does not help, because
detection does not depend on it.

---

## Phase 4 — SQL injection: 22 obfuscation attempts

Two batches. Batch 1 (12 payloads) varied the *cosmetics*: inline comments,
MySQL versioned comments (`/*!50000*/`), hexadecimal literals, scientific
notation, case variation, `UNION SELECT`, and alternative whitespace. Batch 2
(10 payloads) varied the *grammar*:

| # | Payload | Status | Rules |
|---|---|---|---|
| 1 | `1' AND 1 LIKE 1-- -` | 403 | 942100 |
| 2 | `1' AND 'a' LIKE 'a'-- -` | 403 | 942100 |
| 3 | `1' AND 1 BETWEEN 0 AND 2-- -` | 403 | 942100 |
| 4 | `1' AND 1 IN (1)-- -` | 403 | 942100 |
| 5 | `1' AND GREATEST(1,1)=1-- -` | 403 | 942100, 942151 |
| 6 | `1' AND IF(1,1,0)=1-- -` | 403 | 942100 |
| 7 | `1' AND CASE WHEN 1 THEN 1 ELSE 0 END=1-- -` | 403 | 942100, 942230 |
| 8 | `1' AND ASCII('a')=97-- -` | 403 | 942100, 942151 |
| 9 | `1' AND STRCMP('a','a')=0-- -` | 403 | 942100, 942151 |
| 10 | `1' AND 1<=>1-- -` | 403 | 942100 |

Plus HTTP Parameter Pollution (`?id=1&id=1' OR 1=1-- -`) → **403**, 942100 — CRS
inspected both values.

**Result: 22/22 blocked.** 942100 (libinjection) fired on every attempt; secondary
rules (942151 SQL functions, 942230 conditional statements, 942190/942360 UNION,
942500 MySQL in-line comments, 942160 time-based) added depth.

**Conclusion:** at PL1, CRS SQLi detection is a parser, not a pattern list.
Re-spelling the payload does not change its token structure, so obfuscation buys
nothing. This is a control that works.

---

## Phase 5 — Command injection: 4 confirmed bypasses

Endpoint: `POST /vulnerabilities/exec/`, parameter `ip`.
GET requests only re-render the form; DVWA reads `$_POST['ip']`.

| # | Payload (`ip=`) | Status | Output | Rules fired |
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

Rows 1–4 are **execution-confirmed**: HTTP 200, shell output in the response, and
**no 93xxxx rule in the audit log** — the request was not merely allowed, it was
never even scored. Reproduced identically on `DIRECT:8081`, confirming the defect
is the application's and the WAF is the only difference.

**Why the split?** The 932xxx rules are fixed phrase lists and regexes, not a shell
grammar. At paranoia level 1, 932160 is documented as matching commands **with a full
path**: its data file contains `bin/cat` and `bin/id`, not `cat` and `id`. It also
contains file paths such as `etc/passwd`. Rows 5–9 therefore matched because every one of
them referenced `/etc/passwd` (930120 scores restricted-file access independently), not
because the command was spelled `cat`.

Bare values confirm the model: `ip=cat`, `ip=id`, `ip=pwd` and `ip=uname` all return
`200`; `ip=whoami` returns `403` under 932260, a regex of bare command names. Conversely,
the separator (`;`, `|`, `&&`, newline) is irrelevant to detection, because the rules match
a command token, not shell syntax.

**Conclusion:** command injection at PL1 is protected by a keyword list. Lists
have gaps, and `id` sits in one. This is the lab's primary finding.

---

## Phase 6 — HTTP request smuggling

Raw TCP probes sent to port 80 with `Host: lab.local`.

| Probe | Bytes sent (framing) | Response | What ModSecurity saw |
|---|---|---|---|
| CL+TE classic | `Content-Length: 6` + `Transfer-Encoding: chunked`, body `0\r\n\r\nG` | **200 OK**, 1 response | Host, **Transfer-Encoding**, Connection — no Content-Length; body empty |
| TE.CL chunked | `TE: chunked` + `CL: 4`, chunk containing `GPOST / HTTP/1.1` | **0 responses** (socket closed; Apache logged 400 "Error reading request body") | same — CL absent |
| TE space-before-colon | `Transfer-Encoding : chunked` | **400 Bad Request** | rejected during header parsing |

Control test: identical body with `Content-Length: 6` **only** → the WAF logged
`Content-Length: 6` and the body `0\r\n\r\nG`. This isolates the cause.

**Root cause of the 200:** Apache 2.4.68 enforces RFC 7230 §3.3.3 by discarding
`Content-Length` whenever `Transfer-Encoding` is present, *before* ModSecurity
phase 1 executes. By the time the rules run there is only one framing header left,
so no parser differential can exist between front end and backend.

**Consequence for the rule set:** CRS **920181** ("Content-Length and
Transfer-Encoding headers present", PL1, +3) exists and is loaded, but is
structurally unable to fire in this topology. The control that protected the
deployment was the HTTP server's message framing, not WAF detection — an
important distinction when documenting defence in depth.

**No desynchronisation was achieved.** Every probe produced at most one response
and the backend received at most one request. Caveat: these were single-request
probes with `Connection: close`; a full desync proof of concept requires a
persistent connection carrying two requests. That said, with one framing header
surviving normalisation, the two parsers have nothing to disagree about.

---

## Phase 7 — Custom rules close both gaps

`rules/custom-cmdi.conf`, mounted at
`/opt/owasp-crs/plugins/custom-after.conf`.

| # | Payload | Before | After | Rule |
|---|---|---|---|---|
| 1 | `127.0.0.1;id` | 200 + `uid=33` | **403** | 1000001 |
| 2 | `127.0.0.1\|id` | 200 + `uid=33` | **403** | 1000001 |
| 3 | `127.0.0.1&&id` | 200 + `uid=33` | **403** | 1000001 |
| 4 | newline + `id` | 200 + `uid=33` | **403** | 1000001 |
| 5 | ``;`id` `` | 200 (no output) | **403** | 1000001 |
| 6 | `;cat /etc/passwd` | 403 | 403 | 930120, 932160 (CRS) |
| 7 | `;$(id)` | 403 | 403 | 932130 (CRS) |
| 8 | `127.0.0.1` (benign) | 200 | **200** | — |
| 9 | `8.8.8.8` (benign) | 200 | **200** | — |
| 10 | `localhost` (benign) | 200 | **200** | — |
| 11 | CL+TE smuggling probe | 200 | **403** | 1000002 |

Rule 1000001 is an **allow-list**: `ip` must match `^[0-9a-zA-Z.:-]+$`. It blocks
all five bypasses without knowing which separator or command was used, and still
permits legitimate addresses — the property a keyword list cannot offer.

Rule 1000002 rejects any request carrying `Transfer-Encoding`. Because Phase 6
proved detection is impossible after Apache's normalisation, this is a policy
control rather than a signature: the application never needs chunked request
bodies, so the header is refused outright.

**Result:** 5/5 bypasses closed, 3/3 benign inputs unaffected, smuggling probe
now refused with 403.

---

## Phase 9 — Coverage map and regression

Phase 7 proved the rules block the payloads that motivated them. Phase 9 asks the harder
question: does `1000001` block the class? Full narrative: `07-tuning-cycle.md`.

### 9.1 Coverage map (rule temporarily disabled)

`SecRuleRemoveById 1000001` appended to `rules/custom-cmdi.conf`, `docker restart waf`,
confirmed by `ip=127.0.0.1;id` → `200`.

| Payload | CRS only | With 1000001 | Rules logged when blocked |
|---|---|---|---|
| `127.0.0.1;ls` | 403 | 403 | 932125, 932340 |
| `127.0.0.1;pwd` | **200** | **403** | 1000001 |
| `127.0.0.1;uname -a` | 403 | 403 | 932235, 932260 |
| `127.0.0.1;hostname` | 403 | 403 | 932235, 932340, 932380 |
| `127.0.0.1;ps aux` | **200** | **403** | 1000001 |
| `127.0.0.1;env` | 403 | 403 | 932340 |
| `127.0.0.1;date` | **200** | **403** | 1000001 |
| `127.0.0.1\|\|id` | **200** | **403** | 1000001 |
| `127.0.0.1&id` | **200** | **403** | 1000001 |

Execution proof with the rule off: `pwd` → `/var/www/html/vulnerabilities/exec`,
`ps aux` → `www-data`, `date` → `2026`, `&id` → `uid=33`. `||id` produced no output
because `||` short-circuits on a successful left operand.

**The two separators matter.** `||` and `&` were not part of Phase 5, and neither is
scored at PL1: CRS enumerates command names and does not model shell grammar.

### 9.2 Regression of all 37 payloads

`scripts/regression.ps1` replays `payloads/sqli.txt` and `payloads/cmdi.txt`;
`payloads/smuggling.py` covers the three raw probes.

| Set | Payloads | Refused | Bypassed |
|---|---|---|---|
| SQL injection | 22 | 22 | 0 |
| Command injection | 12 | 12 | 0 |
| Request smuggling | 3 | 3 | 0 |
| **Total** | **37** | **37** | **0** |

36 × `403`. The space-before-colon `Transfer-Encoding` probe returns `400`, refused by
Apache's header parser before ModSecurity phase 1 — refused, but not by a rule.

### 9.3 False positives

| Check | Result |
|---|---|
| `127.0.0.1`, `8.8.8.8`, `localhost`, `::1`, `2001:4860:4860::8888`, `scanme.nmap.org` | 200 (6/6) |
| `/`, `/vulnerabilities/sqli/?id=1&Submit=Submit`, `/vulnerabilities/brute/` | 200 (3/3) |
| `/instructions.php` | **403** — outbound, see 9.4 |

### 9.4 Outbound false positive (F6)

`/instructions.php`: `403` through the WAF, `200` direct. Inbound score 0; outbound
score 18 against threshold 4.

```
rules: 951230, 951250, 953100, 953110, 959100, 980170
```

The page quotes `ERROR 1045 (28000)` and `fopen` from DVWA's own README, so content
inspection treats documentation as disclosure. It also emits a genuine PHP warning
(`Cannot modify header information - headers already sent`, `instructions.php:5`), so
the block is partly a true positive. Remedy: fix the warning, then narrow outbound
rules for that path.

**Result:** 37/37 payloads refused, 0 bypasses, 6/6 legitimate inputs accepted, one
documented outbound false positive.
