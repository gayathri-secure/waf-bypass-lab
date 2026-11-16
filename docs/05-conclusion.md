# 05 — Findings, risk, and remediation

## Findings

**F1 — SQL injection detection at PL1 is robust (control effective).**
22 obfuscation variants plus HTTP Parameter Pollution were all blocked. 942100
(libinjection) fires on token structure, so comments, hex literals, versioned
comments, case changes and scientific notation are all neutralised. Severity of
the residual risk on this path: negligible while CRS is loaded.

**F2 — Command injection detection at PL1 is a keyword list (control bypassed).**
`;id`, `|id`, `&&id` and newline+`id` returned HTTP 200 with `uid=33(www-data)` in
the response body and **no 93xxxx rule in the audit log**. `id` is simply absent
from the command-name lists in 932160/932380, so no amount of shell obfuscation was
needed — the plain command sufficed. Four independently confirmed bypasses of the
same control.

**F3 — The vulnerable parameter had no input validation (root cause).**
DVWA concatenates `$_POST['ip']` into a shell command. The WAF was the only
control, and a WAF is a compensating control, not a fix. The correct boundary is
in the application.

**F4 — Anti-smuggling coverage is provided by normalisation, not detection.**
Apache strips `Content-Length` when `Transfer-Encoding` is present, so CRS 920181
could not evaluate. No smuggling was possible, but the reason matters: a front end
that preserved both headers would leave the deployment relying on a rule that was
never exercised in testing.

**F5 — WAF inspection happens after HTTP normalisation.**
Anything the front-end rewrites is invisible to rules written against the raw
request. This is a structural limit of inline WAFs, not a CRS defect, and it is
why F4's compensating rule had to be a policy decision.

## Risk summary

| Finding | Class | Likelihood | Impact | Rating |
|---|---|---|---|---|
| F2 — command injection bypass | RCE as `www-data` | high (no skill required) | critical | **Critical** |
| F3 — missing input validation | root cause of F2 | — | critical | **Critical** |
| F4 — rule 920181 ineffective | smuggling | low (normalisation mitigates) | high if it worked | **Low** |
| F5 — post-normalisation inspection | evasion | medium | varies | **Medium** (inherent) |
| SQLi path | data disclosure | very low | high | **Low** |

Bypass F2 is rated Critical rather than High because exploitation needs no
specialised tooling: four characters and the word `id` produced remote command
execution, and the WAF logged nothing.

## Remediation

### Implemented in this lab

1. **Rule 1000001 — positive security model** for the vulnerable parameter.
   Allow-list `^[0-9a-zA-Z.:-]+$`, scoped to the endpoint by URI and parameter.
   Verified: 5/5 bypasses blocked, 3/3 legitimate inputs still served.
2. **Rule 1000002 — protocol policy** rejecting `Transfer-Encoding`, compensating
   for 920181 being unreachable after Apache's normalisation.
3. Both rules are mounted as a CRS plugin (`custom-after.conf`) so they load after
   the CRS rule set and survive container recreation.

### Recommended beyond the lab

- **Fix the application.** Validate input server-side, use `escapeshellarg()` /
  `proc_open()` with an argument vector, and never concatenate user data into a
  shell string. A WAF does not remove a vulnerability; it delays exploitation.
- **Drop privileges.** The web process runs as `www-data`; it should not have a
  shell at all where avoidable (`disable_functions`, container seccomp, read-only
  root filesystem).
- **Raise paranoia progressively.** PL1 was bypassed on command injection; PL2/PL3
  widen the command lists considerably. Measure the false-positive cost before
  enabling — that is exactly what a lab like this is for.
- **Monitor anomaly scores, not just blocks.** Rules 920350 and 980170 were the
  only entries on the bypassing requests; a correlation alert on "200 response
  with inbound score ≥ 3 on a shell-injection endpoint" would have surfaced the
  attack during Phase 5 even though nothing blocked.
- **Assert framing policy at the edge.** Reject or normalise conflicting
  `Content-Length`/`Transfer-Encoding` in the front end and alert on it; do not
  assume the WAF rule will catch it.

## Limitations

- Single target (DVWA at security level `low`) and a single attacker host. Results
  should not be generalised to other applications without re-testing.
- CRS was only exercised at paranoia level 1 with an inbound threshold of 5.
- The custom rule is written for one endpoint and one parameter; it is a
  demonstration of the allow-list pattern, not a deployable rule set.
- Request-smuggling testing used single-request probes on `Connection: close`.
  A definitive desynchronisation PoC would require pipelined requests on a
  persistent connection.
- The WAF sees every client as `172.18.0.1` because of Docker NAT, so per-client
  rate limiting and attribution were not exercised.
- Outbound (response) rules were not tested.

## Conclusion

CRS 4.30.0 at PL1 does an excellent job where its detector is a parser (SQL
injection) and a poor one where its detector is a list (command injection). The
practical lesson is that "the WAF is enabled" is not a security property: the
detection model behind each rule class determines what survives. A five-line
allow-list rule closed the gap that twelve crafted payloads could not, and the
same test harness proved it closed nothing else.
