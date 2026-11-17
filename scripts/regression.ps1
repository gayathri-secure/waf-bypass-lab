<#
  Phase 9 regression - replays every archived payload with the custom rules armed.
  Expected result: every request refused with 403. Anything else prints FAIL.
  Usage:  powershell -ExecutionPolicy Bypass -File scripts\regression.ps1
#>
param(
    [string]$Base    = "http://localhost",
    [string]$CsvPath = "evidence\logs\phase9-regression.csv"
)

$ErrorActionPreference = "Stop"

function Read-Payloads([string]$Path) {
    Get-Content -LiteralPath $Path |
        Where-Object { $_.Trim() -ne "" -and -not $_.TrimStart().StartsWith("#") } |
        ForEach-Object { $_.Replace("<TAB>", "`t").Replace("<NL>", "`n") }
}

$sqli = Read-Payloads "payloads\sqli.txt"
$cmdi = Read-Payloads "payloads\cmdi.txt"

$results = New-Object System.Collections.Generic.List[object]

foreach ($p in $sqli) {
    $code = curl.exe -s -o NUL -w "%{http_code}" -G `
        --data-urlencode "id=$p" --data-urlencode "Submit=Submit" `
        "$Base/vulnerabilities/sqli/"
    $results.Add([pscustomobject]@{ Class = "sqli"; Payload = $p; Status = $code })
}

foreach ($p in $cmdi) {
    $code = curl.exe -s -o NUL -w "%{http_code}" `
        --data-urlencode "ip=$p" --data-urlencode "Submit=Submit" `
        "$Base/vulnerabilities/exec/"
    $results.Add([pscustomobject]@{ Class = "cmdi"; Payload = $p; Status = $code })
}

$n = 0
foreach ($r in $results) {
    $n++
    $mark  = if ($r.Status -eq "403") { "ok  " } else { "FAIL" }
    $shown = $r.Payload -replace "`n", "\n" -replace "`t", "\t"
    "{0,2}. {1} {2} {3,-4} {4}" -f $n, $mark, $r.Status, $r.Class, $shown
}

""
$results | Group-Object Class | ForEach-Object {
    $ok = @($_.Group | Where-Object { $_.Status -eq "403" }).Count
    "{0}: {1} / {2} refused with 403" -f $_.Name, $ok, $_.Count
}
""

$fail = @($results | Where-Object { $_.Status -ne "403" })
if ($fail.Count -eq 0) {
    "RESULT: {0} / {1} refused. No bypass." -f $results.Count, $results.Count
} else {
    "RESULT: {0} / {1} refused. Not refused:" -f ($results.Count - $fail.Count), $results.Count
    $fail | ForEach-Object { "  {0}  {1}  {2}" -f $_.Status, $_.Class, $_.Payload }
}

$results | Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
"CSV written to $CsvPath"
