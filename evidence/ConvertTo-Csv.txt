docker logs --since 30m waf 2>&1 |
  Select-String -Pattern '^\{"transaction"' |
  ForEach-Object {
    $t   = $_.Line | ConvertFrom-Json
    $ids = [regex]::Matches(($t.audit_data.messages -join ' '), '\[id "(\d+)"\]') |
           ForEach-Object { $_.Groups[1].Value }
    [pscustomobject]@{
      Time   = $t.transaction.time
      Status = $t.response.status
      URI    = $t.request.request_line
      Rules  = (($ids | Select-Object -Unique) -join ',')
    }
  } | Format-Table -AutoSize -Wrap
