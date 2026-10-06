param([ValidateSet('low', 'medium', 'high')][string]$Level = 'medium', [ValidateSet(1, 2, 4)][int]$Workers = 1)
$ErrorActionPreference = 'Stop'
$taskBase = 'http://127.0.0.1:3000'
$taskHealth = Invoke-RestMethod -Uri "$taskBase/health/backend" -TimeoutSec 5
if ($taskHealth.status -ne 'ok') { throw 'Backend unavailable' }
$taskBody = @{mode='dvwa';target='dvwa';dvwa_level=$Level;workers=$Workers} | ConvertTo-Json
$taskScan = Invoke-RestMethod -Uri "$taskBase/api/scans" -Method Post -ContentType 'application/json' -Body $taskBody -TimeoutSec 10
$taskDeadline = (Get-Date).AddSeconds(45)
do {
    Start-Sleep -Seconds 1
    $taskStatus = Invoke-RestMethod -Uri "$taskBase/api/scans/$($taskScan.scan_id)" -TimeoutSec 5
} while ($taskStatus.status -notin @('COMPLETED', 'FAILED') -and (Get-Date) -lt $taskDeadline)
if ($taskStatus.status -ne 'COMPLETED') { throw "DVWA audit failed: $($taskStatus.error_message)" }
$taskResults = Invoke-RestMethod -Uri "$taskBase/api/scans/$($taskScan.scan_id)/results" -TimeoutSec 5
$taskEvents = Invoke-RestMethod -Uri "$taskBase/api/scans/$($taskScan.scan_id)/events" -TimeoutSec 5
$taskProbes = @($taskEvents.events | Where-Object event_type -eq 'PAYLOAD_EXECUTED' | ForEach-Object { $_.message | ConvertFrom-Json })
if ($taskResults.total -lt 1) { throw "Expected SQL Injection findings on DVWA $Level" }
if ($taskProbes.Count -ne 2 -or @($taskProbes | Where-Object execution_type -ne 'REAL').Count -ne 0) { throw 'Expected two real HTTP probes' }
if ($taskResults.remediation_report.kernel_defense_policy) { throw 'HTTP scan must not claim kernel evidence' }
if ($Level -eq 'medium' -and $taskResults.remediation_report.code_examples[0].secure_code -notlike '*POST*') { throw 'Medium remediation must use POST input' }
if ($Level -eq 'high' -and ($taskResults.remediation_report.code_examples[0].secure_code -notlike '*SESSION*' -or $taskResults.remediation_report.code_examples[0].secure_code -notlike '*filter_var*')) { throw 'High remediation must validate session input' }
$taskRequests = @($taskEvents.events | Where-Object event_type -eq 'LAB_ACTIVITY' | ForEach-Object { $_.message | ConvertFrom-Json } | Where-Object { $_.stage -eq 'probe' -and $_.state -in @('completed', 'http_error') })
if ($taskRequests.Count -ne 6) { throw 'Expected six measured HTTP probe responses' }
if ($Level -eq 'medium' -and @($taskRequests | Where-Object method -ne 'POST').Count -ne 0) { throw 'Medium requires POST probes' }
if (@($taskProbes | Where-Object { $_.name -like '*booleana*' -and $_.result -eq 'DETECTED' -and $_.baseline_records -eq 1 -and $_.true_records -eq 1 -and $_.observed_records -eq 0 }).Count -ne 1) { throw 'Repeated boolean evidence missing' }
if ($Level -eq 'high') {
    $taskInputs = @($taskEvents.events | Where-Object event_type -eq 'LAB_ACTIVITY' | ForEach-Object { $_.message | ConvertFrom-Json } | Where-Object { $_.stage -eq 'input' -and $_.state -eq 'completed' })
    if ($taskInputs.Count -ne 6 -or @($taskInputs | Where-Object method -ne 'POST').Count -ne 0 -or @($taskRequests | Where-Object method -ne 'GET').Count -ne 0) { throw 'High must preserve six POST + GET pairs' }
    if ($taskProbes[0].result -notin @('NOT_DETECTED', 'DETECTED')) { throw 'High error probe must retain the actual measured result' }
}
$taskMetrics = ($taskEvents.events | Where-Object event_type -eq 'DVWA_METRICS' | Select-Object -Last 1).message | ConvertFrom-Json
$taskExpectedRequests = 4 * $Workers + 6
if ($Level -eq 'high') { $taskExpectedRequests += 6 }
if ($taskMetrics.workers -ne $Workers -or $taskMetrics.completed_probes -ne 6 -or $taskMetrics.http_requests -ne $taskExpectedRequests -or $taskMetrics.inconclusive -ne 0 -or $taskMetrics.failed_requests -ne 0) { throw 'Worker metrics or workload changed' }
if (@($taskRequests | Where-Object { $null -eq $_.duration_ms -or $null -eq $_.records }).Count -ne 0) { throw 'Missing measured timing or row counts' }
Write-Output "DVWA $Level audit completed: $($taskResults.total) findings, $($taskProbes.Count) real probes, $($taskRequests.Count) measured requests, scan=$($taskScan.scan_id)"
$taskProbes | Select-Object name,result,status_code,baseline_records,true_records,observed_records | Format-Table -AutoSize
$taskRequests | Select-Object summary,method,status_code,duration_ms,records | Format-Table -AutoSize
