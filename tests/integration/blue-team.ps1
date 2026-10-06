param([ValidateSet(1, 2, 4)][int[]]$Workers = @(1, 2, 4))
$ErrorActionPreference = 'Stop'
$taskBase = 'http://127.0.0.1:3000'
$taskRows = @()
foreach ($taskLevel in @('low', 'medium', 'high')) {
    foreach ($taskWorkers in $Workers) {
        foreach ($taskVariant in @('vulnerable', 'prepared')) {
            $taskBody = @{mode='dvwa';target='dvwa';dvwa_level=$taskLevel;dvwa_variant=$taskVariant;workers=$taskWorkers} | ConvertTo-Json
            $taskScan = Invoke-RestMethod -Uri "$taskBase/api/scans" -Method Post -ContentType 'application/json' -Body $taskBody -TimeoutSec 10
            $taskDeadline = (Get-Date).AddSeconds(60)
            do {
                Start-Sleep -Milliseconds 200
                $taskStatus = Invoke-RestMethod -Uri "$taskBase/api/scans/$($taskScan.scan_id)" -TimeoutSec 5
            } while ($taskStatus.status -notin @('COMPLETED', 'FAILED') -and (Get-Date) -lt $taskDeadline)
            if ($taskStatus.status -ne 'COMPLETED') { throw "$taskLevel/$taskVariant failed: $($taskStatus.error_message)" }
            $taskResults = Invoke-RestMethod -Uri "$taskBase/api/scans/$($taskScan.scan_id)/results" -TimeoutSec 5
            $taskEvents = Invoke-RestMethod -Uri "$taskBase/api/scans/$($taskScan.scan_id)/events" -TimeoutSec 5
            $taskProbes = @($taskEvents.events | Where-Object event_type -eq 'PAYLOAD_EXECUTED' | ForEach-Object { $_.message | ConvertFrom-Json })
            $taskTeam = $taskResults.remediation_report.blue_team
            if ($taskTeam.sensor_status -ne 'NOT_CONNECTED') { throw 'HTTP report claimed a connected kernel sensor' }
            if ($taskProbes.Count -ne 2) { throw 'Missing HTTP evidence' }
            if ($taskVariant -eq 'vulnerable') {
                if ($taskResults.total -lt 1 -or $taskTeam.verification -ne 'PATCH_AVAILABLE') { throw 'Vulnerable control did not detect SQLi' }
            } else {
                if ($taskResults.total -ne 0 -or $taskTeam.verification -ne 'HTTP_RETEST_PASSED' -or $taskTeam.measured_requests -ne 6 -or $taskTeam.rejected_inputs -ne 5 -or $taskTeam.baseline_records -ne 1) { throw "Incorrect prepared verdict: $($taskTeam | ConvertTo-Json -Compress)" }
                if (@($taskProbes | Where-Object result -ne 'NOT_DETECTED').Count -ne 0) { throw 'Prepared module probes were inconclusive or detected' }
            }
            $taskRows += [pscustomobject]@{Level=$taskLevel;Workers=$taskWorkers;Variant=$taskVariant;Findings=$taskResults.total;Verification=$taskTeam.verification;Scan=$taskScan.scan_id}
        }
    }
}
$taskRows | Format-Table -AutoSize
Write-Output "Blue team matrix passed: $($taskRows.Count) real scans"
