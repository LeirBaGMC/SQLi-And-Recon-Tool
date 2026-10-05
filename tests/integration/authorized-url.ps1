param(
    [ValidateSet('', 'FAILED', 'COMPLETED')][string]$ExpectedStatus = '',
    [string]$TargetURL = 'http://127.0.0.1:8080/health?id=1'
)

$ErrorActionPreference = 'Stop'
$scanRequest = @{ mode = 'authorized_url'; url = $TargetURL; authorization_confirmed = $true } | ConvertTo-Json
$scan = Invoke-RestMethod -Method Post -Uri 'http://localhost:8080/api/scans' -ContentType 'application/json' -Body $scanRequest
$scanEndpoint = "http://localhost:8080/api/scans/$($scan.scan_id)"
$deadline = (Get-Date).AddSeconds(90)
do {
    Start-Sleep -Milliseconds 400
    $status = Invoke-RestMethod $scanEndpoint
} while ($status.status -notin @('COMPLETED', 'FAILED') -and (Get-Date) -lt $deadline)
if ($status.status -notin @('COMPLETED', 'FAILED')) { throw 'El escaneo no alcanzó un estado final.' }
if ($ExpectedStatus -and $status.status -ne $ExpectedStatus) { throw "Estado inesperado: $($status.status), esperado: $ExpectedStatus" }
if (-not $status.completed_at) { throw 'No se guardó el momento de finalización.' }

$events = (Invoke-RestMethod "$scanEndpoint/events").events
if (-not ($events | Where-Object event_type -eq 'TARGET_SELECTED')) { throw 'No se seleccionó el análisis directo.' }
if ($events | Where-Object event_type -eq 'DISCOVERY_STARTED') { throw 'Una URL con parámetros no debe iniciar un rastreo.' }
$activity = @($events | Where-Object event_type -eq 'HTTP_ACTIVITY' | ForEach-Object { $_.message | ConvertFrom-Json })
$finished = @($activity | Where-Object state -ne 'running')
if ($finished.Count -eq 0) { throw 'No se registró la respuesta o el fallo de la petición.' }
if ($status.status -eq 'FAILED') {
    if (-not $status.error_message) { throw 'El estado FAILED perdió su mensaje de error.' }
    $failedEvent = @($events | Where-Object event_type -eq 'SCAN_FAILED')[-1]
    if ($failedEvent.message -ne $status.error_message) { throw 'La API no conservó la causa del fallo.' }
    if ($finished[0].state -eq 'failed' -and @($events | Where-Object event_type -eq 'PAYLOAD_EXECUTED').Count -gt 0) { throw 'Un fallo inicial de conexión no debe producir un veredicto SQL.' }
}
Write-Output "Flujo externo verificado: estado=$($status.status), peticiones finalizadas=$($finished.Count), scan=$($scan.scan_id)"
if ($status.error_message) { Write-Output $status.error_message }
$finished | Format-Table summary, state, method, status_code, duration_ms, response_bytes
