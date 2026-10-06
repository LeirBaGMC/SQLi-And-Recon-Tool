# Restarts only the backend. Run with no other active scans in this local lab.
param([string]$BaseURL = 'http://127.0.0.1:3000')
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent

function Wait-ReviewScan([string]$ScanID) {
    $deadline = (Get-Date).AddSeconds(30)
    do {
        $status = Invoke-RestMethod "$BaseURL/api/scans/$ScanID" -TimeoutSec 5
        if ($status.status -in @('COMPLETED', 'FAILED')) { return $status }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date) -lt $deadline)
    throw 'El escaneo no alcanzó un estado final.'
}

$pending = docker compose -f "$taskRoot/compose.yaml" exec -T scanner-db sh -c 'MYSQL_PWD="$MYSQL_PASSWORD" mysql -u"$MYSQL_USER" "$MYSQL_DATABASE" -Nse "SELECT COUNT(*) FROM scans WHERE status IN (\"QUEUED\",\"RUNNING\");"'
if ($LASTEXITCODE -ne 0) { throw 'No se pudo comprobar si hay otros escaneos activos.' }
if ([int]$pending -ne 0) { throw 'Hay otros escaneos activos. Espera antes de ejecutar esta prueba de reinicio.' }

$body = @{mode='authorized_url';url='http://127.0.0.1:8080/health?id=1';authorization_confirmed=$true} | ConvertTo-Json
$completed = Invoke-RestMethod "$BaseURL/api/scans" -Method Post -ContentType 'application/json' -Body $body -TimeoutSec 5
$original = Wait-ReviewScan $completed.scan_id
if ($original.status -ne 'COMPLETED') { throw 'La prueba base no se completó.' }

$interrupted = Invoke-RestMethod "$BaseURL/api/scans" -Method Post -ContentType 'application/json' -Body $body -TimeoutSec 5
$before = Invoke-RestMethod "$BaseURL/api/scans/$($interrupted.scan_id)" -TimeoutSec 5
if ($before.status -notin @('QUEUED', 'RUNNING')) { throw 'La segunda prueba terminó antes de poder interrumpirla.' }
docker compose -f "$taskRoot/compose.yaml" restart -t 0 backend
if ($LASTEXITCODE -ne 0) { throw 'El backend no se pudo reiniciar.' }

$deadline = (Get-Date).AddSeconds(60)
$ready = $false
do {
    try { $health = Invoke-RestMethod "$BaseURL/health/backend" -TimeoutSec 2; $ready = $health.status -eq 'ok' } catch { $ready = $false }
    if (-not $ready) { Start-Sleep -Milliseconds 250 }
} while (-not $ready -and (Get-Date) -lt $deadline)
if (-not $ready) { throw 'El backend no volvió a estar disponible.' }

$recovered = Wait-ReviewScan $interrupted.scan_id
$events = (Invoke-RestMethod "$BaseURL/api/scans/$($interrupted.scan_id)/events" -TimeoutSec 5).events
$failureEvents = @($events | Where-Object event_type -eq 'SCAN_FAILED')
if ($recovered.status -ne 'FAILED' -or -not $recovered.completed_at -or $recovered.error_message -notmatch 'reinicio del backend' -or $failureEvents.Count -ne 1 -or $failureEvents[0].message -ne $recovered.error_message) { throw 'La interrupción perdió el estado final o su evidencia.' }
$preserved = Wait-ReviewScan $completed.scan_id
if ($preserved.status -ne 'COMPLETED' -or $preserved.completed_at -ne $original.completed_at) { throw 'Se modificó un escaneo ya completado.' }
Write-Output "Recuperación verificada: $($interrupted.scan_id) quedó FAILED con causa y timestamp; $($completed.scan_id) se conservó COMPLETED."
