[CmdletBinding()]
param(
    [string]$Runtime,
    [ValidateRange(1, 86400)][int]$IntervalSeconds = 30,
    [ValidateRange(0, 604800)][int]$DurationSeconds = 0,
    [string]$Output = (Join-Path $PWD 'wesp-health.jsonl'),
    [string[]]$ExpectedClient,
    [string]$ExpectedEspClientSha256,
    [string]$ExpectedDriverSha256
)

$ErrorActionPreference = 'Continue'
if (-not $Runtime) { $Runtime = Join-Path (Split-Path -Parent $PSScriptRoot) 'build\Release\wesplab-runtime.exe' }
$previous = $null
$deadline = if ($DurationSeconds) { [DateTime]::UtcNow.AddSeconds($DurationSeconds) } else { [DateTime]::MaxValue }
while ([DateTime]::UtcNow -lt $deadline) {
    $started = [DateTime]::UtcNow
    $snapshotText = (& $Runtime snapshot 2>&1) -join "`n"
    $snapshotExit = $LASTEXITCODE
    try { $snapshot = $snapshotText | ConvertFrom-Json } catch { $snapshot = $null }
    $dll = Join-Path $env:SystemRoot 'System32\espclient.dll'
    $driver = Join-Path $env:SystemRoot 'System32\drivers\wesp.sys'
    $dllHash = if (Test-Path -LiteralPath $dll) { (Get-FileHash -LiteralPath $dll -Algorithm SHA256).Hash.ToLowerInvariant() }
    $driverHash = if (Test-Path -LiteralPath $driver) { (Get-FileHash -LiteralPath $driver -Algorithm SHA256).Hash.ToLowerInvariant() }
    $missing = @()
    if ($snapshot -and $ExpectedClient) {
        $missing = @($ExpectedClient | Where-Object { $_ -notin @($snapshot.registered) })
    }
    $normalized = if ($snapshot) {
        (@($snapshot.registered | Sort-Object) -join ',') + '|' + (@($snapshot.connected | Sort-Object) -join ',')
    }
    $record = [ordered]@{
        schema = 'wesplab.health-heartbeat.v1'
        timestamp_utc = $started.ToString('o')
        latency_ms = [int]([DateTime]::UtcNow - $started).TotalMilliseconds
        snapshot_exit_code = $snapshotExit
        registered = if ($snapshot) { @($snapshot.registered) } else { @() }
        connected = if ($snapshot) { @($snapshot.connected) } else { @() }
        missing_expected_clients = $missing
        state_changed = ($null -ne $previous -and $normalized -ne $previous)
        espclient_sha256 = $dllHash
        driver_sha256 = $driverHash
        espclient_integrity_ok = (-not $ExpectedEspClientSha256 -or $dllHash -eq $ExpectedEspClientSha256.ToLowerInvariant())
        driver_integrity_ok = (-not $ExpectedDriverSha256 -or $driverHash -eq $ExpectedDriverSha256.ToLowerInvariant())
        error = if ($snapshot) { $null } else { $snapshotText }
    }
    $record | ConvertTo-Json -Depth 6 -Compress | Add-Content -LiteralPath $Output -Encoding UTF8
    if ($missing.Count -or -not $record.espclient_integrity_ok -or -not $record.driver_integrity_ok) {
        Write-Warning 'WESP health policy violation recorded'
    }
    $previous = $normalized
    $remainingMs = [int][Math]::Max(0, ($deadline - [DateTime]::UtcNow).TotalMilliseconds)
    $sleepMs = if ($DurationSeconds) { [Math]::Min($IntervalSeconds * 1000, $remainingMs) } else { $IntervalSeconds * 1000 }
    if ($sleepMs -gt 0) { Start-Sleep -Milliseconds $sleepMs }
}
