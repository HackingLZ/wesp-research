[CmdletBinding()]
param(
    [string]$Runtime,
    [ValidateRange(1, 86400)]
    [int]$IntervalSeconds = 30,
    [ValidateRange(0, 604800)]
    [int]$DurationSeconds = 0,
    [string]$Output = (Join-Path $PWD 'wesp-state-changes.jsonl')
)

$ErrorActionPreference = 'Stop'
if (-not $Runtime) { $Runtime = Join-Path (Split-Path -Parent $PSScriptRoot) 'build\Release\wesplab-runtime.exe' }
$previous = $null
Write-Host 'Watching registered/connected WESP client state. Press Ctrl+C to stop.'
$deadline = if ($DurationSeconds) { [DateTime]::UtcNow.AddSeconds($DurationSeconds) } else { [DateTime]::MaxValue }
while ([DateTime]::UtcNow -lt $deadline) {
    $current = (& $Runtime snapshot | ConvertFrom-Json)
    $normalized = [pscustomobject]@{
        registered = @($current.registered | Sort-Object)
        connected = @($current.connected | Sort-Object)
    } | ConvertTo-Json -Compress
    if ($null -ne $previous -and $normalized -ne $previous) {
        [pscustomobject]@{
            schema = 'wesplab.state-change.v1'
            timestamp_utc = [DateTime]::UtcNow.ToString('o')
            state = ($normalized | ConvertFrom-Json)
        } | ConvertTo-Json -Depth 4 -Compress | Add-Content -LiteralPath $Output -Encoding UTF8
        Write-Warning "WESP state changed; appended $Output"
    }
    $previous = $normalized
    $remainingMs = [int][Math]::Max(0, ($deadline - [DateTime]::UtcNow).TotalMilliseconds)
    $sleepMs = if ($DurationSeconds) { [Math]::Min($IntervalSeconds * 1000, $remainingMs) } else { $IntervalSeconds * 1000 }
    if ($sleepMs -gt 0) { Start-Sleep -Milliseconds $sleepMs }
}
