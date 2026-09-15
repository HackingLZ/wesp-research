[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Runtime,
    [string]$ToolRoot,
    [string]$OutputDirectory = 'C:\WespLab\validation\live',
    [ValidateRange(1, 100)][int]$CanaryCount = 5,
    [ValidateRange(1, 100)][int]$QueueIterations = 3
)

$ErrorActionPreference = 'Stop'
if (-not $ToolRoot) { $ToolRoot = Split-Path -Parent $PSScriptRoot }
$marker = Join-Path $env:ProgramData 'wesplab\LAB_MACHINE'
if (-not (Test-Path -LiteralPath $marker)) { throw "Missing disposable-VM marker: $marker" }
if (-not (Test-Path -LiteralPath $Runtime)) { throw "Runtime not found: $Runtime" }
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$monitorOut = Join-Path $OutputDirectory 'monitor.stdout.txt'
$monitorErr = Join-Path $OutputDirectory 'monitor.stderr.txt'
$capture = Join-Path $OutputDirectory 'notifications.jsonl'
$canaries = Join-Path $OutputDirectory 'canaries.jsonl'
$monitor = Start-Process -FilePath $Runtime -ArgumentList @('monitor-process', '10', '--write', '--capture', $capture) `
    -RedirectStandardOutput $monitorOut -RedirectStandardError $monitorErr -PassThru
Start-Sleep -Seconds 2
& (Join-Path $PSScriptRoot 'Invoke-WespCanary.ps1') -Count $CanaryCount -Output $canaries
if (-not $monitor.WaitForExit(20000)) {
    Stop-Process -Id $monitor.Id -Force
    throw 'Process monitor timed out'
}
$monitorText = (Get-Content -LiteralPath $monitorOut -Raw -ErrorAction SilentlyContinue)
if ($monitorText -notmatch '\[\+\] events:') {
    throw "Process monitor did not report clean completion; see $monitorOut and $monitorErr"
}
$eventCount = if (Test-Path -LiteralPath $capture) { @(Get-Content -LiteralPath $capture).Count } else { 0 }
if ($eventCount -lt $CanaryCount) { throw "Expected at least $CanaryCount ProcessCreate events; captured $eventCount" }

$queueOutput = Join-Path $OutputDirectory 'queue-stress.jsonl'
& (Join-Path $PSScriptRoot 'Invoke-WespQueueStress.ps1') -Iterations $QueueIterations -Seconds 1 `
    -Runtime $Runtime -Output $queueOutput

$healthOutput = Join-Path $OutputDirectory 'health.jsonl'
& (Join-Path $PSScriptRoot 'Watch-WespHealth.ps1') -Runtime $Runtime -IntervalSeconds 1 -DurationSeconds 3 `
    -Output $healthOutput -ExpectedEspClientSha256 'abaa0d1e21dda04fc089aa41be155d86a8a2b972399ceb9a810a64c3508e4619' `
    -ExpectedDriverSha256 'c8426fa3ad9fe3a9a4c79cb4398d4804816d4f182c7a4bd96d4c5526cda41dcd'

$stateOutput = Join-Path $OutputDirectory 'state-changes.jsonl'
$stateOut = Join-Path $OutputDirectory 'state-watch.stdout.txt'
$stateErr = Join-Path $OutputDirectory 'state-watch.stderr.txt'
$watcher = Start-Process -FilePath 'powershell.exe' -ArgumentList @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $PSScriptRoot 'Watch-WespState.ps1'),
    '-Runtime', $Runtime, '-IntervalSeconds', '1', '-DurationSeconds', '6', '-Output', $stateOutput
) -RedirectStandardOutput $stateOut -RedirectStandardError $stateErr -PassThru
$stateGuid = '{7B94E0E1-8B8B-4BE4-A743-315519DA26D7}'
Start-Sleep -Seconds 2
& $Runtime register $stateGuid --write --name 'WespLab state canary' --altitude '385000.54323'
if ($LASTEXITCODE -ne 0) { throw 'State-canary registration failed' }
Start-Sleep -Seconds 2
& $Runtime remove $stateGuid --write
if ($LASTEXITCODE -ne 0) { throw 'State-canary cleanup failed' }
if (-not $watcher.WaitForExit(15000)) {
    Stop-Process -Id $watcher.Id -Force
    throw 'State watcher timed out'
}
if (-not (Test-Path -LiteralPath $stateOutput) -or @(Get-Content -LiteralPath $stateOutput).Count -lt 2) {
    throw 'State watcher did not record both registration and removal'
}

$crossGuid = '{8B94E0E1-8B8B-4BE4-A743-315519DA26D7}'
try {
    & $Runtime register $crossGuid --write --name 'WespLab cross-client canary' --altitude '385000.54324'
    if ($LASTEXITCODE -ne 0) { throw 'Cross-client target registration failed' }
    & $Runtime remove $crossGuid --write --cross-client-test
    if ($LASTEXITCODE -ne 0) { throw 'Cross-client unregister test failed' }
} finally {
    & $Runtime remove $crossGuid --write 2>$null | Out-Null
}

$summary = [ordered]@{
    schema = 'wesplab.live-validation.v1'
    timestamp_utc = [DateTime]::UtcNow.ToString('o')
    monitor_events = $eventCount
    canary_iterations = $CanaryCount
    queue_iterations = $QueueIterations
    health_heartbeats = @(Get-Content -LiteralPath $healthOutput).Count
    state_changes = @(Get-Content -LiteralPath $stateOutput).Count
    cross_client_unregister = 'succeeded'
}
$summaryPath = Join-Path $OutputDirectory 'summary.json'
$summary | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $summaryPath -Encoding UTF8
Write-Host "Live validation passed: $summaryPath"
