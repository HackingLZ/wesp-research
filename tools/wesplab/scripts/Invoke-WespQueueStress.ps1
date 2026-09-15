[CmdletBinding()]
param(
    [ValidateRange(1, 1000)]
    [int]$Iterations = 10,
    [ValidateRange(1, 3600)]
    [int]$Seconds = 2,
    [string]$Runtime,
    [string]$Output = (Join-Path $PWD 'queue-stress.jsonl')
)

$ErrorActionPreference = 'Stop'
if (-not $Runtime) { $Runtime = Join-Path (Split-Path -Parent $PSScriptRoot) 'build\Release\wesplab-runtime.exe' }
$marker = Join-Path $env:ProgramData 'wesplab\LAB_MACHINE'
if (-not (Test-Path $marker)) { throw "Missing disposable-VM marker: $marker" }

for ($iteration = 1; $iteration -le $Iterations; $iteration++) {
    $started = [DateTime]::UtcNow
    & $Runtime monitor-process $Seconds --write 2>&1 |
        Set-Content -LiteralPath (Join-Path $env:TEMP "wesplab-queue-$iteration.log") -Encoding UTF8
    [pscustomobject]@{
        schema = 'wesplab.queue-stress-row.v1'
        iteration = $iteration
        started_utc = $started.ToString('o')
        elapsed_ms = [int]([DateTime]::UtcNow - $started).TotalMilliseconds
        exit_code = $LASTEXITCODE
    } | ConvertTo-Json -Compress | Add-Content -LiteralPath $Output -Encoding UTF8
    if ($LASTEXITCODE -ne 0) { throw "Queue iteration $iteration failed; preserve the VM and collect a dump" }
}
Write-Host "Completed $Iterations queue lifecycles; results: $Output"
