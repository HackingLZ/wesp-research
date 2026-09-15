[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Rule,
    [string]$Runtime,
    [string]$WespLab,
    [ValidateRange(1, 86400)][int]$Seconds = 60,
    [string]$Capture = (Join-Path $PWD 'notifications.jsonl')
)

$ErrorActionPreference = 'Stop'
if (-not $Runtime) { $Runtime = Join-Path (Split-Path -Parent $PSScriptRoot) 'build\Release\wesplab-runtime.exe' }
if (-not $WespLab) { $WespLab = Join-Path (Split-Path -Parent $PSScriptRoot) 'wesplab.py' }
$python = Get-Command py.exe -ErrorAction SilentlyContinue
if (-not $python) { $python = Get-Command python.exe -ErrorAction SilentlyContinue }
if (-not $python) { throw 'Python 3 is required to compile the rule DSL.' }
$temporary = Join-Path $env:TEMP ('wesplab-rule-' + [Guid]::NewGuid().ToString('N') + '.json')
try {
    & $python.Source $WespLab rule-compile $Rule -o $temporary
    if ($LASTEXITCODE -ne 0) { throw 'Rule compilation failed.' }
    $ir = Get-Content -LiteralPath $temporary -Raw | ConvertFrom-Json
    if (-not $ir.adapter.live_supported) {
        throw "This build adapter cannot safely materialize the rule: $($ir.adapter.reason)"
    }
    & $Runtime monitor-process $Seconds --write --capture $Capture
    if ($LASTEXITCODE -ne 0) { throw "Rule runtime failed: $LASTEXITCODE" }
} finally {
    Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
}
