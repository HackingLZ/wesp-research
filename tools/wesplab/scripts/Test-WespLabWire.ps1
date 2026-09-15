[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Runtime,
    [string]$ToolRoot,
    [string]$OutputDirectory = 'C:\WespLab\validation\wire'
)

$ErrorActionPreference = 'Stop'
if (-not $ToolRoot) { $ToolRoot = Split-Path -Parent $PSScriptRoot }
$marker = Join-Path $env:ProgramData 'wesplab\LAB_MACHINE'
if (-not (Test-Path -LiteralPath $marker)) { throw "Missing disposable-VM marker: $marker" }
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$python = Get-Command python.exe -ErrorAction Stop
$recorder = Join-Path $ToolRoot 'optional\frida\record_wesp_wire.py'
$capture = Join-Path $OutputDirectory 'wire.jsonl'
$validation = Join-Path $OutputDirectory 'validation.json'
$consumerOut = Join-Path $OutputDirectory 'consumer.stdout.txt'
$consumerErr = Join-Path $OutputDirectory 'consumer.stderr.txt'

$consumer = Start-Process -FilePath $Runtime -ArgumentList @('watch-clients', '8') `
    -RedirectStandardOutput $consumerOut -RedirectStandardError $consumerErr -PassThru
try {
    Start-Sleep -Milliseconds 500
    & $python.Source $recorder $consumer.Id -o $capture --duration 5
    if ($LASTEXITCODE -ne 0) { throw "Wire recorder failed: $LASTEXITCODE" }
    if (-not $consumer.WaitForExit(15000)) { throw 'Read-only consumer timed out' }
    & $python.Source (Join-Path $ToolRoot 'wesplab.py') wire-validate $capture -o $validation
    if ($LASTEXITCODE -ne 0) { throw "Wire validation failed: $LASTEXITCODE" }
    $records = @(Get-Content -LiteralPath $capture).Count
    if ($records -lt 2) { throw "Expected multiple wire records; captured $records" }
    Write-Host "Wire validation passed with $records records: $validation"
} finally {
    if (-not $consumer.HasExited) { Stop-Process -Id $consumer.Id -Force -ErrorAction SilentlyContinue }
}
