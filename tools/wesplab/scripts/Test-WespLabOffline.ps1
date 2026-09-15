[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Runtime,
    [Parameter(Mandatory)][string]$BuildManifest,
    [Parameter(Mandatory)][string]$AuthzResults,
    [string]$OutputDirectory = (Join-Path $PWD 'wesplab-offline-validation')
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$tool = Join-Path $root 'wesplab.py'
$python = (Get-Command python.exe -ErrorAction Stop).Source
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$results = @()

function Invoke-WespStep([string]$Name, [scriptblock]$Action) {
    $started = [DateTime]::UtcNow
    $errorText = $null
    try {
        & $Action
        $exitCode = $LASTEXITCODE
        if ($null -eq $exitCode) { $exitCode = 0 }
    } catch {
        $exitCode = 1
        $errorText = $_.Exception.Message
    }
    $script:results += [pscustomobject]@{
        name = $Name
        exit_code = $exitCode
        elapsed_ms = [int]([DateTime]::UtcNow - $started).TotalMilliseconds
        error = $errorText
    }
    if ($exitCode -ne 0) { throw "Validation step failed: $Name ($exitCode) $errorText" }
}

$dll = Join-Path $env:SystemRoot 'System32\espclient.dll'
$driver = Join-Path $env:SystemRoot 'System32\drivers\wesp.sys'
$snapshot = Join-Path $OutputDirectory 'live-snapshot.json'

Invoke-WespStep 'inspect' { & $python $tool inspect $dll -o (Join-Path $OutputDirectory 'inspect.json') }
Invoke-WespStep 'snapshot-binaries' { & $python $tool snapshot $dll $driver -o (Join-Path $OutputDirectory 'binaries.json') }
Invoke-WespStep 'binary-diff' { & $python $tool diff $dll $dll -o (Join-Path $OutputDirectory 'binary-diff.json') }
Invoke-WespStep 'abi-check' { & $python $tool abi-check $dll -o (Join-Path $OutputDirectory 'abi-check.json') }
Invoke-WespStep 'live-snapshot' { (& $Runtime snapshot) | Set-Content -LiteralPath $snapshot -Encoding UTF8; if ($LASTEXITCODE -ne 0) { throw 'snapshot failed' } }
Invoke-WespStep 'state-diff' { & $python $tool state-diff $snapshot $snapshot -o (Join-Path $OutputDirectory 'state-diff.json') }
Invoke-WespStep 'protocol' { & $python $tool protocol -o (Join-Path $OutputDirectory 'protocol.json') }
Invoke-WespStep 'corpus' { & $python $tool corpus -o (Join-Path $OutputDirectory 'corpus.json') }
Invoke-WespStep 'notification-decode' { & $python $tool notification-decode (Join-Path $root 'examples\notification-capture.jsonl') -o (Join-Path $OutputDirectory 'notification.json') }
Invoke-WespStep 'build-diff' { & $python $tool build-diff $BuildManifest $BuildManifest -o (Join-Path $OutputDirectory 'build-diff.json') }
Invoke-WespStep 'rule-compile-confirmed' { & $python $tool rule-compile (Join-Path $root 'examples\process-create.rule.json') -o (Join-Path $OutputDirectory 'rule-confirmed.json') }
Invoke-WespStep 'rule-compile-filtered' { & $python $tool rule-compile (Join-Path $root 'examples\filtered-process.rule.json') -o (Join-Path $OutputDirectory 'rule-filtered.json') }
Invoke-WespStep 'timeline' { & $python $tool timeline (Join-Path $root 'examples\notification-capture.jsonl') -o (Join-Path $OutputDirectory 'timeline.html') }
Invoke-WespStep 'wire-validate' { & $python $tool wire-validate (Join-Path $root 'examples\wire-capture.json') -o (Join-Path $OutputDirectory 'wire-validation.json') }
Invoke-WespStep 'health' { & $python $tool health (Join-Path $root 'examples\notification-capture.jsonl') -o (Join-Path $OutputDirectory 'health.json') }
Invoke-WespStep 'authz-report' { & $python $tool authz-report $AuthzResults -o (Join-Path $OutputDirectory 'authz-report.json') }

[pscustomobject]@{
    schema = 'wesplab.offline-validation.v1'
    created_utc = [DateTime]::UtcNow.ToString('o')
    passed = @($results | Where-Object exit_code -eq 0).Count
    failed = @($results | Where-Object exit_code -ne 0).Count
    steps = $results
} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'validation.json') -Encoding UTF8
Write-Host "Validated $($results.Count) offline commands; output: $OutputDirectory"
