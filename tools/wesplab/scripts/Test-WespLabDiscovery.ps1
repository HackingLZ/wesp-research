[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ClientGuid,
    [Parameter(Mandatory)][string]$Runtime,
    [string]$OutputDirectory = (Join-Path $PWD 'wesplab-discovery')
)

$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$steps = @()

function Invoke-Discovery([string]$Name, [string[]]$Arguments) {
    $started = [DateTime]::UtcNow
    $text = (& $Runtime @Arguments 2>&1) -join "`n"
    $exitCode = $LASTEXITCODE
    $text | Set-Content -LiteralPath (Join-Path $OutputDirectory ($Name + '.txt')) -Encoding UTF8
    $script:steps += [pscustomobject]@{
        name = $Name
        arguments = $Arguments
        exit_code = $exitCode
        elapsed_ms = [int]([DateTime]::UtcNow - $started).TotalMilliseconds
    }
}

Invoke-Discovery 'doctor' @('doctor', '--json')
Invoke-Discovery 'clients-registered' @('clients', 'registered', '--json')
Invoke-Discovery 'clients-connected' @('clients', 'connected', '--json')
Invoke-Discovery 'snapshot' @('snapshot')
Invoke-Discovery 'authz' @('authz-probe', $ClientGuid)
Invoke-Discovery 'capabilities-0-4096' @('capabilities', $ClientGuid, '0', '4096', '--json')

$families = 'client', 'event', 'token', 'mailslot', 'pipe', 'ktm', 'desktop',
    'registry-object', 'registry', 'disk', 'volume', 'file-object', 'file',
    'stream', 'process', 'thread'
foreach ($family in $families) {
    Invoke-Discovery ("properties-$family") @('properties', $ClientGuid, $family, '0', '512', '--json')
}
foreach ($kind in 'rules', 'queues', 'collections') {
    foreach ($selector in 0..3) {
        Invoke-Discovery ("ids-$kind-$selector") @('ids', $ClientGuid, $kind, [string]$selector, '--json')
    }
}

[pscustomobject]@{
    schema = 'wesplab.discovery-validation.v1'
    created_utc = [DateTime]::UtcNow.ToString('o')
    client = $ClientGuid
    passed = @($steps | Where-Object exit_code -eq 0).Count
    failed = @($steps | Where-Object exit_code -ne 0).Count
    steps = $steps
} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'validation.json') -Encoding UTF8
Write-Host "Discovery complete: $(@($steps | Where-Object exit_code -eq 0).Count) passed, $(@($steps | Where-Object exit_code -ne 0).Count) failed"
