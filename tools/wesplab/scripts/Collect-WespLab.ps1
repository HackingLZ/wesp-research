[CmdletBinding()]
param(
    [string]$Runtime,
    [string]$OutputDirectory = (Join-Path $PWD ('wesplab-' + (Get-Date -Format 'yyyyMMdd-HHmmss')))
)

$ErrorActionPreference = 'Stop'
if (-not $Runtime) { $Runtime = Join-Path (Split-Path -Parent $PSScriptRoot) 'build\Release\wesplab-runtime.exe' }
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
& $Runtime doctor --json | Set-Content (Join-Path $OutputDirectory 'doctor.json') -Encoding UTF8
& $Runtime snapshot | Set-Content (Join-Path $OutputDirectory 'snapshot.json') -Encoding UTF8
Get-CimInstance Win32_OperatingSystem |
    Select-Object Caption, Version, BuildNumber, OSArchitecture |
    ConvertTo-Json | Set-Content (Join-Path $OutputDirectory 'os.json') -Encoding UTF8
$manifestProviders = @(Get-WinEvent -ListProvider 'Microsoft.Windows.WESP.*' -ErrorAction SilentlyContinue |
    Select-Object Name, Id, LogLinks)
[pscustomobject]@{
    schema = 'wesplab.etw-providers.v1'
    trace_logging = @(
        [pscustomobject]@{ name = 'Microsoft.Windows.WESP.Client'; id = '{EA3FDB23-A523-45DB-BBC2-7B3BDDF65666}' }
        [pscustomobject]@{ name = 'Microsoft.Windows.WESP.Driver'; id = '{EDFDCE69-B825-484F-BD28-2A91DACD4A0F}' }
    )
    manifest_registered = $manifestProviders
} | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $OutputDirectory 'providers.json') -Encoding UTF8
Write-Host "Collected $OutputDirectory"
