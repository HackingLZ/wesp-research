[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Etl,
    [string]$Csv = ([IO.Path]::ChangeExtension($Etl, '.csv')),
    [string]$WespLab,
    [string]$Html = ([IO.Path]::ChangeExtension($Etl, '.html'))
)

$ErrorActionPreference = 'Stop'
if (-not $WespLab) { $WespLab = Join-Path (Split-Path -Parent $PSScriptRoot) 'wesplab.py' }
& tracerpt.exe $Etl -of CSV -o $Csv -y | Out-Host
if ($LASTEXITCODE -ne 0) { throw "tracerpt failed: $LASTEXITCODE" }
$python = Get-Command py.exe -ErrorAction SilentlyContinue
if (-not $python) { $python = Get-Command python.exe -ErrorAction SilentlyContinue }
if (-not $python) {
    Write-Warning "Trace converted to $Csv; install Python 3 to produce the correlated HTML view."
    return
}
& $python.Source $WespLab timeline $Csv -o $Html
if ($LASTEXITCODE -ne 0) { throw "timeline conversion failed: $LASTEXITCODE" }
Write-Host "Created $Html"
