[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$build = Join-Path $root 'build'
cmake -S $root -B $build -A ARM64
if ($LASTEXITCODE -ne 0) { throw 'CMake configuration failed' }
cmake --build $build --config $Configuration --parallel
if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
Write-Host "Built $(Join-Path $build "$Configuration\wesplab-runtime.exe")"
