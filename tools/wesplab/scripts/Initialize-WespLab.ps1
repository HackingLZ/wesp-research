[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$IUnderstandThisIsDisposable
)

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this command from an elevated PowerShell session.'
}
if (-not $IUnderstandThisIsDisposable) {
    throw 'Refusing to mark this machine as a lab. Add -IUnderstandThisIsDisposable.'
}

$directory = Join-Path $env:ProgramData 'wesplab'
$marker = Join-Path $directory 'LAB_MACHINE'
if ($PSCmdlet.ShouldProcess($marker, 'Create disposable-VM safety marker')) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    [pscustomobject]@{
        schema = 'wesplab.lab-marker.v1'
        acknowledged_utc = [DateTime]::UtcNow.ToString('o')
        user = $identity.Name
        computer = $env:COMPUTERNAME
        build = "$($cv.CurrentBuild).$($cv.UBR)"
    } | ConvertTo-Json | Set-Content -LiteralPath $marker -Encoding UTF8
    Write-Host "Created $marker"
}
