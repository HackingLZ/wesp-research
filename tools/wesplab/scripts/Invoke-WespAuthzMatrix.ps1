[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string[]]$ClientGuid,
    [string]$Runtime,
    [string]$Output = (Join-Path $PWD 'authz-results.jsonl'),
    [switch]$IncludeSystem,
    [PSCredential]$Credential
)

$ErrorActionPreference = 'Stop'
if (-not $Runtime) { $Runtime = Join-Path (Split-Path -Parent $PSScriptRoot) 'build\Release\wesplab-runtime.exe' }
$worker = Join-Path $PSScriptRoot 'Invoke-WespAuthzWorker.ps1'
$outputPath = [IO.Path]::GetFullPath($Output)
$argumentList = @('-NoProfile', '-File', $worker, '-Runtime', $Runtime,
    '-Output', $outputPath, '-PrincipalLabel', 'current', '-ClientGuid') + $ClientGuid
$current = Start-Process -FilePath 'powershell.exe' -ArgumentList $argumentList -PassThru -Wait
if ($current.ExitCode -ne 0) { throw "Current-principal worker failed: $($current.ExitCode)" }

if ($Credential) {
    $credentialArgs = @('-NoProfile', '-File', $worker, '-Runtime', $Runtime,
        '-Output', $outputPath, '-PrincipalLabel', 'credential', '-ClientGuid') + $ClientGuid
    $child = Start-Process -FilePath 'powershell.exe' -Credential $Credential -ArgumentList $credentialArgs -PassThru -Wait
    if ($child.ExitCode -ne 0) { throw "Credential worker failed: $($child.ExitCode)" }
}

if ($IncludeSystem) {
    $marker = Join-Path $env:ProgramData 'wesplab\LAB_MACHINE'
    if (-not (Test-Path -LiteralPath $marker)) { throw "SYSTEM testing requires disposable-VM marker: $marker" }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $admin = [Security.Principal.WindowsPrincipal]::new($identity).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $admin) { throw 'SYSTEM testing requires an elevated PowerShell session.' }
    $taskName = 'WespLab-Authz-' + [Guid]::NewGuid().ToString('N')
    $systemArgs = @('-NoProfile', '-File', ('"' + $worker + '"'), '-Runtime', ('"' + $Runtime + '"'),
        '-Output', ('"' + $outputPath + '"'), '-PrincipalLabel', 'system', '-ClientGuid') + $ClientGuid
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ($systemArgs -join ' ')
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    try {
        Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal | Out-Null
        Start-ScheduledTask -TaskName $taskName
        $deadline = [DateTime]::UtcNow.AddMinutes(2)
        do {
            Start-Sleep -Milliseconds 250
            $state = (Get-ScheduledTask -TaskName $taskName).State
        } while ($state -eq 'Running' -and [DateTime]::UtcNow -lt $deadline)
        if ($state -eq 'Running') { throw 'SYSTEM worker timed out' }
    } finally {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }
}
Write-Host "Authorization matrix written to $outputPath"
