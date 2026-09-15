[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$ClientGuid,
    [Parameter(Mandatory)][string]$Runtime,
    [Parameter(Mandatory)][string]$Output,
    [string]$PrincipalLabel = 'current'
)

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$groups = @($identity.Groups | ForEach-Object { $_.Value })
$integrity = @((& whoami.exe /groups /fo csv /nh) | ForEach-Object {
    if ($_ -match '"(S-1-16-[0-9]+)"') { $Matches[1] }
})
foreach ($guid in $ClientGuid) {
    $started = [DateTime]::UtcNow
    $text = (& $Runtime authz-probe $guid 2>&1) -join "`n"
    $exitCode = $LASTEXITCODE
    try { $probe = $text | ConvertFrom-Json } catch { $probe = $null }
    [pscustomobject]@{
        schema = 'wesplab.authz-matrix-row.v2'
        timestamp_utc = $started.ToString('o')
        process_id = $PID
        principal_label = $PrincipalLabel
        user = $identity.Name
        user_sid = $identity.User.Value
        elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        integrity_sids = $integrity
        target = $guid
        exit_code = $exitCode
        result = $probe
        raw_error = if ($probe) { $null } else { $text }
    } | ConvertTo-Json -Depth 8 -Compress | Add-Content -LiteralPath $Output -Encoding UTF8
}
