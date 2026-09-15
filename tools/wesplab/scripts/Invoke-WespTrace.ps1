[CmdletBinding()]
param(
    [ValidateSet('Start', 'Stop', 'Status')]
    [string]$Action,
    [string]$Output = (Join-Path $PWD 'wesplab.etl')
)

$ErrorActionPreference = 'Stop'
$session = 'WespLab'
$providers = @(
    # TraceLogging providers are not manifest-registered, so logman cannot
    # resolve their names. These IDs come from each binary's provider metadata.
    '{EA3FDB23-A523-45DB-BBC2-7B3BDDF65666}', # Microsoft.Windows.WESP.Client
    '{EDFDCE69-B825-484F-BD28-2A91DACD4A0F}'  # Microsoft.Windows.WESP.Driver
)

switch ($Action) {
    'Start' {
        # Binary mode writes the exact requested path. (bincirc silently adds
        # _000001, which breaks the conversion command shown in the docs.)
        $arguments = @('create', 'trace', $session, '-ow', '-o', $Output, '-f', 'bin', '-max', '256',
            '-p', $providers[0], '0xffffffffffffffff', '0xff')
        & logman.exe @arguments | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "logman create failed: $LASTEXITCODE" }
        & logman.exe update trace $session -p $providers[1] '0xffffffffffffffff' '0xff' | Out-Host
        if ($LASTEXITCODE -ne 0) {
            & logman.exe delete $session | Out-Null
            throw "logman provider update failed: $LASTEXITCODE"
        }
        & logman.exe start $session | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "logman start failed: $LASTEXITCODE" }
        Write-Host "Tracing to $Output"
    }
    'Stop' {
        & logman.exe stop $session | Out-Host
        $stop = $LASTEXITCODE
        & logman.exe delete $session | Out-Host
        if ($stop -ne 0) { throw "logman stop failed: $stop" }
        if (-not (Test-Path -LiteralPath $Output)) {
            $directory = Split-Path -Parent ([IO.Path]::GetFullPath($Output))
            $stem = [IO.Path]::GetFileNameWithoutExtension($Output)
            $extension = [IO.Path]::GetExtension($Output)
            $generated = @(Get-ChildItem -LiteralPath $directory -Filter "${stem}_*${extension}" |
                Sort-Object LastWriteTimeUtc -Descending)
            if ($generated.Count -eq 1) {
                Move-Item -LiteralPath $generated[0].FullName -Destination $Output -Force
            } elseif ($generated.Count -ne 0) {
                throw "Multiple numbered trace files match $Output; refusing to guess"
            }
        }
        if (-not (Test-Path -LiteralPath $Output)) { throw "Trace output was not created: $Output" }
        Write-Host "Trace saved to $Output"
    }
    'Status' {
        & logman.exe query $session
        exit $LASTEXITCODE
    }
}
