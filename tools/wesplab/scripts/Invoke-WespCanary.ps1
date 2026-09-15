[CmdletBinding()]
param(
    [ValidateRange(1, 10000)]
    [int]$Count = 10,
    [string]$Output = (Join-Path $PWD 'wesp-canary.jsonl')
)

$ErrorActionPreference = 'Stop'
$root = Join-Path $env:TEMP 'wesplab-canary'
New-Item -ItemType Directory -Path $root -Force | Out-Null

for ($index = 0; $index -lt $Count; $index++) {
    $base = 'wesplab-' + [Guid]::NewGuid().ToString('N')
    $fileMarker = $base + '-file'
    $file = Join-Path $root ($fileMarker + '.txt')
    Set-Content -LiteralPath $file -Value $fileMarker -Encoding ASCII
    Move-Item -LiteralPath $file -Destination ($file + '.renamed') -Force
    Remove-Item -LiteralPath ($file + '.renamed') -Force
    [pscustomobject]@{ schema = 'wesplab.canary-stimulus.v1'; timestamp_utc = [DateTime]::UtcNow.ToString('o'); kind = 'file'; marker = $fileMarker; iteration = $index } |
        ConvertTo-Json -Compress | Add-Content -LiteralPath $Output -Encoding UTF8

    $registryMarker = $base + '-registry'
    $key = "HKCU:\Software\wesplab\$registryMarker"
    New-Item -Path $key -Force | Out-Null
    Set-ItemProperty -Path $key -Name Value -Value $registryMarker
    Remove-Item -Path $key -Force
    [pscustomobject]@{ schema = 'wesplab.canary-stimulus.v1'; timestamp_utc = [DateTime]::UtcNow.ToString('o'); kind = 'registry'; marker = $registryMarker; iteration = $index } |
        ConvertTo-Json -Compress | Add-Content -LiteralPath $Output -Encoding UTF8

    $processMarker = $base + '-process'
    $process = Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList "/c echo $processMarker>nul" -PassThru -Wait
    if ($process.ExitCode -ne 0) { throw "Canary process failed: $($process.ExitCode)" }
    [pscustomobject]@{ schema = 'wesplab.canary-stimulus.v1'; timestamp_utc = [DateTime]::UtcNow.ToString('o'); kind = 'process'; marker = $processMarker; iteration = $index } |
        ConvertTo-Json -Compress | Add-Content -LiteralPath $Output -Encoding UTF8
}
Write-Host "Generated $Count process/file/registry canary sequences; evidence: $Output"
