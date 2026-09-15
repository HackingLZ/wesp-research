[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path $PWD ('wesp-build-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))),
    [string]$WespLab,
    [switch]$IncludeMicrosoftBinaries
)

$ErrorActionPreference = 'Stop'
if (-not $WespLab) { $WespLab = Join-Path (Split-Path -Parent $PSScriptRoot) 'wesplab.py' }

function Get-PeMetadata([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    $reader = [IO.BinaryReader]::new($stream)
    try {
        if ($reader.ReadUInt16() -ne 0x5A4D) { throw "Not a PE image: $Path" }
        $stream.Position = 0x3c
        $peOffset = $reader.ReadUInt32()
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) { throw "Invalid PE signature: $Path" }
        $machine = $reader.ReadUInt16()
        $sections = $reader.ReadUInt16()
        $timestamp = $reader.ReadUInt32()
        $stream.Position = $peOffset + 24
        $magic = $reader.ReadUInt16()
        $stream.Position = $peOffset + 24 + 56
        $imageSize = $reader.ReadUInt32()
        $stream.Position = $peOffset + 24 + 70
        $dllCharacteristics = $reader.ReadUInt16()
        [pscustomobject]@{
            machine = switch ($machine) { 0x8664 { 'x64' } 0xAA64 { 'arm64' } 0x014c { 'x86' } default { '0x{0:x4}' -f $machine } }
            section_count = $sections
            pe_timestamp = $timestamp
            optional_magic = '0x{0:x4}' -f $magic
            image_size = $imageSize
            dll_characteristics = '0x{0:x4}' -f $dllCharacteristics
        }
    } finally {
        $reader.Dispose()
        $stream.Dispose()
    }
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$schemaDirectory = Join-Path $OutputDirectory 'etw-schema'
New-Item -ItemType Directory -Path $schemaDirectory -Force | Out-Null

$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$providers = 'Microsoft.Windows.WESP.Client', 'Microsoft.Windows.WESP.Driver'
$providerGuids = [ordered]@{
    'Microsoft.Windows.WESP.Client' = '{EA3FDB23-A523-45DB-BBC2-7B3BDDF65666}'
    'Microsoft.Windows.WESP.Driver' = '{EDFDCE69-B825-484F-BD28-2A91DACD4A0F}'
}
$schemaHashes = @()
foreach ($provider in $providers) {
    $safeName = $provider.Replace('.', '_') + '.xml'
    $target = Join-Path $schemaDirectory $safeName
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $lines = @(& wevtutil.exe gp $provider /ge:true /gm:true /f:xml 2>&1 |
        ForEach-Object { $_.ToString() })
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = $savedPreference
    $lines | Set-Content -LiteralPath $target -Encoding UTF8
    if ($exitCode -eq 0) {
        $schemaHashes += (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

$artifacts = @()
$paths = @(
    (Join-Path $env:SystemRoot 'System32\espclient.dll'),
    (Join-Path $env:SystemRoot 'System32\drivers\wesp.sys')
)
foreach ($path in $paths) {
    if (-not (Test-Path -LiteralPath $path)) { continue }
    $item = Get-Item -LiteralPath $path
    $signature = Get-AuthenticodeSignature -LiteralPath $path
    $pe = Get-PeMetadata -Path $path
    $exports = @()
    $exportSource = $null
    $dumpbin = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
    if ($dumpbin -and $item.Extension -eq '.dll') {
        $exports = @(& $dumpbin.Source /nologo /exports $path 2>$null |
            ForEach-Object { if ($_ -match '^\s+\d+\s+[0-9A-F]+\s+[0-9A-F]+\s+(\S+)') { $Matches[1] } })
        $exportSource = 'dumpbin'
    } elseif ($item.Extension -eq '.dll' -and (Test-Path -LiteralPath $WespLab)) {
        $python = Get-Command python.exe -ErrorAction SilentlyContinue
        if ($python) {
            $savedPreference = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            $inspectionText = (& $python.Source $WespLab inspect $path 2>$null) -join "`n"
            $inspectionExit = $LASTEXITCODE
            $ErrorActionPreference = $savedPreference
            if ($inspectionExit -eq 0) {
                $inspection = $inspectionText | ConvertFrom-Json
                $exports = @($inspection.exports)
                $exportSource = 'wesplab-pe-parser'
            }
        }
    }
    $record = [ordered]@{
        logical_name = $item.Name
        path = $item.FullName
        size = $item.Length
        version = $item.VersionInfo.FileVersion
        product_version = $item.VersionInfo.ProductVersion
        machine = $pe.machine
        section_count = $pe.section_count
        pe_timestamp = $pe.pe_timestamp
        optional_magic = $pe.optional_magic
        image_size = $pe.image_size
        dll_characteristics = $pe.dll_characteristics
        sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        signer = $signature.SignerCertificate.Subject
        signature_status = [string]$signature.Status
        exports = $exports
        export_source = $exportSource
    }
    if ($IncludeMicrosoftBinaries) {
        $binaryDirectory = Join-Path $OutputDirectory 'binaries'
        New-Item -ItemType Directory -Path $binaryDirectory -Force | Out-Null
        $copy = Join-Path $binaryDirectory $item.Name
        Copy-Item -LiteralPath $path -Destination $copy
        $record['captured_path'] = $copy
    }
    $artifacts += [pscustomobject]$record
}

$schemaDigest = $null
if ($schemaHashes.Count) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes(($schemaHashes | Sort-Object) -join "`n")
        $schemaDigest = [Convert]::ToHexString($sha.ComputeHash($bytes)).ToLowerInvariant()
    } finally { $sha.Dispose() }
}

$manifest = [ordered]@{
    schema = 'wesplab.build-harvest.v1'
    created_utc = [DateTime]::UtcNow.ToString('o')
    computer = $env:COMPUTERNAME
    windows_build = "$($cv.CurrentBuild).$($cv.UBR)"
    build_lab = $cv.BuildLabEx
    artifacts = $artifacts
    etw_providers = $providers
    etw_provider_guids = $providerGuids
    etw_manifest_metadata_available = [bool]($schemaHashes.Count)
    etw_schema_sha256 = $schemaDigest
    microsoft_binaries_included = [bool]$IncludeMicrosoftBinaries
}
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'build.json') -Encoding UTF8
Write-Host "Harvested build evidence to $OutputDirectory"
