$ErrorActionPreference = 'SilentlyContinue'

$commands = 'cmake.exe', 'clang-cl.exe', 'cl.exe', 'msbuild.exe', 'vswhere.exe'
foreach ($command in $commands) {
    $found = Get-Command $command -ErrorAction SilentlyContinue
    [pscustomobject]@{ Command = $command; Path = $found.Source } | ConvertTo-Json -Compress
}

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (Test-Path $vswhere) {
    & $vswhere -products * -requires Microsoft.VisualStudio.Component.VC.Tools.ARM64 -property installationPath
}
