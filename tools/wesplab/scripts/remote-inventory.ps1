$ErrorActionPreference = 'Continue'

$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$ui = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\WindowsSelfHost\UI\Selection' -ErrorAction SilentlyContinue
$app = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\WindowsSelfHost\Applicability' -ErrorAction SilentlyContinue

[pscustomobject]@{
    Product = $cv.ProductName
    DisplayVersion = $cv.DisplayVersion
    Build = $cv.CurrentBuild
    UBR = $cv.UBR
    BuildLabEx = $cv.BuildLabEx
    Edition = $cv.EditionID
    FlightRing = $ui.UIRing
    FlightBranch = $ui.UIBranch
    Ring = $app.Ring
    BranchName = $app.BranchName
    ContentType = $app.ContentType
} | ConvertTo-Json -Compress

Get-Item "$env:SystemRoot\System32\espclient.dll", "$env:SystemRoot\System32\drivers\wesp.sys" -ErrorAction SilentlyContinue |
    ForEach-Object {
        [pscustomobject]@{
            Path = $_.FullName
            FileVersion = $_.VersionInfo.FileVersion
            ProductVersion = $_.VersionInfo.ProductVersion
            Length = $_.Length
            Sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        } | ConvertTo-Json -Compress
    }

[pscustomobject]@{
    PendingCBS = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    PendingWU = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    FreeGB = [math]::Round((Get-Volume -DriveLetter C).SizeRemaining / 1GB, 1)
    SizeGB = [math]::Round((Get-Volume -DriveLetter C).Size / 1GB, 1)
} | ConvertTo-Json -Compress

$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$result = $searcher.Search("IsInstalled=0 and IsHidden=0")
$result.Updates | ForEach-Object {
    [pscustomobject]@{
        UpdateTitle = $_.Title
        KB = @($_.KBArticleIDs)
        RebootRequired = $_.RebootRequired
        EulaAccepted = $_.EulaAccepted
    } | ConvertTo-Json -Compress
}
