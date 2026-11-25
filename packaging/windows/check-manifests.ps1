# The winget and Scoop manifests that packaging/windows/update.sh wrote, checked on Windows before a release
# (ci.yml's winget-scoop job), from the repository root and as an administrator:
#
#   pwsh packaging/windows/check-manifests.ps1 <manifests> <dist>
#
# <manifests> is update.sh's <out>, written from the MSIs and zips in <dist>. Each address in the manifests must be
# the release's, for a file in <dist>; copies of them then point at <dist>, served on this computer, in place of the
# release. winget validates its manifests as written, installs LimarePDF from them and removes it again; then Scoop
# installs it from its manifest and removes it. After each install, the programs installed are the same as in this
# computer's architecture's zip, and the command line runs; after each removal, nothing is left.
#
# winget 1.28 or later reads the manifests' schema: an earlier one, or none, is replaced by the version set below,
# from its release on GitHub. Scoop is installed with its installer at the commit set below, which brings Scoop's
# current version.
param([Parameter(Mandatory)] [string]$Manifests, [Parameter(Mandatory)] [string]$Dist)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

$wingetTag = 'v1.29.380'
$wingetFiles = @{
  'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle' = '65DEA9C01CE08EE7B763366B27C0E651F97DB857C11CA9B9C301826C10092F2E'
  'DesktopAppInstaller_Dependencies.zip' = 'BA875AFE9D190F61218985AC0292A99D1DB710BF93E13C68944CA9D89F0D82D1'
}
$scoopInstaller = 'https://raw.githubusercontent.com/ScoopInstaller/Install/1e2f334083d609986d8c8bc9e31ae8e87c39fab4/install.ps1'
$scoopInstallerSha256 = '94F983B190438311E006B957DB7C8422709E0BA62A6C2AC04E278164108F2512'

$version = (Select-String -Path Cargo.toml -Pattern '^version = "(.*)"' | Select-Object -First 1).Matches[0].Groups[1].Value
$release = "https://github.com/smaug42/limarepdf/releases/download/v$version/"
$port = 8642
$served = "http://127.0.0.1:$port/"
$Dist = (Resolve-Path $Dist).Path
$work = Join-Path ($env:RUNNER_TEMP ?? [IO.Path]::GetTempPath()) 'limarepdf-manifests'
Remove-Item -Recurse -Force $work -ErrorAction Ignore
New-Item -ItemType Directory $work | Out-Null
$arch = if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq 'Arm64') { 'arm64' } else { 'x86_64' }
$folder = "$env:ProgramFiles\LimarePDF"
$uninstall = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'

function Expect($path, $there) {
  if ((Test-Path $path) -ne $there) { throw "$path is $(if ($there) { 'missing' } else { 'still there' })" }
}
function Installed($count) {
  $found = @(Get-ItemProperty $uninstall -ErrorAction SilentlyContinue | Where-Object DisplayName -eq 'LimarePDF')
  if ($found.Count -ne $count) { throw "$($found.Count) LimarePDF installed, not $count" }
}
function Download($url, $file, $sha256) {
  Invoke-WebRequest $url -OutFile $file
  if ((Get-FileHash $file -Algorithm SHA256).Hash -ne $sha256) { throw "$url isn't the one expected" }
}
# The programs in a folder are this architecture's zip's, and the command line runs, saying this version.
$zip = Join-Path $work 'zip'
Expand-Archive (Join-Path $Dist "limarepdf-$version-windows-$arch.zip") $zip
function Programs($there, $cli) {
  foreach ($exe in 'limarepdf.exe', 'limarepdf-cli.exe') {
    $want = (Get-FileHash "$zip\limarepdf-$version-windows-$arch\$exe").Hash
    if ((Get-FileHash "$there\$exe").Hash -ne $want) { throw "$there\$exe isn't the $arch zip's" }
  }
  $said = & $cli --version
  if ($said -ne "limarepdf-cli $version") { throw "$cli --version said '$said'" }
}

# The copies, pointing at <dist>.
$copies = Join-Path $work 'manifests'
Copy-Item -Recurse $Manifests $copies
$named = 0
foreach ($file in Get-ChildItem $copies -Recurse -File) {
  $text = [IO.File]::ReadAllText($file.FullName)
  foreach ($url in [regex]::Matches($text, 'https?://[^\s"'']+\.(msi|zip)').Value) {
    if (-not $url.StartsWith($release)) { throw "$($file.Name): $url isn't the release's" }
    Expect (Join-Path $Dist $url.Substring($release.Length)) $true
    $named++
  }
  [IO.File]::WriteAllText($file.FullName, $text.Replace($release, $served))
}
if ($named -ne 4) { throw "The manifests name $named release files, not 4" }
$server = Start-Process python -ArgumentList '-m', 'http.server', $port, '--bind', '127.0.0.1', '--directory', $Dist -PassThru
try {
  for ($i = 0; $i -lt 40; $i++) {
    try { Invoke-WebRequest $served -Method Head | Out-Null; break } catch { Start-Sleep -Milliseconds 250 }
  }

  # winget
  $have = if (Get-Command winget -ErrorAction SilentlyContinue) { winget --version } else { 'none' }
  Write-Output "winget: $have"
  if ($have -eq 'none' -or [version]$have.TrimStart('v') -lt [version]'1.28') {
    $files = Join-Path $work 'winget'
    New-Item -ItemType Directory $files | Out-Null
    foreach ($name in $wingetFiles.Keys) {
      Download "https://github.com/microsoft/winget-cli/releases/download/$wingetTag/$name" "$files\$name" $wingetFiles[$name]
    }
    Expand-Archive "$files\DesktopAppInstaller_Dependencies.zip" "$files\dependencies"
    $machine = if ($arch -eq 'arm64') { 'arm64' } else { 'x64' }
    $dependencies = (Get-ChildItem "$files\dependencies\$machine\*.appx").FullName
    Add-AppxPackage "$files\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" -DependencyPath $dependencies `
      -ForceUpdateFromAnyVersion -ForceApplicationShutdown
    $env:PATH = "$env:LOCALAPPDATA\Microsoft\WindowsApps;$env:PATH"
    Write-Output "winget: $(winget --version)"
  }
  $manifest = "manifests\c\ClaytonCornell\LimarePDF\$version"
  winget validate --manifest (Join-Path $Manifests "winget-pkgs\$manifest")
  winget settings --enable LocalManifestFiles
  $winget = Join-Path $copies "winget-pkgs\$manifest"
  $log = Join-Path $work 'winget.log'
  $quiet = '--silent', '--accept-source-agreements', '--disable-interactivity'
  try {
    winget install --manifest $winget --log $log --accept-package-agreements @quiet
  } catch {
    if (Test-Path $log) { Get-Content $log -Tail 80 }
    throw
  }
  Installed 1
  Programs $folder "$folder\limarepdf-cli.exe"
  winget uninstall --manifest $winget @quiet
  Installed 0; Expect $folder $false

  # Scoop, whose scripts each run in a PowerShell of their own, away from this script's preferences: a command
  # they expect may fail (git, looking up a bucket after a failed checksum) would otherwise stop them.
  $installer = Join-Path $work 'install.ps1'
  Download $scoopInstaller $installer $scoopInstallerSha256
  pwsh -NoProfile -File $installer -RunAsAdmin
  $scoop = "$env:USERPROFILE\scoop"
  $env:PATH = "$scoop\shims;$env:PATH"
  $shortcut = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Scoop Apps\LimarePDF.lnk"
  pwsh -NoProfile -File "$scoop\shims\scoop.ps1" install (Join-Path $copies 'scoop-limarepdf\bucket\limarepdf.json')
  Programs "$scoop\apps\limarepdf\current" "$scoop\shims\limarepdf-cli.exe"
  Expect $shortcut $true
  pwsh -NoProfile -File "$scoop\shims\scoop.ps1" uninstall limarepdf
  Expect "$scoop\apps\limarepdf" $false; Expect "$scoop\shims\limarepdf-cli.exe" $false; Expect $shortcut $false
} finally {
  Stop-Process $server
}
