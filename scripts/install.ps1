$ErrorActionPreference = "Stop"

$repo = $env:SIS_GITHUB_REPO
if ([string]::IsNullOrWhiteSpace($repo)) {
  $repo = "michiel/sis-pdf"
}

$installDir = $env:SIS_INSTALL_DIR
if ([string]::IsNullOrWhiteSpace($installDir)) {
  $installDir = Join-Path $env:LOCALAPPDATA "sis\bin"
}

$target = "x86_64-pc-windows-msvc"
$ext = "zip"

$apiUrl = "https://api.github.com/repos/$repo/releases?per_page=20"
$releases = Invoke-RestMethod -Headers @{"User-Agent" = "sis-install"} -Uri $apiUrl
$suffix = "-$target.$ext"
$release = $null
$asset = $null
foreach ($entry in $releases) {
  if ($entry.draft) {
    continue
  }
  $candidate = $entry.assets | Where-Object { $_.name -like "sis-*$suffix" } | Select-Object -First 1
  if ($candidate) {
    $release = $entry
    $asset = $candidate
    break
  }
}
if (-not $asset) {
  throw "No release asset found for $target"
}

$tempDir = Join-Path $env:TEMP ("sis-install-" + [guid]::NewGuid())
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
try {
  $archivePath = Join-Path $tempDir $assetName
  Invoke-WebRequest -Headers @{"User-Agent" = "sis-install"} -Uri $asset.browser_download_url -OutFile $archivePath
  Expand-Archive -Path $archivePath -DestinationPath $tempDir -Force
  New-Item -ItemType Directory -Force -Path $installDir | Out-Null
  Copy-Item (Join-Path $tempDir "sis.exe") (Join-Path $installDir "sis.exe") -Force
  Write-Host "Installed sis $($release.tag_name) to $installDir\sis.exe"
  if (-not (Get-Command sis -ErrorAction SilentlyContinue)) {
    Write-Host "Add $installDir to your PATH to run sis"
  }
} finally {
  Remove-Item -Recurse -Force -Path $tempDir
}
