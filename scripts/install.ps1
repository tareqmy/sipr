# sipr installer for Windows
# Supported platforms: Windows (x86_64)
# Usage: irm https://raw.githubusercontent.com/tareqmy/sipr/master/scripts/install.ps1 | iex
#   $env:VERSION = "v0.27.1"   install a specific release instead of the latest
#   $env:GITHUB_TOKEN = "..."  authenticate GitHub requests

$ErrorActionPreference = "Stop"

$repo_owner = "tareqmy"
$repo_name = "sipr"
$github_raw_url = "https://raw.githubusercontent.com/$repo_owner/$repo_name/master"
$github_api_url = "https://api.github.com/repos/$repo_owner/$repo_name"
$github_releases_url = "https://github.com/$repo_owner/$repo_name/releases"

function Write-Info ($msg)    { Write-Host -ForegroundColor Cyan "[info] $msg" }
function Write-Success ($msg) { Write-Host -ForegroundColor Green "[success] $msg" }
function Write-ErrorMsg ($msg) { Write-Host -ForegroundColor Red "[error] $msg"; exit 1 }

# 1. Architecture
$arch = $env:PROCESSOR_ARCHITECTURE
if ($arch -eq "AMD64") {
    $target = "x86_64-pc-windows-msvc"
} else {
    Write-ErrorMsg "Unsupported Windows architecture: $arch. sipr ships x86_64 Windows binaries only."
}

# 2. Version
$headers = @{}
if ($env:GITHUB_TOKEN) { $headers["Authorization"] = "token $env:GITHUB_TOKEN" }

$version = ""
if ($env:VERSION) {
    $version = $env:VERSION.Trim()
    Write-Info "Using specified version: $version"
} else {
    Write-Info "Querying latest version..."
    try {
        $version = (Invoke-RestMethod -Uri "$github_raw_url/.version" -Headers $headers).Trim()
    } catch {
        try {
            $release = Invoke-RestMethod -Uri "$github_api_url/releases/latest" -Headers $headers
            $version = $release.tag_name
        } catch {
            Write-ErrorMsg "Could not resolve the latest version. Check your network or set `$env:VERSION."
        }
    }
}
if (-not $version.StartsWith("v")) { $version = "v$version" }
Write-Info "Using version: $version"

# 3. Install directory (per user, no administrator rights needed)
$install_dir = Join-Path $env:USERPROFILE ".sipr\bin"
if (-not (Test-Path $install_dir)) {
    New-Item -ItemType Directory -Path $install_dir -Force | Out-Null
}
Write-Info "Installing into: $install_dir"

# 4. Download and extract
$asset_name = "sipr-$version-$target.zip"
$download_url = "$github_releases_url/download/$version/$asset_name"
$tmp_dir = Join-Path $env:TEMP "sipr-install-$([Guid]::NewGuid())"
New-Item -ItemType Directory -Path $tmp_dir -Force | Out-Null
$zip_path = Join-Path $tmp_dir $asset_name

Write-Info "Downloading $download_url"
try {
    if ($env:GITHUB_TOKEN) {
        $release_json = Invoke-RestMethod -Uri "$github_api_url/releases/tags/$version" -Headers $headers
        $asset = $release_json.assets | Where-Object { $_.name -eq $asset_name }
        if (-not $asset) { Write-ErrorMsg "Release $version has no asset named $asset_name." }
        $headers["Accept"] = "application/octet-stream"
        Invoke-WebRequest -Uri $asset.url -Headers $headers -OutFile $zip_path
    } else {
        Invoke-WebRequest -Uri $download_url -OutFile $zip_path
    }
} catch {
    Write-ErrorMsg "Download failed: $_"
}

Write-Info "Extracting..."
try {
    Expand-Archive -Path $zip_path -DestinationPath $tmp_dir -Force
} catch {
    Write-ErrorMsg "Failed to extract the archive: $_"
}

$exe_path = Get-ChildItem -Path $tmp_dir -Filter "sipr.exe" -Recurse | Select-Object -First 1
if (-not $exe_path) { Write-ErrorMsg "sipr.exe not found in $asset_name." }

$dest_path = Join-Path $install_dir "sipr.exe"
Write-Info "Installing sipr.exe to $dest_path"
Move-Item -Path $exe_path.FullName -Destination $dest_path -Force
Remove-Item -Path $tmp_dir -Recurse -Force

# 5. PATH
$path_var = [Environment]::GetEnvironmentVariable("Path", "User")
$path_parts = $path_var -split ";" | Where-Object { $_ -ne "" }
if ($path_parts -notcontains $install_dir) {
    [Environment]::SetEnvironmentVariable("Path", "$path_var;$install_dir", "User")
    $env:Path += ";$install_dir"
    Write-Success "Added $install_dir to your user PATH."
} else {
    Write-Info "$install_dir is already on your PATH."
}

Write-Success "sipr $version installed. Open a new terminal and run: sipr -h"
