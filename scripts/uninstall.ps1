# sipr uninstaller for Windows (for installs made by scripts/install.ps1)
# Usage: irm https://raw.githubusercontent.com/tareqmy/sipr/master/scripts/uninstall.ps1 | iex

$ErrorActionPreference = "Stop"

function Write-Info ($msg)    { Write-Host -ForegroundColor Cyan "[info] $msg" }
function Write-Success ($msg) { Write-Host -ForegroundColor Green "[success] $msg" }

$install_dir = Join-Path $env:USERPROFILE ".sipr\bin"
$exe_path = Join-Path $install_dir "sipr.exe"

if (Test-Path $exe_path) {
    Write-Info "Removing sipr.exe..."
    Remove-Item -Path $exe_path -Force
}

if ((Test-Path $install_dir) -and ((Get-ChildItem -Path $install_dir).Count -eq 0)) {
    Write-Info "Removing empty $install_dir..."
    Remove-Item -Path $install_dir -Force
}

Write-Info "Removing $install_dir from your user PATH..."
$path_var = [Environment]::GetEnvironmentVariable("Path", "User")
if ($path_var) {
    $parts = $path_var -split ";" | Where-Object { $_ -ne "" -and $_ -ne $install_dir }
    [Environment]::SetEnvironmentVariable("Path", ($parts -join ";"), "User")
}

Write-Success "sipr has been uninstalled."
