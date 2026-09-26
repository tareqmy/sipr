$ErrorActionPreference = 'Stop'

$toolsDir   = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$packageId  = 'sipr'
$url64      = 'https://github.com/tareqmy/sipr/releases/download/v0.28.0/sipr-v0.28.0-x86_64-pc-windows-msvc.zip'
$checksum64 = 'WINDOWS_ZIP_SHA256' # Automatically updated by CD on release

$packageArgs = @{
  packageName   = $packageId
  unzipLocation = $toolsDir
  url64bit      = $url64
  checksum64    = $checksum64
  checksumType64= 'sha256'
}

Install-ChocolateyZipPackage @packageArgs

$exePath = Join-Path $toolsDir "sipr.exe"
Install-BinFile -Name "sipr" -Path $exePath
