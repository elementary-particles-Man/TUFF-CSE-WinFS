param (
    [string]$Configuration = "Release",
    [string]$Platform = "x64",
    [switch]$NoBuild
)

if ($IsWindows -eq $false -or $env:OS -ne "Windows_NT") {
    Write-Error "This script must be run on a Windows host."
    exit 1
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SlnPath = Join-Path $ScriptDir "TUFF-CSE-WinFS.sln"
$VcxprojPath = Join-Path $ScriptDir "tuffcsewinfs.vcxproj"

if (-not (Test-Path $SlnPath) -and -not (Test-Path $VcxprojPath)) {
    Write-Error "Project files not found. Cannot proceed."
    exit 1
}

if ($NoBuild) {
    Write-Host "Project boundary validation successful (NoBuild specified)."
    exit 0
}

if ((Get-Command msbuild -ErrorAction SilentlyContinue) -eq $null) {
    Write-Error "MSBuild not found. WDK or Visual Studio Build Tools required."
    exit 1
}

Write-Host "Building driver project..."
msbuild $VcxprojPath /p:Configuration=$Configuration /p:Platform=$Platform

$SysPath = Join-Path $ScriptDir "$Platform\$Configuration\tuffcsewinfs.sys"
if (Test-Path $SysPath) {
    Write-Host "Build completed successfully. Sys file generated at: $SysPath"
} else {
    Write-Warning "Build completed but tuffcsewinfs.sys was not found."
}
