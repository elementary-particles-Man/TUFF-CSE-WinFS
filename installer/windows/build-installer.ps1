[CmdletBinding()]
param(
    [string]$RepoRoot = "",
    [string]$OutputDir = ""
)

$ErrorActionPreference = "Stop"

function Write-Section {
    param([string]$Message)
    Write-Host ""
    Write-Host "== $Message =="
}

$DefaultRepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = $DefaultRepoRoot
} else {
    $RepoRoot = (Resolve-Path $RepoRoot).Path
}

$InstallerRoot = Join-Path $RepoRoot "installer\windows"
$TargetRelease = Join-Path $RepoRoot "target\release"
$SetupExe = Join-Path $TargetRelease "TuffCseWinFsSetup.exe"
$CtlExe = Join-Path $TargetRelease "tuff-cse-winfsctl.exe"

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $RepoRoot "artifacts\windows-installer"
} else {
    $ResolvedOutput = Resolve-Path $OutputDir -ErrorAction SilentlyContinue
    if ($ResolvedOutput) {
        $OutputDir = $ResolvedOutput.Path
    }
}

$StagingDir = Join-Path $OutputDir "staging"
$PackageDir = Join-Path $StagingDir "TUFF-CSE-WinFS"
New-Item -ItemType Directory -Force -Path $PackageDir | Out-Null

foreach ($file in @($SetupExe, $CtlExe)) {
    if (-not (Test-Path $file)) {
        throw "Required release binary not found: $file. Run 'cargo build --release --bins' first."
    }
}

Write-Section "Fixed Point"
if (Test-Path $CtlExe) {
    & $CtlExe rc-status
    if ($LASTEXITCODE -ne 0) {
        throw "rc-status failed."
    }
}

Write-Section "Staging Package"
Copy-Item $SetupExe (Join-Path $PackageDir "TuffCseWinFsSetup.exe") -Force
Copy-Item $CtlExe (Join-Path $PackageDir "tuff-cse-winfsctl.exe") -Force
Copy-Item (Join-Path $InstallerRoot "assets\README-FIRST.txt") (Join-Path $PackageDir "README-FIRST.txt") -Force
Copy-Item (Join-Path $InstallerRoot "assets\LICENSE.rtf") (Join-Path $PackageDir "LICENSE.rtf") -Force
Copy-Item (Join-Path $InstallerRoot "PACKAGE_MANIFEST.md") (Join-Path $PackageDir "PACKAGE_MANIFEST.md") -Force
Copy-Item (Join-Path $InstallerRoot "TUFF-CSE-WinFS.wxs") (Join-Path $PackageDir "TUFF-CSE-WinFS.wxs") -Force

$GitSha = $(git -C $RepoRoot rev-parse --short HEAD).Trim()
if (-not $GitSha) {
    $GitSha = "unknown"
}

$ArtifactZip = Join-Path $OutputDir "TUFF-CSE-WinFS-$GitSha-public-windows-installer.zip"
if (Test-Path $ArtifactZip) {
    Remove-Item $ArtifactZip -Force
}

Write-Section "Create Portable Artifact"
Compress-Archive -Path (Join-Path $PackageDir "*") -DestinationPath $ArtifactZip -Force

Write-Host "Portable installer artifact created:"
Write-Host $ArtifactZip
