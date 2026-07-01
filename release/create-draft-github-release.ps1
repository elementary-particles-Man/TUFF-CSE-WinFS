[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$InputPath
)

$ErrorActionPreference = "Stop"

function Resolve-AbsolutePath {
    param([string]$Path)

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $Path))
}

function Invoke-Git {
    param([string[]]$Args)

    & git @Args
    if ($LASTEXITCODE -ne 0) {
        throw "git $($Args -join ' ') failed."
    }
}

function Invoke-Gh {
    param([string[]]$Args)

    & gh @Args
    if ($LASTEXITCODE -ne 0) {
        throw "gh $($Args -join ' ') failed."
    }
}

$ResolvedInputPath = Resolve-AbsolutePath $InputPath
$InputDir = Split-Path -Parent $ResolvedInputPath
$VerificationScript = Join-Path $PSScriptRoot "verify-draft-release-inputs.ps1"
& $VerificationScript -InputPath $ResolvedInputPath

$Input = Get-Content -Path $ResolvedInputPath -Raw | ConvertFrom-Json
$TagName = $Input.tag_name
$TargetCommitish = $Input.target_commitish
$ReleaseName = $Input.release_name
$ResolvedReleaseNotes = Resolve-AbsolutePath (Join-Path $InputDir $Input.release_notes)

Invoke-Git @("show-ref", "--tags", "--verify", "--quiet", "refs/tags/$TagName")
if ($LASTEXITCODE -ne 0) {
    throw "Tag does not exist locally: $TagName"
}

$ReleaseExists = $false
$releaseViewOutput = & gh release view $TagName 2>&1
if ($LASTEXITCODE -eq 0) {
    $ReleaseExists = $true
}
elseif ($releaseViewOutput -notmatch "not found") {
    throw "gh release view failed: $releaseViewOutput"
}

if ($ReleaseExists) {
    throw "Release already exists for tag: $TagName"
}

$Assets = @()
foreach ($asset in $Input.assets) {
    $assetPath = Resolve-AbsolutePath (Join-Path $InputDir $asset.path)
    if ($asset.kind -eq "checksums" -or $asset.kind -eq "artifact_manifest" -or $asset.kind -eq "release_notes" -or $asset.kind -eq "portable_zip") {
        $Assets += $assetPath
    }
}

$GhArgs = @(
    "release",
    "create",
    $TagName,
    "--draft",
    "--prerelease",
    "--verify-tag",
    "--target",
    $TargetCommitish,
    "--title",
    $ReleaseName,
    "--notes-file",
    $ResolvedReleaseNotes
)

foreach ($assetPath in $Assets) {
    $GhArgs += $assetPath
}

Invoke-Gh $GhArgs

Write-Host "Draft GitHub Release created for tag $TagName."
