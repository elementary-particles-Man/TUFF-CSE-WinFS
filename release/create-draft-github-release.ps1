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

function Resolve-InputPath {
    param(
        [string]$BaseDir,
        [string]$Path
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return Resolve-AbsolutePath $Path
    }

    return Resolve-AbsolutePath (Join-Path $BaseDir $Path)
}

function Invoke-Git {
    param([string[]]$CommandArgs)

    & git @CommandArgs
    if ($LASTEXITCODE -ne 0) {
        throw "git $($CommandArgs -join ' ') failed."
    }
}

function Invoke-Gh {
    param([string[]]$CommandArgs)

    & gh @CommandArgs
    if ($LASTEXITCODE -ne 0) {
        throw "gh $($CommandArgs -join ' ') failed."
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
$ResolvedReleaseNotes = Resolve-InputPath -BaseDir $InputDir -Path $Input.release_notes

Invoke-Git -CommandArgs @("show-ref", "--tags", "--verify", "--quiet", "refs/tags/$TagName")
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
    $assetPath = Resolve-InputPath -BaseDir $InputDir -Path $asset.path
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

Invoke-Gh -CommandArgs $GhArgs

Write-Host "Draft GitHub Release created for tag $TagName."
