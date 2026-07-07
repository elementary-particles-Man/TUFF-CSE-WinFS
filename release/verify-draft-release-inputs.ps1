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

function Get-Sha256Hex {
    param([string]$Path)

    return (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLowerInvariant()
}

function Read-DraftReleaseInput {
    param([string]$Path)

    return Get-Content -Path $Path -Raw | ConvertFrom-Json
}

function Assert-True {
    param(
        [bool]$Condition,
        [string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

$ResolvedInputPath = Resolve-AbsolutePath $InputPath
$InputDir = Split-Path -Parent $ResolvedInputPath
$Input = Read-DraftReleaseInput -Path $ResolvedInputPath

Assert-True ($Input.tag_name -match '^v1\.0\.0-rc[1-9][0-9]*$') "Invalid RC tag name: $($Input.tag_name)"
Assert-True ($Input.draft -eq $true) "draft must be true."
Assert-True ($Input.prerelease -eq $true) "prerelease must be true."

if ($Input.PSObject.Properties.Name -contains "publish") {
    Assert-True ($Input.publish -eq $false) "publish must be false."
}

Assert-True (-not [string]::IsNullOrWhiteSpace($Input.workflow_ref)) "Missing workflow_ref."
Assert-True (-not [string]::IsNullOrWhiteSpace($Input.release_name)) "Missing release_name."
Assert-True (-not [string]::IsNullOrWhiteSpace($Input.artifact_manifest)) "Missing artifact_manifest."
Assert-True (-not [string]::IsNullOrWhiteSpace($Input.checksums)) "Missing checksums."
Assert-True (-not [string]::IsNullOrWhiteSpace($Input.release_notes)) "Missing release_notes."

if ($Input.PSObject.Properties.Name -contains "release_target_commitish" -and
    $Input.PSObject.Properties.Name -contains "target_commitish" -and
    -not [string]::IsNullOrWhiteSpace($Input.release_target_commitish) -and
    -not [string]::IsNullOrWhiteSpace($Input.target_commitish)) {
    Assert-True ($Input.release_target_commitish -eq $Input.target_commitish) "release_target_commitish must match target_commitish."
}

$TargetCommitish = if ($Input.PSObject.Properties.Name -contains "release_target_commitish" -and -not [string]::IsNullOrWhiteSpace($Input.release_target_commitish)) {
    $Input.release_target_commitish
} else {
    $Input.target_commitish
}

Assert-True (-not [string]::IsNullOrWhiteSpace($TargetCommitish)) "Missing target_commitish."

$HeadCommit = (git rev-parse HEAD).Trim()
$ResolvedTargetCommit = (git rev-parse --verify "$TargetCommitish^{commit}").Trim()
Assert-True ($ResolvedTargetCommit -eq $HeadCommit) "target_commitish must match the current HEAD commit."

$ResolvedManifest = Resolve-InputPath -BaseDir $InputDir -Path $Input.artifact_manifest
$ResolvedChecksums = Resolve-InputPath -BaseDir $InputDir -Path $Input.checksums
$ResolvedReleaseNotes = Resolve-InputPath -BaseDir $InputDir -Path $Input.release_notes

foreach ($path in @($ResolvedManifest, $ResolvedChecksums, $ResolvedReleaseNotes)) {
    Assert-True (Test-Path $path) "Missing required release file: $path"
}

if (-not $Input.assets) {
    throw "Missing assets."
}

$AllowedKinds = @("portable_zip", "artifact_manifest", "checksums", "release_notes")
Assert-True ($Input.assets.Count -eq 4) "Draft release must expose exactly four assets."

$ChecksumMap = @{}
foreach ($line in Get-Content -Path $ResolvedChecksums) {
    if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith("#")) {
        continue
    }
    if ($line -notmatch '^SHA256 \((.+)\) = ([0-9A-Fa-f]{64})$') {
        throw "Invalid checksum line: $line"
    }
    $ChecksumMap[$matches[1]] = $matches[2].ToLowerInvariant()
}

foreach ($asset in $Input.assets) {
    foreach ($field in @("kind", "name", "path", "label")) {
        if ($asset.PSObject.Properties.Name -notcontains $field) {
            throw "Asset entry missing field: $field"
        }
    }

    Assert-True ($AllowedKinds -contains $asset.kind) "Unsupported asset kind: $($asset.kind)"
    Assert-True (-not [string]::IsNullOrWhiteSpace($asset.name)) "Missing asset name."

    $assetPath = Resolve-InputPath -BaseDir $InputDir -Path $asset.path
    Assert-True (Test-Path $assetPath) "Missing asset file: $assetPath"

    if ($asset.kind -eq "checksums") {
        continue
    }

    $assetBaseName = Split-Path -Leaf $assetPath
    $actualHash = Get-Sha256Hex $assetPath
    Assert-True ($ChecksumMap.ContainsKey($assetBaseName)) "Checksum entry missing for $assetBaseName"
    Assert-True ($ChecksumMap[$assetBaseName] -eq $actualHash) "Checksum mismatch for $assetBaseName"
}

$ManifestData = Get-Content -Path $ResolvedManifest -Raw | ConvertFrom-Json
Assert-True ($ManifestData.artifacts.Count -ge 1) "Manifest does not contain artifacts."
Assert-True ($ChecksumMap.ContainsKey((Split-Path -Leaf $ResolvedManifest))) "Checksum entry missing for release manifest."
Assert-True (
    $ChecksumMap[(Split-Path -Leaf $ResolvedManifest)] -eq (Get-Sha256Hex $ResolvedManifest)
) "Checksum mismatch for release manifest."

Write-Host "Draft release input verification succeeded."
