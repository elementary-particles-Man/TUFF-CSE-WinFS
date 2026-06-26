[CmdletBinding()]
param(
    [string]$RepoRoot = "",
    [string]$ArtifactRoot = "",
    [string]$OutputRoot = "",
    [string]$SourceCommit = "",
    [string]$BuildWorkflow = "public-release-artifact",
    [string]$BoundaryStatus = "draft-release-boundary"
)

$ErrorActionPreference = "Stop"

function Resolve-AbsolutePath {
    param([string]$Path)

    return (Resolve-Path $Path).Path
}

function Get-Sha256Hex {
    param([string]$Path)

    return (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLowerInvariant()
}

function New-ArtifactRecord {
    param(
        [string]$ArtifactName,
        [string]$ArtifactKind,
        [string]$ArtifactPath,
        [string]$SourceCommit,
        [string]$BuildWorkflow,
        [string]$GeneratedAt,
        [string]$BoundaryStatus
    )

    $info = Get-Item $ArtifactPath
    [pscustomobject]@{
        artifact_name   = $ArtifactName
        artifact_kind   = $ArtifactKind
        source_commit   = $SourceCommit
        build_workflow  = $BuildWorkflow
        sha256          = Get-Sha256Hex $ArtifactPath
        size_bytes      = [int64]$info.Length
        generated_at    = $GeneratedAt
        boundary_status = $BoundaryStatus
    }
}

$RepoRoot = if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    Resolve-AbsolutePath (Join-Path $PSScriptRoot "..")
} else {
    Resolve-AbsolutePath $RepoRoot
}

$ArtifactRoot = if ([string]::IsNullOrWhiteSpace($ArtifactRoot)) {
    Resolve-AbsolutePath (Join-Path $RepoRoot "artifacts\windows-installer")
} else {
    Resolve-AbsolutePath $ArtifactRoot
}

$OutputRoot = if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    Join-Path $RepoRoot ".tuff-cse-winfs-dev\p7b-release"
} else {
    $resolved = Resolve-Path $OutputRoot -ErrorAction SilentlyContinue
    if ($resolved) {
        $resolved.Path
    } else {
        [System.IO.Path]::GetFullPath($OutputRoot)
    }
}

if ([string]::IsNullOrWhiteSpace($SourceCommit)) {
    $SourceCommit = (git -C $RepoRoot rev-parse HEAD).Trim()
}

if (Test-Path $OutputRoot) {
    Remove-Item $OutputRoot -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null

$ReleaseNotesSource = Join-Path $RepoRoot "release\V1_RC_RELEASE_NOTES.md"
if (-not (Test-Path $ReleaseNotesSource)) {
    throw "Release notes source not found: $ReleaseNotesSource"
}

$PortableZipSource = Get-ChildItem -Path $ArtifactRoot -File -Filter "*-public-windows-installer.zip" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
if (-not $PortableZipSource) {
    throw "Portable installer zip not found under $ArtifactRoot"
}

$PortableZipTarget = Join-Path $OutputRoot $PortableZipSource.Name
$ReleaseNotesTarget = Join-Path $OutputRoot "V1_RC_RELEASE_NOTES.md"
Copy-Item $PortableZipSource.FullName $PortableZipTarget -Force
Copy-Item $ReleaseNotesSource $ReleaseNotesTarget -Force

$GeneratedAt = [DateTimeOffset]::UtcNow.ToString("o")
$PortableZipRecord = New-ArtifactRecord `
    -ArtifactName $PortableZipSource.Name `
    -ArtifactKind "portable_zip" `
    -ArtifactPath $PortableZipTarget `
    -SourceCommit $SourceCommit `
    -BuildWorkflow $BuildWorkflow `
    -GeneratedAt $GeneratedAt `
    -BoundaryStatus $BoundaryStatus

$MsiSource = Get-ChildItem -Path $ArtifactRoot -File -Filter "*.msi" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

$ArtifactRecords = @($PortableZipRecord)
$MsiRecord = $null

if ($MsiSource) {
    $MsiTarget = Join-Path $OutputRoot $MsiSource.Name
    Copy-Item $MsiSource.FullName $MsiTarget -Force
    $MsiRecord = New-ArtifactRecord `
        -ArtifactName $MsiSource.Name `
        -ArtifactKind "wix_msi_candidate" `
        -ArtifactPath $MsiTarget `
        -SourceCommit $SourceCommit `
        -BuildWorkflow $BuildWorkflow `
        -GeneratedAt $GeneratedAt `
        -BoundaryStatus $BoundaryStatus
    $ArtifactRecords += $MsiRecord
}

$ReleaseNotesRecord = New-ArtifactRecord `
    -ArtifactName "V1_RC_RELEASE_NOTES.md" `
    -ArtifactKind "release_notes" `
    -ArtifactPath $ReleaseNotesTarget `
    -SourceCommit $SourceCommit `
    -BuildWorkflow $BuildWorkflow `
    -GeneratedAt $GeneratedAt `
    -BoundaryStatus $BoundaryStatus

$ChecksumLines = @(
    "# TUFF-CSE-WinFS v1 RC public release artifact checksum report",
    "# Generated at $GeneratedAt",
    "# Source commit: $SourceCommit",
    "# Build workflow: $BuildWorkflow",
    "",
    ("SHA256 ({0}) = {1}" -f $PortableZipRecord.artifact_name, $PortableZipRecord.sha256),
)

if ($MsiRecord) {
    $ChecksumLines += ("SHA256 ({0}) = {1}" -f $MsiRecord.artifact_name, $MsiRecord.sha256)
}

$ChecksumLines += @(
    ("SHA256 (V1_RC_RELEASE_NOTES.md) = {0}" -f $ReleaseNotesRecord.sha256)
)

$ChecksumsTarget = Join-Path $OutputRoot "V1_RC_CHECKSUMS.sha256"
Set-Content -Path $ChecksumsTarget -Value $ChecksumLines -Encoding utf8

$ChecksumsRecord = New-ArtifactRecord `
    -ArtifactName "V1_RC_CHECKSUMS.sha256" `
    -ArtifactKind "checksums" `
    -ArtifactPath $ChecksumsTarget `
    -SourceCommit $SourceCommit `
    -BuildWorkflow $BuildWorkflow `
    -GeneratedAt $GeneratedAt `
    -BoundaryStatus $BoundaryStatus

$ArtifactRecords += $ReleaseNotesRecord
$ArtifactRecords += $ChecksumsRecord

$Manifest = [pscustomobject]@{
    schema_version = "2026-06-p7b"
    release_line   = "TUFF-CSE-WinFS v1 RC"
    boundary_status = $BoundaryStatus
    artifacts      = $ArtifactRecords
}

$ManifestTarget = Join-Path $OutputRoot "V1_RC_ARTIFACT_MANIFEST.json"
$Manifest | ConvertTo-Json -Depth 6 | Set-Content -Path $ManifestTarget -Encoding utf8

Write-Host "Public release artifact bundle created:"
Write-Host $OutputRoot
