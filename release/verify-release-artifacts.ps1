[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Manifest,
    [Parameter(Mandatory = $true)]
    [string]$Checksums
)

$ErrorActionPreference = "Stop"

function Get-Sha256Hex {
    param([string]$Path)

    return (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLowerInvariant()
}

function Parse-ChecksumFile {
    param([string]$Path)

    $map = @{}
    foreach ($line in Get-Content -Path $Path) {
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith("#")) {
            continue
        }

        if ($line -notmatch '^SHA256 \((.+)\) = ([0-9A-Fa-f]{64})$') {
            throw "Invalid checksum line: $line"
        }

        $map[$matches[1]] = $matches[2].ToLowerInvariant()
    }

    return $map
}

$ManifestPath = (Resolve-Path $Manifest).Path
$ChecksumsPath = (Resolve-Path $Checksums).Path
$BundleRoot = Split-Path -Parent $ManifestPath
$ManifestData = Get-Content -Path $ManifestPath -Raw | ConvertFrom-Json

if (-not $ManifestData.artifacts) {
    throw "Manifest does not contain artifacts."
}

$AllowedKinds = @("portable_zip", "wix_msi_candidate", "checksums", "release_notes")
$ChecksumMap = Parse-ChecksumFile -Path $ChecksumsPath

if (-not $ChecksumMap.ContainsKey((Split-Path -Leaf $ManifestPath))) {
    throw "Checksum entry missing for release manifest."
}

if ($ChecksumMap[(Split-Path -Leaf $ManifestPath)] -ne (Get-Sha256Hex $ManifestPath)) {
    throw "Checksum mismatch for release manifest."
}

foreach ($artifact in $ManifestData.artifacts) {
    foreach ($field in @("artifact_name", "artifact_kind", "source_commit", "build_workflow", "sha256", "size_bytes", "generated_at", "boundary_status")) {
        if ($artifact.PSObject.Properties.Name -notcontains $field) {
            throw "Manifest artifact entry missing field: $field"
        }
    }

    if ($AllowedKinds -notcontains $artifact.artifact_kind) {
        throw "Unsupported artifact kind: $($artifact.artifact_kind)"
    }

    $artifactPath = Join-Path $BundleRoot $artifact.artifact_name
    if (-not (Test-Path $artifactPath)) {
        throw "Artifact file not found: $artifactPath"
    }

    $actualHash = Get-Sha256Hex $artifactPath
    if ($actualHash -ne $artifact.sha256.ToLowerInvariant()) {
        throw "Manifest SHA256 mismatch for $($artifact.artifact_name)"
    }

    $actualSize = (Get-Item $artifactPath).Length
    if ($actualSize -ne [int64]$artifact.size_bytes) {
        throw "Manifest size mismatch for $($artifact.artifact_name)"
    }

    if ($artifact.artifact_kind -ne "checksums") {
        if (-not $ChecksumMap.ContainsKey($artifact.artifact_name)) {
            throw "Checksum entry missing for $($artifact.artifact_name)"
        }

        if ($ChecksumMap[$artifact.artifact_name] -ne $actualHash) {
            throw "Checksum mismatch for $($artifact.artifact_name)"
        }
    }
}

Write-Host "Release artifact verification succeeded."
