[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Repository,
    [Parameter(Mandatory = $true)]
    [string]$TagName,
    [Parameter(Mandatory = $true)]
    [string]$ReleaseName,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedTargetCommitish,
    [Parameter(Mandatory = $true)]
    [long]$ArtifactRunId,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedRc1MetadataSha256,
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory
)

$ErrorActionPreference = "Stop"
$WorkflowMainCommit = "a408ec1dbbceedf1fc3a41be769c431a78ebef6e"
$ValidateOnlyWorkflowRunId = 29280376557
$CreateWorkflowRunId = 29280420925
$ExpectedRc2ReleaseId = 353395540
$ExpectedRc1ReleaseId = 350514171
$ExpectedAssets = [ordered]@{
    "TUFF-CSE-WinFS-08d0d25-public-windows-installer.zip" = 1307789
    "V1_RC_ARTIFACT_MANIFEST.json" = 1093
    "V1_RC_CHECKSUMS.sha256" = 553
    "V1_RC_RELEASE_NOTES.md" = 1095
}
$SecretPatterns = @(
    '-----BEGIN ([A-Z ]+ )?PRIVATE KEY-----',
    'github_pat_[A-Za-z0-9_]{20,}',
    'gh[pousr]_[A-Za-z0-9]{20,}',
    'AKIA[0-9A-Z]{16}',
    'ASIA[0-9A-Z]{16}'
)

function Assert-True {
    param(
        [bool]$Condition,
        [string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Invoke-Checked {
    param(
        [string]$Command,
        [string[]]$CommandArgs
    )

    $output = & $Command @CommandArgs
    if ($LASTEXITCODE -ne 0) {
        throw "$Command $($CommandArgs -join ' ') failed."
    }
    return $output
}

function Get-Sha256Hex {
    param([string]$Path)

    return (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLowerInvariant()
}

function Get-TextSha256Hex {
    param([string]$Text)

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $hash = [System.Security.Cryptography.SHA256]::HashData($bytes)
    return [System.Convert]::ToHexString($hash).ToLowerInvariant()
}

function ConvertFrom-RestRelease {
    param([object]$RestRelease)

    return [ordered]@{
        assets = @($RestRelease.assets | ForEach-Object {
            [ordered]@{
                apiUrl = $_.url
                contentType = $_.content_type
                createdAt = $_.created_at
                downloadCount = [long]$_.download_count
                id = $_.node_id
                label = $_.label
                name = $_.name
                size = [long]$_.size
                state = $_.state
                updatedAt = $_.updated_at
                url = $_.browser_download_url
            }
        })
        isDraft = [bool]$RestRelease.draft
        isPrerelease = [bool]$RestRelease.prerelease
        publishedAt = $RestRelease.published_at
        tagName = $RestRelease.tag_name
        targetCommitish = $RestRelease.target_commitish
        name = $RestRelease.name
        url = $RestRelease.html_url
    }
}

function Get-FixedRelease {
    param(
        [long]$ReleaseId,
        [string]$ExpectedTag
    )

    $restJson = (Invoke-Checked -Command "gh" -CommandArgs @(
        "api", "repos/$Repository/releases/$ReleaseId"
    )) -join "`n"
    $restRelease = $restJson | ConvertFrom-Json
    Assert-True ([long]$restRelease.id -eq $ReleaseId) "Release ID mismatch."
    Assert-True ($restRelease.tag_name -eq $ExpectedTag) "Release tag mismatch."
    return [ordered]@{
        rest = $restRelease
        normalized = ConvertFrom-RestRelease -RestRelease $restRelease
    }
}

function Save-ReleaseAsset {
    param(
        [string]$ApiUrl,
        [string]$Path
    )

    $headers = @{
        Accept = "application/octet-stream"
        Authorization = "Bearer $env:GH_TOKEN"
        "X-GitHub-Api-Version" = "2022-11-28"
    }
    Invoke-WebRequest -Uri $ApiUrl -Headers $headers -OutFile $Path
}

function Test-FileByteIdentity {
    param(
        [string]$LeftPath,
        [string]$RightPath
    )

    $left = [System.IO.File]::OpenRead($LeftPath)
    $right = [System.IO.File]::OpenRead($RightPath)
    try {
        if ($left.Length -ne $right.Length) {
            return $false
        }

        $leftBuffer = [byte[]]::new(81920)
        $rightBuffer = [byte[]]::new(81920)
        while (($leftCount = $left.Read($leftBuffer, 0, $leftBuffer.Length)) -gt 0) {
            $rightCount = $right.Read($rightBuffer, 0, $rightBuffer.Length)
            if ($leftCount -ne $rightCount) {
                return $false
            }
            for ($index = 0; $index -lt $leftCount; $index++) {
                if ($leftBuffer[$index] -ne $rightBuffer[$index]) {
                    return $false
                }
            }
        }
        return $right.ReadByte() -eq -1
    }
    finally {
        $left.Dispose()
        $right.Dispose()
    }
}

function Assert-ExpectedFiles {
    param([string]$Directory)

    $actualNames = @(Get-ChildItem -Path $Directory -File | ForEach-Object Name | Sort-Object)
    $expectedNames = @($ExpectedAssets.Keys | Sort-Object)
    Assert-True ($actualNames.Count -eq $expectedNames.Count) "Unexpected file count in $Directory."
    Assert-True (($actualNames -join "`n") -eq ($expectedNames -join "`n")) "Unexpected files in $Directory."

    foreach ($name in $expectedNames) {
        $path = Join-Path $Directory $name
        Assert-True ((Get-Item -Path $path).Length -eq [long]$ExpectedAssets[$name]) "Unexpected size for $name."
    }
}

function Read-ChecksumMap {
    param([string]$Path)

    $map = @{}
    foreach ($line in Get-Content -Path $Path) {
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith("#")) {
            continue
        }
        if ($line -notmatch '^SHA256 \((.+)\) = ([0-9A-Fa-f]{64})$') {
            throw "Invalid checksum line."
        }
        $map[$matches[1]] = $matches[2].ToLowerInvariant()
    }
    return $map
}

function Assert-Checksums {
    param([string]$Directory)

    $checksumPath = Join-Path $Directory "V1_RC_CHECKSUMS.sha256"
    $map = Read-ChecksumMap -Path $checksumPath
    $expectedEntries = @(
        "TUFF-CSE-WinFS-08d0d25-public-windows-installer.zip",
        "V1_RC_ARTIFACT_MANIFEST.json",
        "V1_RC_RELEASE_NOTES.md"
    ) | Sort-Object
    $actualEntries = @($map.Keys | Sort-Object)
    Assert-True (($actualEntries -join "`n") -eq ($expectedEntries -join "`n")) "Unexpected checksum entries."

    foreach ($name in $expectedEntries) {
        $actualHash = Get-Sha256Hex -Path (Join-Path $Directory $name)
        Assert-True ($map[$name] -eq $actualHash) "Checksum mismatch for $name."
    }
}

function Assert-Manifest {
    param(
        [string]$Directory,
        [string]$ExpectedCommit
    )

    $manifestPath = Join-Path $Directory "V1_RC_ARTIFACT_MANIFEST.json"
    $manifest = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json
    Assert-True ($manifest.artifacts.Count -ge 1) "Manifest does not contain artifacts."
    foreach ($artifact in $manifest.artifacts) {
        Assert-True ($artifact.source_commit -eq $ExpectedCommit) "Manifest source_commit mismatch."
        Assert-True ($artifact.build_workflow -eq "public-release-artifact") "Manifest build_workflow mismatch."
        $assetPath = Join-Path $Directory $artifact.artifact_name
        Assert-True (Test-Path -Path $assetPath -PathType Leaf) "Manifest asset is missing."
        Assert-True ((Get-Item -Path $assetPath).Length -eq [long]$artifact.size_bytes) "Manifest asset size mismatch."
        Assert-True ((Get-Sha256Hex -Path $assetPath) -eq $artifact.sha256.ToLowerInvariant()) "Manifest asset hash mismatch."
    }
}

function Assert-SecretScanClean {
    param(
        [string[]]$Files,
        [string]$ZipPath,
        [string]$ExtractDirectory
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        foreach ($entry in $archive.Entries) {
            Assert-True (-not $entry.FullName.StartsWith("/")) "Unsafe archive path."
            Assert-True ($entry.FullName -notmatch '(^|/)\.\.(/|$)') "Unsafe archive path."
            Assert-True ($entry.FullName -notmatch '(?i)(^|/)\.env($|\.)|\.(pem|key|pfx|p12|jks|keystore)$') "Forbidden archive entry."
        }
    }
    finally {
        $archive.Dispose()
    }

    Expand-Archive -Path $ZipPath -DestinationPath $ExtractDirectory
    $scanFiles = @($Files) + @(Get-ChildItem -Path $ExtractDirectory -File -Recurse | ForEach-Object FullName)
    foreach ($path in $scanFiles) {
        $bytes = [System.IO.File]::ReadAllBytes($path)
        $text = [System.Text.Encoding]::UTF8.GetString($bytes)
        foreach ($pattern in $SecretPatterns) {
            Assert-True ($text -notmatch $pattern) "Secret or key material signature detected."
        }
    }
}

function Get-AssetEvidence {
    param([string]$Directory)

    return @($ExpectedAssets.Keys | Sort-Object | ForEach-Object {
        $path = Join-Path $Directory $_
        [ordered]@{
            name = $_
            size = [long](Get-Item -Path $path).Length
            sha256 = Get-Sha256Hex -Path $path
        }
    })
}

function Write-HashReport {
    param(
        [object[]]$Assets,
        [string]$Path
    )

    $lines = @($Assets | ForEach-Object { "SHA256 ($($_.name)) = $($_.sha256)" })
    Set-Content -Path $Path -Value $lines -Encoding utf8
}

Assert-True ($Repository -match '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') "Invalid repository."
Assert-True ($TagName -match '^v1\.0\.0-rc[1-9][0-9]*$') "Invalid RC tag."
Assert-True ($ExpectedTargetCommitish -match '^[0-9a-f]{40}$') "Invalid target commit."
Assert-True ($ExpectedRc1MetadataSha256 -match '^[0-9a-f]{64}$') "Invalid RC1 metadata hash."

$tagLines = @(Invoke-Checked -Command "git" -CommandArgs @("ls-remote", "--tags", "origin", "refs/tags/$TagName", "refs/tags/$TagName^{}"))
Assert-True ($tagLines.Count -ge 1) "Remote tag does not exist."
$peeledLine = @($tagLines | Where-Object { $_ -match '\^\{\}$' } | Select-Object -First 1)
$tagLine = if ($peeledLine.Count -eq 1) { $peeledLine[0] } else { $tagLines[0] }
$tagTarget = ($tagLine -split "\s+")[0].ToLowerInvariant()
Assert-True ($tagTarget -eq $ExpectedTargetCommitish) "Remote tag target mismatch."

$fixedRc2 = Get-FixedRelease -ReleaseId $ExpectedRc2ReleaseId -ExpectedTag $TagName
$release = $fixedRc2.normalized
Assert-True ($release.tagName -eq $TagName) "Release tag mismatch."
Assert-True ($release.name -eq $ReleaseName) "Release name mismatch."
Assert-True ($release.targetCommitish -eq $ExpectedTargetCommitish) "Release target mismatch."
Assert-True ($release.isDraft -eq $true) "Release must remain draft."
Assert-True ($release.isPrerelease -eq $true) "Release must remain prerelease."
Assert-True ($null -eq $release.publishedAt) "Release must remain unpublished."
Assert-True ($release.assets.Count -eq $ExpectedAssets.Count) "Unexpected release asset count."

$releaseAssetNames = @($release.assets | ForEach-Object name | Sort-Object)
$expectedAssetNames = @($ExpectedAssets.Keys | Sort-Object)
Assert-True (($releaseAssetNames -join "`n") -eq ($expectedAssetNames -join "`n")) "Unexpected release assets."
foreach ($asset in $release.assets) {
    Assert-True ([long]$asset.size -eq [long]$ExpectedAssets[$asset.name]) "Unexpected release asset size."
}

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) "tuff-cse-winfs-p7g-$([guid]::NewGuid().ToString('N'))"
$sourceDirectory = Join-Path $temporaryRoot "source"
$releaseDirectory = Join-Path $temporaryRoot "release"
$extractDirectory = Join-Path $temporaryRoot "extracted"
New-Item -ItemType Directory -Path $sourceDirectory, $releaseDirectory, $extractDirectory | Out-Null

try {
    Invoke-Checked -Command "gh" -CommandArgs @(
        "run", "download", "$ArtifactRunId", "--repo", $Repository,
        "--name", "public-release-artifact-bundle", "--dir", $sourceDirectory
    ) | Out-Null
    foreach ($asset in $fixedRc2.rest.assets) {
        Assert-True ($ExpectedAssets.Contains($asset.name)) "Unexpected release asset."
        Save-ReleaseAsset -ApiUrl $asset.url -Path (Join-Path $releaseDirectory $asset.name)
    }

    Assert-ExpectedFiles -Directory $sourceDirectory
    Assert-ExpectedFiles -Directory $releaseDirectory
    Assert-Checksums -Directory $sourceDirectory
    Assert-Checksums -Directory $releaseDirectory
    Assert-Manifest -Directory $sourceDirectory -ExpectedCommit $ExpectedTargetCommitish
    Assert-Manifest -Directory $releaseDirectory -ExpectedCommit $ExpectedTargetCommitish

    foreach ($name in $ExpectedAssets.Keys) {
        $sourcePath = Join-Path $sourceDirectory $name
        $releasePath = Join-Path $releaseDirectory $name
        Assert-True ((Get-Sha256Hex -Path $sourcePath) -eq (Get-Sha256Hex -Path $releasePath)) "Asset SHA256 mismatch."
        Assert-True (Test-FileByteIdentity -LeftPath $sourcePath -RightPath $releasePath) "Asset byte identity mismatch."
    }

    $releaseFiles = @($ExpectedAssets.Keys | ForEach-Object { Join-Path $releaseDirectory $_ })
    Assert-SecretScanClean `
        -Files $releaseFiles `
        -ZipPath (Join-Path $releaseDirectory "TUFF-CSE-WinFS-08d0d25-public-windows-installer.zip") `
        -ExtractDirectory $extractDirectory

    $fixedRc1 = Get-FixedRelease -ReleaseId $ExpectedRc1ReleaseId -ExpectedTag "v1.0.0-rc1"
    $rc1ForHash = [ordered]@{
        assets = $fixedRc1.normalized.assets
        isDraft = $fixedRc1.normalized.isDraft
        isPrerelease = $fixedRc1.normalized.isPrerelease
        publishedAt = $fixedRc1.normalized.publishedAt
        tagName = $fixedRc1.normalized.tagName
        targetCommitish = $fixedRc1.normalized.targetCommitish
    }
    $rc1Json = $rc1ForHash | ConvertTo-Json -Depth 6 -Compress
    $rc1Hash = Get-TextSha256Hex -Text ($rc1Json + "`n")
    Assert-True ($rc1Hash -eq $ExpectedRc1MetadataSha256) "RC1 metadata SHA256 mismatch."

    $releaseEvidence = Get-AssetEvidence -Directory $releaseDirectory
    $sourceEvidence = Get-AssetEvidence -Directory $sourceDirectory
    $verificationRunId = if ($env:GITHUB_RUN_ID -match '^[1-9][0-9]*$') { [long]$env:GITHUB_RUN_ID } else { $null }
    $evidence = [ordered]@{
        schema_version = "2026-07-p7g"
        repository = $Repository
        tag_name = $TagName
        tag_target_commit = $tagTarget
        release_name = $release.name
        release_target_commitish = $release.targetCommitish
        is_draft = [bool]$release.isDraft
        is_prerelease = [bool]$release.isPrerelease
        published_at = $release.publishedAt
        workflow_main_commit = $WorkflowMainCommit
        source_main_commit = $ExpectedTargetCommitish
        artifact_workflow_run_id = [long]$ArtifactRunId
        validate_only_workflow_run_id = [long]$ValidateOnlyWorkflowRunId
        create_workflow_run_id = [long]$CreateWorkflowRunId
        verification_workflow_run_id = $verificationRunId
        assets = $releaseEvidence
        source_artifact_assets = $sourceEvidence
        byte_identity_verified = $true
        manifest_verified = $true
        checksums_verified = $true
        secret_scan_clean = $true
        rc1_metadata_sha256 = $rc1Hash
        generated_at_utc = [DateTimeOffset]::UtcNow.ToString("o")
    }

    New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
    $evidencePath = Join-Path $OutputDirectory "V1_RC2_DRAFT_RELEASE_EVIDENCE.json"
    $releaseHashPath = Join-Path $OutputDirectory "V1_RC2_RELEASE_ASSET_SHA256.txt"
    $sourceHashPath = Join-Path $OutputDirectory "V1_RC2_SOURCE_ARTIFACT_SHA256.txt"
    $evidenceJson = $evidence | ConvertTo-Json -Depth 8
    Set-Content -Path $evidencePath -Value $evidenceJson -Encoding utf8
    Write-HashReport -Assets $releaseEvidence -Path $releaseHashPath
    Write-HashReport -Assets $sourceEvidence -Path $sourceHashPath

    $schemaPath = Join-Path $PSScriptRoot "V1_RC_DRAFT_RELEASE_EVIDENCE.schema.json"
    Assert-True ($evidenceJson | Test-Json -SchemaFile $schemaPath) "Evidence JSON does not match the schema."
    Write-Host "Existing draft release verification succeeded."
}
finally {
    if (Test-Path -Path $temporaryRoot) {
        Remove-Item -Path $temporaryRoot -Recurse -Force
    }
}
