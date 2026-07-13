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
    [long]$Rc1ReleaseId,
    [Parameter(Mandatory = $true)]
    [long]$Rc2ReleaseId,
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory
)

$ErrorActionPreference = "Stop"
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

function Assert-GhTokenPrefix {
    Assert-True (-not [string]::IsNullOrWhiteSpace($env:GH_TOKEN)) "GH_TOKEN is required."
    Assert-True ($env:GH_TOKEN.StartsWith("github_pat_")) "GH_TOKEN must begin with github_pat_."
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

function Get-NormalizedReleaseMetadata {
    param([object]$NormalizedRelease)

    return [ordered]@{
        assets = $NormalizedRelease.assets
        isDraft = $NormalizedRelease.isDraft
        isPrerelease = $NormalizedRelease.isPrerelease
        publishedAt = $NormalizedRelease.publishedAt
        tagName = $NormalizedRelease.tagName
        targetCommitish = $NormalizedRelease.targetCommitish
    }
}

function Get-ReleaseMetadataSha256 {
    param([object]$NormalizedRelease)

    $json = (Get-NormalizedReleaseMetadata -NormalizedRelease $NormalizedRelease) | ConvertTo-Json -Depth 6 -Compress
    return Get-TextSha256Hex -Text ($json + "`n")
}

Assert-True ($Repository -match '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') "Invalid repository."
Assert-True ($TagName -match '^v1\.0\.0-rc[1-9][0-9]*$') "Invalid RC tag."
Assert-True ($ExpectedTargetCommitish -match '^[0-9a-f]{40}$') "Invalid target commit."
Assert-True ($ExpectedRc1MetadataSha256 -match '^[0-9a-f]{64}$') "Invalid RC1 metadata hash."
Assert-GhTokenPrefix

$userOutput = Invoke-Checked -Command "gh" -CommandArgs @("api", "user")
Assert-True (-not [string]::IsNullOrWhiteSpace(($userOutput -join "`n"))) "GET /user failed."

$repositoryOutput = Invoke-Checked -Command "gh" -CommandArgs @("api", "repos/$Repository")
$repository = ($repositoryOutput -join "`n") | ConvertFrom-Json
Assert-True ($repository.full_name -eq $Repository) "Repository access verification failed."

$tagLines = @(Invoke-Checked -Command "git" -CommandArgs @("ls-remote", "--tags", "origin", "refs/tags/$TagName", "refs/tags/$TagName^{}"))
Assert-True ($tagLines.Count -ge 1) "Remote tag does not exist."
$peeledLine = @($tagLines | Where-Object { $_ -match '\^\{\}$' } | Select-Object -First 1)
$tagLine = if ($peeledLine.Count -eq 1) { $peeledLine[0] } else { $tagLines[0] }
$tagTarget = ($tagLine -split "\s+")[0].ToLowerInvariant()
Assert-True ($tagTarget -eq $ExpectedTargetCommitish) "Remote tag target mismatch."

$fixedRc1 = Get-FixedRelease -ReleaseId $Rc1ReleaseId -ExpectedTag "v1.0.0-rc1"
$fixedRc2 = Get-FixedRelease -ReleaseId $Rc2ReleaseId -ExpectedTag $TagName

$rc1 = $fixedRc1.normalized
$rc2 = $fixedRc2.normalized
Assert-True ($rc1.tagName -eq "v1.0.0-rc1") "RC1 tag mismatch."
Assert-True ($rc1.name -eq "TUFF-CSE-WinFS v1.0.0-rc1") "RC1 release name mismatch."
Assert-True ($rc1.targetCommitish -eq "9cecb2fe09789176491d82e917b0cd4d694e68f6") "RC1 target mismatch."
Assert-True ($rc1.isDraft -eq $true) "RC1 must remain draft."
Assert-True ($rc1.isPrerelease -eq $true) "RC1 must remain prerelease."
Assert-True ($null -eq $rc1.publishedAt) "RC1 must remain unpublished."

Assert-True ($rc2.tagName -eq $TagName) "RC2 tag mismatch."
Assert-True ($rc2.name -eq $ReleaseName) "RC2 release name mismatch."
Assert-True ($rc2.targetCommitish -eq $ExpectedTargetCommitish) "RC2 target mismatch."
Assert-True ($rc2.isDraft -eq $true) "RC2 must remain draft."
Assert-True ($rc2.isPrerelease -eq $true) "RC2 must remain prerelease."
Assert-True ($null -eq $rc2.publishedAt) "RC2 must remain unpublished."
Assert-True ($rc2.assets.Count -eq $ExpectedAssets.Count) "Unexpected release asset count."

$releaseAssetNames = @($rc2.assets | ForEach-Object name | Sort-Object)
$expectedAssetNames = @($ExpectedAssets.Keys | Sort-Object)
Assert-True (($releaseAssetNames -join "`n") -eq ($expectedAssetNames -join "`n")) "Unexpected release assets."
foreach ($asset in $rc2.assets) {
    Assert-True ([long]$asset.size -eq [long]$ExpectedAssets[$asset.name]) "Unexpected release asset size."
}

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) "tuff-cse-winfs-p7h-$([guid]::NewGuid().ToString('N'))"
$sourceDirectory = Join-Path $temporaryRoot "source"
$releaseDirectory = Join-Path $temporaryRoot "release"
$extractDirectory = Join-Path $temporaryRoot "extracted"
New-Item -ItemType Directory -Path $sourceDirectory, $releaseDirectory, $extractDirectory | Out-Null

try {
    Invoke-Checked -Command "gh" -CommandArgs @(
        "run", "download", "$ArtifactRunId", "--repo", $Repository,
        "--name", "public-release-artifact-bundle", "--dir", $sourceDirectory
    ) | Out-Null
    foreach ($asset in $rc2.assets) {
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

    $rc1MetadataSha256 = Get-ReleaseMetadataSha256 -NormalizedRelease $rc1
    $rc2MetadataSha256 = Get-ReleaseMetadataSha256 -NormalizedRelease $rc2
    Assert-True ($rc1MetadataSha256 -eq $ExpectedRc1MetadataSha256) "RC1 metadata SHA256 mismatch."

    $evidence = [ordered]@{
        repository = $Repository
        credential_class = "fine-grained-personal-access-token"
        credential_prefix_verified = $true
        repository_access_verified = $true
        contents_read_verified = $true
        actions_read_verified = $true
        rc1_draft_read_verified = $true
        rc2_draft_read_verified = $true
        release_assets_read_verified = $true
        source_artifact_read_verified = $true
        byte_identity_verified = $true
        rc1_metadata_sha256 = $rc1MetadataSha256
        rc2_metadata_sha256 = $rc2MetadataSha256
        mutation_attempted = $false
        generated_at_utc = [DateTimeOffset]::UtcNow.ToString("o")
    }

    New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
    $evidencePath = Join-Path $OutputDirectory "P7H_DRAFT_READ_CREDENTIAL_EVIDENCE.json"
    $evidenceJson = $evidence | ConvertTo-Json -Depth 8
    Set-Content -Path $evidencePath -Value $evidenceJson -Encoding utf8

    $schemaPath = Join-Path $PSScriptRoot "P7H_DRAFT_READ_CREDENTIAL_EVIDENCE.schema.json"
    Assert-True ($evidenceJson | Test-Json -SchemaFile $schemaPath) "Evidence JSON does not match the schema."
    Assert-True ($evidenceJson -notmatch 'github_pat_|P7G_DRAFT_READ_|P7H_DRAFT_READ_') "Credential marker leaked into evidence."
    Write-Host "Draft read credential verification succeeded."
}
finally {
    if (Test-Path -Path $temporaryRoot) {
        Remove-Item -Path $temporaryRoot -Recurse -Force
    }
}
