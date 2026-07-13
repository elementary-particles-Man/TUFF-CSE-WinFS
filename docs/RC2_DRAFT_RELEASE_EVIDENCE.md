# RC2 Draft Release Evidence

P7G independently verifies the fixed `v1.0.0-rc2` draft release without changing its tag, release metadata, publication state, or assets.

## Fixed Inputs

- RC tag: `v1.0.0-rc2`
- RC tag and release target: `08d0d252857d5140baa355d894e921a6a408318e`
- Release name: `TUFF-CSE-WinFS v1.0.0-rc2`
- Source Public Release Artifact run: `29277061565`
- P7F validate-only run: `29280376557`
- P7F create run: `29280420925`
- P7F workflow main commit: `a408ec1dbbceedf1fc3a41be769c431a78ebef6e`
- Fixed RC1 metadata SHA256: `c210fafa095d58f53f3954f737110f3a442c4ef8ba09ccd8ec47a18c11869d8a`

## Verification

The manual `Verify Draft GitHub Release` workflow has only `contents: read` and `actions: read` permissions. It runs `release/verify-existing-draft-release.ps1`, which:

1. resolves the remote RC2 tag and verifies its target commit;
2. verifies the release name, target, draft, prerelease, unpublished state, and exact four-asset set;
3. downloads the source workflow artifact and release assets into separate temporary directories;
4. verifies names, sizes, SHA256 reports, manifest metadata, and byte identity;
5. scans the bundle and expanded ZIP for private-key and token signatures;
6. recomputes the normalized RC1 metadata hash; and
7. emits schema-validated, machine-readable evidence.

## Evidence Artifact

The workflow uploads `tuff-cse-winfs-v1.0.0-rc2-draft-release-evidence` containing:

- `V1_RC2_DRAFT_RELEASE_EVIDENCE.json`
- `V1_RC2_RELEASE_ASSET_SHA256.txt`
- `V1_RC2_SOURCE_ARTIFACT_SHA256.txt`

The JSON contract is defined by `release/V1_RC_DRAFT_RELEASE_EVIDENCE.schema.json` with schema version `2026-07-p7g`.

## Non-Mutating Boundary

The verifier performs only remote reads, temporary downloads, hashing, comparison, scanning, and evidence generation. It does not change Git refs, GitHub Releases, release assets, installation state, signing state, hardware-backed services, or provider connections.
