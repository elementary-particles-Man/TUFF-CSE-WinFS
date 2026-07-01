# Public Release Artifacts

TUFF-CSE-WinFS P7B public release artifact checksum and draft-release boundary fixes the public release artifact boundary for the v1 RC.
It sits on the v1 RC completed boundary and the P7A public Windows installer package boundary.

## Bundle Layout

The public release bundle is built from the installer artifact and the draft release notes.

- `TUFF-CSE-WinFS-<source_commit>-public-windows-installer.zip`
- `V1_RC_RELEASE_NOTES.md`
- `V1_RC_CHECKSUMS.sha256`
- `V1_RC_ARTIFACT_MANIFEST.json`

## Artifact Kinds

- `portable_zip` for the public Windows installer zip.
- `wix_msi_candidate` for a future MSI candidate boundary.
- `release_notes` for the draft release notes.
- `checksums` for the SHA256 report.

## Verification

1. Run `tuff-cse-winfsctl rc-status`.
2. Run `TuffCseWinFsSetup -- install --dry-run`.
3. Run `TuffCseWinFsSetup -- verify --policy examples/cse-install-policy.example.json`.
4. Run `release/build-release-manifest.ps1`.
5. Run `release/verify-release-artifacts.ps1`.

## Draft Release Boundary

The bundle supports draft release staging only. It does not publish a GitHub Release and it does not add live installation, signing, KMS/HSM, TPM live API, or CSE crypto I/O.

## P7C Draft Release Asset Boundary

P7C connects the RC tag candidate to a draft GitHub Release asset boundary. It uses the verified public release bundle, attaches only the public installer zip, manifest, checksum report, and release notes, and keeps publish disabled.

### Deferred After v1 RC

- Live driver install
- Driver signing
- TPM live API use
- Actual CSE crypto I/O
