# Public Release Notes Template

## Release Line

- v1 RC completed boundary
- P7A public Windows installer package boundary
- P7B public release artifact checksum and draft-release boundary
- P7C RC tag and draft GitHub Release asset boundary

## Included Artifacts

- Portable Windows installer zip
- Release manifest
- SHA256 checksum report
- Draft release notes

## Verification Order

1. `tuff-cse-winfsctl rc-status`
2. `TuffCseWinFsSetup -- install --dry-run`
3. `TuffCseWinFsSetup -- verify --policy examples/cse-install-policy.example.json`
4. `release/build-release-manifest.ps1`
5. `release/verify-release-artifacts.ps1`
6. `release/verify-draft-release-inputs.ps1`
7. `release/create-draft-github-release.ps1`

## Deferred After v1 RC

- Live driver install
- `pnputil` execution
- Driver signing
- Live service install
- Live KMS/HSM/CloudKMS/PKCS#11 integration
- TPM live API use
- Actual CSE crypto I/O
- GitHub Release publication
