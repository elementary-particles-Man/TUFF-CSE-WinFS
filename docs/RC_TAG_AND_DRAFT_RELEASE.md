# RC Tag and Draft Release

P7C connects the fixed RC tag candidate to a draft GitHub Release asset boundary.

## Required Order

1. Run `tuff-cse-winfsctl rc-status`.
2. Verify the release manifest and checksum report with `release/verify-release-artifacts.ps1`.
3. Verify the draft release input with `release/verify-draft-release-inputs.ps1`.
4. Create the draft release with `release/create-draft-github-release.ps1`.

## Tag Rule

- RC tags must use `v1.0.0-rcN`.
- The initial candidate is `v1.0.0-rc1`.
- The tag target commit is the P7C `main` head.

## Asset Boundary

Only these assets may be attached to the draft release:

- Public Windows installer zip
- Release manifest JSON
- SHA256 checksum report
- Draft release notes

## Deferred Work

- GitHub Release publication
- Live driver install
- `pnputil`
- Driver signing
- Live service install
- CSE crypto I/O
- TPM live API
- KMS/HSM/CloudKMS/PKCS#11 live integration
