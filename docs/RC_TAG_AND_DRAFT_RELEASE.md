# RC Tag and Draft Release

P7C connects the fixed RC tag candidate to a draft GitHub Release asset boundary.
P7E keeps the same draft asset boundary but makes the workflow reproducible by separating the workflow ref from the release target commit.

## Required Order

1. Run `tuff-cse-winfsctl rc-status`.
2. Verify the release manifest and checksum report with `release/verify-release-artifacts.ps1`.
3. Verify the draft release input with `release/verify-draft-release-inputs.ps1`.
4. Create the draft release with `release/create-draft-github-release.ps1`.
5. Use `validate_only=true` first when you only want to verify the bundle and input without creating the release.
6. The create path must fail if the RC tag or release already exists; otherwise GitHub creates the tag at the verified release target while creating the draft.

## Tag Rule

- RC tags must use `v1.0.0-rcN`.
- The initial candidate is `v1.0.0-rc1`.
- The tag target commit is the P7C `main` head.
- The workflow ref is recorded separately from the release target commit.
- The release target is verified independently from the workflow checkout HEAD.
- Validation-only does not require or create the RC tag.
- Draft creation rejects an existing local or remote tag before GitHub creates the new tag at the verified target.

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
