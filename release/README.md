# Release Boundary

This directory holds the public release artifact boundary for TUFF-CSE-WinFS v1 RC.

## Contents

- `V1_RC_RELEASE_NOTES.md`
- `V1_RC_ARTIFACT_MANIFEST.template.json`
- `V1_RC_CHECKSUMS.template.sha256`
- `V1_RC_DRAFT_RELEASE_INPUT.template.json`
- `RC_TAG_POLICY.md`
- `DRAFT_RELEASE_ASSET_POLICY.md`
- `build-release-manifest.ps1`
- `verify-release-artifacts.ps1`
- `verify-draft-release-inputs.ps1`
- `create-draft-github-release.ps1`

## Boundary

- Public artifact packaging only.
- Draft release notes only.
- RC tag naming and manual draft release creation only.
- No GitHub Release publish step.
- No live driver install, service install, signing, KMS/HSM/CloudKMS/PKCS#11 integration, TPM live API, or CSE crypto I/O.

## Flow

1. Build the release binaries.
2. Build the public Windows installer artifact.
3. Generate the release manifest and SHA256 checksums.
4. Verify the public release bundle.
5. Validate the RC tag and draft release input, then create the draft GitHub Release.
