# Public Release Checklist

Use this checklist before publishing the Windows installer artifact.

## Required Checks

- `tuff-cse-winfsctl rc-status` passes.
- `TuffCseWinFsSetup -- install --dry-run` passes.
- `TuffCseWinFsSetup -- verify --policy examples/cse-install-policy.example.json` passes.
- The portable artifact zip is produced.
- The package manifest contains only the public package boundary contents.
- The release manifest and SHA256 checksum report are produced.
- The public release artifact bundle verifies successfully.
- The RC tag follows `v1.0.0-rcN`.
- Run the draft release workflow once with `validate_only=true` to verify the bundle before creating the release.
- The draft release input validates successfully.
- The draft release contains only the public installer zip, manifest, checksum report, and draft release notes.
- The draft release remains unpublished.
- The read-only P7G verifier confirms the remote tag target, release metadata, exact assets, source artifact byte identity, manifest, checksums, secret scan, and fixed RC1 metadata hash.
- The P7G evidence JSON validates against `release/V1_RC_DRAFT_RELEASE_EVIDENCE.schema.json`.
- The P7H verifier confirms the fine-grained read credential, repository restriction, release asset reads, source artifact reads, and byte identity without recording token material.
- The P7H evidence JSON validates against `release/P7H_DRAFT_READ_CREDENTIAL_EVIDENCE.schema.json`.

## Prohibited Checks

- No live driver installation.
- No live service installation.
- No signing step.
- No KMS/HSM/CloudKMS/PKCS#11 live integration.
- No TPM live API use.
- No CSE crypto I/O.
- No GitHub Release publish.
- No tag overwrite.
- No force tag.
- No mutation of an existing tag, draft release, or release asset during evidence verification.

## Release Notes

- The artifact is a packaging boundary, not an installation boundary.
- The artifact is intended for public distribution of the v1 RC binaries and docs.
- The release bundle is a draft release boundary only.
- P7C only adds the RC tag candidate and draft release asset boundary.
