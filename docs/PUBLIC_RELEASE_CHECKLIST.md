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

## Prohibited Checks

- No live driver installation.
- No live service installation.
- No signing step.
- No KMS/HSM/CloudKMS/PKCS#11 live integration.
- No TPM live API use.
- No CSE crypto I/O.
- No GitHub Release publish.

## Release Notes

- The artifact is a packaging boundary, not an installation boundary.
- The artifact is intended for public distribution of the v1 RC binaries and docs.
- The release bundle is a draft release boundary only.
