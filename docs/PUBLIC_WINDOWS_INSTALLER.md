# Public Windows Installer

TUFF-CSE-WinFS P7A defines the public Windows installer package boundary for the v1 RC.

## Target

- Package the release binaries into a public artifact.
- Provide a safe boundary for distribution and preflight checks.
- Keep live installation and live hardware or key-management integrations out of scope.

## What It Does

- Stages `TuffCseWinFsSetup.exe` and `tuff-cse-winfsctl.exe`.
- Carries `README-FIRST.txt`, `LICENSE.rtf`, `PACKAGE_MANIFEST.md`, and a WiX scaffold.
- Produces a portable zip artifact when WiX tooling is unavailable.
- Verifies the fixed point by running `tuff-cse-winfsctl rc-status`.

## What It Does Not Do

- No live driver installation.
- No live service installation.
- No signing step in this phase.
- No KMS, HSM, CloudKMS, PKCS#11, TPM live API, or CSE crypto I/O.

## Preflight

1. Build release binaries.
2. Confirm `tuff-cse-winfsctl rc-status`.
3. Confirm installer dry-run.
4. Confirm installer verify.

## Public Artifact

The public artifact is a package boundary only. It is safe to share because it contains no runtime secrets and no installation side effects.

For the P7B public release bundle, this package is wrapped with a manifest, SHA256 checksum report, and draft release notes. The bundle still does not publish a GitHub Release.
