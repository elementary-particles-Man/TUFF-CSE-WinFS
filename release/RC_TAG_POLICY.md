# RC Tag Policy

TUFF-CSE-WinFS P7C fixes the RC tag boundary before any GitHub Release draft is created.

## Tag Format

- RC tags must use the form `v1.0.0-rcN`.
- `N` must be a positive integer.
- The initial candidate is `v1.0.0-rc1`.

## Tag Scope

- The tag target commit must be the P7C `main` head that was fixed for the draft release boundary.
- Tag creation is limited to a manual release workflow or an explicit release script boundary.
- Existing tags must never be overwritten.
- Force push and force tag behavior are prohibited.

## Release Boundary

- The tag is only a release candidate marker.
- It does not publish a GitHub Release.
- It does not add driver installation, signing, service installation, CSE crypto I/O, TPM live API use, or live KMS/HSM/CloudKMS/PKCS#11 integration.
