# Public Windows Installer Package Manifest

## Included Files

- `TuffCseWinFsSetup.exe`
- `tuff-cse-winfsctl.exe`
- `README-FIRST.txt`
- `LICENSE.rtf`
- `PACKAGE_MANIFEST.md`
- `TUFF-CSE-WinFS.wxs`

## Boundary Notes

- The package is a public release artifact boundary, not a live installation path.
- The package may be zipped for distribution when WiX tooling is unavailable.
- The package does not perform driver installation, signing, or service installation.
- The package does not add live KMS, HSM, CloudKMS, PKCS#11, TPM, or CSE I/O integration.
- The outer P7B release bundle adds the release manifest, checksum report, and draft release notes.

## Verification Notes

- Confirm `tuff-cse-winfsctl rc-status` before packaging.
- Confirm `TuffCseWinFsSetup -- install --dry-run` before packaging.
- Confirm `TuffCseWinFsSetup -- verify --policy <policy>` before packaging.
