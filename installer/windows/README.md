# Public Windows Installer Package Boundary

This directory holds the public packaging boundary for TUFF-CSE-WinFS v1 RC.

## Scope

- Stage the release binaries into a distributable package.
- Provide a portable zip artifact for public release.
- Keep a WiX scaffold in-tree for future MSI packaging work.
- Preserve the RC fixed point exposed by `tuff-cse-winfsctl rc-status`.

## Non-Goals

- No live driver installation.
- No live service installation.
- No signing step in this boundary.
- No KMS, HSM, CloudKMS, PKCS#11, TPM live API, or CSE crypto I/O.

## Package Contents

- `TuffCseWinFsSetup.exe`
- `tuff-cse-winfsctl.exe`
- `README-FIRST.txt`
- `LICENSE.rtf`
- `PACKAGE_MANIFEST.md`
- `TUFF-CSE-WinFS.wxs`

## Build Entry Point

Run `installer/windows/build-installer.ps1` from a Windows shell after the release binaries have been built.

