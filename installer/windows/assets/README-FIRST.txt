TUFF-CSE-WinFS Public Windows Installer Package

Before running anything:

1. Open a Windows Administrator shell.
2. Run `tuff-cse-winfsctl rc-status` and confirm the v1 RC fixed point.
3. Run `TuffCseWinFsSetup -- install --policy examples/cse-install-policy.example.json --dry-run`.
4. Run `TuffCseWinFsSetup -- verify --policy examples/cse-install-policy.example.json`.
5. Use this package only as a public release artifact boundary.

This package does not perform live driver installation, service installation, signing, KMS/HSM/CloudKMS/PKCS#11 integration, TPM live API use, or CSE crypto I/O.

