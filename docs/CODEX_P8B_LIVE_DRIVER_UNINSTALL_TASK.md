# CODEX Task — P8B Explicit Windows Driver Uninstall Boundary

## Base

- Repository: `elementary-particles-Man/TUFF-CSE-WinFS`
- Base branch: `main`
- Base commit: `d9bf34e83f98fc74bee1226965479015c538f61b`
- Create branch: `feature/p8b-live-driver-uninstall-boundary`

## Goal

Implement the explicit Windows driver-package uninstall lifecycle that follows P8A. The implementation must remain non-mutating unless the caller supplies a dedicated live-uninstall flag.

## Required implementation

1. Extend `TuffCseWinFsSetup uninstall` with:
   - `--driver-package <PATH>`
   - `--live-driver-uninstall`
   - `--live-driver-uninstall` must require `--driver-package`.
   - Existing `--force` must not itself trigger live driver removal.
   - Without `--live-driver-uninstall`, preserve the current non-mutating uninstall behavior.

2. Add a pure uninstall-plan boundary:
   - Validate the driver package using the existing package model.
   - Require `DriverPackageState::DistributionCandidate` (INF/SYS/CAT).
   - Canonicalize the INF path.
   - Represent the plan and result explicitly.

3. Windows live execution:
   - Use the Windows `DiUninstallDriverW` API with the fully-qualified INF path.
   - Use `Flags = 0`.
   - Capture `NeedReboot`.
   - Return distinct results for success, success-with-reboot-required, and error.
   - Include the Windows error code in failures.
   - Do not auto-reboot.
   - Do not call the API outside Windows; fail closed there.

4. Scope exclusions:
   - No driver install execution.
   - No service install/remove.
   - No device disable/remove.
   - No data unsealing.
   - No management-directory deletion.
   - No CSE crypto I/O.
   - No TPM/KMS/HSM integration.
   - No RC1/RC2/tag/asset/publish-state mutation.

5. Tests:
   - Distribution-candidate package builds an uninstall plan with the canonical INF path.
   - Missing SYS or CAT is rejected before OS execution.
   - Non-Windows live uninstall fails closed.
   - CLI rejects `--live-driver-uninstall` without `--driver-package`.
   - CLI without the live flag remains non-mutating.
   - Reboot-required result is represented without initiating reboot.
   - Existing P6Z/P7/P8A tests remain green.
   - No test or CI workflow may execute a real install or uninstall.

6. Documentation/constants:
   - Add P8B phase/boundary constants.
   - Add a concise P8B section to the detailed design/README where existing phase boundaries are documented.
   - Preserve the P6Z fixed-point meaning while explicitly separating P8A/P8B post-RC live lifecycle paths.

## Implementation constraints

- Prefer a target-specific Windows dependency (`windows-sys`/equivalent) or a minimal correct FFI binding. Keep non-Windows builds clean.
- Do not parse localized `pnputil` text to discover `oem#.inf`.
- Do not introduce temporary diagnostic workflows into the final tree.
- Do not claim live validation; no real driver uninstall is to be performed in CI or during this task.

## Required verification

Run and fix until all pass:

```text
cargo fmt --check
cargo test --all-targets
```

Then push the branch, open a PR against `main`, and wait for:

```text
CI
Windows Installer Artifact
Public Release Artifact
```

Report branch, commits, PR number, workflow run IDs/conclusions, and final git status. Do not merge until all three checks are green.
