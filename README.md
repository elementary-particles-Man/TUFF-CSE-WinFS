# TUFF-CSE-WinFS v1

TUFF-CSE-WinFS v1 is a specialized security layer for Windows, designed to provide hardware-bound, inline sector-level encryption for local data volumes across multiple filesystems including NTFS, exFAT, FAT32, and FAT.

This project implements a **Confidential Software Environment (CSE)** vault that ensures data stored on local data partitions remains encrypted and inaccessible unless mounted on its uniquely paired host hardware.

## Core Mandate

**"Never let plaintext touch the physical media."**

Unlike traditional volume encryption, TUFF-CSE-WinFS v1 binds the encryption key to the specific combination of:
1.  **Host TPM** (Trusted Platform Module)
2.  **Hardware Identity** (Composite ID from CPU, Board, Storage, etc.)
3.  **Admin-defined Base Key**

## Key Features

-   **Sector-Level Inline Sealing:** Encryption occurs at the logical sector level or CSE block size, preserving sector layout.
-   **Hardware-Bound Security:** Data is cryptographically tied to the host machine and the specific partition identity.
-   **Cross-Filesystem Support:** Supports NTFS, exFAT, FAT32, and FAT on local data volumes.
-   **Background Sealing:** Uses a Bitmap (BTM) and Journal (JRN) to track encryption status, allowing for immediate use while data is sealed in the background.
-   **Volume Filter Driver:** Operates below the filesystem layer to intercept and seal all read/write operations at the volume level.
-   **Maintenance/Recovery Mode:** Built-in commands for `seal-all` and `unseal-all` for system administration and maintenance.
-   **Non-System Focus:** Specifically targets data partitions and external media, excluding boot/system volumes to ensure OS stability.

## Architecture

The project follows a tiered implementation plan:
-   **P0 (Deployment):** Dedicated installer (`TuffCseWinFsSetup.exe`) and signed driver package deployment.
-   **P1 (Kernel Core):** Volume filter driver (`tuffcsewinfs.sys`) for production-grade inline sealing.
-   **P2 (Management & Optimization):** Administrative CUI (`tuff-cse-winfsctl.exe`) and CSE core performance optimization.

### Data Flow
```text
Application
   ↓
Windows I/O Manager
   ↓
Filesystem (NTFS / exFAT / FAT32 / FAT)
   ↓
TUFF-CSE-WinFS Volume Filter (Sector-Level Sealing)
   ↓
Volume / Disk / USB Storage
   ↓
Physical SSD/Media (Encrypted Sectors)
```

## Management & Deployment

-   **Installer:** `TuffCseWinFsSetup.exe` handles automated installation. Inspired by the TUFF-INSTALLER structure and CLI conventions, but operates as a dedicated standalone package for Windows.
-   **Employee Workflow:**
    1.  Deploy the package provided by the System Department.
    2.  Open an Administrator Terminal.
    3.  Copy and paste the command line provided in the official email instructions.
    4.  Copy the one-line completion code and reply to the System Department.
-   **Admin CUI:**
    -   `tuff-cse-winfsctl.exe seal-all`: Enforce encryption across the entire target volume.
    -   `tuff-cse-winfsctl.exe unseal-all`: Remove encryption for maintenance (requires admin authorization).

## Technical Specifications

-   **Encryption Unit:** Matches the Volume Logical Sector Size or CSE block size.
-   **Key Management:** MK (Master Key), TK (Target Key), and PK (Partition Key) bundle, bound via MK-Device.
-   **State Management:** BTM (Bitmap), JRN (Journal), and META files stored in `C:\ProgramData\TUFF-CSE-WinFS\devices\`.

## Current Phase: P2A (Binding Model / Key-Material Boundary)

The project is currently in the **P2A** phase. This stage establishes the logical boundary for hardware and host binding without executing actual cryptographic operations or hardware queries.

### P2A Highlights:
-   **Binding Model:** Defines structures for `BindingPolicy`, `BindingDescriptor`, and `KeyDerivationPlan`.
-   **Strict Separation:** `ManagedPolicy` (for operation authorization) and `BindingPolicy` (for key material constraints) are separated.
-   **No Raw Secrets:** Ensures that raw TPM identities, host UUIDs, device serials, and generated keys are never persisted, displayed, or logged. Only salted fingerprints and descriptor IDs are retained.
-   **Operation Clarity:** Explicitly separates `unlock` (local usage), `export` (re-sealing for external transfer), `eject` (safe removal), `rebind` (ownership boundary transfer), and `recover` (restoring safety boundaries).

## Current Phase: P3B (Recovery Key / Rebind Model Boundary)

The project is currently in the **P3B** phase. This stage defines the contract for volume recovery and ownership transfer (rebind) without executing actual cryptographic restorations or host migrations.

### P3B Highlights:
-   **Recovery Model:** Defines `RecoveryPolicy`, `RecoveryKeyDescriptor`, and `RecoveryPlan`. The `recover` command now generates a recovery plan based on a provided key fingerprint.
-   **Rebind Model:** Defines `RebindPolicy`, `RebindPlan`, and `RebindManifest`. The `rebind` command generates a rebind plan/manifest to prepare for host ownership transfer.
-   **Strict Boundaries:** Separates the *plan* (metadata generation) from the *action* (actual key restoration). P3B focuses entirely on the plan and journal recording.
-   **No Secret Persistence:** Ensures that raw recovery keys and raw host identifiers are never persisted. Only fingerprints and plan IDs are used in manifests and journals.

*Note: P3B focuses on the recovery/rebind contract. It does not implement actual TPM interaction, cryptographic key restoration, rebind descriptor replacement, AD/KMS/HSM/quorum integration (planned for P5/P6).*

### Recovery Plan Example
To generate a recovery plan for a bound volume:
```powershell
cargo run --bin tuff-cse-winfsctl -- recover --volume D: --recovery-key-fp RK-FP-001 --reason LOST_HOST
```

### Rebind Plan Example
To generate a rebind manifest for transfer:
```powershell
cargo run --bin tuff-cse-winfsctl -- rebind --volume D: --new-host-fp HOST-FP-NEW-001 --reason DEVICE_UPGRADE
```

### Recovery Example


To check and recover stale volume states:
```powershell
cargo run --bin tuff-cse-winfsctl -- status --volume D: --recover-stale
```

## Current Phase: P3C (Manual Export/Rebind/Recover State Implementation)

The project is currently in the **P3C** phase. This stage implements manual confirmation-based state transitions for export, rebind, and recover plans.

### P3C Highlights:
-   **Manual Confirmation Flow:** Introduces a formal "Manual Complete" and "Manual Cancel" flow for existing plans. This provides a safety check before a plan is considered finalized.
-   **Plan Lifecycle:** Plans now transition through states: `Planned` -> `ManualConfirmationRequired` -> `ManualConfirmed` -> `Completed` (or `Cancelled`).
-   **Token Hashing:** Manual confirmation tokens are used for validation but are strictly stored as SHA-256 hashes. Raw tokens never touch the disk.
-   **Manual Audit Journal:** Dedicated flow records are stored under `JRN/manual/`, providing a clear audit trail of who finalized a plan and why.
-   **Strict Separation:** Finalizing a plan in P3C does *not* trigger actual data movement, cryptographic restoration, or driver-level changes. It establishes the *management* boundary of completion.

*Note: P3C focuses on manual state management. Local admin approval (P4), AD integration (P5), and Enterprise KMS (P6) are scheduled for later phases.*

### Completing an Export Plan
```powershell
cargo run --bin tuff-cse-winfsctl -- export --volume D: --complete-plan <EXPORT_ID> --confirm CONFIRM-EXPORT-001 --reason MANUAL_HANDOFF_CONFIRMED
```

### Cancelling a Recovery Plan
```powershell
cargo run --bin tuff-cse-winfsctl -- recover --volume D: --cancel-plan <RECO_PLAN_ID> --confirm CONFIRM-CANCEL-001 --reason USER_CANCELLED
```

## P6A (Enterprise Recovery Authority Boundary)

P6A defines the first enterprise recovery boundary. It introduces offline authority, quorum, and recovery-decision metadata for imported or dev-generated enterprise recovery flows. It does **not** connect to live KMS/HSM, PKCS#11, cloud KMS SDKs, TPM APIs, driver I/O, or key-restoration logic.

### P6A Highlights
- `EnterpriseAuthorityPolicy`, `EnterpriseQuorumPolicy`, `EnterpriseRecoveryRequest`, `EnterpriseRecoveryDecision`, and `EnterpriseRecoveryEnforcer` are added as offline metadata and enforcement types.
- `enterprise-authority`, `enterprise-quorum`, and `enterprise-recovery` CLI subcommands import, inspect, and evaluate offline records.
- Enterprise recovery does not bypass P5C domain recovery, P5B domain approval, P4B local approval, or P3C manual confirmation.
- Raw authority material, principals, KMS/HSM secrets, and key material are not persisted, displayed, or journaled.

### CLI Examples
```powershell
cargo run --bin tuff-cse-winfsctl -- enterprise-authority import --policy examples/enterprise-authority-policy.example.json
cargo run --bin tuff-cse-winfsctl -- enterprise-quorum import --policy examples/enterprise-quorum-policy.example.json
cargo run --bin tuff-cse-winfsctl -- enterprise-recovery request --operation recover --volume D:
TUFF_CSE_WINFS_ALLOW_DEV_ENTERPRISE_RECOVERY=1 cargo run --bin tuff-cse-winfsctl -- enterprise-recovery dev-approve --request-id <REQUEST_ID>
```

`TUFF_CSE_WINFS_ALLOW_DEV_ENTERPRISE_RECOVERY=1` is required for the dev approval and deny commands.

## P6B (Enterprise Provider Adapter Boundary)

P6B adds an offline enterprise provider adapter boundary on top of P6A. It models provider policy, attestation summaries, and provider-gated recovery evaluation without connecting to live KMS/HSM, cloud KMS SDKs, PKCS#11, TPM APIs, or driver I/O.

### P6B Highlights
- `EnterpriseProviderPolicy` and `EnterpriseProviderAttestationSummary` are imported as offline metadata only.
- `enterprise-provider` CLI subcommands import, inspect, and evaluate stored provider records.
- Enterprise provider evaluation does not bypass P6A enterprise recovery, P5C domain recovery, P5B domain approval, P4B local approval, or P3C manual confirmation.
- Provider credentials, API keys, client secrets, tokens, private keys, KMS secrets, HSM secrets, and raw TPM material are not persisted, displayed, or journaled.

### Provider CLI Examples
```powershell
cargo run --bin tuff-cse-winfsctl -- enterprise-provider import --policy examples/enterprise-provider-policy.example.json
cargo run --bin tuff-cse-winfsctl -- enterprise-provider import-attestation --attestation examples/enterprise-provider-attestation.example.json
cargo run --bin tuff-cse-winfsctl -- enterprise-provider status --enterprise-provider EP-001
cargo run --bin tuff-cse-winfsctl -- enterprise-provider evaluate --enterprise-provider EP-001 --operation recover --volume D:
```

## Current Phase: P6C (Enterprise Provider Lifecycle Boundary)

P6C adds an offline/imported lifecycle event, revocation, rotation, and attestation renewal boundary on top of P6B. It ensures that revoked, superseded, rotated, or expired enterprise providers fail-closed and cannot pass the recovery enforcer, using signed journals and metadata verification.

### P6C Highlights
- Implements `EnterpriseProviderLifecycleEvent`, `EnterpriseProviderRotationPlan`, `EnterpriseProviderRotationDecision`, and custom debug formats.
- Integrates `EnterpriseProviderLifecycleEnforcer` in the validation sequence to verify provider generation, active lifecycle state, and canonical lifecycle hash consistency.
- Enhances `tuff-cse-winfsctl` CLI with subcommands: `import-event`, `status`, `revoke`, `rotation-plan`, `rotate-complete`, and `renew-attestation`.
- Prevents bypassed evaluations: revoked, superseded, rotated (old generation), or expired providers are strictly rejected.
- Includes lifecycle metadata fields in the P4C signed canonical payload to detect any tampering with active generations or states.
- Assures zero credentials, KMS/HSM secrets, or key material are persisted, logged, or exposed.

### CLI Examples
```powershell
# Import activation event
TUFF_CSE_WINFS_ALLOW_DEV_PROVIDER_LIFECYCLE=1 cargo run --bin tuff-cse-winfsctl -- enterprise-provider lifecycle import-event --event examples/enterprise-provider-lifecycle-event.example.json

# Check lifecycle status
TUFF_CSE_WINFS_ALLOW_DEV_PROVIDER_LIFECYCLE=1 cargo run --bin tuff-cse-winfsctl -- enterprise-provider lifecycle status --enterprise-provider EP-001

# Create rotation plan
TUFF_CSE_WINFS_ALLOW_DEV_PROVIDER_LIFECYCLE=1 cargo run --bin tuff-cse-winfsctl -- enterprise-provider lifecycle rotation-plan --enterprise-provider EP-001 --next-generation 2

# Complete rotation
TUFF_CSE_WINFS_ALLOW_DEV_PROVIDER_LIFECYCLE=1 cargo run --bin tuff-cse-winfsctl -- enterprise-provider lifecycle rotate-complete --rotation-plan PLAN-ROT-EP-001-1781984115

# Revoke provider
TUFF_CSE_WINFS_ALLOW_DEV_PROVIDER_LIFECYCLE=1 cargo run --bin tuff-cse-winfsctl -- enterprise-provider lifecycle revoke --enterprise-provider EP-001 --reason administrative-revocation
```

## Current Phase: P6Z (v1 RC Release Gate)

P6Z freezes the v1 RC boundary at P6C. It does not add live KMS/HSM, Cloud KMS, PKCS#11, key recovery, CSE encrypted I/O, TPM real API, or driver runtime I/O.

### RC Status
```powershell
cargo run --bin tuff-cse-winfsctl -- rc-status
```

### RC Gate Summary
- `cargo fmt --check`
- `cargo test --all-targets`
- Ubuntu and Windows CI
- installer dry-run and verify
- signed journal verification
- secret and forbidden-boundary grep checks

## Current Phase: P7A (Public Windows Installer Package Boundary)

P7A packages the v1 RC into a public Windows release artifact boundary. It stages the release binaries, keeps a WiX scaffold in-tree, and publishes a portable zip artifact when WiX tooling is unavailable.

### Public Installer Entry Points
- [`docs/PUBLIC_WINDOWS_INSTALLER.md`](docs/PUBLIC_WINDOWS_INSTALLER.md)
- [`docs/PUBLIC_RELEASE_CHECKLIST.md`](docs/PUBLIC_RELEASE_CHECKLIST.md)
- [`installer/windows/README.md`](installer/windows/README.md)
- [`installer/windows/build-installer.ps1`](installer/windows/build-installer.ps1)

### Public Installer Boundary
- Package only the release binaries and public docs.
- Keep live driver install, service install, signing, KMS/HSM/CloudKMS/PKCS#11, TPM live API, and CSE crypto I/O out of scope.
- Confirm `rc-status`, install dry-run, and verify before packaging.

## Current Phase: P7B (Public Release Artifact Checksum / Draft Release Boundary)

P7B wraps the P7A installer package in a public release artifact bundle. It adds the release manifest, SHA256 checksums, and draft release notes without publishing a GitHub Release.

### Public Release Entry Points
- [`docs/PUBLIC_RELEASE_ARTIFACTS.md`](docs/PUBLIC_RELEASE_ARTIFACTS.md)
- [`docs/PUBLIC_RELEASE_NOTES_TEMPLATE.md`](docs/PUBLIC_RELEASE_NOTES_TEMPLATE.md)
- [`release/README.md`](release/README.md)
- [`release/build-release-manifest.ps1`](release/build-release-manifest.ps1)
- [`release/verify-release-artifacts.ps1`](release/verify-release-artifacts.ps1)
- [`docs/RC2_DRAFT_RELEASE_EVIDENCE.md`](docs/RC2_DRAFT_RELEASE_EVIDENCE.md)
- [`release/verify-existing-draft-release.ps1`](release/verify-existing-draft-release.ps1)

### Public Release Boundary
- Package the P7A portable zip into a release bundle.
- Generate the release manifest and SHA256 checksum report.
- Keep GitHub Release publication deferred; draft release notes only.
- Keep live driver install, service install, signing, KMS/HSM/CloudKMS/PKCS#11, TPM live API, and CSE crypto I/O out of scope.

## Current Phase: P7C (RC Tag / Draft GitHub Release Asset Boundary)

P7C connects the fixed `v1.0.0-rcN` tag candidate to a draft GitHub Release asset boundary. It keeps the release draft manual and fail-closed, and it does not publish a GitHub Release.
P7E keeps that boundary reproducible by separating the workflow ref from the release target commit and by supporting `validate_only` runs.
P7F proves that flow with the fixed RC2 tag and draft release. P7G adds an independent, read-only evidence workflow that re-verifies the tag, metadata, source artifact, four release assets, manifest, checksums, byte identity, secret scan, and RC1 metadata hash.

### P7C Highlights
- `release/RC_TAG_POLICY.md` fixes the RC tag format to `v1.0.0-rcN`.
- `release/V1_RC_DRAFT_RELEASE_INPUT.template.json` defines the draft release input boundary.
- `release/verify-draft-release-inputs.ps1` validates the draft release asset set and checksum alignment.
- `release/create-draft-github-release.ps1` creates a draft prerelease only and supports validation-only runs.
- `.github/workflows/draft-github-release.yml` is workflow_dispatch-only.
- `.github/workflows/verify-draft-github-release.yml` is workflow_dispatch-only and uses read-only repository and Actions permissions.
- `release/verify-existing-draft-release.ps1` emits schema-validated P7G evidence without changing GitHub state.

### P7C Boundary
- Attach only the public installer zip, release manifest, checksum report, and draft release notes.
- Keep GitHub Release publish deferred.
- Keep existing tags untouched and never use force tag behavior.
- Keep workflow execution ref separate from the release target commit.
- Require validation-only to succeed without a tag, then reject any existing tag or release before a non-force tag push and verified draft creation.
- Bind the release artifact manifest source commit to the verified release target.
- Keep live driver install, service install, signing, KMS/HSM/CloudKMS/PKCS#11, TPM live API, and CSE crypto I/O out of scope.

## Current Phase: P8A (Explicit Windows Driver Install Boundary)

P8A makes live Windows driver installation explicit. The default path remains non-mutating, and `pnputil.exe` runs only when `--live-driver-install` is supplied with a distribution-candidate driver package.

### P8A Highlights
- `src/install.rs` validates the driver package and requires `--driver-package` for live installation.
- `src/driver.rs` builds a fixed `pnputil.exe /add-driver <INF> /install` plan for distribution-candidate packages.
- `tests/p8a_live_driver_install_boundary.rs` keeps the boundary non-mutating in CI.

## Current Phase: P8B (Explicit Windows Driver Uninstall Boundary)

P8B mirrors P8A for uninstall. The default path remains non-mutating, and `DiUninstallDriverW` runs only when `--live-driver-uninstall` is supplied with a distribution-candidate driver package on Windows.

### P8B Highlights
- `src/uninstall.rs` validates the package, builds a pure uninstall plan, and keeps the default path non-mutating.
- `src/driver.rs` canonicalizes the INF path and executes `DiUninstallDriverW` only on Windows.
- `tests/p8b_live_driver_uninstall_boundary.rs` covers plan validation, non-mutating CLI behavior, and the non-Windows fail-closed path.

## Current Phase: P8C (Read-Only Windows Driver State Verification Boundary)

P8C keeps verification read-only. `verify` now queries SCM state for the fixed `tuffcsewinfs` service and compares it against the kernel-driver, demand-start, `System32\drivers\tuffcsewinfs.sys` boundary.

### P8C Highlights
- `src/driver_state.rs` performs read-only SCM queries only and fail-closes on non-Windows.
- `src/verify.rs` reports the read-only driver state query before the legacy `PENDING_DRIVER_PHASE` marker.
- `tests/p8c_read_only_driver_state_verification_boundary.rs` covers the expected path layout and source boundary.

## Current Phase: P4A (Local Policy / Local Admin Approval Boundary)

The project is currently in the **P4A** phase. This stage establishes the model and structural boundary for local administrator approvals.

### P4A Highlights:
-   **Approval Model:** Defines `LocalPolicy`, `LocalApprovalRequest`, and `LocalApprovalDecision` to manage the local approval lifecycle.
-   **Approval Subcommands:** Adds `approval request`, `approval approve`, `approval deny`, and `approval status` to the CLI.
-   **Security Boundary:** Ensures that no raw Windows SIDs, credentials, or authentication tokens are persisted. All principals are managed via salted fingerprints.
-   **Audit Integration:** Approval requests and decisions are recorded in the management store and referenced in the operation journal.
-   **Policy Enforcement Boundary:** Prepares for enforcing local admin approval for sensitive operations like `export`, `rebind`, and `recover`.

*Note: P4A focuses on the logical boundary. Actual Windows SID verification, UAC integration (P4B), and signed audit journals (P4C) are planned for subsequent P4 sub-phases.*

### Requesting an Approval
```powershell
cargo run --bin tuff-cse-winfsctl -- approval request --operation Export --target-plan PLAN-001 --reason MANAGED_EXPORT --principal-fp USER-FP-001
```

### Approving a Request
```powershell
cargo run --bin tuff-cse-winfsctl -- approval approve --approval-id APPR-001 --admin-fp ADMIN-FP-001 --reason APPROVED
```

## CI & Validation

This project uses GitHub Actions to ensure cross-platform compatibility and code quality. The CI pipeline runs on both `ubuntu-latest` and `windows-latest` for every push and pull request.

### CI Coverage
The current CI (P0.5) covers the following Rust CLI and infrastructure checks:
-   **Formatting:** `cargo fmt --check`
-   **Testing:** `cargo test --all-targets`
-   **Installation Logic:** `cargo run --bin TuffCseWinFsSetup -- install --policy examples/cse-install-policy.example.json --dry-run`
-   **Policy Verification:** `cargo run --bin TuffCseWinFsSetup -- verify --policy examples/cse-install-policy.example.json`

*Note: CI does not perform Windows kernel driver builds, driver signing, or hardware-level operations (pnputil, raw LBA access) in this phase.*

### Local Validation
To run the same checks locally, use the following commands:
```bash
cargo fmt --check
cargo test --all-targets
cargo run --bin TuffCseWinFsSetup -- install --policy examples/cse-install-policy.example.json --dry-run
cargo run --bin TuffCseWinFsSetup -- verify --policy examples/cse-install-policy.example.json
```

## License

This project is licensed under the [MIT License](LICENSE).
