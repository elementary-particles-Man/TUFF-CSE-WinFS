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
