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
-   **Single-Host State (P2B legacy):** Binding descriptors, derivation plans, and volume states are persisted to disk under `ProgramData`, enabling state-aware management.

## Current Phase: P3A (Managed Export Manifest Boundary)

The project is currently in the **P3A** phase. This stage introduces the boundary for managed data exports, distinguishing between local usage (`unlock`) and transfer-oriented operations (`export`).

### P3A Highlights:
-   **Export Manifests:** Defines `ExportPolicy`, `ExportRecipient`, `ExportPlan`, and `ExportManifest` to manage the lifecycle of data handovers.
-   **Managed Export Boundary:** The `export` command now generates detailed manifest and plan files under `ProgramData\TUFF-CSE-WinFS\devices\META\exports\`.
-   **Operation Clarity:** Explicitly separates `unlock` (local usage), `export` (re-sealing for external transfer), `eject` (safe removal), and `rebind` (ownership boundary transfer).
-   **No Secret Exposure:** Ensures that recipient private keys and real key material are never handled or persisted. Manifests contain recipient IDs and key fingerprints for validation.

*Note: P3A focuses on the export contract and metadata. It does not implement actual data copying, re-sealing, recipient public-key encryption, or rebind/recover logic (planned for P3B/P3C).*

### Export Example
To generate an export plan and manifest for a bound volume:
```powershell
cargo run --bin tuff-cse-winfsctl -- export --volume D: --recipient RECIPIENT-ID-001 --recipient-key-fp FP-ABCD-1234
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
