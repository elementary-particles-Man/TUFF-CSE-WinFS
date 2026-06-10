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

## Current Phase: P1B (Windows Driver Build Boundary)

The project is currently in the **P1B** phase. This stage introduces the Visual Studio / WDK project structure necessary to build the Windows volume filter driver.

### P1B Highlights:
-   **WDK Build Boundary:** Includes `TUFF-CSE-WinFS.sln`, `tuffcsewinfs.vcxproj`, and a manual build script (`build-driver.ps1`) to compile the driver.
-   **Installer Enhancements:** The installer now detects `BuildReadySource` (INF/vcxproj/sln) and `BuiltUnsigned` (INF/SYS) states, clarifying the package's readiness for distribution.
-   **No Built-in Signing:** P1B focuses purely on compilation. The resulting `.sys` file is unsigned. Driver signing (`tuffcsewinfs.cat`), `pnputil` deployment, and actual CSE cryptography are deferred to later phases.

*Note: GitHub Actions primarily validates the Rust CLI. To test the WDK driver build, you must run the build script manually on a Windows host with the WDK installed, or trigger the `driver-wdk-manual.yml` workflow on GitHub.*

### Local Driver Build
To compile the pass-through driver skeleton locally on Windows (requires WDK):
```powershell
powershell -ExecutionPolicy Bypass -File driver/windows/build-driver.ps1 -Configuration Release -Platform x64
```

## CI & Validation

This project uses GitHub Actions to ensure cross-platform compatibility and code quality. The CI pipeline runs on both `ubuntu-latest` and `windows-latest` for every push and pull request.

### CI Coverage
The current CI (P0.5) covers the following Rust CLI and infrastructure checks:
-   **Formatting:** `cargo fmt --check`
-   **Testing:** `cargo test --all-targets`
-   **Installation Logic:** `cargo run -- install --policy examples/cse-install-policy.example.json --dry-run`
-   **Policy Verification:** `cargo run -- verify --policy examples/cse-install-policy.example.json`

*Note: CI does not perform Windows kernel driver builds, driver signing, or hardware-level operations (pnputil, raw LBA access) in this phase.*

### Local Validation
To run the same checks locally, use the following commands:
```bash
cargo fmt --check
cargo test --all-targets
cargo run -- install --policy examples/cse-install-policy.example.json --dry-run
cargo run -- verify --policy examples/cse-install-policy.example.json
```

## License

This project is licensed under the [MIT License](LICENSE).
