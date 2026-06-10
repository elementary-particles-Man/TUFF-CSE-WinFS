# TUFF-CSE-WinFS v1 Windows Driver (P1A Skeleton)

This directory contains the source code and configuration for the Windows volume filter driver.

## Current Phase: P1A (Driver Package Boundary)

The current implementation is a **pass-through skeleton**.

### Status
-   **Functionality:** Pass-through only. Intercepts IRPs and passes them directly to the lower device stack.
-   **CSE Processing:** NOT IMPLEMENTED (Planned for P2).
-   **Driver Signing:** NOT SIGNED (Required for P1B/Production).
-   **Distribution:** `tuffcsewinfs.sys` and `tuffcsewinfs.cat` are not yet included in the source tree.

### Components
-   `src/tuffcsewinfs.c`: WDM/KMDF filter driver entry points and pass-through dispatch.
-   `include/tuffcsewinfs.h`: Header with device extension and constants.
-   `tuffcsewinfs.inf`: Installation directive template.

## Build Requirements (P1B+)

Building the driver requires:
-   Windows Driver Kit (WDK)
-   Enterprise WDK (EWDK) or Visual Studio with WDK extension.

*Note: The main project CI (Rust) does not build this driver in the P1A phase.*

## Installation

In this phase, the `TuffCseWinFsSetup.exe` installer validates the presence of the `tuffcsewinfs.inf` file but does not perform actual driver installation (`pnputil`).
