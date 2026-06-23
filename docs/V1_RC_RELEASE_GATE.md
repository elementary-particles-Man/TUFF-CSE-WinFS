# V1 RC Release Gate

This document fixes the acceptance line for the v1 RC.

## RC Gates

The RC is accepted only when all of the following pass:

- `cargo fmt --check`
- `cargo test --all-targets`
- Ubuntu and Windows CI
- installer `install --dry-run`
- installer `verify --policy`
- signed journal verify
- secret grep against the smoke store and source tree
- forbidden boundary grep against the source tree and docs

## Operation Completion Line

Employee and clerk operations complete only through the existing operation and manual-flow paths.

- `complete_plan` and `cancel_plan` remain manual-flow completion controls.
- The RC gate does not add a new installer completion path.
- The RC gate does not add a new driver installation path.

## Secret Policy

The RC keeps the existing no-plaintext rule:

- no plaintext MK, TK, PK, or basekey
- no raw principal, raw provider credential, API key, client secret, token, or private key
- no provider credential, KMS secret, HSM secret, or raw TPM material in stdout, stderr, META, or journal payloads

## Status Command

`tuff-cse-winfsctl rc-status` reports:

- the fixed v1 boundary phase
- main-independent build info
- completed phases
- reserved live integrations
- forbidden boundaries

