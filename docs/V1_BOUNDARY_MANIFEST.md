# V1 Boundary Manifest

TUFF-CSE-WinFS v1 fixes the logical boundary at the end of P6C and reserves P6Z as the release-gate line.

## Completed v1 Boundary Phases

| Phase | Boundary |
| --- | --- |
| P1A | Installer skeleton and policy model |
| P1B | Driver package classification only |
| P1C | Operation contract and state transitions |
| P2A | Single-host binding model |
| P2B | Runtime recovery model |
| P2C | Runtime state recovery guardrails |
| P3A | Export manifest boundary |
| P3B | Rebind and recovery model |
| P3C | Manual flow state and completion tokens |
| P4A | Local policy and approval model |
| P4B | Local approval enforcement |
| P4C | Signed audit journal |
| P5A | Domain policy model |
| P5B | Domain approval enforcement |
| P5C | Domain recovery workflow |
| P6A | Enterprise recovery authority boundary |
| P6B | Enterprise provider adapter boundary |
| P6C | Enterprise provider lifecycle, revocation, rotation, and attestation renewal boundary |

## Release Gate Line

P6Z does not add a new product capability. It freezes the v1 RC boundary, documents the supported surface, and verifies that no post-v1 live integration slipped into the tree.

## Completed In v1

- Offline/imported policy, approval, recovery, provider, and lifecycle metadata.
- Signed journal canonical payloads with P4C, P5, and P6 metadata fields.
- Secret non-persistence for provider credentials, API keys, client secrets, tokens, private keys, KMS secrets, HSM secrets, basekeys, MK, TK, PK, and raw principals.
- Installer dry-run and verify flows.
- CLI reporting for RC status and boundary state.

## Deferred After v1

- Live KMS, HSM, Cloud KMS, and PKCS#11 connections.
- Key recovery or key restoration flows.
- CSE encrypted I/O.
- TPM real API use.
- Driver runtime I/O, pnputil, signing, and installation side effects.
- Raw LBA, partition resize, and AnchorProvider behavior.

## Boundary Rules

- AD inputs are policy, approval, and audit principal inputs, not keys.
- `unlock` means transition to managed unlocked runtime state.
- `export` means reseal for transfer, not restore or decrypt.
- `eject` means safe removal, not a write path.
- `rebind` means ownership boundary transfer, not credential migration.

