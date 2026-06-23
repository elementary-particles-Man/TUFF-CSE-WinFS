# V1 Forbidden Boundary

The following boundaries stay out of v1 RC scope and must not be revived as live integrations.

## Explicit Exclusions

- ReFS
- RAW volumes
- network volumes
- system volume mutation
- pagefile handling
- crashdump handling
- hibernation handling
- EFI partition mutation
- MSR usage
- Recovery partition mutation
- OEM partition mutation
- BitLocker conflict handling

## Storage and Layout Rules

- no raw LBA anchor
- no physical tail LBA dependency
- no partition resize path
- no AnchorProvider resurrection

## Live Integration Ban

- no live KMS connection
- no live HSM connection
- no Cloud KMS SDK connection
- no PKCS#11 live connection

## Driver and Crypto Ban

- no driver runtime I/O
- no key restoration path
- no CSE encrypted I/O path
- no TPM real API path

