# Draft Read Credential Minimization

P7H narrows the read-only credential used for draft release verification from a broad repository OAuth token to a fine-grained personal access token with only the permissions needed to read the TUFF-CSE-WinFS repository, draft releases, release assets, and the source Actions artifact.

## Required Secret

- Secret name: `P7G_DRAFT_READ_FINE_GRAINED_TOKEN`
- Token class: fine-grained personal access token
- Resource owner: `elementary-particles-Man`
- Repository access: only `TUFF-CSE-WinFS`
- Permissions: `contents: read`, `actions: read`

The token itself must never be printed, persisted, or copied into repository files. Only the `github_pat_` prefix check and successful read operations are recorded.

## Verification Flow

1. A repository owner creates the fine-grained PAT in GitHub settings.
2. The owner stores it as the `P7G_DRAFT_READ_FINE_GRAINED_TOKEN` repository Actions secret.
3. `.github/workflows/verify-draft-read-credential.yml` runs `release/verify-draft-read-credential.ps1`.
4. The verifier checks the token prefix, reads `/user`, the repository metadata, the fixed RC1 and RC2 release IDs, the four RC2 release assets, and the source artifact bundle.
5. The verifier emits schema-validated evidence with no token material.

## Migration Boundary

P7H keeps the release state unchanged. It does not create, edit, delete, upload, or publish GitHub Releases; it does not mutate Git refs; and it does not perform any installation, signing, TPM, KMS/HSM, PKCS#11, or driver operations.
