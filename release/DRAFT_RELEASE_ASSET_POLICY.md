# Draft Release Asset Policy

P7C limits the GitHub Release draft asset boundary to public release artifacts only.

## Allowed Assets

- Public Windows installer zip
- Release manifest JSON
- SHA256 checksum report
- Draft release notes

## Disallowed Assets

- Driver packages
- Build inputs
- PDBs, symbols, or debug files
- Sensitive secret material or raw TPM material
- Anything that would require publishing a live release or adding live install or signing behavior

## Asset Rules

- Assets must exist before draft release creation.
- Asset names must match the verified release bundle.
- Asset checksums must match the verified checksum report where applicable.
- No asset may contain secret material or sensitive credential material.
