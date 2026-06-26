#[cfg(test)]
mod tests {
    use regex::Regex;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn read(path: impl AsRef<Path>) -> String {
        fs::read_to_string(path).unwrap()
    }

    fn assert_not_contains(text: &str, needle: &str) {
        assert!(
            !text.contains(needle),
            "unexpected forbidden string `{needle}` found"
        );
    }

    #[test]
    fn release_manifest_template_carries_required_fields_and_safe_kinds() {
        let root = repo_root();
        let manifest = read(root.join("release/V1_RC_ARTIFACT_MANIFEST.template.json"));
        let checksum_line = Regex::new(r"^SHA256 \((.+)\) = ([0-9a-f]{64})$").unwrap();
        let checksum_template = read(root.join("release/V1_RC_CHECKSUMS.template.sha256"));

        for needle in [
            "\"artifact_name\"",
            "\"artifact_kind\"",
            "\"source_commit\"",
            "\"build_workflow\"",
            "\"sha256\"",
            "\"size_bytes\"",
            "\"generated_at\"",
            "\"boundary_status\"",
            "\"portable_zip\"",
            "\"wix_msi_candidate\"",
            "\"checksums\"",
            "\"release_notes\"",
        ] {
            assert!(manifest.contains(needle), "missing `{needle}`");
        }

        for forbidden in [
            "password",
            "auth token",
            "basekey",
            "MK",
            "TK",
            "PK",
            "private key",
            "provider credential",
            "KMS secret",
            "HSM secret",
        ] {
            assert_not_contains(&manifest, forbidden);
        }

        assert!(checksum_line.is_match(
            "SHA256 (TUFF-CSE-WinFS-a15c209-public-windows-installer.zip) = 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ));
        assert!(checksum_template.contains(
            "SHA256 (TUFF-CSE-WinFS-<source_commit>-public-windows-installer.zip) = <sha256>"
        ));
    }

    #[test]
    fn release_notes_template_and_notes_record_post_v1_lines() {
        let root = repo_root();
        let notes = read(root.join("release/V1_RC_RELEASE_NOTES.md"));
        let template = read(root.join("docs/PUBLIC_RELEASE_NOTES_TEMPLATE.md"));
        let public_docs = read(root.join("docs/PUBLIC_RELEASE_ARTIFACTS.md"));

        assert_eq!(tuff_cse_winfs::P7B_PUBLIC_RELEASE_PHASE, "P7B");
        assert_eq!(
            tuff_cse_winfs::P7B_PUBLIC_RELEASE_BOUNDARY,
            "Public Release Artifact Checksum Draft Release Boundary"
        );

        let ctl = std::env::var("CARGO_BIN_EXE_tuff-cse-winfsctl").unwrap();
        let output = Command::new(ctl).arg("rc-status").output().unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("public release readiness: P7B / Public Release Artifact Checksum Draft Release Boundary"));
        assert!(stdout.contains("public release artifacts: portable zip release artifact, release manifest, SHA256 checksum report, draft release notes"));

        for text in [&notes, &template, &public_docs] {
            assert!(text.contains("v1 RC completed boundary"));
            assert!(text.contains("P7A public Windows installer package boundary"));
            assert!(
                text.contains("P7B public release artifact checksum and draft-release boundary")
            );
            assert!(text.contains("Live driver install"));
            assert!(text.contains("Driver signing"));
            assert!(text.contains("TPM live API use"));
        }

        assert_not_contains(&notes, "GitHub Release publish");
        assert_not_contains(&template, "GitHub Release publish");
        assert_not_contains(&public_docs, "GitHub Release publish");
    }

    #[test]
    fn checksum_script_uses_get_file_hash_and_verifier_rejects_mismatch() {
        let root = repo_root();
        let build_script = read(root.join("release/build-release-manifest.ps1"));
        let verify_script = read(root.join("release/verify-release-artifacts.ps1"));
        let workflow = read(root.join(".github/workflows/public-release-artifact.yml"));
        let p7a_test = read(root.join("tests/p7a_public_windows_installer_package_boundary.rs"));
        let installer_build = read(root.join("installer/windows/build-installer.ps1"));
        let installer_manifest = read(root.join("installer/windows/PACKAGE_MANIFEST.md"));
        let installer_readme = read(root.join("installer/windows/README.md"));
        let installer_readme_first = read(root.join("installer/windows/assets/README-FIRST.txt"));

        assert!(build_script.contains("Get-FileHash -Algorithm SHA256"));
        assert!(build_script.contains("V1_RC_ARTIFACT_MANIFEST.json"));
        assert!(build_script.contains("V1_RC_CHECKSUMS.sha256"));
        assert!(verify_script.contains("Checksum mismatch"));
        assert!(verify_script.contains("Manifest SHA256 mismatch"));
        assert!(workflow.contains("public-release-artifact"));
        assert!(workflow.contains("actions/upload-artifact@v4"));
        assert!(workflow.contains("build-release-manifest.ps1"));
        assert!(workflow.contains("verify-release-artifacts.ps1"));

        for text in [&build_script, &verify_script, &workflow] {
            assert_not_contains(text, "pnputil");
            assert_not_contains(text, "signtool sign");
            assert_not_contains(text, "Start-Service");
            assert_not_contains(text, "New-Service");
            assert_not_contains(text, "live KMS");
            assert_not_contains(text, "live HSM");
            assert_not_contains(text, "PKCS#11 connect");
            assert_not_contains(text, "raw LBA");
            assert_not_contains(text, "partition resize");
            assert_not_contains(text, "AnchorProvider");
        }

        for text in [
            &installer_build,
            &installer_manifest,
            &installer_readme,
            &installer_readme_first,
        ] {
            assert_not_contains(text, "pnputil.exe");
            assert_not_contains(text, "signtool sign");
            assert_not_contains(text, "Start-Service");
            assert_not_contains(text, "New-Service");
        }

        assert!(installer_build.contains("public-windows-installer"));
        assert!(installer_manifest.contains("public release artifact boundary"));
        assert!(installer_readme.contains("public release artifact boundary"));
        assert!(installer_readme_first.contains("public release artifact boundary"));
        assert!(p7a_test.contains("P7A_PUBLIC_INSTALLER_PHASE"));
    }
}
