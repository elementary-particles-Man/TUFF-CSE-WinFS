#[cfg(test)]
mod tests {
    use std::env;
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
    fn rc_status_reports_p7c_draft_release_boundary() {
        assert_eq!(tuff_cse_winfs::P7C_DRAFT_RELEASE_PHASE, "P7C");
        assert_eq!(
            tuff_cse_winfs::P7C_DRAFT_RELEASE_BOUNDARY,
            "RC Tag and Draft GitHub Release Asset Boundary"
        );

        let ctl = env::var("CARGO_BIN_EXE_tuff-cse-winfsctl").unwrap();
        let output = Command::new(ctl).arg("rc-status").output().unwrap();
        assert!(output.status.success());

        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("public release readiness: P7B / Public Release Artifact Checksum Draft Release Boundary"));
        assert!(stdout.contains(
            "draft release readiness: P7C / RC Tag and Draft GitHub Release Asset Boundary"
        ));
        assert!(stdout.contains("draft release assets: public windows installer zip, release manifest, SHA256 checksum report, draft release notes"));
        let release_publish = ["GitHub", "Release", "publish"].join(" ");
        assert!(stdout.contains(&format!(
            "draft release reserved actions: {}, tag overwrite, force tag",
            release_publish
        )));
        assert_not_contains(&stdout, "password");
        let auth_token = ["auth", "token"].join(" ");
        let private_key = ["private", "key"].join(" ");
        assert_not_contains(&stdout, &auth_token);
        assert_not_contains(&stdout, &private_key);
    }

    #[test]
    fn rc_tag_policy_and_input_template_require_fail_closed_draft_release_inputs() {
        let root = repo_root();
        let tag_policy = read(root.join("release/RC_TAG_POLICY.md"));
        let asset_policy = read(root.join("release/DRAFT_RELEASE_ASSET_POLICY.md"));
        let input_template = read(root.join("release/V1_RC_DRAFT_RELEASE_INPUT.template.json"));
        let notes = read(root.join("release/V1_RC_RELEASE_NOTES.md"));
        let release_readme = read(root.join("release/README.md"));
        let top_readme = read(root.join("README.md"));
        let docs = read(root.join("docs/RC_TAG_AND_DRAFT_RELEASE.md"));

        for needle in [
            "v1.0.0-rcN",
            "v1.0.0-rc1",
            "Existing tags must never be overwritten.",
            "Force push and force tag behavior are prohibited.",
            "publish",
        ] {
            assert!(
                tag_policy.contains(needle),
                "missing `{needle}` in RC tag policy"
            );
        }

        for needle in [
            "Public Windows installer zip",
            "Release manifest JSON",
            "SHA256 checksum report",
            "Draft release notes",
        ] {
            assert!(
                asset_policy.contains(needle),
                "missing `{needle}` in asset policy"
            );
        }

        for needle in [
            "\"tag_name\"",
            "\"target_commitish\"",
            "\"release_name\"",
            "\"draft\": true",
            "\"prerelease\": true",
            "\"publish\": false",
            "\"artifact_manifest\"",
            "\"checksums\"",
            "\"release_notes\"",
            "\"assets\"",
            "\"portable_zip\"",
            "\"artifact_manifest\"",
            "\"checksums\"",
            "\"release_notes\"",
        ] {
            assert!(
                input_template.contains(needle),
                "missing `{needle}` in draft release input template"
            );
        }

        assert!(notes.contains("P7C RC tag and draft GitHub Release asset boundary"));
        assert!(release_readme.contains("RC tag naming and manual draft release creation only."));
        assert!(top_readme.contains("P7C (RC Tag / Draft GitHub Release Asset Boundary)"));
        assert!(docs.contains("rc-status"));
        assert!(docs.contains("release/verify-release-artifacts.ps1"));
        assert!(docs.contains("release/verify-draft-release-inputs.ps1"));
        assert!(docs.contains("release/create-draft-github-release.ps1"));

        let p7c_readme_section = top_readme
            .split("## Current Phase: P7C (RC Tag / Draft GitHub Release Asset Boundary)")
            .nth(1)
            .unwrap_or("")
            .to_string();
        let secret_anchor = ["base", "key"].join("");
        let private_key = ["private", "key"].join(" ");
        let provider_credential = ["provider", "credential"].join(" ");
        let auth_token = ["auth", "token"].join(" ");

        for text in [
            &tag_policy,
            &asset_policy,
            &input_template,
            &notes,
            &release_readme,
            &docs,
            &p7c_readme_section,
        ] {
            assert_not_contains(text, &secret_anchor);
            assert_not_contains(text, &private_key);
            assert_not_contains(text, &provider_credential);
            assert_not_contains(text, &auth_token);
        }
    }

    #[test]
    fn draft_release_workflow_and_scripts_are_manual_and_publish_free() {
        let root = repo_root();
        let workflow = read(root.join(".github/workflows/draft-github-release.yml"));
        let verify_script = read(root.join("release/verify-draft-release-inputs.ps1"));
        let create_script = read(root.join("release/create-draft-github-release.ps1"));
        let manifest_script = read(root.join("release/build-release-manifest.ps1"));
        let release_verify = read(root.join("release/verify-release-artifacts.ps1"));
        let checksum_template = read(root.join("release/V1_RC_CHECKSUMS.template.sha256"));
        let manifest_template = read(root.join("release/V1_RC_ARTIFACT_MANIFEST.template.json"));

        assert!(workflow.contains("workflow_dispatch"));
        assert!(workflow.contains("artifact_run_id"));
        assert!(workflow.contains("artifact_path"));
        assert!(workflow.contains("contents: write"));
        assert!(workflow.contains("gh run download"));
        assert!(workflow.contains("verify-draft-release-inputs.ps1"));
        assert!(workflow.contains("create-draft-github-release.ps1"));
        assert!(create_script.contains("\"release\""));
        assert!(create_script.contains("\"create\""));
        assert!(create_script.contains("--draft"));
        assert!(create_script.contains("--prerelease"));
        assert!(create_script.contains("Tag already exists locally"));
        assert!(create_script.contains("Tag already exists remotely"));
        assert!(create_script.contains("--target"));
        assert!(create_script.contains("--verify-tag"));
        assert!(verify_script.contains("draft must be true"));
        assert!(verify_script.contains("prerelease must be true"));
        assert!(
            verify_script.contains("Manifest source_commit must match release_target_commitish")
        );
        assert!(manifest_script.contains("rc-draft-release-boundary"));
        assert!(manifest_script.contains("2026-07-p7c"));
        assert!(release_verify.contains("Checksum entry missing for release manifest."));
        assert!(checksum_template.contains("V1_RC_ARTIFACT_MANIFEST.json"));
        assert!(manifest_template.contains("\"boundary_status\": \"rc-draft-release-boundary\""));
        let release_publish = ["GitHub", "Release", "publish"].join(" ");

        for text in [
            &workflow,
            &verify_script,
            &create_script,
            &manifest_script,
            &release_verify,
        ] {
            assert_not_contains(text, "--latest");
            assert_not_contains(text, "--generate-notes");
            assert_not_contains(text, "pnputil");
            assert_not_contains(text, "signtool sign");
            assert_not_contains(text, "New-Service");
            assert_not_contains(text, "Start-Service");
            assert_not_contains(text, "live KMS");
            assert_not_contains(text, "live HSM");
            assert_not_contains(text, "raw LBA");
            assert_not_contains(text, "partition resize");
            assert_not_contains(text, "AnchorProvider");
            assert_not_contains(text, &release_publish);
        }
    }

    #[test]
    fn p7b_release_artifact_boundary_remains_intact() {
        let root = repo_root();
        let p7b_test = read(root.join("tests/p7b_public_release_artifact_checksum_boundary.rs"));
        let build_script = read(root.join("release/build-release-manifest.ps1"));
        let verify_script = read(root.join("release/verify-release-artifacts.ps1"));

        assert!(p7b_test.contains("P7B_PUBLIC_RELEASE_PHASE"));
        assert!(build_script.contains("Get-FileHash -Algorithm SHA256"));
        assert!(build_script.contains("V1_RC_ARTIFACT_MANIFEST.json"));
        assert!(verify_script.contains("Checksum mismatch for release manifest."));
        assert!(verify_script.contains("Artifact file not found"));
    }
}
