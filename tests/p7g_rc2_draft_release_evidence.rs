#[cfg(test)]
mod tests {
    use serde_json::Value;
    use std::fs;
    use std::path::{Path, PathBuf};

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn read(path: impl AsRef<Path>) -> String {
        fs::read_to_string(path).unwrap()
    }

    fn assert_contains(text: &str, needle: &str) {
        assert!(text.contains(needle), "missing `{needle}`");
    }

    #[test]
    fn workflow_is_manual_read_only_and_runs_only_the_evidence_verifier() {
        let workflow = read(repo_root().join(".github/workflows/verify-draft-github-release.yml"));
        let trigger = workflow.split("permissions:").next().unwrap_or("");

        assert_contains(trigger, "workflow_dispatch:");
        assert!(!trigger.contains("push:"));
        assert!(!trigger.contains("pull_request:"));
        assert_contains(&workflow, "contents: read");
        assert_contains(&workflow, "actions: read");
        assert!(!workflow.contains(&["contents", "write"].join(": ")));
        assert_contains(&workflow, "persist-credentials: false");
        assert_contains(&workflow, "verify-existing-draft-release.ps1");
        assert!(!workflow.contains("create-draft-github-release.ps1"));
        assert_contains(
            &workflow,
            "tuff-cse-winfs-v1.0.0-rc2-draft-release-evidence",
        );
    }

    #[test]
    fn script_is_non_mutating_and_enforces_the_fixed_rc2_boundary() {
        let script = read(repo_root().join("release/verify-existing-draft-release.ps1"));

        for parameter in [
            "$Repository",
            "$TagName",
            "$ReleaseName",
            "$ExpectedTargetCommitish",
            "$ArtifactRunId",
            "$ExpectedRc1MetadataSha256",
            "$OutputDirectory",
        ] {
            assert_contains(&script, parameter);
        }

        for forbidden in [
            ["gh", "release", "create"].join(" "),
            ["gh", "release", "edit"].join(" "),
            ["gh", "release", "delete"].join(" "),
            ["gh", "release", "upload"].join(" "),
            ["git", "tag"].join(" "),
            ["git", "push"].join(" "),
            ["git", "update-ref"].join(" "),
        ] {
            assert!(
                !script.contains(&forbidden),
                "forbidden command `{forbidden}`"
            );
        }

        for required in [
            "ls-remote",
            "refs/tags/$TagName^{}",
            "Remote tag target mismatch.",
            "$ExpectedRc2ReleaseId = 353395540",
            "$ExpectedRc1ReleaseId = 350514171",
            "repos/$Repository/releases/$ReleaseId",
            "Release must remain draft.",
            "Release must remain prerelease.",
            "Release must remain unpublished.",
            "Unexpected release asset count.",
            "Asset SHA256 mismatch.",
            "Asset byte identity mismatch.",
            "Manifest source_commit mismatch.",
            "public-release-artifact",
            "RC1 metadata SHA256 mismatch.",
            "V1_RC2_DRAFT_RELEASE_EVIDENCE.json",
            "V1_RC2_RELEASE_ASSET_SHA256.txt",
            "V1_RC2_SOURCE_ARTIFACT_SHA256.txt",
        ] {
            assert_contains(&script, required);
        }
    }

    #[test]
    fn schema_requires_complete_machine_readable_evidence() {
        let schema_text =
            read(repo_root().join("release/V1_RC_DRAFT_RELEASE_EVIDENCE.schema.json"));
        let schema: Value = serde_json::from_str(&schema_text).unwrap();
        let required = schema["required"].as_array().unwrap();

        assert_eq!(
            schema["properties"]["schema_version"]["const"],
            "2026-07-p7g"
        );
        for field in [
            "repository",
            "tag_name",
            "tag_target_commit",
            "release_name",
            "release_target_commitish",
            "is_draft",
            "is_prerelease",
            "published_at",
            "workflow_main_commit",
            "source_main_commit",
            "artifact_workflow_run_id",
            "validate_only_workflow_run_id",
            "create_workflow_run_id",
            "verification_workflow_run_id",
            "assets",
            "source_artifact_assets",
            "byte_identity_verified",
            "manifest_verified",
            "checksums_verified",
            "secret_scan_clean",
            "rc1_metadata_sha256",
            "generated_at_utc",
        ] {
            assert!(
                required.iter().any(|value| value == field),
                "missing `{field}`"
            );
        }

        let asset_required = schema["$defs"]["asset"]["required"].as_array().unwrap();
        for field in ["name", "size", "sha256"] {
            assert!(
                asset_required.iter().any(|value| value == field),
                "missing asset field `{field}`"
            );
        }
    }
}
