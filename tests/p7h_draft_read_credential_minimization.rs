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
    fn workflow_is_manual_read_only_and_uses_the_fine_grained_secret() {
        let workflow = read(repo_root().join(".github/workflows/verify-draft-read-credential.yml"));

        assert_contains(&workflow, "workflow_dispatch:");
        assert_contains(&workflow, "contents: read");
        assert_contains(&workflow, "actions: read");
        assert_contains(&workflow, "persist-credentials: false");
        assert_contains(&workflow, "secrets.P7G_DRAFT_READ_FINE_GRAINED_TOKEN");
        assert!(!workflow.contains("contents: write"));
        assert!(!workflow.contains("P7G_DRAFT_READ_TOKEN"));
        assert_contains(&workflow, "verify-draft-read-credential.ps1");
        assert_contains(
            &workflow,
            "tuff-cse-winfs-p7h-draft-read-credential-evidence",
        );
    }

    #[test]
    fn script_requires_a_fine_grained_pat_and_remains_read_only() {
        let script = read(repo_root().join("release/verify-draft-read-credential.ps1"));

        for parameter in [
            "$Repository",
            "$TagName",
            "$ReleaseName",
            "$ExpectedTargetCommitish",
            "$ArtifactRunId",
            "$ExpectedRc1MetadataSha256",
            "$Rc1ReleaseId",
            "$Rc2ReleaseId",
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
            ["Invoke-RestMethod", "-Method", "Post"].join(" "),
            ["Invoke-RestMethod", "-Method", "Patch"].join(" "),
            ["Invoke-RestMethod", "-Method", "Put"].join(" "),
            ["Invoke-RestMethod", "-Method", "Delete"].join(" "),
        ] {
            assert!(
                !script.contains(&forbidden),
                "forbidden command `{forbidden}`"
            );
        }

        for required in [
            "GH_TOKEN must begin with github_pat_.",
            "-Command \"gh\"",
            "\"api\", \"user\"",
            "repos/$Repository",
            "repos/$Repository/releases/$ReleaseId",
            "public-release-artifact-bundle",
            "Asset SHA256 mismatch.",
            "Asset byte identity mismatch.",
            "RC1 metadata SHA256 mismatch.",
            "P7H_DRAFT_READ_CREDENTIAL_EVIDENCE.json",
            "credential_class = \"fine-grained-personal-access-token\"",
            "mutation_attempted = $false",
        ] {
            assert_contains(&script, required);
        }
    }

    #[test]
    fn schema_requires_minimal_credential_evidence_without_token_fields() {
        let schema_text =
            read(repo_root().join("release/P7H_DRAFT_READ_CREDENTIAL_EVIDENCE.schema.json"));
        let schema: Value = serde_json::from_str(&schema_text).unwrap();
        let required = schema["required"].as_array().unwrap();

        assert_eq!(
            schema["properties"]["credential_class"]["const"],
            "fine-grained-personal-access-token"
        );
        assert_eq!(schema["properties"]["mutation_attempted"]["const"], false);
        for field in [
            "repository",
            "credential_class",
            "credential_prefix_verified",
            "repository_access_verified",
            "contents_read_verified",
            "actions_read_verified",
            "rc1_draft_read_verified",
            "rc2_draft_read_verified",
            "release_assets_read_verified",
            "source_artifact_read_verified",
            "byte_identity_verified",
            "rc1_metadata_sha256",
            "rc2_metadata_sha256",
            "mutation_attempted",
            "generated_at_utc",
        ] {
            assert!(
                required.iter().any(|value| value == field),
                "missing `{field}`"
            );
        }

        for prohibited in [
            "\"token\"",
            "\"authorization\"",
            "\"secret\"",
            "\"credential_value\"",
            "\"token_suffix\"",
            "\"token_hash\"",
        ] {
            assert!(
                !schema_text.contains(prohibited),
                "unexpected field `{prohibited}` in schema"
            );
        }
    }

    #[test]
    fn docs_and_readmes_describe_the_migration_boundary() {
        let doc = read(repo_root().join("docs/DRAFT_READ_CREDENTIAL_MINIMIZATION.md"));
        let rc2_doc = read(repo_root().join("docs/RC2_DRAFT_RELEASE_EVIDENCE.md"));
        let release_readme = read(repo_root().join("release/README.md"));
        let checklist = read(repo_root().join("docs/PUBLIC_RELEASE_CHECKLIST.md"));
        let top_readme = read(repo_root().join("README.md"));

        assert_contains(&doc, "P7G_DRAFT_READ_FINE_GRAINED_TOKEN");
        assert_contains(&doc, "fine-grained personal access token");
        assert_contains(&doc, ".github/workflows/verify-draft-read-credential.yml");
        assert_contains(&rc2_doc, "P7G_DRAFT_READ_FINE_GRAINED_TOKEN");
        assert_contains(&release_readme, "verify-draft-read-credential.ps1");
        assert_contains(&release_readme, "P7H");
        assert_contains(&checklist, "P7H");
        assert_contains(&top_readme, "P7H (Draft Read Credential Minimization)");
    }
}
