#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn read(path: impl AsRef<Path>) -> String {
        fs::read_to_string(path).unwrap()
    }

    fn assert_contains(text: &str, needle: &str) {
        assert!(
            text.contains(needle),
            "missing `{needle}` in inspected file"
        );
    }

    fn assert_not_contains(text: &str, needle: &str) {
        assert!(
            !text.contains(needle),
            "unexpected `{needle}` found in inspected file"
        );
    }

    #[test]
    fn workflow_separates_checkout_ref_from_release_target_and_supports_validate_only() {
        let root = repo_root();
        let workflow = read(root.join(".github/workflows/draft-github-release.yml"));

        assert_contains(&workflow, "workflow_dispatch");
        assert_contains(&workflow, "validate_only");
        assert_contains(&workflow, "WORKFLOW_REF");
        assert_contains(&workflow, "release_target_commitish");
        assert_contains(&workflow, "target_commitish");
        assert_contains(&workflow, "fetch-depth: 0");
        assert_contains(&workflow, "fetch-tags: true");
        assert_contains(&workflow, "if: ${{ inputs.validate_only }}");
        assert_contains(&workflow, "if: ${{ !inputs.validate_only }}");
        assert_contains(&workflow, "-ValidateOnly");
        assert_not_contains(&workflow, "ref: ${{ inputs.target_commitish }}");
        assert_not_contains(&workflow, "ref: ${{ inputs.release_target_commitish }}");
    }

    #[test]
    fn scripts_and_template_record_workflow_ref_and_validate_only_boundary() {
        let root = repo_root();
        let template = read(root.join("release/V1_RC_DRAFT_RELEASE_INPUT.template.json"));
        let verify_script = read(root.join("release/verify-draft-release-inputs.ps1"));
        let create_script = read(root.join("release/create-draft-github-release.ps1"));

        for needle in [
            "\"workflow_ref\"",
            "\"release_target_commitish\"",
            "\"target_commitish\"",
            "\"release_name\": \"TUFF-CSE-WinFS v1.0.0-rc1\"",
        ] {
            assert_contains(&template, needle);
        }

        assert_contains(&verify_script, "Missing workflow_ref.");
        assert_contains(&verify_script, "release_target_commitish");
        assert_contains(
            &verify_script,
            "release_target_commitish must match target_commitish",
        );
        assert_contains(
            &verify_script,
            "target_commitish must match the current HEAD commit",
        );
        assert_contains(&verify_script, "Resolve-InputPath");

        assert_contains(&create_script, "[switch]$ValidateOnly");
        assert_contains(
            &create_script,
            "Draft GitHub Release validation only; creation skipped",
        );
        assert_contains(
            &create_script,
            "release_target_commitish must match target_commitish",
        );
        assert_contains(&create_script, "--draft");
        assert_contains(&create_script, "--prerelease");
        assert_contains(&create_script, "--verify-tag");
        assert_not_contains(&create_script, "gh release edit");
        assert_not_contains(&create_script, "--draft=false");
        assert_not_contains(&create_script, "publish");
    }

    #[test]
    fn docs_record_reproducible_draft_release_flow() {
        let root = repo_root();
        let readme = read(root.join("README.md"));
        let checklist = read(root.join("docs/PUBLIC_RELEASE_CHECKLIST.md"));
        let design = read(root.join("docs/DETAILED_DESIGN.md"));
        let rc_docs = read(root.join("docs/RC_TAG_AND_DRAFT_RELEASE.md"));

        assert_contains(&readme, "validate_only");
        assert_contains(
            &readme,
            "separating the workflow ref from the release target commit",
        );
        assert_contains(&checklist, "validate_only=true");
        assert_contains(&design, "workflow ref と release target commit");
        assert_contains(&design, "supports `-ValidateOnly`");
        assert_contains(&rc_docs, "workflow ref is recorded separately");
    }
}
