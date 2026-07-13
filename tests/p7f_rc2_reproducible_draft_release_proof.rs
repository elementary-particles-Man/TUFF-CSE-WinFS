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

    #[test]
    fn workflow_accepts_fixed_release_name_and_keeps_validation_non_mutating() {
        let root = repo_root();
        let workflow = read(root.join(".github/workflows/draft-github-release.yml"));
        let create_script = read(root.join("release/create-draft-github-release.ps1"));

        assert!(workflow.contains("release_name:"));
        assert!(workflow.contains("RELEASE_NAME: ${{ inputs.release_name }}"));
        assert!(workflow.contains("release_name    = $env:RELEASE_NAME"));

        let validate_only = create_script.find("if ($ValidateOnly)").unwrap();
        let local_tag_check = create_script.find("git show-ref").unwrap();
        let remote_tag_check = create_script.find("git ls-remote").unwrap();
        let release_lookup = create_script.find("gh release view").unwrap();
        let release_create = create_script.find("\"create\"").unwrap();

        assert!(validate_only < local_tag_check);
        assert!(validate_only < remote_tag_check);
        assert!(validate_only < release_lookup);
        assert!(validate_only < release_create);
    }

    #[test]
    fn create_path_fails_closed_then_allows_gh_to_create_tag_at_target() {
        let root = repo_root();
        let create_script = read(root.join("release/create-draft-github-release.ps1"));

        assert!(create_script.contains("Tag already exists locally"));
        assert!(create_script.contains("Tag already exists remotely"));
        assert!(create_script.contains("Release already exists for tag"));
        assert!(create_script.contains("--target"));
        assert!(create_script.contains("--draft"));
        assert!(create_script.contains("--prerelease"));
        assert!(!create_script.contains("--verify-tag"));
        assert!(!create_script.contains("gh release edit"));
        assert!(!create_script.contains("git tag -f"));
        assert!(!create_script.contains("--force"));
    }

    #[test]
    fn input_validation_binds_artifacts_and_release_name_to_target() {
        let root = repo_root();
        let verify_script = read(root.join("release/verify-draft-release-inputs.ps1"));

        assert!(verify_script.contains("release_name must match the RC tag name"));
        assert!(
            verify_script.contains("Manifest source_commit must match release_target_commitish")
        );
        assert!(verify_script.contains("Manifest build_workflow must be public-release-artifact"));
        assert!(!verify_script.contains("refs/tags/$($Input.tag_name)^{commit}"));
    }
}
