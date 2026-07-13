#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    #[test]
    fn repository_parameter_is_not_shadowed_by_case_insensitive_powershell_variable_names() {
        let script = fs::read_to_string(
            repo_root().join("release/verify-draft-read-credential.ps1"),
        )
        .unwrap();

        assert!(script.contains("$repositoryMetadata = ($repositoryOutput -join \"`n\") | ConvertFrom-Json"));
        assert!(script.contains("$repositoryMetadata.full_name -ieq $Repository"));
        assert!(!script.contains("$repository = ($repositoryOutput -join \"`n\") | ConvertFrom-Json"));
    }
}
