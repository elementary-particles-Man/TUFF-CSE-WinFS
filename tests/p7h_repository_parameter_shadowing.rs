#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    const FIXED_ASSIGNMENT: &str =
        "$repositoryMetadata = ($repositoryOutput -join \"`n\") | ConvertFrom-Json";
    const SHADOWING_ASSIGNMENT: &str =
        "$repository = ($repositoryOutput -join \"`n\") | ConvertFrom-Json";

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn read(path: &str) -> String {
        fs::read_to_string(repo_root().join(path)).unwrap()
    }

    #[test]
    fn repository_parameter_is_not_shadowed_by_case_insensitive_powershell_variable_names() {
        let script = read("release/verify-draft-read-credential.ps1");

        assert!(script.contains(FIXED_ASSIGNMENT));
        assert!(script.contains("$repositoryMetadata.full_name -ieq $Repository"));
        assert!(!script.contains(SHADOWING_ASSIGNMENT));
    }
}
