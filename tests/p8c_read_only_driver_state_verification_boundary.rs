#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use tuff_cse_winfs::driver_state::{
        expected_driver_binary_path_from_system_root, DRIVER_EXPECTED_BINARY_RELATIVE_PATH,
        DRIVER_EXPECTED_SERVICE_TYPE, DRIVER_EXPECTED_SERVICE_TYPE_LABEL,
        DRIVER_EXPECTED_START_TYPE, DRIVER_EXPECTED_START_TYPE_LABEL, DRIVER_SERVICE_NAME,
    };

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn read(path: impl AsRef<Path>) -> String {
        fs::read_to_string(path).unwrap()
    }

    fn assert_contains(text: &str, needle: &str) {
        assert!(text.contains(needle), "missing `{needle}`");
    }

    fn assert_not_contains(text: &str, needle: &str) {
        assert!(
            !text.contains(needle),
            "unexpected forbidden string `{needle}` found"
        );
    }

    #[test]
    fn expected_binary_path_uses_system32_driver_layout() {
        let path = expected_driver_binary_path_from_system_root(Path::new(r"C:\Windows"));
        assert_eq!(
            path,
            PathBuf::from(r"C:\Windows\System32\drivers\tuffcsewinfs.sys")
        );
    }

    #[test]
    fn source_and_docs_define_read_only_driver_state_boundary() {
        let readme = read(repo_root().join("README.md"));
        let design = read(repo_root().join("docs/DETAILED_DESIGN.md"));
        let verify_source = read(repo_root().join("src/verify.rs"));
        let state_source = read(repo_root().join("src/driver_state.rs"));
        let lib_source = read(repo_root().join("src/lib.rs"));

        assert_contains(
            &readme,
            "P8C (Read-Only Windows Driver State Verification Boundary)",
        );
        assert_contains(
            &design,
            "P8C Read-Only Windows Driver State Verification Boundary",
        );
        assert_contains(&verify_source, "Driver State Query: service=");
        assert_contains(&verify_source, "Driver Status: PENDING_DRIVER_PHASE");
        assert_contains(&state_source, "OpenSCManagerW");
        assert_contains(&state_source, "OpenServiceW");
        assert_contains(&state_source, "QueryServiceConfigW");
        assert_contains(&state_source, "QueryServiceStatusEx");
        assert_contains(&state_source, DRIVER_SERVICE_NAME);
        assert_contains(&state_source, DRIVER_EXPECTED_BINARY_RELATIVE_PATH);
        assert_contains(&state_source, DRIVER_EXPECTED_SERVICE_TYPE_LABEL);
        assert_contains(&state_source, DRIVER_EXPECTED_START_TYPE_LABEL);
        assert_contains(&lib_source, "P8C_READ_ONLY_DRIVER_STATE_PHASE");
        assert_contains(
            &lib_source,
            "Read-Only Windows Driver State Verification Boundary",
        );
        assert_eq!(DRIVER_EXPECTED_SERVICE_TYPE, 0x0000_0001);
        assert_eq!(DRIVER_EXPECTED_START_TYPE, 0x0000_0003);
    }

    #[test]
    fn state_source_remains_read_only_and_fail_closed() {
        let state_source = read(repo_root().join("src/driver_state.rs"));
        assert_not_contains(&state_source, "CreateServiceW");
        assert_not_contains(&state_source, "ChangeServiceConfig");
        assert_not_contains(&state_source, "ControlService");
        assert_not_contains(&state_source, "StartService");
        assert_not_contains(&state_source, "DeleteService");
        assert_not_contains(&state_source, "service install");
        assert_not_contains(&state_source, "service remove");
        assert_not_contains(&state_source, "service reconfigure");
    }
}
