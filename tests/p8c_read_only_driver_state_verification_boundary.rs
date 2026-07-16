#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use tuff_cse_winfs::driver_state::{
        evaluate_driver_service_configuration, expected_driver_binary_path_from_system_directory,
        expected_driver_binary_path_from_system_root, map_windows_service_error,
        map_windows_service_state, normalize_driver_binary_path, DriverConfigurationFinding,
        DriverRuntimeState, DriverServiceConfiguration, DRIVER_EXPECTED_BINARY_RELATIVE_PATH,
        DRIVER_EXPECTED_SERVICE_TYPE, DRIVER_EXPECTED_SERVICE_TYPE_LABEL,
        DRIVER_EXPECTED_START_TYPE, DRIVER_EXPECTED_START_TYPE_LABEL, DRIVER_SERVICE_NAME,
        ERROR_SERVICE_DOES_NOT_EXIST_CODE,
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
    fn system_directory_helper_does_not_duplicate_system32() {
        assert_eq!(
            expected_driver_binary_path_from_system_directory(Path::new(r"C:\Windows\System32")),
            PathBuf::from(r"C:\Windows\System32\drivers\tuffcsewinfs.sys")
        );
    }

    #[test]
    fn maps_all_windows_service_states_and_unknown() {
        let expected = [
            (1, DriverRuntimeState::Stopped),
            (2, DriverRuntimeState::StartPending),
            (3, DriverRuntimeState::StopPending),
            (4, DriverRuntimeState::Running),
            (5, DriverRuntimeState::ContinuePending),
            (6, DriverRuntimeState::PausePending),
            (7, DriverRuntimeState::Paused),
        ];
        for (value, state) in expected {
            assert_eq!(map_windows_service_state(value), state);
        }
        assert_eq!(
            map_windows_service_state(99),
            DriverRuntimeState::Unknown(99)
        );
    }

    #[test]
    fn missing_service_error_maps_to_not_installed() {
        assert_eq!(
            map_windows_service_error(ERROR_SERVICE_DOES_NOT_EXIST_CODE, "missing"),
            DriverRuntimeState::NotInstalled
        );
        assert_eq!(
            map_windows_service_error(5, "access denied"),
            DriverRuntimeState::Error {
                windows_error_code: 5,
                message: "access denied".to_string()
            }
        );
    }

    #[test]
    fn configuration_evaluation_accepts_kernel_driver_bit_and_expected_values() {
        let expected = PathBuf::from(r"C:\Windows\System32\drivers\tuffcsewinfs.sys");
        let observed = DriverServiceConfiguration {
            service_type: DRIVER_EXPECTED_SERVICE_TYPE | 0x10,
            start_type: DRIVER_EXPECTED_START_TYPE,
            binary_path: Some(expected.clone()),
        };
        assert!(evaluate_driver_service_configuration(&observed, &expected).is_empty());
    }

    #[test]
    fn configuration_evaluation_reports_each_mismatch() {
        let expected = PathBuf::from(r"C:\Windows\System32\drivers\tuffcsewinfs.sys");
        let observed = DriverServiceConfiguration {
            service_type: 2,
            start_type: 2,
            binary_path: Some(PathBuf::from(r"C:\wrong.sys")),
        };
        let findings = evaluate_driver_service_configuration(&observed, &expected);
        assert!(findings.iter().any(|finding| matches!(
            finding,
            DriverConfigurationFinding::ServiceTypeMismatch { .. }
        )));
        assert!(findings.iter().any(|finding| matches!(
            finding,
            DriverConfigurationFinding::StartTypeMismatch { .. }
        )));
        assert!(findings.iter().any(|finding| matches!(
            finding,
            DriverConfigurationFinding::BinaryPathMismatch { .. }
        )));
    }

    #[test]
    fn normalizes_windows_system_root_and_device_path_forms() {
        let expected = Path::new(r"C:\Windows\System32\drivers\tuffcsewinfs.sys");
        let forms = [
            r"C:\Windows\System32\drivers\tuffcsewinfs.sys",
            r#""C:\Windows\System32\drivers\tuffcsewinfs.sys""#,
            r"%SystemRoot%\System32\drivers\tuffcsewinfs.sys",
            r"\SystemRoot\System32\drivers\tuffcsewinfs.sys",
            r"\??\C:\Windows\System32\drivers\tuffcsewinfs.sys",
            r"\\?\C:\Windows\System32\drivers\tuffcsewinfs.sys",
        ];
        for form in forms {
            assert_eq!(
                normalize_driver_binary_path(Path::new(form), expected),
                normalize_driver_binary_path(expected, expected),
                "failed to normalize {form}"
            );
        }
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
        for forbidden in [
            "DiInstallDriver",
            "DiUninstallDriver",
            "device mutation",
            "reboot",
        ] {
            assert_not_contains(&state_source, forbidden);
        }
    }

    #[test]
    fn verify_cli_preserves_default_and_accepts_live_flag() {
        let binary = env!("CARGO_BIN_EXE_TuffCseWinFsSetup");
        let default_output = Command::new(binary)
            .args(["verify"])
            .output()
            .expect("run default verify");
        let default_text = String::from_utf8_lossy(&default_output.stdout);
        assert!(default_output.status.success());
        assert!(default_text.contains("Driver Status: PENDING_DRIVER_PHASE"));
        assert!(!default_text.contains("Driver State Query"));

        let live_output = Command::new(binary)
            .args(["verify", "--live-driver-status"])
            .output()
            .expect("run live verify");
        if cfg!(not(windows)) {
            let live_text = String::from_utf8_lossy(&live_output.stderr);
            assert!(!live_output.status.success());
            assert!(live_text.contains("unsupported on non-Windows platforms"));
        }
    }
}
