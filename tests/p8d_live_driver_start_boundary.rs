#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;
    use tuff_cse_winfs::driver_control::{
        build_driver_start_plan, start_driver_live, DriverStartResult,
    };
    use tuff_cse_winfs::driver_state::{
        DriverConfigurationFinding, DriverRuntimeState, DriverServiceConfiguration,
        DriverStateVerificationOutcome, DriverStateVerificationReport, DRIVER_SERVICE_NAME,
    };

    fn report(
        state: DriverRuntimeState,
        outcome: DriverStateVerificationOutcome,
        findings: Vec<DriverConfigurationFinding>,
        configuration: Option<DriverServiceConfiguration>,
    ) -> DriverStateVerificationReport {
        DriverStateVerificationReport {
            service_name: DRIVER_SERVICE_NAME,
            expected_service_type: 1,
            expected_start_type: 3,
            expected_binary_path: PathBuf::from(r"C:\Windows\System32\drivers\tuffcsewinfs.sys"),
            observed_configuration: configuration,
            observed_runtime_state: state,
            configuration_findings: findings,
            outcome,
            detail: String::new(),
        }
    }

    fn verified_report(state: DriverRuntimeState) -> DriverStateVerificationReport {
        report(
            state,
            DriverStateVerificationOutcome::Verified,
            Vec::new(),
            Some(DriverServiceConfiguration {
                service_type: 1,
                start_type: 3,
                binary_path: Some(PathBuf::from(
                    r"C:\Windows\System32\drivers\tuffcsewinfs.sys",
                )),
            }),
        )
    }

    #[test]
    fn stopped_verified_report_produces_executable_plan() {
        let plan = build_driver_start_plan(&verified_report(DriverRuntimeState::Stopped))
            .expect("stopped state should authorize start");
        assert_eq!(plan.service_name, DRIVER_SERVICE_NAME);
        assert_eq!(plan.expected_precondition, DriverRuntimeState::Stopped);
    }

    #[test]
    fn running_and_start_pending_are_already_in_progress_without_execution() {
        assert_eq!(
            build_driver_start_plan(&verified_report(DriverRuntimeState::Running)),
            Err(DriverStartResult::AlreadyRunning)
        );
        assert_eq!(
            build_driver_start_plan(&verified_report(DriverRuntimeState::StartPending)),
            Err(DriverStartResult::AlreadyStarting)
        );
    }

    #[test]
    fn non_startable_states_are_rejected_without_execution() {
        let states = [
            DriverRuntimeState::NotInstalled,
            DriverRuntimeState::StopPending,
            DriverRuntimeState::ContinuePending,
            DriverRuntimeState::PausePending,
            DriverRuntimeState::Paused,
            DriverRuntimeState::Unknown(99),
        ];
        for state in states {
            let result = build_driver_start_plan(&verified_report(state));
            assert!(matches!(result, Err(DriverStartResult::Rejected { .. })));
        }
        assert!(matches!(
            build_driver_start_plan(&verified_report(DriverRuntimeState::Error {
                windows_error_code: 5,
                message: "access denied".to_string(),
            })),
            Err(DriverStartResult::Error {
                windows_error_code: 5,
                ..
            })
        ));
    }

    #[test]
    fn mismatched_or_malformed_reports_are_rejected() {
        let mismatch = report(
            DriverRuntimeState::Stopped,
            DriverStateVerificationOutcome::Mismatch,
            Vec::new(),
            Some(DriverServiceConfiguration {
                service_type: 1,
                start_type: 3,
                binary_path: None,
            }),
        );
        assert!(matches!(
            build_driver_start_plan(&mismatch),
            Err(DriverStartResult::Rejected { .. })
        ));

        let finding = verified_report(DriverRuntimeState::Stopped);
        let finding = report(
            finding.observed_runtime_state,
            DriverStateVerificationOutcome::Verified,
            vec![DriverConfigurationFinding::StartTypeMismatch {
                observed: 2,
                expected: 3,
            }],
            finding.observed_configuration,
        );
        assert!(matches!(
            build_driver_start_plan(&finding),
            Err(DriverStartResult::Rejected { .. })
        ));

        let unsupported = report(
            DriverRuntimeState::Unknown(0),
            DriverStateVerificationOutcome::Unsupported,
            Vec::new(),
            None,
        );
        assert!(matches!(
            build_driver_start_plan(&unsupported),
            Err(DriverStartResult::Rejected { .. })
        ));
    }

    #[test]
    fn cli_start_without_live_flag_is_non_mutating() {
        let binary = env!("CARGO_BIN_EXE_TuffCseWinFsSetup");
        let output = Command::new(binary)
            .args(["start"])
            .output()
            .expect("run non-live start");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success());
        assert!(stdout.contains(DRIVER_SERVICE_NAME));
        assert!(stdout.contains("start remains disabled"));
        assert!(!stdout.contains("Driver Start Result"));
        assert!(!stdout.contains("OpenSCManagerW"));
    }

    #[test]
    fn cli_start_accepts_explicit_live_flag_without_running_it() {
        let binary = env!("CARGO_BIN_EXE_TuffCseWinFsSetup");
        let output = Command::new(binary)
            .args(["start", "--help"])
            .output()
            .expect("parse live start flag");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success());
        assert!(stdout.contains("--live-driver-start"));
    }

    #[test]
    fn live_start_fails_closed_on_non_windows_without_execution() {
        if cfg!(windows) {
            return;
        }
        assert_eq!(start_driver_live(), DriverStartResult::UnsupportedPlatform);
        let binary = env!("CARGO_BIN_EXE_TuffCseWinFsSetup");
        let output = Command::new(binary)
            .args(["start", "--live-driver-start"])
            .output()
            .expect("run live start");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success());
        assert!(stderr.contains("Driver start failed"));
        assert!(stderr.contains("UnsupportedPlatform"));
    }

    #[test]
    fn source_and_docs_define_the_read_only_gated_start_boundary() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let source = fs::read_to_string(root.join("src/driver_control.rs")).unwrap();
        let lib = fs::read_to_string(root.join("src/lib.rs")).unwrap();
        let readme = fs::read_to_string(root.join("README.md")).unwrap();
        let design = fs::read_to_string(root.join("docs/DETAILED_DESIGN.md")).unwrap();
        for required in [
            "OpenSCManagerW",
            "OpenServiceW",
            "QueryServiceStatusEx",
            "StartServiceW",
            "SC_MANAGER_CONNECT",
            "SERVICE_START",
            "SERVICE_QUERY_STATUS",
        ] {
            assert!(source.contains(required), "missing `{required}`");
        }
        for forbidden in [
            "CreateService",
            "ChangeServiceConfig",
            "ControlService",
            "DeleteService",
            "DiInstallDriver",
            "DiUninstallDriver",
            "reboot",
            "shutdown",
            "device mutation",
        ] {
            assert!(!source.contains(forbidden), "unexpected `{forbidden}`");
        }
        for required in [
            "P8D_LIVE_DRIVER_START_PHASE",
            "P8D_LIVE_DRIVER_START_BOUNDARY",
            "P8D_LIVE_DRIVER_START_REQUIREMENTS",
            "P8D_LIVE_DRIVER_START_EXCLUSIONS",
        ] {
            assert!(lib.contains(required), "missing `{required}`");
        }
        assert!(readme.contains("P8D (Explicit Windows Driver Start Boundary)"));
        assert!(design.contains("P8D Explicit Windows Driver Start Boundary"));
        assert!(design.contains("P8C read-only verification report"));
    }
}
