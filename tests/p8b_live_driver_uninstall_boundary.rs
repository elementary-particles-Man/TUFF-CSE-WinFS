#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use tempfile::tempdir;
    use tuff_cse_winfs::driver::{
        build_driver_uninstall_plan, execute_driver_uninstall, validate_driver_package,
        DriverPackageState, DriverUninstallResult,
    };
    use tuff_cse_winfs::uninstall::{run_uninstall_with_options, UninstallOptions};

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn read(path: impl AsRef<Path>) -> String {
        fs::read_to_string(path).unwrap()
    }

    fn write_package(include_sys: bool, include_cat: bool) -> tempfile::TempDir {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("tuffcsewinfs.inf"), b"[Version]\n").expect("write inf");
        if include_sys {
            fs::write(dir.path().join("tuffcsewinfs.sys"), b"driver").expect("write sys");
        }
        if include_cat {
            fs::write(dir.path().join("tuffcsewinfs.cat"), b"catalog").expect("write cat");
        }
        dir
    }

    fn assert_contains(text: &str, needle: &str) {
        assert!(text.contains(needle), "missing `{needle}`");
    }

    #[test]
    fn uninstall_plan_requires_distribution_candidate_and_canonical_inf_path() {
        let dir = write_package(true, true);
        let package = validate_driver_package(dir.path()).expect("validate package");
        assert_eq!(package.state, DriverPackageState::DistributionCandidate);

        let plan = build_driver_uninstall_plan(&package).expect("build uninstall plan");
        assert_eq!(
            plan.canonical_inf_path,
            dir.path()
                .join("tuffcsewinfs.inf")
                .canonicalize()
                .expect("canonical inf")
        );
        assert_eq!(plan.package_root, dir.path());
    }

    #[test]
    fn missing_sys_or_cat_rejects_live_uninstall_plan() {
        for (include_sys, include_cat) in [(true, false), (false, true), (false, false)] {
            let dir = write_package(include_sys, include_cat);
            let package = validate_driver_package(dir.path()).expect("validate package");
            assert_ne!(package.state, DriverPackageState::DistributionCandidate);

            let error =
                build_driver_uninstall_plan(&package).expect_err("must reject non-candidate");
            assert!(error.to_string().contains("distribution candidate package"));
        }
    }

    #[test]
    fn cli_remains_non_mutating_without_live_flag() {
        let dir = write_package(true, true);
        run_uninstall_with_options(
            false,
            Some(dir.path().to_path_buf()),
            UninstallOptions {
                live_driver_uninstall: false,
            },
        )
        .expect("non-mutating uninstall");
    }

    #[cfg(not(windows))]
    #[test]
    fn live_uninstall_fails_closed_outside_windows() {
        let dir = write_package(true, true);
        let package = validate_driver_package(dir.path()).expect("validate package");
        let plan = build_driver_uninstall_plan(&package).expect("build uninstall plan");

        match execute_driver_uninstall(&plan) {
            DriverUninstallResult::Error {
                windows_error_code,
                message,
            } => {
                assert_eq!(windows_error_code, 0);
                assert!(message.contains("supported only on Windows"));
            }
            other => panic!("unexpected live uninstall result: {other:?}"),
        }
    }

    #[test]
    fn source_and_constants_describe_the_uninstall_boundary() {
        let readme = read(repo_root().join("README.md"));
        let design = read(repo_root().join("docs/DETAILED_DESIGN.md"));
        let driver_source = read(repo_root().join("src/driver.rs"));
        let uninstall_source = read(repo_root().join("src/uninstall.rs"));
        let main_source = read(repo_root().join("src/main.rs"));

        assert_contains(&readme, "P8B (Explicit Windows Driver Uninstall Boundary)");
        assert_contains(&design, "P8B Explicit Windows Driver Uninstall Boundary");
        assert_contains(&driver_source, "DiUninstallDriverW");
        assert_contains(&driver_source, "need_reboot");
        assert_contains(&driver_source, "SuccessWithRebootRequired");
        assert_contains(&uninstall_source, "DiUninstallDriverW");
        assert_contains(&uninstall_source, "live_driver_uninstall");
        assert_contains(&main_source, "live_driver_uninstall");
        assert_contains(&main_source, "driver_package");

        assert_eq!(tuff_cse_winfs::P8B_LIVE_DRIVER_UNINSTALL_PHASE, "P8B");
        assert_eq!(
            tuff_cse_winfs::P8B_LIVE_DRIVER_UNINSTALL_BOUNDARY,
            "Explicit Windows Driver Uninstall Boundary"
        );
        assert!(tuff_cse_winfs::P8B_LIVE_DRIVER_UNINSTALL_REQUIREMENTS
            .contains(&"explicit --live-driver-uninstall flag"));
        assert!(tuff_cse_winfs::P8B_LIVE_DRIVER_UNINSTALL_EXCLUSIONS
            .contains(&"automatic driver uninstall"));
        assert!(matches!(
            DriverUninstallResult::SuccessWithRebootRequired,
            DriverUninstallResult::SuccessWithRebootRequired
        ));
    }
}
