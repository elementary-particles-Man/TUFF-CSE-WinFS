#[cfg(test)]
mod tests {
    use std::fs;
    use tempfile::tempdir;
    use tuff_cse_winfs::driver::{self, DriverInstallResult, DriverPackageState};

    #[test]
    fn test_missing_package_path_rejected() {
        let result = driver::validate_driver_package("non_existent_path_xyz");
        assert!(result.is_err());
    }

    #[test]
    fn test_directory_without_inf_rejected() {
        let dir = tempdir().unwrap();
        let result = driver::validate_driver_package(dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_directory_with_inf_accepted_as_source_skeleton() {
        let dir = tempdir().unwrap();
        let inf_path = dir.path().join("tuffcsewinfs.inf");
        fs::write(inf_path, "stub inf").unwrap();

        let pkg = driver::validate_driver_package(dir.path()).unwrap();
        assert_eq!(pkg.state, DriverPackageState::SourceSkeleton);
        assert!(pkg.sys_path.is_none());
        assert!(pkg.cat_path.is_none());
    }

    #[test]
    fn test_directory_with_build_files_accepted_as_build_ready_source() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("tuffcsewinfs.inf"), "stub inf").unwrap();
        fs::write(dir.path().join("tuffcsewinfs.vcxproj"), "stub vcxproj").unwrap();
        fs::write(dir.path().join("TUFF-CSE-WinFS.sln"), "stub sln").unwrap();

        let pkg = driver::validate_driver_package(dir.path()).unwrap();
        assert_eq!(pkg.state, DriverPackageState::BuildReadySource);
        assert!(pkg.sys_path.is_none());
        assert!(pkg.cat_path.is_none());
    }

    #[test]
    fn test_directory_with_sys_but_no_cat_accepted_as_built_unsigned() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("tuffcsewinfs.inf"), "stub inf").unwrap();
        fs::write(dir.path().join("tuffcsewinfs.sys"), "stub sys").unwrap();

        let pkg = driver::validate_driver_package(dir.path()).unwrap();
        assert_eq!(pkg.state, DriverPackageState::BuiltUnsigned);
        assert!(pkg.sys_path.is_some());
        assert!(pkg.cat_path.is_none());
    }

    #[test]
    fn test_directory_with_all_files_accepted_as_distribution_candidate() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("tuffcsewinfs.inf"), "stub inf").unwrap();
        fs::write(dir.path().join("tuffcsewinfs.sys"), "stub sys").unwrap();
        fs::write(dir.path().join("tuffcsewinfs.cat"), "stub cat").unwrap();

        let pkg = driver::validate_driver_package(dir.path()).unwrap();
        assert_eq!(pkg.state, DriverPackageState::DistributionCandidate);
        assert!(pkg.sys_path.is_some());
        assert!(pkg.cat_path.is_some());
    }

    #[test]
    fn test_install_driver_package_stub() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("tuffcsewinfs.inf"), "stub inf").unwrap();
        let pkg = driver::validate_driver_package(dir.path()).unwrap();

        let result = driver::install_driver_package(&pkg);
        match result {
            DriverInstallResult::PendingDriverPhase => {}
            _ => panic!("Expected PendingDriverPhase in P1A stub"),
        }
    }
}
