use std::ffi::OsString;
use std::fs;
use tempfile::tempdir;
use tuff_cse_winfs::driver::{
    build_driver_install_plan, install_driver_package, install_driver_package_live,
    validate_driver_package, DriverInstallResult, DriverPackageState,
};

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

#[test]
fn distribution_candidate_builds_fixed_pnputil_install_plan() {
    let dir = write_package(true, true);
    let package = validate_driver_package(dir.path()).expect("validate package");
    assert_eq!(package.state, DriverPackageState::DistributionCandidate);

    let plan = build_driver_install_plan(&package).expect("build install plan");
    assert_eq!(plan.executable, OsString::from("pnputil.exe"));
    assert_eq!(plan.arguments.len(), 3);
    assert_eq!(plan.arguments[0], OsString::from("/add-driver"));
    assert_eq!(plan.arguments[1], plan.inf_path.as_os_str());
    assert_eq!(plan.arguments[2], OsString::from("/install"));
    assert_eq!(
        plan.inf_path,
        dir.path()
            .join("tuffcsewinfs.inf")
            .canonicalize()
            .expect("canonical inf")
    );
}

#[test]
fn unsigned_package_is_rejected_before_command_execution() {
    let dir = write_package(true, false);
    let package = validate_driver_package(dir.path()).expect("validate package");
    assert_eq!(package.state, DriverPackageState::BuiltUnsigned);

    let error = build_driver_install_plan(&package).expect_err("unsigned package must fail");
    assert!(error
        .to_string()
        .contains("requires a distribution candidate package"));
}

#[test]
fn legacy_install_entry_point_remains_non_mutating() {
    let dir = write_package(true, true);
    let package = validate_driver_package(dir.path()).expect("validate package");

    assert_eq!(
        install_driver_package(&package),
        DriverInstallResult::PendingDriverPhase
    );
}

#[cfg(not(windows))]
#[test]
fn live_install_fails_closed_outside_windows() {
    let dir = write_package(true, true);
    let package = validate_driver_package(dir.path()).expect("validate package");

    let result = install_driver_package_live(&package);
    match result {
        DriverInstallResult::Error(message) => {
            assert!(message.contains("supported only on Windows"));
        }
        other => panic!("unexpected live install result: {other:?}"),
    }
}
