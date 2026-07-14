use crate::driver::{self, DriverPackageState, DriverUninstallResult};
use anyhow::{anyhow, Result};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UninstallOptions {
    pub live_driver_uninstall: bool,
}

pub fn run_uninstall(force: bool) -> Result<()> {
    run_uninstall_with_options(force, None, UninstallOptions::default())
}

pub fn run_uninstall_with_options(
    force: bool,
    driver_package_path: Option<PathBuf>,
    options: UninstallOptions,
) -> Result<()> {
    println!("TUFF-CSE-WinFS v1 - Starting Uninstallation");

    if options.live_driver_uninstall && driver_package_path.is_none() {
        return Err(anyhow!(
            "--live-driver-uninstall requires --driver-package."
        ));
    }

    let driver_pkg = if let Some(path) = driver_package_path {
        println!("Checking driver package at {:?}", path);
        let pkg = driver::validate_driver_package(path)?;
        match pkg.state {
            DriverPackageState::DistributionCandidate => {
                println!("  Driver Package: Distribution Ready (INF/SYS/CAT found).");
            }
            DriverPackageState::BuiltUnsigned => {
                println!(
                    "  Driver Package: Built Unsigned (INF/SYS found, CAT missing). Not ready for live uninstall."
                );
            }
            DriverPackageState::BuildReadySource => {
                println!("  Driver Package: Build Ready Source (INF/vcxproj/sln found).");
            }
            DriverPackageState::SourceSkeleton => {
                println!("  Driver Package: Source Skeleton (INF found).");
            }
            DriverPackageState::Invalid => {}
        }
        Some(pkg)
    } else {
        println!("No driver package specified. Uninstall will remain non-mutating.");
        None
    };

    if !options.live_driver_uninstall {
        if let Some(pkg) = driver_pkg.as_ref() {
            let plan = driver::build_driver_uninstall_plan(pkg)?;
            println!(
                "Driver uninstall plan prepared for {:?}.",
                plan.canonical_inf_path
            );
            println!(
                "Driver uninstall remains disabled. Use --live-driver-uninstall explicitly on Windows to execute DiUninstallDriverW."
            );
        } else if force {
            println!("Force flag detected. (P8B stub: actual uninstall skipped safety)");
            println!(
                "Status: Actual driver removal remains pending explicit live-uninstall boundary."
            );
            println!("Status: Management directory cleanup not performed in P8B boundary.");
        } else {
            println!(
                "Status: Actual driver removal remains pending explicit live-uninstall boundary."
            );
            println!("Status: Management directory cleanup not performed in P8B boundary.");
        }
        return Ok(());
    }

    let pkg =
        driver_pkg.ok_or_else(|| anyhow!("--live-driver-uninstall requires --driver-package."))?;
    let plan = driver::build_driver_uninstall_plan(&pkg)?;
    match driver::execute_driver_uninstall(&plan) {
        DriverUninstallResult::Success => {
            println!("Driver uninstall completed successfully.");
        }
        DriverUninstallResult::SuccessWithRebootRequired => {
            println!("Driver uninstall completed successfully. Reboot required.");
        }
        DriverUninstallResult::Error {
            windows_error_code,
            message,
        } => {
            return Err(anyhow!(
                "Driver uninstall failed (Windows error {}): {}",
                windows_error_code,
                message
            ));
        }
    }

    Ok(())
}
