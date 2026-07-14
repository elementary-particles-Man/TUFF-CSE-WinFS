use crate::completion;
use crate::driver;
use crate::layout;
use crate::policy;
use crate::volume;
use anyhow::{anyhow, Result};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InstallOptions {
    pub dry_run: bool,
    pub live_driver_install: bool,
}

pub fn run_install(
    policy_path: PathBuf,
    driver_package_path: Option<PathBuf>,
    dry_run: bool,
) -> Result<()> {
    run_install_with_options(
        policy_path,
        driver_package_path,
        InstallOptions {
            dry_run,
            live_driver_install: false,
        },
    )
}

pub fn run_install_with_options(
    policy_path: PathBuf,
    driver_package_path: Option<PathBuf>,
    options: InstallOptions,
) -> Result<()> {
    println!("TUFF-CSE-WinFS v1 - Starting Installation");

    if options.dry_run && options.live_driver_install {
        return Err(anyhow!("--dry-run and --live-driver-install cannot be used together."));
    }
    if options.live_driver_install && driver_package_path.is_none() {
        return Err(anyhow!("--live-driver-install requires --driver-package."));
    }

    // 1. Load Policy
    let policy = policy::load_policy(&policy_path)?;
    println!("Policy ID: {} loaded.", policy.policy_id);

    // 2. Evaluate Targets
    let mut target_count = 0;
    let mut excluded_count = 0;
    for target in &policy.targets {
        if !target.cse {
            continue;
        }
        let eval = volume::evaluate_target(&target.volume);
        if eval.is_target {
            target_count += 1;
            println!("Target Volume: {} [{}]", eval.volume, eval.reason);
        } else {
            excluded_count += 1;
            println!("Excluded Volume: {} [{}]", eval.volume, eval.reason);
        }
    }

    // 3. Check Driver Package
    let driver_pkg = if let Some(path) = driver_package_path {
        println!("Checking driver package at {:?}", path);
        let pkg = driver::validate_driver_package(path)?;
        match pkg.state {
            driver::DriverPackageState::DistributionCandidate => {
                println!("  Driver Package: Distribution Ready (INF/SYS/CAT found).");
            }
            driver::DriverPackageState::BuiltUnsigned => {
                println!(
                    "  Driver Package: Built Unsigned (INF/SYS found, CAT missing). Not ready for distribution."
                );
            }
            driver::DriverPackageState::BuildReadySource => {
                println!("  Driver Package: Build Ready Source (INF/vcxproj/sln found).");
            }
            driver::DriverPackageState::SourceSkeleton => {
                println!("  Driver Package: Source Skeleton (INF found).");
            }
            driver::DriverPackageState::Invalid => {}
        }
        Some(pkg)
    } else {
        println!("No driver package specified. Driver installation will be skipped.");
        None
    };

    if options.dry_run {
        println!("Dry-run complete. No changes made.");
        return Ok(());
    }

    // 4. Ensure Layout
    let root = layout::management_root();
    println!("Initializing management directory at {:?}", root);
    layout::ensure_layout(&root)?;

    // 5. Install Driver
    if let Some(pkg) = driver_pkg {
        let result = if options.live_driver_install {
            driver::install_driver_package_live(&pkg)
        } else {
            driver::install_driver_package(&pkg)
        };

        match result {
            driver::DriverInstallResult::Success => {
                println!("Driver installation completed successfully.");
            }
            driver::DriverInstallResult::PendingDriverPhase => {
                println!(
                    "Driver installation remains disabled. Use --live-driver-install explicitly on Windows to execute pnputil.exe."
                );
            }
            driver::DriverInstallResult::Error(message) => {
                return Err(anyhow!(message));
            }
        }
    }

    // 6. Generate Completion Code
    let hostname = hostname::get()?.to_string_lossy().to_string();
    let fp = completion::generate_fingerprint(&policy.policy_id, &hostname);
    let code = completion::build_success_code(
        &fp,
        &hostname,
        target_count,
        excluded_count,
        completion::CompletionStatus::BackgroundSealing,
    );

    println!("\nInstallation Summary:");
    println!("{}", code);

    Ok(())
}
