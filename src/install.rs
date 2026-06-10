use crate::completion;
use crate::driver;
use crate::layout;
use crate::policy;
use crate::volume;
use anyhow::Result;
use std::path::PathBuf;

pub fn run_install(
    policy_path: PathBuf,
    driver_package_path: Option<PathBuf>,
    dry_run: bool,
) -> Result<()> {
    println!("TUFF-CSE-WinFS v1 - Starting Installation");

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
        Some(driver::validate_driver_package(path)?)
    } else {
        println!("No driver package specified. Driver installation will be skipped in this phase.");
        None
    };

    if dry_run {
        println!("Dry-run complete. No changes made.");
        return Ok(());
    }

    // 4. Ensure Layout
    let root = layout::management_root();
    println!("Initializing management directory at {:?}", root);
    layout::ensure_layout(&root)?;

    // 5. Install Driver (Stub)
    if let Some(pkg) = driver_pkg {
        match driver::install_driver_package(&pkg) {
            driver::DriverInstallResult::PendingDriverPhase => {
                println!("Driver installation is PENDING (Phase P1 Required).");
            }
            _ => println!("Driver installation handled."),
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
