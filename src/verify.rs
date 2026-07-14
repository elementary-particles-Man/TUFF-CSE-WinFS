use crate::driver_state;
use crate::layout;
use crate::policy;
use anyhow::Result;
use std::path::PathBuf;

pub fn run_verify(policy_path: Option<PathBuf>) -> Result<()> {
    println!("TUFF-CSE-WinFS v1 - Starting Verification");

    // 1. Check Layout
    let root = layout::management_root();
    println!("Checking management directory at {:?}", root);
    if !root.exists() {
        println!("Management directory NOT FOUND.");
    } else {
        println!("Management directory FOUND.");
        let subdirs = ["BTM", "JRN", "META", "KEYS"];
        for subdir in &subdirs {
            let mut path = root.clone();
            path.push(subdir);
            if path.exists() {
                println!(" Subdir {}: OK", subdir);
            } else {
                println!(" Subdir {}: MISSING", subdir);
            }
        }
    }

    // 2. Check Policy if provided
    if let Some(path) = policy_path {
        println!("Checking policy at {:?}", path);
        match policy::load_policy(&path) {
            Ok(p) => println!(" Policy {}: Valid", p.policy_id),
            Err(e) => println!(" Policy Error: {}", e),
        }
    }

    // 3. Read-only driver state verification boundary
    let report = driver_state::collect_driver_state_verification_report();
    println!(
        "Driver State Query: service={} expected_type={} expected_start={} expected_binary={:?}",
        report.service_name,
        driver_state::DRIVER_EXPECTED_SERVICE_TYPE_LABEL,
        driver_state::DRIVER_EXPECTED_START_TYPE_LABEL,
        report.expected_binary_path
    );
    println!("Driver State Query Outcome: {:?}", report.outcome);
    println!("Driver State Query Detail: {}", report.detail);
    if let Some(observed_type) = report.observed_service_type {
        println!(" Observed service type: {}", observed_type);
    }
    if let Some(observed_start_type) = report.observed_start_type {
        println!(" Observed start type: {}", observed_start_type);
    }
    if let Some(observed_binary_path) = report.observed_binary_path {
        println!(" Observed binary path: {:?}", observed_binary_path);
    }
    if let Some(observed_state) = report.observed_current_state {
        println!(" Observed current state: {}", observed_state);
    }

    // Keep the legacy phase marker so CI and documentation remain stable.
    println!("Driver Status: PENDING_DRIVER_PHASE");

    Ok(())
}
