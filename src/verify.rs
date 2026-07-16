use crate::driver_state;
use crate::layout;
use crate::policy;
use anyhow::{anyhow, Result};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VerifyOptions {
    pub live_driver_status: bool,
}

pub fn run_verify(policy_path: Option<PathBuf>) -> Result<()> {
    run_verify_with_options(policy_path, VerifyOptions::default())
}

pub fn run_verify_with_options(policy_path: Option<PathBuf>, options: VerifyOptions) -> Result<()> {
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

    if options.live_driver_status {
        let report = driver_state::collect_driver_state_verification_report();
        if matches!(
            report.outcome,
            driver_state::DriverStateVerificationOutcome::Unsupported
        ) {
            return Err(anyhow!(
                "--live-driver-status is unsupported on non-Windows platforms: {}",
                report.detail
            ));
        }
        println!(
            "Driver State Query: service={} expected_type={} expected_start={} expected_binary={:?}",
            report.service_name,
            driver_state::DRIVER_EXPECTED_SERVICE_TYPE_LABEL,
            driver_state::DRIVER_EXPECTED_START_TYPE_LABEL,
            report.expected_binary_path
        );
        println!("Driver Runtime State: {:?}", report.observed_runtime_state);
        println!(
            "Observed Configuration: {:?}",
            report.observed_configuration
        );
        println!(
            "Configuration Findings: {:?}",
            report.configuration_findings
        );
        println!("Driver State Query Outcome: {:?}", report.outcome);
        println!("Driver State Query Detail: {}", report.detail);
        if let driver_state::DriverRuntimeState::Error {
            windows_error_code, ..
        } = &report.observed_runtime_state
        {
            println!("Windows Error Code: {}", windows_error_code);
        }
    } else {
        // Keep the legacy phase marker and output stable on the default path.
        println!("Driver Status: PENDING_DRIVER_PHASE");
    }

    Ok(())
}
