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
                println!("  Subdir {}: OK", subdir);
            } else {
                println!("  Subdir {}: MISSING", subdir);
            }
        }
    }

    // 2. Check Policy if provided
    if let Some(path) = policy_path {
        println!("Checking policy at {:?}", path);
        match policy::load_policy(&path) {
            Ok(p) => println!("  Policy {}: Valid", p.policy_id),
            Err(e) => println!("  Policy Error: {}", e),
        }
    }

    // 3. Driver Status (Stub)
    println!("Driver Status: PENDING_DRIVER_PHASE");

    Ok(())
}
