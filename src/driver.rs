use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq, Eq)]
pub enum DriverPackageState {
    SourceSkeleton,        // INF exists, but SYS/CAT might be missing (P1A)
    DistributionCandidate, // INF, SYS, and CAT all exist (P1B+)
    Invalid,               // No root or no INF
}

pub struct DriverPackage {
    pub root: PathBuf,
    pub inf_path: PathBuf,
    pub sys_path: Option<PathBuf>,
    pub cat_path: Option<PathBuf>,
    pub state: DriverPackageState,
}

pub fn validate_driver_package<P: AsRef<Path>>(path: P) -> Result<DriverPackage> {
    let root = path.as_ref();
    if !root.exists() || !root.is_dir() {
        return Err(anyhow!(
            "Driver package root not found or not a directory: {:?}",
            root
        ));
    }

    let inf_path = root.join("tuffcsewinfs.inf");
    if !inf_path.exists() {
        return Err(anyhow!("Driver package missing INF file: {:?}", inf_path));
    }

    let sys_path = root.join("tuffcsewinfs.sys");
    let cat_path = root.join("tuffcsewinfs.cat");

    let sys_exists = sys_path.exists();
    let cat_exists = cat_path.exists();

    let state = if sys_exists && cat_exists {
        DriverPackageState::DistributionCandidate
    } else {
        DriverPackageState::SourceSkeleton
    };

    Ok(DriverPackage {
        root: root.to_path_buf(),
        inf_path,
        sys_path: if sys_exists { Some(sys_path) } else { None },
        cat_path: if cat_exists { Some(cat_path) } else { None },
        state,
    })
}

pub enum DriverInstallResult {
    Success,
    PendingDriverPhase,
    Error(String),
}

pub fn install_driver_package(_package: &DriverPackage) -> DriverInstallResult {
    // P0/P1A stub
    DriverInstallResult::PendingDriverPhase
}
