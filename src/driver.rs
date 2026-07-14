use anyhow::{anyhow, Result};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

#[cfg(windows)]
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverPackageState {
    SourceSkeleton,        // INF exists, but SYS/CAT might be missing (P1A)
    BuildReadySource,      // INF, vcxproj, sln exist (P1B)
    BuiltUnsigned,         // INF, SYS exist, but CAT missing
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

#[derive(Debug, PartialEq, Eq)]
pub struct DriverInstallPlan {
    pub executable: OsString,
    pub arguments: Vec<OsString>,
    pub inf_path: PathBuf,
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
    let vcxproj_path = root.join("tuffcsewinfs.vcxproj");
    let sln_path = root.join("TUFF-CSE-WinFS.sln");

    let sys_exists = sys_path.exists();
    let cat_exists = cat_path.exists();
    let build_ready = vcxproj_path.exists() && sln_path.exists();

    let state = if sys_exists && cat_exists {
        DriverPackageState::DistributionCandidate
    } else if sys_exists {
        DriverPackageState::BuiltUnsigned
    } else if build_ready {
        DriverPackageState::BuildReadySource
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

pub fn build_driver_install_plan(package: &DriverPackage) -> Result<DriverInstallPlan> {
    if package.state != DriverPackageState::DistributionCandidate {
        return Err(anyhow!(
            "Live driver installation requires a distribution candidate package (INF/SYS/CAT). Current state: {:?}",
            package.state
        ));
    }

    if package.sys_path.as_ref().map_or(true, |path| !path.is_file()) {
        return Err(anyhow!("Driver package SYS file is missing."));
    }
    if package.cat_path.as_ref().map_or(true, |path| !path.is_file()) {
        return Err(anyhow!("Driver package CAT file is missing."));
    }

    let inf_path = package
        .inf_path
        .canonicalize()
        .map_err(|error| anyhow!("Failed to resolve driver INF path: {error}"))?;

    Ok(DriverInstallPlan {
        executable: OsString::from("pnputil.exe"),
        arguments: vec![
            OsString::from("/add-driver"),
            inf_path.as_os_str().to_owned(),
            OsString::from("/install"),
        ],
        inf_path,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum DriverInstallResult {
    Success,
    PendingDriverPhase,
    Error(String),
}

pub fn install_driver_package(_package: &DriverPackage) -> DriverInstallResult {
    DriverInstallResult::PendingDriverPhase
}

pub fn install_driver_package_live(package: &DriverPackage) -> DriverInstallResult {
    let plan = match build_driver_install_plan(package) {
        Ok(plan) => plan,
        Err(error) => return DriverInstallResult::Error(error.to_string()),
    };

    #[cfg(not(windows))]
    {
        let _ = plan;
        DriverInstallResult::Error(
            "Live driver installation is supported only on Windows.".to_string(),
        )
    }

    #[cfg(windows)]
    {
        let output = match Command::new(&plan.executable)
            .args(&plan.arguments)
            .output()
        {
            Ok(output) => output,
            Err(error) => {
                return DriverInstallResult::Error(format!(
                    "Failed to execute pnputil.exe: {error}"
                ));
            }
        };

        if output.status.success() {
            return DriverInstallResult::Success;
        }

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let detail = if !stderr.is_empty() { stderr } else { stdout };
        let detail = if detail.is_empty() {
            format!("exit status {}", output.status)
        } else {
            detail
        };

        DriverInstallResult::Error(format!("pnputil.exe driver installation failed: {detail}"))
    }
}
