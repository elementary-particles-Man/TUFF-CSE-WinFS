use std::path::{Path, PathBuf};

pub const DRIVER_SERVICE_NAME: &str = "tuffcsewinfs";
pub const DRIVER_EXPECTED_SERVICE_TYPE: u32 = 0x0000_0001;
pub const DRIVER_EXPECTED_START_TYPE: u32 = 0x0000_0003;
pub const DRIVER_EXPECTED_BINARY_RELATIVE_PATH: &str = r"System32\drivers\tuffcsewinfs.sys";
pub const DRIVER_EXPECTED_SERVICE_TYPE_LABEL: &str = "SERVICE_KERNEL_DRIVER";
pub const DRIVER_EXPECTED_START_TYPE_LABEL: &str = "SERVICE_DEMAND_START";
pub const ERROR_SERVICE_DOES_NOT_EXIST_CODE: u32 = 1060;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverRuntimeState {
    NotInstalled,
    Stopped,
    StartPending,
    StopPending,
    Running,
    ContinuePending,
    PausePending,
    Paused,
    Unknown(u32),
    Error {
        windows_error_code: u32,
        message: String,
    },
}

pub fn map_windows_service_state(state: u32) -> DriverRuntimeState {
    match state {
        1 => DriverRuntimeState::Stopped,
        2 => DriverRuntimeState::StartPending,
        3 => DriverRuntimeState::StopPending,
        4 => DriverRuntimeState::Running,
        5 => DriverRuntimeState::ContinuePending,
        6 => DriverRuntimeState::PausePending,
        7 => DriverRuntimeState::Paused,
        other => DriverRuntimeState::Unknown(other),
    }
}

pub fn map_windows_service_error(
    windows_error_code: u32,
    message: impl Into<String>,
) -> DriverRuntimeState {
    if windows_error_code == ERROR_SERVICE_DOES_NOT_EXIST_CODE {
        DriverRuntimeState::NotInstalled
    } else {
        DriverRuntimeState::Error {
            windows_error_code,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverServiceConfiguration {
    pub service_type: u32,
    pub start_type: u32,
    pub binary_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverConfigurationFinding {
    ServiceTypeMismatch {
        observed: u32,
        expected_bit: u32,
    },
    StartTypeMismatch {
        observed: u32,
        expected: u32,
    },
    BinaryPathMismatch {
        observed: Option<PathBuf>,
        expected: PathBuf,
    },
}

pub fn evaluate_driver_service_configuration(
    observed: &DriverServiceConfiguration,
    expected_binary_path: impl AsRef<Path>,
) -> Vec<DriverConfigurationFinding> {
    let expected_binary_path = expected_binary_path.as_ref().to_path_buf();
    let mut findings = Vec::new();

    if observed.service_type & DRIVER_EXPECTED_SERVICE_TYPE == 0 {
        findings.push(DriverConfigurationFinding::ServiceTypeMismatch {
            observed: observed.service_type,
            expected_bit: DRIVER_EXPECTED_SERVICE_TYPE,
        });
    }
    if observed.start_type != DRIVER_EXPECTED_START_TYPE {
        findings.push(DriverConfigurationFinding::StartTypeMismatch {
            observed: observed.start_type,
            expected: DRIVER_EXPECTED_START_TYPE,
        });
    }
    if observed
        .binary_path
        .as_ref()
        .map(|path| {
            normalize_driver_binary_path(path, &expected_binary_path)
                != normalize_driver_binary_path(&expected_binary_path, &expected_binary_path)
        })
        .unwrap_or(true)
    {
        findings.push(DriverConfigurationFinding::BinaryPathMismatch {
            observed: observed.binary_path.clone(),
            expected: expected_binary_path,
        });
    }

    findings
}

pub fn expected_driver_binary_path_from_windows_root(system_root: impl AsRef<Path>) -> PathBuf {
    let root = system_root
        .as_ref()
        .to_string_lossy()
        .trim_end_matches(['\\', '/'])
        .to_string();
    PathBuf::from(format!(r"{root}\System32\drivers\tuffcsewinfs.sys"))
}

pub fn expected_driver_binary_path_from_system_root(system_root: impl AsRef<Path>) -> PathBuf {
    expected_driver_binary_path_from_windows_root(system_root)
}

pub fn expected_driver_binary_path_from_system_directory(
    system_directory: impl AsRef<Path>,
) -> PathBuf {
    let system_directory = system_directory
        .as_ref()
        .to_string_lossy()
        .trim_end_matches(['\\', '/'])
        .to_string();
    PathBuf::from(format!(r"{system_directory}\drivers\tuffcsewinfs.sys"))
}

pub fn normalize_driver_binary_path(path: impl AsRef<Path>, expected: impl AsRef<Path>) -> String {
    let expected = expected.as_ref().to_string_lossy().replace('/', "\\");
    let system_root = expected
        .strip_suffix(r"\System32\drivers\tuffcsewinfs.sys")
        .unwrap_or("");
    let mut normalized = path.as_ref().to_string_lossy().trim().to_string();
    if normalized.len() >= 2 && normalized.starts_with('"') && normalized.ends_with('"') {
        normalized = normalized[1..normalized.len() - 1].to_string();
    }
    normalized = normalized.replace('/', "\\");
    let lower = normalized.to_ascii_lowercase();
    let root_lower = system_root.to_ascii_lowercase();
    let normalized = if lower.starts_with(r"%systemroot%\") {
        format!(r"{}\{}", system_root, &normalized[13..])
    } else if lower.starts_with(r"\systemroot\") {
        format!(r"{}{}", system_root, &normalized[11..])
    } else if lower.starts_with(r"\??\") {
        normalized[4..].to_string()
    } else if lower.starts_with(r"\\?\") {
        normalized[4..].to_string()
    } else {
        normalized
    };
    let normalized = normalized.trim_end_matches('\\').to_ascii_lowercase();
    if normalized.starts_with(&root_lower) {
        normalized
    } else {
        normalized
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverStateVerificationOutcome {
    Verified,
    MissingService,
    Mismatch,
    Unsupported,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverStateVerificationReport {
    pub service_name: &'static str,
    pub expected_service_type: u32,
    pub expected_start_type: u32,
    pub expected_binary_path: PathBuf,
    pub observed_configuration: Option<DriverServiceConfiguration>,
    pub observed_runtime_state: DriverRuntimeState,
    pub configuration_findings: Vec<DriverConfigurationFinding>,
    pub outcome: DriverStateVerificationOutcome,
    pub detail: String,
}

pub fn collect_driver_state_verification_report() -> DriverStateVerificationReport {
    #[cfg(windows)]
    {
        return collect_driver_state_verification_report_windows();
    }

    #[cfg(not(windows))]
    {
        DriverStateVerificationReport {
            service_name: DRIVER_SERVICE_NAME,
            expected_service_type: DRIVER_EXPECTED_SERVICE_TYPE,
            expected_start_type: DRIVER_EXPECTED_START_TYPE,
            expected_binary_path: expected_driver_binary_path_from_windows_root(Path::new(
                r"C:\Windows",
            )),
            observed_configuration: None,
            observed_runtime_state: DriverRuntimeState::Error {
                windows_error_code: 0,
                message: "Read-only SCM queries are available only on Windows.".to_string(),
            },
            configuration_findings: Vec::new(),
            outcome: DriverStateVerificationOutcome::Unsupported,
            detail: "Read-only SCM queries are available only on Windows.".to_string(),
        }
    }
}

#[cfg(windows)]
fn collect_driver_state_verification_report_windows() -> DriverStateVerificationReport {
    use std::ffi::OsString;
    use std::io;
    use std::mem::{size_of, MaybeUninit};
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_SERVICE_DOES_NOT_EXIST};
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceConfigW,
        QueryServiceStatusEx, QUERY_SERVICE_CONFIGW, SC_HANDLE, SC_MANAGER_CONNECT,
        SC_STATUS_PROCESS_INFO, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_STATUS_PROCESS,
    };
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

    #[derive(Debug)]
    struct ServiceHandle(SC_HANDLE);

    impl Drop for ServiceHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CloseServiceHandle(self.0) };
            }
        }
    }

    fn base_report(expected_binary_path: PathBuf) -> DriverStateVerificationReport {
        DriverStateVerificationReport {
            service_name: DRIVER_SERVICE_NAME,
            expected_service_type: DRIVER_EXPECTED_SERVICE_TYPE,
            expected_start_type: DRIVER_EXPECTED_START_TYPE,
            expected_binary_path,
            observed_configuration: None,
            observed_runtime_state: DriverRuntimeState::Unknown(0),
            configuration_findings: Vec::new(),
            outcome: DriverStateVerificationOutcome::Error,
            detail: String::new(),
        }
    }

    let mut buffer = vec![0u16; 32768];
    let len = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if len == 0 {
        let mut report = base_report(expected_driver_binary_path_from_windows_root(Path::new(
            r"C:\Windows",
        )));
        let code = unsafe { GetLastError() };
        let message = io::Error::from_raw_os_error(code as i32).to_string();
        report.observed_runtime_state = map_windows_service_error(code, message.clone());
        report.detail = format!("GetSystemDirectoryW failed: {message}");
        return report;
    }
    buffer.truncate(len as usize);
    let system_directory = PathBuf::from(OsString::from_wide(&buffer));
    let expected_binary_path = expected_driver_binary_path_from_system_directory(&system_directory);

    let scm = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if scm.is_null() {
        let code = unsafe { GetLastError() };
        let message = io::Error::from_raw_os_error(code as i32).to_string();
        let mut report = base_report(expected_binary_path);
        report.observed_runtime_state = map_windows_service_error(code, message.clone());
        report.detail = format!("OpenSCManagerW failed: {message}");
        return report;
    }
    let scm = ServiceHandle(scm);
    let service_name: Vec<u16> = DRIVER_SERVICE_NAME.encode_utf16().chain(Some(0)).collect();
    let service = unsafe {
        OpenServiceW(
            scm.0,
            service_name.as_ptr(),
            SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG,
        )
    };
    if service.is_null() {
        let code = unsafe { GetLastError() };
        let message = io::Error::from_raw_os_error(code as i32).to_string();
        let mut report = base_report(expected_binary_path);
        report.observed_runtime_state = map_windows_service_error(code, message.clone());
        report.outcome = if code == ERROR_SERVICE_DOES_NOT_EXIST {
            DriverStateVerificationOutcome::MissingService
        } else {
            DriverStateVerificationOutcome::Error
        };
        report.detail = format!("OpenServiceW failed: {message}");
        return report;
    }
    let service = ServiceHandle(service);

    let mut bytes_needed = 0u32;
    unsafe { QueryServiceConfigW(service.0, std::ptr::null_mut(), 0, &mut bytes_needed) };
    if bytes_needed == 0 {
        let code = unsafe { GetLastError() };
        let message = io::Error::from_raw_os_error(code as i32).to_string();
        let mut report = base_report(expected_binary_path);
        report.observed_runtime_state = map_windows_service_error(code, message.clone());
        report.detail = format!("QueryServiceConfigW sizing failed: {message}");
        return report;
    }
    let word_count = (bytes_needed as usize + size_of::<usize>() - 1) / size_of::<usize>();
    let mut config_buffer = vec![0usize; word_count];
    let ok = unsafe {
        QueryServiceConfigW(
            service.0,
            config_buffer.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW,
            (config_buffer.len() * size_of::<usize>()) as u32,
            &mut bytes_needed,
        )
    };
    if ok == 0 {
        let code = unsafe { GetLastError() };
        let message = io::Error::from_raw_os_error(code as i32).to_string();
        let mut report = base_report(expected_binary_path);
        report.observed_runtime_state = map_windows_service_error(code, message.clone());
        report.detail = format!("QueryServiceConfigW failed: {message}");
        return report;
    }
    let config = unsafe { &*(config_buffer.as_ptr() as *const QUERY_SERVICE_CONFIGW) };
    let binary_path = if config.lpBinaryPathName.is_null() {
        None
    } else {
        let mut length = 0usize;
        unsafe {
            while *config.lpBinaryPathName.add(length) != 0 {
                length += 1;
            }
            Some(PathBuf::from(OsString::from_wide(
                std::slice::from_raw_parts(config.lpBinaryPathName, length),
            )))
        }
    };
    let observed_configuration = DriverServiceConfiguration {
        service_type: config.dwServiceType,
        start_type: config.dwStartType,
        binary_path,
    };
    let findings =
        evaluate_driver_service_configuration(&observed_configuration, &expected_binary_path);

    let mut status = MaybeUninit::<SERVICE_STATUS_PROCESS>::zeroed();
    let mut status_bytes_needed = 0u32;
    let status_ok = unsafe {
        QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            status.as_mut_ptr() as *mut u8,
            size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut status_bytes_needed,
        )
    };
    if status_ok == 0 {
        let code = unsafe { GetLastError() };
        let message = io::Error::from_raw_os_error(code as i32).to_string();
        let mut report = base_report(expected_binary_path);
        report.observed_configuration = Some(observed_configuration);
        report.configuration_findings = findings;
        report.observed_runtime_state = map_windows_service_error(code, message.clone());
        report.outcome = DriverStateVerificationOutcome::Error;
        report.detail = format!("QueryServiceStatusEx failed: {message}");
        return report;
    }
    let runtime_state = map_windows_service_state(unsafe { status.assume_init().dwCurrentState });
    let outcome = if findings.is_empty() {
        DriverStateVerificationOutcome::Verified
    } else {
        DriverStateVerificationOutcome::Mismatch
    };
    DriverStateVerificationReport {
        service_name: DRIVER_SERVICE_NAME,
        expected_service_type: DRIVER_EXPECTED_SERVICE_TYPE,
        expected_start_type: DRIVER_EXPECTED_START_TYPE,
        expected_binary_path,
        observed_configuration: Some(observed_configuration),
        observed_runtime_state: runtime_state,
        configuration_findings: findings.clone(),
        outcome,
        detail: if findings.is_empty() {
            "Read-only driver configuration matched the expected boundary.".to_string()
        } else {
            format!("Configuration findings: {findings:?}")
        },
    }
}
