use std::path::{Path, PathBuf};

pub const DRIVER_SERVICE_NAME: &str = "tuffcsewinfs";
pub const DRIVER_EXPECTED_SERVICE_TYPE: u32 = 0x0000_0001;
pub const DRIVER_EXPECTED_START_TYPE: u32 = 0x0000_0003;
pub const DRIVER_EXPECTED_BINARY_RELATIVE_PATH: &str = r"System32\drivers\tuffcsewinfs.sys";
pub const DRIVER_EXPECTED_SERVICE_TYPE_LABEL: &str = "SERVICE_KERNEL_DRIVER";
pub const DRIVER_EXPECTED_START_TYPE_LABEL: &str = "SERVICE_DEMAND_START";

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
    pub observed_service_type: Option<u32>,
    pub observed_start_type: Option<u32>,
    pub observed_binary_path: Option<PathBuf>,
    pub observed_current_state: Option<u32>,
    pub outcome: DriverStateVerificationOutcome,
    pub detail: String,
}

pub fn expected_driver_binary_path_from_system_root(system_root: impl AsRef<Path>) -> PathBuf {
    let root = system_root
        .as_ref()
        .to_string_lossy()
        .trim_end_matches(['\\', '/'])
        .to_string();
    PathBuf::from(format!(r"{root}\System32\drivers\tuffcsewinfs.sys",))
}

pub fn collect_driver_state_verification_report() -> DriverStateVerificationReport {
    #[cfg(windows)]
    {
        return collect_driver_state_verification_report_windows();
    }

    #[cfg(not(windows))]
    {
        return DriverStateVerificationReport {
            service_name: DRIVER_SERVICE_NAME,
            expected_service_type: DRIVER_EXPECTED_SERVICE_TYPE,
            expected_start_type: DRIVER_EXPECTED_START_TYPE,
            expected_binary_path: expected_driver_binary_path_from_system_root(Path::new(
                r"C:\Windows",
            )),
            observed_service_type: None,
            observed_start_type: None,
            observed_binary_path: None,
            observed_current_state: None,
            outcome: DriverStateVerificationOutcome::Unsupported,
            detail: "Read-only SCM queries are available only on Windows.".to_string(),
        };
    }
}

#[cfg(windows)]
fn collect_driver_state_verification_report_windows() -> DriverStateVerificationReport {
    use std::ffi::OsString;
    use std::io;
    use std::mem::{size_of, MaybeUninit};
    use std::os::windows::ffi::OsStringExt;
    use std::path::PathBuf;
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_SERVICE_DOES_NOT_EXIST};
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceConfigW,
        QueryServiceStatusEx, QUERY_SERVICE_CONFIGW, SC_HANDLE, SC_MANAGER_CONNECT,
        SC_STATUS_PROCESS_INFO, SERVICE_DEMAND_START, SERVICE_KERNEL_DRIVER, SERVICE_QUERY_CONFIG,
        SERVICE_QUERY_STATUS, SERVICE_STATUS_PROCESS,
    };
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

    #[derive(Debug)]
    struct ServiceHandle(SC_HANDLE);

    impl Drop for ServiceHandle {
        fn drop(&mut self) {
            unsafe {
                CloseServiceHandle(self.0);
            }
        }
    }

    unsafe fn wide_ptr_to_path(ptr: *const u16) -> Option<PathBuf> {
        if ptr.is_null() {
            return None;
        }

        let mut len = 0usize;
        while *ptr.add(len) != 0 {
            len += 1;
        }

        let slice = std::slice::from_raw_parts(ptr, len);
        Some(PathBuf::from(OsString::from_wide(slice)))
    }

    fn normalize_path(path: &Path) -> String {
        path.to_string_lossy()
            .replace('/', "\\")
            .to_ascii_lowercase()
    }

    fn expected_binary_path() -> Result<PathBuf, String> {
        let mut buffer = vec![0u16; 32768];
        let len = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
        if len == 0 {
            return Err(format!(
                "GetSystemDirectoryW failed: {}",
                io::Error::last_os_error()
            ));
        }
        buffer.truncate(len as usize);
        let system_root = PathBuf::from(OsString::from_wide(&buffer));
        Ok(expected_driver_binary_path_from_system_root(system_root))
    }

    let expected_binary_path = match expected_binary_path() {
        Ok(path) => path,
        Err(detail) => {
            return DriverStateVerificationReport {
                service_name: DRIVER_SERVICE_NAME,
                expected_service_type: DRIVER_EXPECTED_SERVICE_TYPE,
                expected_start_type: DRIVER_EXPECTED_START_TYPE,
                expected_binary_path: expected_driver_binary_path_from_system_root(Path::new(
                    r"C:\Windows",
                )),
                observed_service_type: None,
                observed_start_type: None,
                observed_binary_path: None,
                observed_current_state: None,
                outcome: DriverStateVerificationOutcome::Error,
                detail,
            };
        }
    };

    let scm = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if scm == std::ptr::null_mut() {
        return DriverStateVerificationReport {
            service_name: DRIVER_SERVICE_NAME,
            expected_service_type: DRIVER_EXPECTED_SERVICE_TYPE,
            expected_start_type: DRIVER_EXPECTED_START_TYPE,
            expected_binary_path,
            observed_service_type: None,
            observed_start_type: None,
            observed_binary_path: None,
            observed_current_state: None,
            outcome: DriverStateVerificationOutcome::Error,
            detail: format!("OpenSCManagerW failed: {}", io::Error::last_os_error()),
        };
    }

    let scm = ServiceHandle(scm);
    let service_name: Vec<u16> = DRIVER_SERVICE_NAME.encode_utf16().chain(Some(0)).collect();
    let service = unsafe {
        OpenServiceW(
            scm.0,
            service_name.as_ptr(),
            SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS,
        )
    };
    if service == std::ptr::null_mut() {
        let error = unsafe { GetLastError() };
        let outcome = if error == ERROR_SERVICE_DOES_NOT_EXIST {
            DriverStateVerificationOutcome::MissingService
        } else {
            DriverStateVerificationOutcome::Error
        };
        return DriverStateVerificationReport {
            service_name: DRIVER_SERVICE_NAME,
            expected_service_type: DRIVER_EXPECTED_SERVICE_TYPE,
            expected_start_type: DRIVER_EXPECTED_START_TYPE,
            expected_binary_path,
            observed_service_type: None,
            observed_start_type: None,
            observed_binary_path: None,
            observed_current_state: None,
            outcome,
            detail: format!(
                "OpenServiceW failed: {}",
                io::Error::from_raw_os_error(error as i32)
            ),
        };
    }

    let service = ServiceHandle(service);

    let mut bytes_needed: u32 = 0;
    unsafe {
        QueryServiceConfigW(service.0, std::ptr::null_mut(), 0, &mut bytes_needed);
    }
    if bytes_needed == 0 {
        return DriverStateVerificationReport {
            service_name: DRIVER_SERVICE_NAME,
            expected_service_type: DRIVER_EXPECTED_SERVICE_TYPE,
            expected_start_type: DRIVER_EXPECTED_START_TYPE,
            expected_binary_path,
            observed_service_type: None,
            observed_start_type: None,
            observed_binary_path: None,
            observed_current_state: None,
            outcome: DriverStateVerificationOutcome::Error,
            detail: format!(
                "QueryServiceConfigW sizing failed: {}",
                io::Error::last_os_error()
            ),
        };
    }

    let word_count =
        (bytes_needed as usize + std::mem::size_of::<usize>() - 1) / std::mem::size_of::<usize>();
    let mut config_buffer = vec![0usize; word_count];
    let ok = unsafe {
        QueryServiceConfigW(
            service.0,
            config_buffer.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW,
            (config_buffer.len() * std::mem::size_of::<usize>()) as u32,
            &mut bytes_needed,
        )
    };
    if ok == 0 {
        return DriverStateVerificationReport {
            service_name: DRIVER_SERVICE_NAME,
            expected_service_type: DRIVER_EXPECTED_SERVICE_TYPE,
            expected_start_type: DRIVER_EXPECTED_START_TYPE,
            expected_binary_path,
            observed_service_type: None,
            observed_start_type: None,
            observed_binary_path: None,
            observed_current_state: None,
            outcome: DriverStateVerificationOutcome::Error,
            detail: format!("QueryServiceConfigW failed: {}", io::Error::last_os_error()),
        };
    }

    let config = unsafe { &*(config_buffer.as_ptr() as *const QUERY_SERVICE_CONFIGW) };
    let observed_binary_path = unsafe { wide_ptr_to_path(config.lpBinaryPathName) };

    let mut status = MaybeUninit::<SERVICE_STATUS_PROCESS>::zeroed();
    let mut status_bytes_needed: u32 = 0;
    let status_ok = unsafe {
        QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            status.as_mut_ptr() as *mut u8,
            size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut status_bytes_needed,
        )
    };
    let observed_current_state = if status_ok == 0 {
        None
    } else {
        Some(unsafe { status.assume_init().dwCurrentState })
    };

    let mut mismatches = Vec::new();
    if config.dwServiceType != SERVICE_KERNEL_DRIVER {
        mismatches.push(format!(
            "service type {:?} != {}",
            config.dwServiceType, DRIVER_EXPECTED_SERVICE_TYPE_LABEL
        ));
    }
    if config.dwStartType != SERVICE_DEMAND_START {
        mismatches.push(format!(
            "start type {:?} != {}",
            config.dwStartType, DRIVER_EXPECTED_START_TYPE_LABEL
        ));
    }
    if observed_binary_path
        .as_ref()
        .map(|path| normalize_path(path) != normalize_path(&expected_binary_path))
        .unwrap_or(true)
    {
        mismatches.push(format!(
            "binary path {:?} != {:?}",
            observed_binary_path, expected_binary_path
        ));
    }

    let outcome = if mismatches.is_empty() {
        DriverStateVerificationOutcome::Verified
    } else {
        DriverStateVerificationOutcome::Mismatch
    };

    DriverStateVerificationReport {
        service_name: DRIVER_SERVICE_NAME,
        expected_service_type: DRIVER_EXPECTED_SERVICE_TYPE,
        expected_start_type: DRIVER_EXPECTED_START_TYPE,
        expected_binary_path,
        observed_service_type: Some(config.dwServiceType),
        observed_start_type: Some(config.dwStartType),
        observed_binary_path,
        observed_current_state,
        outcome,
        detail: if mismatches.is_empty() {
            "Read-only driver state matched expected kernel-driver boundary.".to_string()
        } else {
            mismatches.join("; ")
        },
    }
}
