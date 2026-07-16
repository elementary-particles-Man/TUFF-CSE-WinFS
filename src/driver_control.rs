use crate::driver_state::{
    self, DriverConfigurationFinding, DriverRuntimeState, DriverStateVerificationOutcome,
    DriverStateVerificationReport, DRIVER_SERVICE_NAME,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverStartPlan {
    pub service_name: &'static str,
    pub expected_precondition: DriverRuntimeState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverStartResult {
    Running,
    StartPending,
    AlreadyRunning,
    AlreadyStarting,
    Rejected {
        reason: String,
    },
    UnsupportedPlatform,
    UnexpectedPostStartState {
        state: DriverRuntimeState,
    },
    Error {
        windows_error_code: u32,
        message: String,
    },
}

pub fn build_driver_start_plan(
    report: &DriverStateVerificationReport,
) -> Result<DriverStartPlan, DriverStartResult> {
    if let DriverRuntimeState::Error {
        windows_error_code,
        message,
    } = &report.observed_runtime_state
    {
        return Err(DriverStartResult::Error {
            windows_error_code: *windows_error_code,
            message: message.clone(),
        });
    }
    if report.outcome != DriverStateVerificationOutcome::Verified {
        return Err(rejected(
            "P8C verification did not produce a Verified report",
        ));
    }
    if report.observed_configuration.is_none() {
        return Err(rejected("P8C report has no observed service configuration"));
    }
    let findings: &[DriverConfigurationFinding] = &report.configuration_findings;
    if !findings.is_empty() {
        return Err(rejected("P8C service configuration contains findings"));
    }

    match &report.observed_runtime_state {
        DriverRuntimeState::Stopped => Ok(DriverStartPlan {
            service_name: DRIVER_SERVICE_NAME,
            expected_precondition: DriverRuntimeState::Stopped,
        }),
        DriverRuntimeState::Running => Err(DriverStartResult::AlreadyRunning),
        DriverRuntimeState::StartPending => Err(DriverStartResult::AlreadyStarting),
        state => Err(rejected(format!(
            "runtime state is not startable: {state:?}"
        ))),
    }
}

pub fn start_driver_live() -> DriverStartResult {
    let report = driver_state::collect_driver_state_verification_report();
    start_driver_live_from_report(&report)
}

pub fn start_driver_live_from_report(report: &DriverStateVerificationReport) -> DriverStartResult {
    if report.outcome == DriverStateVerificationOutcome::Unsupported {
        return DriverStartResult::UnsupportedPlatform;
    }
    let plan = match build_driver_start_plan(&report) {
        Ok(plan) => plan,
        Err(result) => return result,
    };

    #[cfg(windows)]
    {
        execute_driver_start_windows(&plan)
    }
    #[cfg(not(windows))]
    {
        let _ = plan;
        DriverStartResult::UnsupportedPlatform
    }
}

fn rejected(reason: impl Into<String>) -> DriverStartResult {
    DriverStartResult::Rejected {
        reason: reason.into(),
    }
}

#[cfg(windows)]
fn execute_driver_start_windows(plan: &DriverStartPlan) -> DriverStartResult {
    use std::io;
    use std::mem::{size_of, MaybeUninit};
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_SERVICE_ALREADY_RUNNING};
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, StartServiceW,
        SC_HANDLE, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_START,
        SERVICE_STATUS_PROCESS,
    };

    struct ServiceHandle(SC_HANDLE);

    impl Drop for ServiceHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CloseServiceHandle(self.0) };
            }
        }
    }

    fn api_error(api: &str, code: u32) -> DriverStartResult {
        DriverStartResult::Error {
            windows_error_code: code,
            message: format!(
                "{api} failed: {}",
                io::Error::from_raw_os_error(code as i32)
            ),
        }
    }

    fn query_state(service: SC_HANDLE) -> Result<DriverRuntimeState, DriverStartResult> {
        let mut status = MaybeUninit::<SERVICE_STATUS_PROCESS>::zeroed();
        let mut bytes_needed = 0u32;
        let ok = unsafe {
            QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                status.as_mut_ptr() as *mut u8,
                size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut bytes_needed,
            )
        };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            return Err(api_error("QueryServiceStatusEx", code));
        }
        Ok(driver_state::map_windows_service_state(unsafe {
            status.assume_init().dwCurrentState
        }))
    }

    let scm = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if scm.is_null() {
        let code = unsafe { GetLastError() };
        return api_error("OpenSCManagerW", code);
    }
    let scm = ServiceHandle(scm);
    let service_name: Vec<u16> = plan.service_name.encode_utf16().chain(Some(0)).collect();
    let service = unsafe {
        OpenServiceW(
            scm.0,
            service_name.as_ptr(),
            SERVICE_START | SERVICE_QUERY_STATUS,
        )
    };
    if service.is_null() {
        let code = unsafe { GetLastError() };
        return api_error("OpenServiceW", code);
    }
    let service = ServiceHandle(service);

    let pre_start_state = match query_state(service.0) {
        Ok(state) => state,
        Err(error) => return error,
    };
    match pre_start_state {
        DriverRuntimeState::Running => return DriverStartResult::AlreadyRunning,
        DriverRuntimeState::StartPending => return DriverStartResult::AlreadyStarting,
        DriverRuntimeState::Stopped => {}
        state => return rejected(format!("pre-start runtime state is not Stopped: {state:?}")),
    }

    let started = unsafe { StartServiceW(service.0, 0, std::ptr::null()) };
    if started == 0 {
        let code = unsafe { GetLastError() };
        if code == ERROR_SERVICE_ALREADY_RUNNING {
            return DriverStartResult::AlreadyRunning;
        }
        return api_error("StartServiceW", code);
    }

    let post_start_state = match query_state(service.0) {
        Ok(state) => state,
        Err(error) => return error,
    };
    match post_start_state {
        DriverRuntimeState::Running => DriverStartResult::Running,
        DriverRuntimeState::StartPending => DriverStartResult::StartPending,
        state => DriverStartResult::UnexpectedPostStartState { state },
    }
}
