use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrincipalProviderKind {
    WindowsLocal,
    NonWindowsDev,
    TestStub,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LocalPrincipalSnapshot {
    pub provider_kind: PrincipalProviderKind,
    pub principal_fingerprint: String,
    pub elevation_hint: bool,
    pub display_label: String,
}

impl fmt::Debug for LocalPrincipalSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalPrincipalSnapshot")
            .field("provider_kind", &self.provider_kind)
            .field("principal_fingerprint", &self.principal_fingerprint)
            .field("elevation_hint", &self.elevation_hint)
            .field("display_label", &self.display_label)
            .finish()
    }
}

pub trait LocalPrincipalProvider {
    fn get_current_principal(&self) -> Result<LocalPrincipalSnapshot>;
    fn verify_elevation(&self) -> Result<bool>;
}

pub fn compute_fingerprint(raw_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw_id.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(windows)]
pub struct WindowsLocalPrincipalProvider;

#[cfg(windows)]
impl LocalPrincipalProvider for WindowsLocalPrincipalProvider {
    fn get_current_principal(&self) -> Result<LocalPrincipalSnapshot> {
        // Placeholder for real Windows SID retrieval logic.
        // We MUST NOT save or log the actual SID.
        let mock_sid = "S-1-5-21-MOCK-ADMIN";
        let fingerprint = compute_fingerprint(mock_sid);

        Ok(LocalPrincipalSnapshot {
            provider_kind: PrincipalProviderKind::WindowsLocal,
            principal_fingerprint: fingerprint,
            elevation_hint: self.verify_elevation()?,
            display_label: "Local Admin (Windows)".to_string(),
        })
    }

    fn verify_elevation(&self) -> Result<bool> {
        // Placeholder for IsUserAnAdmin() or TokenInformation checks.
        Ok(true)
    }
}

pub struct NonWindowsDevPrincipalProvider;

impl LocalPrincipalProvider for NonWindowsDevPrincipalProvider {
    fn get_current_principal(&self) -> Result<LocalPrincipalSnapshot> {
        if std::env::var("TUFF_CSE_WINFS_ALLOW_DEV_APPROVER").is_err() {
            return Err(anyhow!("Dev approver not allowed in this environment"));
        }

        let mock_id = "DEV-ADMIN-STUB";
        let fingerprint = compute_fingerprint(mock_id);

        Ok(LocalPrincipalSnapshot {
            provider_kind: PrincipalProviderKind::NonWindowsDev,
            principal_fingerprint: fingerprint,
            elevation_hint: true,
            display_label: "Dev Admin (Non-Windows)".to_string(),
        })
    }

    fn verify_elevation(&self) -> Result<bool> {
        Ok(true)
    }
}

pub fn get_default_provider() -> Box<dyn LocalPrincipalProvider> {
    #[cfg(windows)]
    {
        Box::new(WindowsLocalPrincipalProvider)
    }
    #[cfg(not(windows))]
    {
        Box::new(NonWindowsDevPrincipalProvider)
    }
}
