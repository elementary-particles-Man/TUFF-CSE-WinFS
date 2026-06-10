use sha2::{Digest, Sha256};
use time::OffsetDateTime;

pub enum CompletionStatus {
    BackgroundSealing,
    Ready,
    Error(String),
}

impl std::fmt::Display for CompletionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompletionStatus::BackgroundSealing => write!(f, "BACKGROUND-SEALING"),
            CompletionStatus::Ready => write!(f, "READY"),
            CompletionStatus::Error(reason) => write!(f, "ERROR: {}", reason),
        }
    }
}

pub fn generate_fingerprint(policy_id: &str, hostname: &str) -> String {
    let now = OffsetDateTime::now_utc().unix_timestamp().to_string();
    let mut hasher = Sha256::new();
    hasher.update(policy_id);
    hasher.update(hostname);
    hasher.update(now);
    let result = hasher.finalize();
    let hex = hex::encode(result);
    format!("{}-{}", &hex[0..4], &hex[4..8]).to_uppercase()
}

pub fn build_success_code(
    fingerprint: &str,
    host: &str,
    target_count: usize,
    excluded_count: usize,
    status: CompletionStatus,
) -> String {
    format!(
        "CSE-INSTALL-OK FP={} HOST={} TARGET={} EXCLUDED={} STATUS={}",
        fingerprint, host, target_count, excluded_count, status
    )
}

pub fn build_failed_code(fingerprint: &str, host: &str, reason: &str) -> String {
    format!(
        "CSE-INSTALL-FAILED FP={} HOST={} REASON={}",
        fingerprint, host, reason
    )
}
