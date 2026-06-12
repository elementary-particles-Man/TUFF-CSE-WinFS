use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeSessionStatus {
    UnlockedPlaceholder,
    ZeroizeRequired,
    Zeroized,
    Locked,
    CleanRemoved,
    Stale,
    Cleared,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeSession {
    pub session_id: String,
    pub volume_hash: String,
    pub descriptor_id: String,
    pub plan_id: String,
    pub status: RuntimeSessionStatus,
    pub created_at: u64,
    pub last_transition_at: u64,
    pub zeroize_required: bool,
    pub zeroized_at: Option<u64>,
}

impl RuntimeSession {
    pub fn mark_zeroize_required(&mut self) {
        self.zeroize_required = true;
        self.status = RuntimeSessionStatus::ZeroizeRequired;
    }

    pub fn mark_zeroized(&mut self, timestamp: u64) {
        self.zeroized_at = Some(timestamp);
        self.status = RuntimeSessionStatus::Zeroized;
    }

    pub fn is_stale(&self, now: u64, ttl: u64) -> bool {
        if self.status == RuntimeSessionStatus::UnlockedPlaceholder {
            if now > self.last_transition_at + ttl {
                return true;
            }
        }
        false
    }
}
