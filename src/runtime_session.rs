use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeSessionStatus {
    UnlockedPlaceholder,
    Locked,
    CleanRemoved,
    ZeroizeRequiredPlaceholder, // Marker for P2C
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
}
