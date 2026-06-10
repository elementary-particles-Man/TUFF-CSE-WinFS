use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VolumeBindingState {
    Unregistered,
    BoundLocked,
    Unlocked,
    Locked,
    EjectPending,
    CleanRemoved,
    Error,
}

impl Default for VolumeBindingState {
    fn default() -> Self {
        VolumeBindingState::Unregistered
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeRuntimeState {
    pub current: VolumeBindingState,
}

impl VolumeRuntimeState {
    pub fn new() -> Self {
        Self {
            current: VolumeBindingState::Unregistered,
        }
    }
}
