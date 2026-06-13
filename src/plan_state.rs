use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlanLifecycleStatus {
    Planned,
    ManualConfirmationRequired,
    ManualConfirmed,
    Completed,
    Cancelled,
    Rejected,
}

impl Default for PlanLifecycleStatus {
    fn default() -> Self {
        PlanLifecycleStatus::Planned
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanTargetKind {
    ExportPlan,
    RecoveryPlan,
    RebindPlan,
}

pub fn transition_plan_status(
    current: PlanLifecycleStatus,
    target: PlanLifecycleStatus,
) -> Result<PlanLifecycleStatus, &'static str> {
    match (current, target) {
        (PlanLifecycleStatus::Planned, PlanLifecycleStatus::ManualConfirmationRequired) => {
            Ok(PlanLifecycleStatus::ManualConfirmationRequired)
        }
        (PlanLifecycleStatus::Planned, PlanLifecycleStatus::Cancelled) => {
            Ok(PlanLifecycleStatus::Cancelled)
        }
        (PlanLifecycleStatus::ManualConfirmationRequired, PlanLifecycleStatus::ManualConfirmed) => {
            Ok(PlanLifecycleStatus::ManualConfirmed)
        }
        (PlanLifecycleStatus::ManualConfirmationRequired, PlanLifecycleStatus::Cancelled) => {
            Ok(PlanLifecycleStatus::Cancelled)
        }
        (PlanLifecycleStatus::ManualConfirmed, PlanLifecycleStatus::Completed) => {
            Ok(PlanLifecycleStatus::Completed)
        }
        // Direct jump from Planned to Completed if no confirmation required
        (PlanLifecycleStatus::Planned, PlanLifecycleStatus::Completed) => {
            Ok(PlanLifecycleStatus::Completed)
        }
        _ => Err("Invalid plan lifecycle transition"),
    }
}
