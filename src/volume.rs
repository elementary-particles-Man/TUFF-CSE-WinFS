#[derive(Debug, PartialEq, Eq)]
pub enum SupportedFs {
    NTFS,
    ExFAT,
    FAT32,
    FAT,
}

#[derive(Debug)]
pub enum Phase {
    P0,
    P1Required,
    P2Planned,
}

pub struct TargetEvaluation {
    pub volume: String,
    pub is_target: bool,
    pub reason: String,
    pub phase: Phase,
}

pub fn evaluate_target(volume: &str) -> TargetEvaluation {
    // P0 implementation only validates format
    if !volume
        .chars()
        .next()
        .map(|c| c.is_alphabetic())
        .unwrap_or(false)
        || !volume.ends_with(':')
    {
        return TargetEvaluation {
            volume: volume.to_string(),
            is_target: false,
            reason: "Invalid volume format (expected like D:)".to_string(),
            phase: Phase::P0,
        };
    }

    // Stub for actual volume check in P1
    TargetEvaluation {
        volume: volume.to_string(),
        is_target: true, // Assuming true for P0 skeleton if format is OK
        reason: "Format valid. Hardware check pending P1 implementation.".to_string(),
        phase: Phase::P1Required,
    }
}
