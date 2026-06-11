#[cfg(test)]
mod tests {
    use tuff_cse_winfs::managed_policy::ManagedPolicy;
    use tuff_cse_winfs::operations::{
        execute_operation, OperationKind, OperationRequest, OperationStatus,
    };
    use tuff_cse_winfs::volume_state::{VolumeBindingState, VolumeRuntimeState};

    #[test]
    fn test_operation_kind_serializes() {
        let kind = OperationKind::Bind;
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, "\"Bind\"");

        let deserialized: OperationKind = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, OperationKind::Bind);
    }

    #[test]
    fn test_default_managed_policy_allows_standard_ops() {
        let policy = ManagedPolicy::default();
        assert!(policy.allow_status);
        assert!(policy.allow_bind);
        assert!(policy.allow_unlock);
        assert!(policy.allow_lock);
        assert!(policy.allow_eject);
        assert!(policy.allow_audit);
    }

    #[test]
    fn test_default_managed_policy_rejects_reserved_ops() {
        let policy = ManagedPolicy::default();
        assert!(!policy.allow_export);
        assert!(!policy.allow_rebind);
        assert!(!policy.allow_recover);
    }

    fn mock_request(kind: OperationKind) -> OperationRequest {
        OperationRequest {
            operation_id: "test-id".to_string(),
            kind,
            volume: "D:".to_string(),
            requested_by: "test-user".to_string(),
            policy_id: "test-policy".to_string(),
            timestamp: 0,
        }
    }

    #[test]
    fn test_bind_transition() {
        let policy = ManagedPolicy::default();
        let mut state = VolumeRuntimeState {
            current: VolumeBindingState::Unregistered,
        };

        let result =
            execute_operation(mock_request(OperationKind::Bind), &policy, &mut state).unwrap();
        assert_eq!(result.status, OperationStatus::PendingBindingPhase);
        assert_eq!(result.next_state, VolumeBindingState::BoundLocked);
        assert_eq!(state.current, VolumeBindingState::BoundLocked);
    }

    #[test]
    fn test_unlock_transition() {
        let policy = ManagedPolicy::default();
        let mut state = VolumeRuntimeState {
            current: VolumeBindingState::BoundLocked,
        };

        let result =
            execute_operation(mock_request(OperationKind::Unlock), &policy, &mut state).unwrap();
        assert_eq!(result.status, OperationStatus::PendingCryptoPhase);
        assert_eq!(result.next_state, VolumeBindingState::Unlocked);
        assert_eq!(state.current, VolumeBindingState::Unlocked);
    }

    #[test]
    fn test_lock_transition() {
        let policy = ManagedPolicy::default();
        let mut state = VolumeRuntimeState {
            current: VolumeBindingState::Unlocked,
        };

        let result =
            execute_operation(mock_request(OperationKind::Lock), &policy, &mut state).unwrap();
        assert_eq!(result.status, OperationStatus::PendingDriverPhase);
        assert_eq!(result.next_state, VolumeBindingState::Locked);
        assert_eq!(state.current, VolumeBindingState::Locked);
    }

    #[test]
    fn test_eject_transition() {
        let policy = ManagedPolicy::default();
        let mut state = VolumeRuntimeState {
            current: VolumeBindingState::Locked,
        };

        let result =
            execute_operation(mock_request(OperationKind::Eject), &policy, &mut state).unwrap();
        assert_eq!(result.status, OperationStatus::PendingDriverPhase);
        assert_eq!(result.next_state, VolumeBindingState::CleanRemoved);
        assert_eq!(state.current, VolumeBindingState::CleanRemoved);
    }

    #[test]
    fn test_export_returns_reserved() {
        let mut policy = ManagedPolicy::default();
        policy.allow_export = true; // Even if allowed by policy, logic should return Reserved
        let mut state = VolumeRuntimeState::new();

        let result =
            execute_operation(mock_request(OperationKind::Export), &policy, &mut state).unwrap();
        assert_eq!(result.status, OperationStatus::Reserved);
    }

    #[test]
    fn test_rebind_returns_reserved() {
        let mut policy = ManagedPolicy::default();
        policy.allow_rebind = true;
        let mut state = VolumeRuntimeState::new();

        let result =
            execute_operation(mock_request(OperationKind::Rebind), &policy, &mut state).unwrap();
        assert_eq!(result.status, OperationStatus::Reserved);
    }

    #[test]
    fn test_recover_returns_reserved() {
        let mut policy = ManagedPolicy::default();
        policy.allow_recover = true;
        let mut state = VolumeRuntimeState::new();

        let result =
            execute_operation(mock_request(OperationKind::Recover), &policy, &mut state).unwrap();
        assert_eq!(result.status, OperationStatus::Reserved);
    }

    #[test]
    fn test_no_secrets_in_json() {
        let req = mock_request(OperationKind::Bind);
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("basekey"));
        assert!(!json.contains("MK"));
        assert!(!json.contains("TK"));
        assert!(!json.contains("PK"));
    }
}
