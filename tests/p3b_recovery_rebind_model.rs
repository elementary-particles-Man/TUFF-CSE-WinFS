#[cfg(test)]
mod tests {
    use std::fs;
    use tempfile::tempdir;
    use tuff_cse_winfs::binding_store::BindingStore;
    use tuff_cse_winfs::managed_policy::ManagedPolicy;
    use tuff_cse_winfs::operations::{
        execute_managed_operation, execute_rebind_operation, execute_recover_operation,
        OperationKind, OperationRequest, OperationStatus,
    };
    use tuff_cse_winfs::rebind_model::{self, RebindPolicy};
    use tuff_cse_winfs::recovery_key::{self, RecoveryPolicy};

    fn setup_store() -> (tempfile::TempDir, BindingStore) {
        let dir = tempdir().unwrap();
        let store = BindingStore::open_at(dir.path()).unwrap();
        (dir, store)
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
    fn test_default_recovery_policy_validates() {
        let policy = recovery_key::default_recovery_policy();
        assert!(recovery_key::validate_recovery_policy(&policy).is_ok());
    }

    #[test]
    fn test_default_rebind_policy_validates() {
        let policy = rebind_model::default_rebind_policy();
        assert!(rebind_model::validate_rebind_policy(&policy).is_ok());
    }

    #[test]
    fn test_recover_without_bind_is_rejected() {
        let (_dir, store) = setup_store();
        let policy = ManagedPolicy::default();
        let rec_policy = recovery_key::default_recovery_policy();

        let result = execute_recover_operation(
            mock_request(OperationKind::Recover),
            &policy,
            &rec_policy,
            &store,
            "RK-FP-001".to_string(),
            "LOST_HOST".to_string(),
        )
        .unwrap();

        assert_eq!(result.status, OperationStatus::Rejected);
    }

    #[test]
    fn test_rebind_without_bind_is_rejected() {
        let (_dir, store) = setup_store();
        let policy = ManagedPolicy::default();
        let reb_policy = rebind_model::default_rebind_policy();

        let result = execute_rebind_operation(
            mock_request(OperationKind::Rebind),
            &policy,
            &reb_policy,
            &store,
            "NEW-HOST-FP".to_string(),
            None,
            "UPGRADE".to_string(),
        )
        .unwrap();

        assert_eq!(result.status, OperationStatus::Rejected);
    }

    #[test]
    fn test_recover_after_bind_creates_plan() {
        let (_dir, store) = setup_store();
        let policy = ManagedPolicy::default();
        let rec_policy = recovery_key::default_recovery_policy();

        // Bind first
        let _ =
            execute_managed_operation(mock_request(OperationKind::Bind), &policy, &store).unwrap();

        let result = execute_recover_operation(
            mock_request(OperationKind::Recover),
            &policy,
            &rec_policy,
            &store,
            "RK-FP-001".to_string(),
            "LOST_HOST".to_string(),
        )
        .unwrap();

        assert_eq!(result.status, OperationStatus::Accepted);
        assert!(result.reason.contains("Recovery plan generated"));
    }

    #[test]
    fn test_rebind_after_bind_creates_manifest() {
        let (_dir, store) = setup_store();
        let policy = ManagedPolicy::default();
        let reb_policy = rebind_model::default_rebind_policy();

        // Bind first
        let _ =
            execute_managed_operation(mock_request(OperationKind::Bind), &policy, &store).unwrap();

        let result = execute_rebind_operation(
            mock_request(OperationKind::Rebind),
            &policy,
            &reb_policy,
            &store,
            "NEW-HOST-FP".to_string(),
            Some("NEW-PC-01".to_string()),
            "UPGRADE".to_string(),
        )
        .unwrap();

        assert_eq!(result.status, OperationStatus::Accepted);
        assert!(result.reason.contains("Rebind manifest generated"));
    }

    #[test]
    fn test_recovery_plan_no_secrets() {
        let (dir, store) = setup_store();
        let policy = ManagedPolicy::default();
        let rec_policy = recovery_key::default_recovery_policy();

        let _ =
            execute_managed_operation(mock_request(OperationKind::Bind), &policy, &store).unwrap();
        let result = execute_recover_operation(
            mock_request(OperationKind::Recover),
            &policy,
            &rec_policy,
            &store,
            "RK-FP-001".to_string(),
            "LOST_HOST".to_string(),
        )
        .unwrap();

        let plan_id = result.reason.split(": ").nth(1).unwrap();
        let plan_path = dir
            .path()
            .join(format!("KEYS/recovery-plans/{}.plan.json", plan_id));
        let content = fs::read_to_string(plan_path).unwrap();

        assert!(!content.contains("basekey"));
        assert!(!content.contains("MK"));
        assert!(!content.contains("TK"));
        assert!(!content.contains("PK"));
        assert!(!content.contains("RAW_RECOVERY_KEY"));
    }
}
