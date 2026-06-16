#[cfg(test)]
mod tests {
    use tempfile::tempdir;
    use tuff_cse_winfs::binding_store::BindingStore;
    use tuff_cse_winfs::managed_policy::ManagedPolicy;
    use tuff_cse_winfs::operations::{execute_managed_operation, OperationKind, OperationRequest};
    use tuff_cse_winfs::volume_state::{VolumeBindingState};

    fn mock_request(kind: OperationKind, approval_id: Option<String>) -> OperationRequest {
        OperationRequest {
            operation_id: "test-id".to_string(),
            kind,
            volume: "D:".to_string(),
            requested_by: "test-user".to_string(),
            policy_id: "test-policy".to_string(),
            timestamp: 0,
            approval_id,
        }
    }

    #[test]
    fn test_new_store_creates_required_directories() {
        let dir = tempdir().unwrap();
        let _store = BindingStore::open_at(dir.path()).unwrap();

        assert!(dir.path().join("META/bindings").exists());
        assert!(dir.path().join("META/states").exists());
        assert!(dir.path().join("JRN").exists());
    }

    #[test]
    fn test_status_on_unknown_volume_returns_unregistered() {
        let dir = tempdir().unwrap();
        let store = BindingStore::open_at(dir.path()).unwrap();
        let policy = ManagedPolicy::default();

        let result =
            execute_managed_operation(mock_request(OperationKind::Status, None), &policy, &store, None)
                .unwrap();
        assert_eq!(result.next_state, VolumeBindingState::Unregistered);
    }

    #[test]
    fn test_bind_persists_state() {
        let dir = tempdir().unwrap();
        let store = BindingStore::open_at(dir.path()).unwrap();
        let policy = ManagedPolicy::default();

        let _ =
            execute_managed_operation(mock_request(OperationKind::Bind, None), &policy, &store, None)
                .unwrap();

        let state = store.load_volume_state("D:").unwrap();
        assert_eq!(state.current, VolumeBindingState::BoundLocked);
    }

    #[test]
    fn test_bind_persisted_files_contain_no_secrets() {
        use std::fs;
        let dir = tempdir().unwrap();
        let store = BindingStore::open_at(dir.path()).unwrap();
        let policy = ManagedPolicy::default();

        let _ =
            execute_managed_operation(mock_request(OperationKind::Bind, None), &policy, &store, None)
                .unwrap();

        let hash = BindingStore::volume_hash("D:");
        let desc_path = dir.path().join(format!("META/bindings/{}.binding.json", hash));
        let plan_path = dir.path().join(format!("KEYS/plans/{}.plan.json", hash));

        let desc_content = fs::read_to_string(desc_path).unwrap();
        let plan_content = fs::read_to_string(plan_path).unwrap();

        assert!(!desc_content.contains("basekey"));
        assert!(!desc_content.contains("MK"));
        assert!(!desc_content.contains("TK"));
        assert!(!desc_content.contains("PK"));

        assert!(!plan_content.contains("basekey"));
        assert!(!plan_content.contains("MK"));
        assert!(!plan_content.contains("TK"));
        assert!(!plan_content.contains("PK"));
    }

    #[test]
    fn test_unlock_without_bind_is_rejected() {
        let dir = tempdir().unwrap();
        let store = BindingStore::open_at(dir.path()).unwrap();
        let policy = ManagedPolicy::default();

        let result =
            execute_managed_operation(mock_request(OperationKind::Unlock, None), &policy, &store, None)
                .unwrap();
        assert_eq!(
            result.status,
            tuff_cse_winfs::operations::OperationStatus::Rejected
        );
    }

    #[test]
    fn test_full_lifecycle_bind_unlock_lock_eject() {
        let dir = tempdir().unwrap();
        let store = BindingStore::open_at(dir.path()).unwrap();
        let policy = ManagedPolicy::default();

        // 1. Bind
        let _ =
            execute_managed_operation(mock_request(OperationKind::Bind, None), &policy, &store, None)
                .unwrap();

        // 2. Unlock
        let result = execute_managed_operation(
            mock_request(OperationKind::Unlock, None),
            &policy,
            &store,
            None,
        )
        .unwrap();
        assert_eq!(result.next_state, VolumeBindingState::Unlocked);

        let session = store
            .load_runtime_session(&BindingStore::volume_hash("D:"))
            .unwrap();
        assert!(session.is_some());

        // 3. Lock
        let result =
            execute_managed_operation(mock_request(OperationKind::Lock, None), &policy, &store, None)
                .unwrap();
        assert_eq!(result.next_state, VolumeBindingState::Locked);

        let session = store
            .load_runtime_session(&BindingStore::volume_hash("D:"))
            .unwrap()
            .unwrap();
        assert!(session.zeroize_required);

        // 4. Eject
        let result =
            execute_managed_operation(mock_request(OperationKind::Eject, None), &policy, &store, None)
                .unwrap();
        assert_eq!(result.next_state, VolumeBindingState::CleanRemoved);

        let session = store
            .load_runtime_session(&BindingStore::volume_hash("D:"))
            .unwrap();
        assert!(session.is_none());
    }
}
