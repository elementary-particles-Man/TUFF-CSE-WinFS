#[cfg(test)]
mod tests {
    use std::fs;
    use tempfile::tempdir;
    use tuff_cse_winfs::binding_store::BindingStore;
    use tuff_cse_winfs::managed_policy::ManagedPolicy;
    use tuff_cse_winfs::operations::{
        execute_managed_operation, OperationKind, OperationRequest, OperationStatus,
    };
    use tuff_cse_winfs::volume_state::{VolumeBindingState, VolumeRuntimeState};

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
    fn test_new_store_creates_required_directories() {
        let (dir, _store) = setup_store();
        assert!(dir.path().join("META/bindings").exists());
        assert!(dir.path().join("META/states").exists());
        assert!(dir.path().join("KEYS/plans").exists());
        assert!(dir.path().join("JRN/runtime").exists());
    }

    #[test]
    fn test_bind_persisted_files_contain_no_secrets() {
        let (_dir, store) = setup_store();
        let policy = ManagedPolicy::default();
        let _ =
            execute_managed_operation(mock_request(OperationKind::Bind), &policy, &store).unwrap();

        let vol_hash = BindingStore::volume_hash("D:");

        let desc_path = store
            .root_path()
            .join(format!("META/bindings/{}.binding.json", vol_hash));
        let desc_content = fs::read_to_string(desc_path).unwrap();

        let plan_path = store
            .root_path()
            .join(format!("KEYS/plans/{}.plan.json", vol_hash));
        let plan_content = fs::read_to_string(plan_path).unwrap();

        assert!(!desc_content.contains("basekey"));
        assert!(!desc_content.contains("MK"));
        assert!(!desc_content.contains("TK"));
        assert!(!desc_content.contains("PK"));
        assert!(!desc_content.contains("RAW_TPM_DATA"));
        assert!(!desc_content.contains("RAW_DEVICE_UUID"));

        assert!(!plan_content.contains("basekey"));
        assert!(!plan_content.contains("MK"));
        assert!(!plan_content.contains("TK"));
        assert!(!plan_content.contains("PK"));
        assert!(!plan_content.contains("RAW_TPM_DATA"));
        assert!(!plan_content.contains("RAW_DEVICE_UUID"));
    }

    #[test]
    fn test_status_on_unknown_volume_returns_unregistered() {
        let (_dir, store) = setup_store();
        let state = store.load_volume_state("X:").unwrap();
        assert_eq!(state.current, VolumeBindingState::Unregistered);
    }

    #[test]
    fn test_bind_persists_state() {
        let (_dir, store) = setup_store();
        let policy = ManagedPolicy::default();
        let result =
            execute_managed_operation(mock_request(OperationKind::Bind), &policy, &store).unwrap();

        assert_eq!(result.status, OperationStatus::PendingBindingPhase);
        let state = store.load_volume_state("D:").unwrap();
        assert_eq!(state.current, VolumeBindingState::BoundLocked);

        let desc = store.load_binding_descriptor("D:").unwrap();
        assert!(desc.is_some());

        let plan = store.load_key_derivation_plan("D:").unwrap();
        assert!(plan.is_some());
    }

    #[test]
    fn test_unlock_without_bind_is_rejected() {
        let (_dir, store) = setup_store();
        let policy = ManagedPolicy::default();
        let result =
            execute_managed_operation(mock_request(OperationKind::Unlock), &policy, &store)
                .unwrap();

        assert_eq!(result.status, OperationStatus::Rejected);
        assert_eq!(
            result.reason,
            "Binding not found. Cannot perform operation."
        );
    }

    #[test]
    fn test_full_lifecycle_bind_unlock_lock_eject() {
        let (_dir, store) = setup_store();
        let policy = ManagedPolicy::default();
        let vol_hash = BindingStore::volume_hash("D:");

        // Bind
        let _ =
            execute_managed_operation(mock_request(OperationKind::Bind), &policy, &store).unwrap();

        // Unlock
        let res_unlock =
            execute_managed_operation(mock_request(OperationKind::Unlock), &policy, &store)
                .unwrap();
        assert_eq!(res_unlock.status, OperationStatus::PendingCryptoPhase);
        assert_eq!(
            store.load_volume_state("D:").unwrap().current,
            VolumeBindingState::Unlocked
        );

        let session_unlocked = store.load_runtime_session(&vol_hash).unwrap().unwrap();
        assert_eq!(
            session_unlocked.status,
            tuff_cse_winfs::runtime_session::RuntimeSessionStatus::UnlockedPlaceholder
        );

        // Lock
        let res_lock =
            execute_managed_operation(mock_request(OperationKind::Lock), &policy, &store).unwrap();
        assert_eq!(res_lock.status, OperationStatus::PendingDriverPhase);
        assert_eq!(
            store.load_volume_state("D:").unwrap().current,
            VolumeBindingState::Locked
        );

        let session_locked = store.load_runtime_session(&vol_hash).unwrap().unwrap();
        assert_eq!(
            session_locked.status,
            tuff_cse_winfs::runtime_session::RuntimeSessionStatus::Locked
        );

        // Eject
        let res_eject =
            execute_managed_operation(mock_request(OperationKind::Eject), &policy, &store).unwrap();
        assert_eq!(res_eject.status, OperationStatus::PendingDriverPhase);
        assert_eq!(
            store.load_volume_state("D:").unwrap().current,
            VolumeBindingState::CleanRemoved
        );

        let session_ejected = store.load_runtime_session(&vol_hash).unwrap();
        assert!(session_ejected.is_none());

        // Audit
        let _records =
            tuff_cse_winfs::operation_journal::read_journal_records(store.root_path(), &vol_hash)
                .unwrap();
        // Since execute_managed_operation only writes to store state, and the bin writes to the journal in the skeleton, we won't strictly check journal lengths here unless we re-implement the bin logic in the test. The current test just focuses on `execute_managed_operation`'s interactions with the store.
        // The operations command contract test should be verified.
    }
}
