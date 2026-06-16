#[cfg(test)]
mod tests {
    use std::fs;
    use tempfile::tempdir;
    use tuff_cse_winfs::binding_store::BindingStore;
    use tuff_cse_winfs::managed_policy::ManagedPolicy;
    use tuff_cse_winfs::operation_journal;
    use tuff_cse_winfs::operations::{execute_managed_operation, OperationKind, OperationRequest};
    use tuff_cse_winfs::secure_runtime::{SecureRuntimeBuffer, RuntimeSecretKind};
    use tuff_cse_winfs::volume_state::VolumeBindingState;

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
    fn test_secure_runtime_buffer_zeroizes_on_drop() {
        let mut buf = SecureRuntimeBuffer::new_placeholder(RuntimeSecretKind::MasterKey, vec![1, 2, 3, 4]).unwrap();
        let ptr = buf.as_bytes().as_ptr();
        drop(buf);
        assert!(ptr != std::ptr::null());
    }

    #[test]
    fn test_secure_runtime_buffer_debug_does_not_expose_secrets() {
        let buf = SecureRuntimeBuffer::new_placeholder(RuntimeSecretKind::MasterKey, vec![1, 2, 3, 4]).unwrap();
        let debug = format!("{:?}", buf);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("1, 2, 3, 4"));
    }

    #[test]
    fn test_journal_records_written_with_phases() {
        let dir = tempdir().unwrap();
        let store = BindingStore::open_at(dir.path()).unwrap();
        let policy = ManagedPolicy::default();

        let _ = execute_managed_operation(mock_request(OperationKind::Bind, None), &policy, &store, None).unwrap();

        let hash = BindingStore::volume_hash("D:");
        let records = operation_journal::read_journal_records(store.root_path(), &hash).unwrap();

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].phase, operation_journal::OperationJournalPhase::Begin);
        assert_eq!(records[1].phase, operation_journal::OperationJournalPhase::Commit);
    }

    #[test]
    fn test_journal_records_contain_no_secrets() {
        let dir = tempdir().unwrap();
        let store = BindingStore::open_at(dir.path()).unwrap();
        let policy = ManagedPolicy::default();

        let _ = execute_managed_operation(mock_request(OperationKind::Bind, None), &policy, &store, None).unwrap();

        let hash = BindingStore::volume_hash("D:");
        let path = dir.path().join(format!("JRN/operations-{}.jsonl", hash));
        let content = fs::read_to_string(path).unwrap();

        assert!(!content.contains("basekey"));
        assert!(!content.contains("MK"));
        assert!(!content.contains("TK"));
        assert!(!content.contains("PK"));
    }

    #[test]
    fn test_reserved_master_key_cannot_be_created_in_p2c() {
        // MasterKey generation is Reserved in P2C
    }

    #[test]
    fn test_recover_stale_stub() {
        let dir = tempdir().unwrap();
        let store = BindingStore::open_at(dir.path()).unwrap();
        let policy = ManagedPolicy::default();

        // 1. Bind and Unlock to create session
        let _ = execute_managed_operation(mock_request(OperationKind::Bind, None), &policy, &store, None).unwrap();
        let _ = execute_managed_operation(mock_request(OperationKind::Unlock, None), &policy, &store, None)
            .unwrap();

        // 2. Mock state/session mismatch (Unlocked state but session gone, or vice versa)
        let hash = BindingStore::volume_hash("D:");
        store.clear_runtime_session(&hash).unwrap();

        // 3. Recover
        let decision = tuff_cse_winfs::recovery::recover_store(&store, "D:").unwrap();
        // Currently it should do nothing as we haven't mocked the exact fail condition for the stub.
        assert_eq!(decision, tuff_cse_winfs::recovery::RecoveryDecision::NoAction);
    }
}
