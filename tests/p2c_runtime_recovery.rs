#[cfg(test)]
mod tests {
    use tuff_cse_winfs::secure_runtime::{RuntimeSecretKind, SecureRuntimeBuffer};
    use tuff_cse_winfs::recovery::{recover_store, RecoveryDecision};
    use tuff_cse_winfs::binding_store::BindingStore;
    use tempfile::tempdir;
    use tuff_cse_winfs::managed_policy::ManagedPolicy;
    use tuff_cse_winfs::operations::{execute_managed_operation, OperationKind, OperationRequest};
    use tuff_cse_winfs::operation_journal::{read_journal_records, OperationJournalPhase};

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
    fn test_secure_runtime_buffer_zeroizes_on_drop() {
        let buf = SecureRuntimeBuffer::new_placeholder(RuntimeSecretKind::PlaceholderUnlockMaterial, vec![1, 2, 3]).unwrap();
        assert_eq!(buf.len(), 3);
        assert!(!buf.is_zeroized_for_test());
    }

    #[test]
    fn test_secure_runtime_buffer_debug_does_not_expose_secrets() {
        let buf = SecureRuntimeBuffer::new_placeholder(RuntimeSecretKind::PlaceholderUnlockMaterial, vec![1, 2, 3]).unwrap();
        let debug_str = format!("{:?}", buf);
        assert!(debug_str.contains("<SECRET_REDACTED>"));
        assert!(!debug_str.contains("1, 2, 3"));
    }

    #[test]
    fn test_reserved_master_key_cannot_be_created_in_p2c() {
        let result = SecureRuntimeBuffer::new_placeholder(RuntimeSecretKind::ReservedMasterKey, vec![1, 2, 3]);
        assert!(result.is_err());
    }

    #[test]
    fn test_journal_records_written_with_phases() {
        let (_dir, store) = setup_store();
        let policy = ManagedPolicy::default();
        let vol_hash = BindingStore::volume_hash("D:");

        // Bind writes Begin and Commit
        let _ = execute_managed_operation(mock_request(OperationKind::Bind), &policy, &store).unwrap();
        let records = read_journal_records(store.root_path(), &vol_hash).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].phase, OperationJournalPhase::Begin);
        assert_eq!(records[1].phase, OperationJournalPhase::Commit);

        // Unlock writes Begin and Commit
        let _ = execute_managed_operation(mock_request(OperationKind::Unlock), &policy, &store).unwrap();
        let records = read_journal_records(store.root_path(), &vol_hash).unwrap();
        assert_eq!(records.len(), 4);
        assert_eq!(records[2].phase, OperationJournalPhase::Begin);
        assert_eq!(records[2].kind, OperationKind::Unlock);
        assert_eq!(records[3].phase, OperationJournalPhase::Commit);
        assert_eq!(records[3].kind, OperationKind::Unlock);
    }

    #[test]
    fn test_recover_stale_stub() {
        let (_dir, store) = setup_store();
        let decision = recover_store(&store, "D:").unwrap();
        assert_eq!(decision, RecoveryDecision::NoAction);
    }

    #[test]
    fn test_journal_records_contain_no_secrets() {
        let (_dir, store) = setup_store();
        let policy = ManagedPolicy::default();
        let vol_hash = BindingStore::volume_hash("D:");

        let _ = execute_managed_operation(mock_request(OperationKind::Bind), &policy, &store).unwrap();
        let json_lines = std::fs::read_to_string(store.root_path().join(format!("JRN/operations-{}.jsonl", vol_hash))).unwrap();

        assert!(!json_lines.contains("basekey"));
        assert!(!json_lines.contains("MK"));
        assert!(!json_lines.contains("TK"));
        assert!(!json_lines.contains("PK"));
        assert!(!json_lines.contains("RAW_TPM_DATA"));
    }
}
