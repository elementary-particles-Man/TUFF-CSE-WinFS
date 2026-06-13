#[cfg(test)]
mod tests {
    use std::fs;
    use tempfile::tempdir;
    use tuff_cse_winfs::binding_store::BindingStore;
    use tuff_cse_winfs::export_manifest::ExportRecipient;
    use tuff_cse_winfs::export_policy::{self, ExportPolicy};
    use tuff_cse_winfs::managed_policy::ManagedPolicy;
    use tuff_cse_winfs::operations::{
        execute_export_operation, execute_managed_operation, OperationKind, OperationRequest,
        OperationStatus,
    };
    use tuff_cse_winfs::volume_state::VolumeBindingState;

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
    fn test_default_export_policy_validates() {
        let policy = export_policy::default_manifest_only_policy();
        assert!(export_policy::validate_export_policy(&policy).is_ok());
    }

    #[test]
    fn test_export_policy_persist_raw_rejected() {
        let mut policy = export_policy::default_manifest_only_policy();
        policy.persist_raw_identifiers = true;
        assert!(export_policy::validate_export_policy(&policy).is_err());
    }

    #[test]
    fn test_export_policy_allow_plaintext_rejected() {
        let mut policy = export_policy::default_manifest_only_policy();
        policy.allow_plaintext_export = true;
        assert!(export_policy::validate_export_policy(&policy).is_err());
    }

    #[test]
    fn test_export_without_bind_is_rejected() {
        let (_dir, store) = setup_store();
        let policy = ManagedPolicy::default();
        let exp_policy = ExportPolicy::default();
        let recipient = ExportRecipient {
            recipient_id: "REC-001".to_string(),
            recipient_key_fingerprint: "FP-001".to_string(),
            recipient_org_hint: None,
        };

        let result = execute_export_operation(
            mock_request(OperationKind::Export),
            &policy,
            &exp_policy,
            &store,
            recipient,
        )
        .unwrap();

        assert_eq!(result.status, OperationStatus::Rejected);
    }

    #[test]
    fn test_export_after_bind_creates_manifest() {
        let (_dir, store) = setup_store();
        let policy = ManagedPolicy::default();
        let exp_policy = ExportPolicy::default();
        let recipient = ExportRecipient {
            recipient_id: "REC-001".to_string(),
            recipient_key_fingerprint: "FP-001".to_string(),
            recipient_org_hint: None,
        };

        // Bind first
        let _ =
            execute_managed_operation(mock_request(OperationKind::Bind), &policy, &store).unwrap();

        let result = execute_export_operation(
            mock_request(OperationKind::Export),
            &policy,
            &exp_policy,
            &store,
            recipient,
        )
        .unwrap();

        assert_eq!(result.status, OperationStatus::Accepted);
        assert!(result.reason.contains("Export manifest generated"));

        // Check journal
        let vol_hash = BindingStore::volume_hash("D:");
        let records =
            tuff_cse_winfs::operation_journal::read_journal_records(store.root_path(), &vol_hash)
                .unwrap();

        // OperationKind::Export adds Begin/Commit
        let has_export_begin = records.iter().any(|r| {
            r.kind == OperationKind::Export
                && r.phase == tuff_cse_winfs::operation_journal::OperationJournalPhase::Begin
        });
        let has_export_commit = records.iter().any(|r| {
            r.kind == OperationKind::Export
                && r.phase == tuff_cse_winfs::operation_journal::OperationJournalPhase::Commit
        });
        assert!(has_export_begin);
        assert!(has_export_commit);
    }

    #[test]
    fn test_export_manifest_no_secrets() {
        let (dir, store) = setup_store();
        let policy = ManagedPolicy::default();
        let exp_policy = ExportPolicy::default();
        let recipient = ExportRecipient {
            recipient_id: "REC-001".to_string(),
            recipient_key_fingerprint: "FP-001".to_string(),
            recipient_org_hint: None,
        };

        let _ =
            execute_managed_operation(mock_request(OperationKind::Bind), &policy, &store).unwrap();
        let result = execute_export_operation(
            mock_request(OperationKind::Export),
            &policy,
            &exp_policy,
            &store,
            recipient,
        )
        .unwrap();

        let export_id = result.reason.split(": ").nth(1).unwrap();
        let manifest_path = dir.path().join(format!(
            "META/exports/{}.manifest.json",
            export_id.trim_start_matches("MANIFEST-")
        ));
        let content = fs::read_to_string(manifest_path).unwrap();

        assert!(!content.contains("basekey"));
        assert!(!content.contains("MK"));
        assert!(!content.contains("TK"));
        assert!(!content.contains("PK"));
        assert!(!content.contains("RAW_TPM_DATA"));
    }
}
