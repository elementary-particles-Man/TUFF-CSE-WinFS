#[cfg(test)]
mod tests {
    use std::fs;
    use tempfile::tempdir;
    use tuff_cse_winfs::binding_store::BindingStore;
    use tuff_cse_winfs::export_manifest::ExportRecipient;
    use tuff_cse_winfs::export_policy::ExportPolicy;
    use tuff_cse_winfs::local_policy::LocalPolicy;
    use tuff_cse_winfs::managed_policy::ManagedPolicy;
    use tuff_cse_winfs::operations::{
        execute_export_operation, execute_managed_operation, OperationKind, OperationRequest,
    };

    fn mock_request(kind: OperationKind, approval_id: Option<String>) -> OperationRequest {
        OperationRequest {
            operation_id: "test-id".to_string(),
            kind,
            volume: "D:".to_string(),
            requested_by: "test-user".to_string(),
            policy_id: "test-policy".to_string(),
            timestamp: 0,
            approval_id,
            enterprise_authority_policy_id: None,
            enterprise_quorum_policy_id: None,
            enterprise_recovery_decision_id: None,
        }
    }

    #[test]
    fn test_default_export_policy_validates() {
        let policy = ExportPolicy::default();
        assert!(tuff_cse_winfs::export_policy::validate_export_policy(&policy).is_ok());
    }

    #[test]
    fn test_export_policy_allow_plaintext_rejected() {
        let mut policy = ExportPolicy::default();
        policy.allow_plaintext_export = true;
        assert!(tuff_cse_winfs::export_policy::validate_export_policy(&policy).is_err());
    }

    #[test]
    fn test_export_policy_persist_raw_rejected() {
        let mut policy = ExportPolicy::default();
        policy.persist_raw_identifiers = true;
        assert!(tuff_cse_winfs::export_policy::validate_export_policy(&policy).is_err());
    }

    #[test]
    fn test_export_without_bind_is_rejected() {
        let dir = tempdir().unwrap();
        let store = BindingStore::open_at(dir.path()).unwrap();
        let policy = ManagedPolicy::default();
        let exp_policy = ExportPolicy::default();
        let local_policy = LocalPolicy {
            require_local_admin_for_export: false,
            ..LocalPolicy::default()
        };
        let recipient = ExportRecipient {
            recipient_id: "REC-001".to_string(),
            recipient_key_fingerprint: "FP-001".to_string(),
            recipient_org_hint: None,
        };

        let result = execute_export_operation(
            mock_request(OperationKind::Export, None),
            &policy,
            &exp_policy,
            &store,
            recipient,
            false,
            &local_policy,
        )
        .unwrap();

        assert_eq!(
            result.status,
            tuff_cse_winfs::operations::OperationStatus::Rejected
        );
    }

    #[test]
    fn test_export_after_bind_creates_manifest() {
        let dir = tempdir().unwrap();
        let store = BindingStore::open_at(dir.path()).unwrap();
        let policy = ManagedPolicy::default();
        let exp_policy = ExportPolicy::default();
        let local_policy = LocalPolicy {
            require_local_admin_for_export: false,
            ..LocalPolicy::default()
        };
        let recipient = ExportRecipient {
            recipient_id: "REC-001".to_string(),
            recipient_key_fingerprint: "FP-001".to_string(),
            recipient_org_hint: None,
        };

        // Bind first
        let _ = execute_managed_operation(
            mock_request(OperationKind::Bind, None),
            &policy,
            &store,
            None,
        )
        .unwrap();

        let result = execute_export_operation(
            mock_request(OperationKind::Export, None),
            &policy,
            &exp_policy,
            &store,
            recipient,
            false,
            &local_policy,
        )
        .unwrap();

        let export_id = result.reason.split(": ").nth(1).unwrap();
        let manifest_path = dir.path().join(format!(
            "META/exports/{}.manifest.json",
            export_id.trim_start_matches("MANIFEST-")
        ));
        assert!(manifest_path.exists());
    }

    #[test]
    fn test_export_manifest_no_secrets() {
        let dir = tempdir().unwrap();
        let store = BindingStore::open_at(dir.path()).unwrap();
        let policy = ManagedPolicy::default();
        let exp_policy = ExportPolicy::default();
        let local_policy = LocalPolicy {
            require_local_admin_for_export: false,
            ..LocalPolicy::default()
        };
        let recipient = ExportRecipient {
            recipient_id: "REC-001".to_string(),
            recipient_key_fingerprint: "FP-001".to_string(),
            recipient_org_hint: None,
        };

        let _ = execute_managed_operation(
            mock_request(OperationKind::Bind, None),
            &policy,
            &store,
            None,
        )
        .unwrap();
        let result = execute_export_operation(
            mock_request(OperationKind::Export, None),
            &policy,
            &exp_policy,
            &store,
            recipient,
            false,
            &local_policy,
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
    }
}
