#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};
    use tempfile::tempdir;
    use tuff_cse_winfs::binding_store::BindingStore;
    use tuff_cse_winfs::export_manifest::ExportRecipient;
    use tuff_cse_winfs::local_approval;
    use tuff_cse_winfs::local_policy::{LocalOperationClass, LocalPolicy};
    use tuff_cse_winfs::managed_policy::ManagedPolicy;
    use tuff_cse_winfs::operations::{
        execute_export_operation, execute_managed_operation, OperationKind, OperationRequest,
        OperationStatus,
    };

    fn setup_store() -> (tempfile::TempDir, BindingStore) {
        let dir = tempdir().unwrap();
        let store = BindingStore::open_at(dir.path()).unwrap();
        (dir, store)
    }

    fn mock_request(kind: OperationKind, approval_id: Option<String>) -> OperationRequest {
        OperationRequest {
            operation_id: "test-id".to_string(),
            kind,
            volume: "D:".to_string(),
            requested_by: "test-user".to_string(),
            policy_id: "test-policy".to_string(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            approval_id,
        }
    }

    #[test]
    fn test_export_without_approval_is_rejected() {
        let (_dir, store) = setup_store();
        let policy = ManagedPolicy::default();
        let exp_policy = tuff_cse_winfs::export_policy::ExportPolicy::default();
        let local_policy = LocalPolicy::default(); // require_local_admin_for_export = true
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

        // Export should be rejected
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

        assert_eq!(result.status, OperationStatus::Rejected);
        assert!(result.reason.contains("CSE-APPROVAL-REJECTION"));
    }

    #[test]
    fn test_export_with_valid_approval_is_accepted() {
        let (_dir, store) = setup_store();
        let policy = ManagedPolicy::default();
        let exp_policy = tuff_cse_winfs::export_policy::ExportPolicy::default();
        let local_policy = LocalPolicy::default();
        let recipient = ExportRecipient {
            recipient_id: "REC-001".to_string(),
            recipient_key_fingerprint: "FP-001".to_string(),
            recipient_org_hint: None,
        };

        let vol_hash = BindingStore::volume_hash("D:");
        let _ = execute_managed_operation(
            mock_request(OperationKind::Bind, None),
            &policy,
            &store,
            None,
        )
        .unwrap();

        // 1. Create Approval Request
        let request = local_approval::build_approval_request(
            &local_policy,
            LocalOperationClass::Export,
            "PLAN-001".to_string(),
            vol_hash.clone(),
            "USER-FP".to_string(),
            "MANAGED_EXPORT".to_string(),
        );
        store.save_approval_request(&request).unwrap();

        // 2. Approve Request
        let (updated_request, decision) =
            local_approval::approve_request(&request, "ADMIN-FP".to_string(), "OK".to_string());
        store.save_approval_request(&updated_request).unwrap();
        store.save_approval_decision(&decision).unwrap();

        // 3. Export should succeed
        let result = execute_export_operation(
            mock_request(OperationKind::Export, Some(request.approval_id)),
            &policy,
            &exp_policy,
            &store,
            recipient,
            false,
            &local_policy,
        )
        .unwrap();

        assert_eq!(result.status, OperationStatus::Accepted);
    }

    #[test]
    fn test_one_time_approval_consumption() {
        let (_dir, store) = setup_store();
        let policy = ManagedPolicy::default();
        let exp_policy = tuff_cse_winfs::export_policy::ExportPolicy::default();
        let mut local_policy = LocalPolicy::default();
        local_policy.one_time_approval = true;

        let recipient = ExportRecipient {
            recipient_id: "REC-001".to_string(),
            recipient_key_fingerprint: "FP-001".to_string(),
            recipient_org_hint: None,
        };

        let vol_hash = BindingStore::volume_hash("D:");
        let _ = execute_managed_operation(
            mock_request(OperationKind::Bind, None),
            &policy,
            &store,
            None,
        )
        .unwrap();

        let request = local_approval::build_approval_request(
            &local_policy,
            LocalOperationClass::Export,
            "PLAN-001".to_string(),
            vol_hash,
            "USER-FP".to_string(),
            "REASON".to_string(),
        );
        store.save_approval_request(&request).unwrap();
        let (updated_request, decision) =
            local_approval::approve_request(&request, "ADMIN-FP".to_string(), "OK".to_string());
        store.save_approval_request(&updated_request).unwrap();
        store.save_approval_decision(&decision).unwrap();

        // First use - success
        let result1 = execute_export_operation(
            mock_request(OperationKind::Export, Some(request.approval_id.clone())),
            &policy,
            &exp_policy,
            &store,
            recipient.clone(),
            false,
            &local_policy,
        )
        .unwrap();
        assert_eq!(result1.status, OperationStatus::Accepted);

        // Second use - rejection
        let result2 = execute_export_operation(
            mock_request(OperationKind::Export, Some(request.approval_id)),
            &policy,
            &exp_policy,
            &store,
            recipient,
            false,
            &local_policy,
        )
        .unwrap();
        assert_eq!(result2.status, OperationStatus::Rejected);
        assert!(result2.reason.contains("ApprovalAlreadyConsumed"));
    }
}
