#[cfg(test)]
mod tests {
    use tempfile::tempdir;
    use tuff_cse_winfs::binding_store::BindingStore;
    use tuff_cse_winfs::export_manifest::ExportRecipient;
    use tuff_cse_winfs::managed_policy::ManagedPolicy;
    use tuff_cse_winfs::local_policy::LocalPolicy;
    use tuff_cse_winfs::manual_flow::{self, ManualFlowKind};
    use tuff_cse_winfs::operations::{
        execute_export_operation, execute_managed_operation, execute_manual_flow_operation,
        OperationKind, OperationRequest,
    };
    use tuff_cse_winfs::plan_state::PlanLifecycleStatus;
    use std::fs;

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
            timestamp: 0,
            approval_id,
        }
    }

    #[test]
    fn test_manual_confirmation_stores_hash() {
        let vol_hash = "D-HASH".to_string();
        let mflow = manual_flow::prepare_manual_flow(
            ManualFlowKind::ExportComplete,
            "PLAN-ID".to_string(),
            None,
            vol_hash,
            "REASON".to_string(),
            "RAW-TOKEN",
            "OP-ID".to_string(),
        );

        assert_ne!(mflow.confirmation_token_hash, "RAW-TOKEN");
        assert!(manual_flow::verify_confirmation_token(&mflow, "RAW-TOKEN"));
    }

    #[test]
    fn test_export_plan_lifecycle_to_completed() {
        let (_dir, store) = setup_store();
        let policy = ManagedPolicy::default();
        let exp_policy = tuff_cse_winfs::export_policy::ExportPolicy::default();
        let local_policy = LocalPolicy {
             require_local_admin_for_export: false,
             require_local_admin_for_manual_complete: false,
             ..LocalPolicy::default()
        };
        let recipient = ExportRecipient {
            recipient_id: "REC-001".to_string(),
            recipient_key_fingerprint: "FP-001".to_string(),
            recipient_org_hint: None,
        };

        // Bind first
        let _ = execute_managed_operation(mock_request(OperationKind::Bind, None), &policy, &store, None).unwrap();

        // Generate plan with manual confirmation
        let result = execute_export_operation(
            mock_request(OperationKind::Export, None),
            &policy,
            &exp_policy,
            &store,
            recipient,
            true, // require manual confirmation
            &local_policy,
        ).unwrap();

        let export_id = result.reason.split(": ").nth(1).unwrap().trim_start_matches("MANIFEST-EXP-");
        let plan_id = format!("PLAN-{}", export_id);
        
        let plan = store.load_export_plan(export_id).unwrap().unwrap();
        assert_eq!(plan.status, PlanLifecycleStatus::ManualConfirmationRequired);

        // Complete the plan
        let _ = execute_manual_flow_operation(
            mock_request(OperationKind::ManualComplete, None),
            &store,
            ManualFlowKind::ExportComplete,
            plan_id,
            "CONFIRM-EXPORT-001".to_string(),
            "REASON".to_string(),
            &local_policy,
        ).unwrap();

        let updated_plan = store.load_export_plan(export_id).unwrap().unwrap();
        assert_eq!(updated_plan.status, PlanLifecycleStatus::Completed);
    }

    #[test]
    fn test_export_plan_cancel() {
        let (_dir, store) = setup_store();
        let policy = ManagedPolicy::default();
        let exp_policy = tuff_cse_winfs::export_policy::ExportPolicy::default();
        let local_policy = LocalPolicy {
             require_local_admin_for_export: false,
             require_local_admin_for_manual_cancel: false,
             ..LocalPolicy::default()
        };
        let recipient = ExportRecipient {
            recipient_id: "REC-001".to_string(),
            recipient_key_fingerprint: "FP-001".to_string(),
            recipient_org_hint: None,
        };

        let _ = execute_managed_operation(mock_request(OperationKind::Bind, None), &policy, &store, None).unwrap();
        let result = execute_export_operation(
            mock_request(OperationKind::Export, None),
            &policy,
            &exp_policy,
            &store,
            recipient,
            false,
            &local_policy,
        ).unwrap();

        let export_id = result.reason.split(": ").nth(1).unwrap().trim_start_matches("MANIFEST-EXP-");
        let plan_id = format!("PLAN-{}", export_id);

        execute_manual_flow_operation(
            mock_request(OperationKind::ManualCancel, None),
            &store,
            ManualFlowKind::ExportCancel,
            plan_id,
            "ANY-TOKEN".to_string(),
            "USER_ABORT".to_string(),
            &local_policy,
        ).unwrap();

        let updated_plan = store.load_export_plan(export_id).unwrap().unwrap();
        assert_eq!(updated_plan.status, PlanLifecycleStatus::Cancelled);
    }

    #[test]
    fn test_manual_flow_no_secrets() {
        let (dir, store) = setup_store();
        let flow_id = "MFLOW-TEST-001";
        let record = manual_flow::ManualFlowRecord {
            manual_flow_id: flow_id.to_string(),
            kind: ManualFlowKind::ExportComplete,
            status: manual_flow::ManualFlowStatus::Committed,
            target_plan_id: "PLAN-001".to_string(),
            target_manifest_id: None,
            source_volume_hash: "VOL-HASH".to_string(),
            reason_code: "OK".to_string(),
            confirmation_token_hash: "HASH".to_string(),
            created_at: 1234,
            completed_at: Some(1235),
            cancelled_at: None,
            journal_operation_id: "OP-001".to_string(),
        };

        store.save_manual_flow_record(&record).unwrap();
        let path = dir.path().join(format!("JRN/manual/{}.manual.json", flow_id));
        let content = fs::read_to_string(path).unwrap();

        assert!(!content.contains("basekey"));
        assert!(!content.contains("MK"));
        assert!(!content.contains("RAW-TOKEN"));
    }
}
