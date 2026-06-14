#[cfg(test)]
mod tests {
    use std::fs;
    use tempfile::tempdir;
    use tuff_cse_winfs::binding_store::BindingStore;
    use tuff_cse_winfs::local_approval::{self, LocalApprovalStatus};
    use tuff_cse_winfs::local_policy::{self, LocalOperationClass};
    use tuff_cse_winfs::operation_journal::{self};

    fn setup_store() -> (tempfile::TempDir, BindingStore) {
        let dir = tempdir().unwrap();
        let store = BindingStore::open_at(dir.path()).unwrap();
        (dir, store)
    }

    #[test]
    fn test_default_local_policy_validates() {
        let policy = local_policy::default_local_policy();
        assert!(local_policy::validate_local_policy(&policy).is_ok());
    }

    #[test]
    fn test_local_policy_with_persist_raw_rejected() {
        let mut policy = local_policy::default_local_policy();
        policy.persist_raw_admin_identity = true;
        assert!(local_policy::validate_local_policy(&policy).is_err());
    }

    #[test]
    fn test_local_policy_with_zero_ttl_rejected() {
        let mut policy = local_policy::default_local_policy();
        policy.approval_ttl_seconds = 0;
        assert!(local_policy::validate_local_policy(&policy).is_err());
    }

    #[test]
    fn test_export_requires_local_admin_by_default() {
        let policy = local_policy::default_local_policy();
        assert!(local_policy::operation_requires_approval(
            &policy,
            LocalOperationClass::Export
        ));
    }

    #[test]
    fn test_approval_request_lifecycle() {
        let (dir, store) = setup_store();
        let policy = local_policy::default_local_policy();

        let request = local_approval::build_approval_request(
            &policy,
            LocalOperationClass::Export,
            "PLAN-001".to_string(),
            "VOL-HASH".to_string(),
            "USER-FP".to_string(),
            "MANAGED_EXPORT".to_string(),
        );

        store.save_approval_request(&request).unwrap();

        let loaded_request = store
            .load_approval_request(&request.approval_id)
            .unwrap()
            .unwrap();
        assert_eq!(loaded_request.status, LocalApprovalStatus::Requested);

        let (updated_request, decision) = local_approval::approve_request(
            &loaded_request,
            "ADMIN-FP".to_string(),
            "APPROVED_BY_ADMIN".to_string(),
        );

        store.save_approval_request(&updated_request).unwrap();
        store.save_approval_decision(&decision).unwrap();

        let final_request = store
            .load_approval_request(&request.approval_id)
            .unwrap()
            .unwrap();
        assert_eq!(final_request.status, LocalApprovalStatus::Approved);

        let final_decision = store
            .load_approval_decision(&request.approval_id)
            .unwrap()
            .unwrap();
        assert_eq!(final_decision.status, LocalApprovalStatus::Approved);
        assert_eq!(final_decision.approved_by_fingerprint, "ADMIN-FP");
    }

    #[test]
    fn test_approval_expired() {
        let policy = local_policy::LocalPolicy {
            approval_ttl_seconds: 1,
            ..local_policy::default_local_policy()
        };

        let request = local_approval::build_approval_request(
            &policy,
            LocalOperationClass::Export,
            "PLAN-001".to_string(),
            "VOL-HASH".to_string(),
            "USER-FP".to_string(),
            "REASON".to_string(),
        );

        assert!(!local_approval::is_expired(&request, request.created_at));
        assert!(local_approval::is_expired(&request, request.created_at + 2));
    }

    #[test]
    fn test_approval_files_no_secrets() {
        let (dir, store) = setup_store();
        let policy = local_policy::default_local_policy();

        let request = local_approval::build_approval_request(
            &policy,
            LocalOperationClass::Export,
            "PLAN-001".to_string(),
            "VOL-HASH".to_string(),
            "USER-FP".to_string(),
            "REASON".to_string(),
        );

        store.save_approval_request(&request).unwrap();

        let path = dir.path().join(format!(
            "JRN/approvals/{}.request.json",
            request.approval_id
        ));
        let content = fs::read_to_string(path).unwrap();

        assert!(!content.contains("basekey"));
        assert!(!content.contains("MK"));
        assert!(!content.contains("raw SID"));
        assert!(!content.contains("password"));
    }
}
