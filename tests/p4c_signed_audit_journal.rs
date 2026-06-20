#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use tempfile::tempdir;
    use tuff_cse_winfs::audit_signing::{AuditSigner, DevAuditSigner};
    use tuff_cse_winfs::binding_store::BindingStore;
    use tuff_cse_winfs::operation_journal::{self, OperationJournalPhase};
    use tuff_cse_winfs::operations::{execute_managed_operation, OperationKind, OperationRequest};
    use tuff_cse_winfs::volume_state::VolumeBindingState;

    fn setup_store() -> (tempfile::TempDir, BindingStore) {
        let dir = tempdir().unwrap();
        let store = BindingStore::open_at(dir.path()).unwrap();
        (dir, store)
    }

    #[test]
    fn test_dev_audit_signer_env_gate() {
        env::remove_var("TUFF_CSE_WINFS_ALLOW_DEV_AUDIT_SIGNER");
        assert!(DevAuditSigner::new("test-key".to_string()).is_err());

        env::set_var("TUFF_CSE_WINFS_ALLOW_DEV_AUDIT_SIGNER", "1");
        assert!(DevAuditSigner::new("test-key".to_string()).is_ok());
    }

    #[test]
    fn test_tamper_detection_on_record_hash() {
        let (dir, store) = setup_store();
        env::set_var("TUFF_CSE_WINFS_ALLOW_DEV_AUDIT_SIGNER", "1");
        let signer = DevAuditSigner::new("test-key".to_string()).unwrap();
        store
            .save_audit_public_key(&signer.public_key_record())
            .unwrap();

        // 1. Generate signed journal
        let vol_hash = BindingStore::volume_hash("D:");
        let record = operation_journal::OperationJournalRecord {
            seq: 1,
            phase: operation_journal::OperationJournalPhase::Commit,
            operation_id: "op-1".to_string(),
            kind: OperationKind::Bind,
            volume: "D:".to_string(),
            requested_by: "user".to_string(),
            result_status: tuff_cse_winfs::operations::OperationStatus::Accepted,
            previous_state: VolumeBindingState::Unregistered,
            next_state: VolumeBindingState::BoundLocked,
            descriptor_id: None,
            plan_id: None,
            session_id: None,
            manual_flow_id: None,
            approval_id: None,
            decision_id: None,
            enterprise_authority_policy_id: Some("EA-001".to_string()),
            enterprise_quorum_policy_id: Some("EQ-001".to_string()),
            enterprise_recovery_request_id: Some("ERQ-001".to_string()),
            enterprise_recovery_decision_id: Some("ERD-001".to_string()),
            enterprise_provider_policy_id: Some("EP-001".to_string()),
            enterprise_provider_attestation_id: Some("EAT-001".to_string()),
            enterprise_provider_kind: Some(
                tuff_cse_winfs::enterprise_provider::EnterpriseProviderKind::ImportedOfflineProvider,
            ),
            enterprise_provider_health: Some(
                tuff_cse_winfs::enterprise_provider::EnterpriseProviderHealth::OfflineImported,
            ),
            enterprise_provider_attestation_hash: Some("APH-001".to_string()),
            enterprise_recovery_status: Some(
                tuff_cse_winfs::enterprise_recovery::EnterpriseRecoveryStatus::Approved,
            ),
            enterprise_recovery_enforcement_status: Some(
                tuff_cse_winfs::enterprise_recovery_enforcement::EnterpriseRecoveryEnforcementDecision::Allowed,
            ),
            enterprise_recovery_rejection_reason: None,
            enterprise_provider_enforcement_status: Some(
                tuff_cse_winfs::enterprise_provider_enforcement::EnterpriseProviderEnforcementDecision::Allowed,
            ),
            enterprise_provider_rejection_reason: None,
            approval_status: None,
            recovery_reason: None,
            reason: "test".to_string(),
            timestamp: 1234,
            record_hash: None,
            previous_record_hash: None,
            chain_hash: None,
            signing_key_id: None,
            signature_algorithm: None,
            signature: None,
            signed_at: None,
        };
        operation_journal::append_signed_record(
            store.root_path(),
            &vol_hash,
            record,
            &[0u8; 32],
            &signer,
        )
        .unwrap();

        // 2. Tamper with record_hash
        let mut records =
            operation_journal::read_journal_records(store.root_path(), &vol_hash).unwrap();
        records[0].record_hash = Some(vec![0u8; 32]);

        // 3. Verify
        let mut public_keys = std::collections::HashMap::new();
        public_keys.insert("test-key".to_string(), signer.public_key_record());

        assert!(tuff_cse_winfs::audit_chain::verify_journal_chain(&records, &public_keys).is_err());
    }

    #[test]
    fn test_enterprise_metadata_tamper_detection() {
        let (dir, store) = setup_store();
        env::set_var("TUFF_CSE_WINFS_ALLOW_DEV_AUDIT_SIGNER", "1");
        let signer = DevAuditSigner::new("test-key".to_string()).unwrap();
        store
            .save_audit_public_key(&signer.public_key_record())
            .unwrap();

        let vol_hash = BindingStore::volume_hash("D:");
        let record = operation_journal::OperationJournalRecord {
            seq: 1,
            phase: operation_journal::OperationJournalPhase::Commit,
            operation_id: "op-2".to_string(),
            kind: OperationKind::Recover,
            volume: "D:".to_string(),
            requested_by: "user".to_string(),
            result_status: tuff_cse_winfs::operations::OperationStatus::Accepted,
            previous_state: VolumeBindingState::BoundLocked,
            next_state: VolumeBindingState::BoundLocked,
            descriptor_id: None,
            plan_id: None,
            session_id: None,
            manual_flow_id: None,
            approval_id: None,
            decision_id: None,
            enterprise_authority_policy_id: Some("EA-001".to_string()),
            enterprise_quorum_policy_id: Some("EQ-001".to_string()),
            enterprise_recovery_request_id: Some("ERQ-001".to_string()),
            enterprise_recovery_decision_id: Some("ERD-001".to_string()),
            enterprise_provider_policy_id: Some("EP-001".to_string()),
            enterprise_provider_attestation_id: Some("EAT-001".to_string()),
            enterprise_provider_kind: Some(
                tuff_cse_winfs::enterprise_provider::EnterpriseProviderKind::ImportedOfflineProvider,
            ),
            enterprise_provider_health: Some(
                tuff_cse_winfs::enterprise_provider::EnterpriseProviderHealth::OfflineImported,
            ),
            enterprise_provider_attestation_hash: Some("APH-001".to_string()),
            enterprise_recovery_status: Some(
                tuff_cse_winfs::enterprise_recovery::EnterpriseRecoveryStatus::Approved,
            ),
            enterprise_recovery_enforcement_status: Some(
                tuff_cse_winfs::enterprise_recovery_enforcement::EnterpriseRecoveryEnforcementDecision::Allowed,
            ),
            enterprise_recovery_rejection_reason: None,
            enterprise_provider_enforcement_status: Some(
                tuff_cse_winfs::enterprise_provider_enforcement::EnterpriseProviderEnforcementDecision::Allowed,
            ),
            enterprise_provider_rejection_reason: None,
            approval_status: None,
            recovery_reason: None,
            reason: "test".to_string(),
            timestamp: 1234,
            record_hash: None,
            previous_record_hash: None,
            chain_hash: None,
            signing_key_id: None,
            signature_algorithm: None,
            signature: None,
            signed_at: None,
        };
        operation_journal::append_signed_record(
            store.root_path(),
            &vol_hash,
            record,
            &[0u8; 32],
            &signer,
        )
        .unwrap();

        let mut records =
            operation_journal::read_journal_records(store.root_path(), &vol_hash).unwrap();
        records[0].enterprise_recovery_status =
            Some(tuff_cse_winfs::enterprise_recovery::EnterpriseRecoveryStatus::Denied);

        let mut public_keys = std::collections::HashMap::new();
        public_keys.insert("test-key".to_string(), signer.public_key_record());
        assert!(tuff_cse_winfs::audit_chain::verify_journal_chain(&records, &public_keys).is_err());
    }
}
