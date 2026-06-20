#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::process::Command;
    use tempfile::tempdir;
    use tuff_cse_winfs::audit_chain;
    use tuff_cse_winfs::audit_signing::{AuditSigner, DevAuditSigner};
    use tuff_cse_winfs::binding_store::BindingStore;
    use tuff_cse_winfs::enterprise_authority::{
        normalize_enterprise_authority_policy, EnterpriseAuthorityFingerprint,
        EnterpriseAuthorityPolicy, EnterpriseAuthorityPolicyId, EnterpriseAuthorityProviderKind,
    };
    use tuff_cse_winfs::enterprise_provider::{
        compute_enterprise_provider_attestation_hash, normalize_enterprise_provider_attestation,
        normalize_enterprise_provider_policy, EnterpriseProviderAttestationHash,
        EnterpriseProviderAttestationId, EnterpriseProviderAttestationSummary,
        EnterpriseProviderCapability, EnterpriseProviderHealth, EnterpriseProviderKind,
        EnterpriseProviderPolicy, EnterpriseProviderPolicyId,
    };
    use tuff_cse_winfs::enterprise_provider_enforcement::{
        EnterpriseProviderEnforcementDecision, EnterpriseProviderEnforcer,
    };
    use tuff_cse_winfs::enterprise_quorum::{
        normalize_enterprise_quorum_policy, EnterpriseQuorumMemberFingerprint,
        EnterpriseQuorumPolicy, EnterpriseQuorumPolicyId, EnterpriseQuorumThreshold, QuorumRule,
    };
    use tuff_cse_winfs::enterprise_recovery::{
        build_enterprise_recovery_decision, EnterpriseRecoveryDecision,
        EnterpriseRecoveryDecisionId, EnterpriseRecoveryRequest, EnterpriseRecoveryRequestId,
        EnterpriseRecoverySourceKind, EnterpriseRecoveryStatus,
    };
    use tuff_cse_winfs::enterprise_recovery_enforcement::EnterpriseRecoveryEnforcer;
    use tuff_cse_winfs::operation_journal::{self, OperationJournalRecord};
    use tuff_cse_winfs::operations::{OperationKind, OperationStatus};
    use tuff_cse_winfs::volume_state::VolumeBindingState;

    fn setup_store() -> (tempfile::TempDir, BindingStore) {
        let dir = tempdir().unwrap();
        let store = BindingStore::open_at(dir.path()).unwrap();
        (dir, store)
    }

    fn authority_policy() -> EnterpriseAuthorityPolicy {
        normalize_enterprise_authority_policy(EnterpriseAuthorityPolicy {
            policy_id: EnterpriseAuthorityPolicyId("EA-001".to_string()),
            authority_fingerprint: EnterpriseAuthorityFingerprint("AUTH-FP-001".to_string()),
            provider_kind: EnterpriseAuthorityProviderKind::ImportedOfflineAuthority,
            policy_hash: None,
            created_at: 1,
        })
    }

    fn quorum_policy() -> EnterpriseQuorumPolicy {
        normalize_enterprise_quorum_policy(EnterpriseQuorumPolicy {
            policy_id: EnterpriseQuorumPolicyId("EQ-001".to_string()),
            enterprise_authority_policy_id: EnterpriseAuthorityPolicyId("EA-001".to_string()),
            rule: QuorumRule::Threshold,
            threshold: EnterpriseQuorumThreshold(1),
            members: vec![EnterpriseQuorumMemberFingerprint("MEM-001".to_string())],
            policy_hash: None,
            created_at: 1,
        })
        .unwrap()
    }

    fn provider_policy() -> EnterpriseProviderPolicy {
        normalize_enterprise_provider_policy(EnterpriseProviderPolicy {
            policy_id: EnterpriseProviderPolicyId("EP-001".to_string()),
            enterprise_authority_policy_id: EnterpriseAuthorityPolicyId("EA-001".to_string()),
            provider_kind: EnterpriseProviderKind::ImportedOfflineProvider,
            capabilities: vec![
                EnterpriseProviderCapability::RecoveryApprovalOnly,
                EnterpriseProviderCapability::AuditOnly,
            ],
            health: EnterpriseProviderHealth::OfflineImported,
            provider_generation: None,
            policy_hash: None,
            created_at: 1,
        })
    }

    fn provider_attestation() -> EnterpriseProviderAttestationSummary {
        normalize_enterprise_provider_attestation(EnterpriseProviderAttestationSummary {
            attestation_id: EnterpriseProviderAttestationId("EAT-001".to_string()),
            enterprise_provider_id: EnterpriseProviderPolicyId("EP-001".to_string()),
            enterprise_authority_policy_id: EnterpriseAuthorityPolicyId("EA-001".to_string()),
            provider_kind: EnterpriseProviderKind::ImportedOfflineProvider,
            capabilities: vec![EnterpriseProviderCapability::RecoveryApprovalOnly],
            health: EnterpriseProviderHealth::OfflineImported,
            provider_generation: None,
            valid_from: 1,
            valid_until: u64::MAX,
            revoked_at: None,
            attestation_hash: None,
            created_at: 1,
        })
    }

    fn request() -> EnterpriseRecoveryRequest {
        EnterpriseRecoveryRequest {
            request_id: EnterpriseRecoveryRequestId("ERQ-001".to_string()),
            operation_kind: OperationKind::Recover,
            volume_hash: BindingStore::volume_hash("D:"),
            domain_recovery_request_id: "DRQ-001".to_string(),
            domain_recovery_package_id: "DRP-001".to_string(),
            domain_recovery_decision_id: "DRD-001".to_string(),
            enterprise_authority_policy_id: EnterpriseAuthorityPolicyId("EA-001".to_string()),
            enterprise_quorum_policy_id: EnterpriseQuorumPolicyId("EQ-001".to_string()),
            enterprise_provider_id: Some("EP-001".to_string()),
            provider_attestation_hash: Some(
                provider_attestation()
                    .attestation_hash
                    .as_ref()
                    .unwrap()
                    .0
                    .clone(),
            ),
            source_kind: EnterpriseRecoverySourceKind::ImportedOfflineDecision,
            created_at: 1,
        }
    }

    fn decision() -> EnterpriseRecoveryDecision {
        let mut decision = build_enterprise_recovery_decision(
            EnterpriseRecoveryDecisionId("ERD-001".to_string()),
            OperationKind::Recover,
            BindingStore::volume_hash("D:"),
            "DRQ-001".to_string(),
            "DRP-001".to_string(),
            "DRD-001".to_string(),
            EnterpriseAuthorityPolicyId("EA-001".to_string()),
            EnterpriseQuorumPolicyId("EQ-001".to_string()),
            vec![EnterpriseQuorumMemberFingerprint("MEM-001".to_string())],
            1,
            u64::MAX,
            EnterpriseRecoveryStatus::Approved,
            EnterpriseRecoverySourceKind::ImportedOfflineDecision,
        );
        decision.enterprise_provider_id = Some("EP-001".to_string());
        decision.provider_attestation_hash = Some(
            provider_attestation()
                .attestation_hash
                .as_ref()
                .unwrap()
                .0
                .clone(),
        );
        decision.decision_hash =
            tuff_cse_winfs::enterprise_recovery::compute_enterprise_recovery_decision_hash(
                &decision,
            );
        decision
    }

    fn cli_path() -> String {
        env::var("CARGO_BIN_EXE_tuff-cse-winfsctl").unwrap()
    }

    fn run_cli(args: &[&str], store_root: &std::path::Path) -> std::process::Output {
        let mut cmd = Command::new(cli_path());
        cmd.args(args).arg("--store-root").arg(store_root);
        cmd.output().unwrap()
    }

    #[test]
    fn enterprise_provider_policy_and_attestation_persist_only_ids_and_hashes() {
        let (dir, store) = setup_store();
        let policy = provider_policy();
        let attestation = provider_attestation();
        store.save_enterprise_provider_policy(&policy).unwrap();
        store
            .save_enterprise_provider_attestation(&attestation)
            .unwrap();

        let policy_json =
            fs::read_to_string(dir.path().join("META/enterprise-provider/EP-001.json")).unwrap();
        let attestation_json = fs::read_to_string(
            dir.path()
                .join("JRN/enterprise-provider/attestations/EAT-001.json"),
        )
        .unwrap();
        assert!(policy_json.contains("EP-001"));
        assert!(!policy_json.contains("AUTH-FP-001"));
        assert!(policy_json.contains(policy.policy_hash.as_ref().expect("policy hash").0.as_str()));
        assert!(attestation_json.contains("EAT-001"));
        assert!(attestation_json.contains("EP-001"));
        assert!(attestation_json.contains(
            attestation
                .attestation_hash
                .as_ref()
                .expect("attestation hash")
                .0
                .as_str()
        ));
    }

    #[test]
    fn reserved_live_provider_is_rejected() {
        let (_dir, store) = setup_store();
        let provider_policy = normalize_enterprise_provider_policy(EnterpriseProviderPolicy {
            policy_id: EnterpriseProviderPolicyId("EP-RESERVED".to_string()),
            enterprise_authority_policy_id: EnterpriseAuthorityPolicyId("EA-001".to_string()),
            provider_kind: EnterpriseProviderKind::ReservedCloudKms,
            capabilities: vec![EnterpriseProviderCapability::RecoveryApprovalOnly],
            health: EnterpriseProviderHealth::HealthyReserved,
            provider_generation: None,
            policy_hash: None,
            created_at: 1,
        });
        let attestation = provider_attestation();
        let enforcer = EnterpriseRecoveryEnforcer::new(&store);
        let result = enforcer
            .check_enterprise_provider(
                &request(),
                Some(&decision()),
                Some(&provider_policy),
                Some(&attestation),
                Some(&authority_policy()),
            )
            .unwrap();
        assert_eq!(
            result,
            EnterpriseProviderEnforcementDecision::ReservedLiveProvider
        );
    }

    #[test]
    fn capability_missing_rejects_provider_gate() {
        let (_dir, store) = setup_store();
        let provider_policy = normalize_enterprise_provider_policy(EnterpriseProviderPolicy {
            policy_id: EnterpriseProviderPolicyId("EP-001".to_string()),
            enterprise_authority_policy_id: EnterpriseAuthorityPolicyId("EA-001".to_string()),
            provider_kind: EnterpriseProviderKind::ImportedOfflineProvider,
            capabilities: vec![EnterpriseProviderCapability::AuditOnly],
            health: EnterpriseProviderHealth::OfflineImported,
            provider_generation: None,
            policy_hash: None,
            created_at: 1,
        });
        let attestation = provider_attestation();
        let enforcer = EnterpriseRecoveryEnforcer::new(&store);
        let result = enforcer
            .check_enterprise_provider(
                &request(),
                Some(&decision()),
                Some(&provider_policy),
                Some(&attestation),
                Some(&authority_policy()),
            )
            .unwrap();
        assert_eq!(result, EnterpriseProviderEnforcementDecision::Rejected);
    }

    #[test]
    fn authority_mismatch_rejects_provider_gate() {
        let (_dir, store) = setup_store();
        let mut provider_policy = provider_policy();
        provider_policy.enterprise_authority_policy_id =
            EnterpriseAuthorityPolicyId("EA-OTHER".to_string());
        let attestation = provider_attestation();
        let enforcer = EnterpriseRecoveryEnforcer::new(&store);
        let result = enforcer
            .check_enterprise_provider(
                &request(),
                Some(&decision()),
                Some(&provider_policy),
                Some(&attestation),
                Some(&authority_policy()),
            )
            .unwrap();
        assert_eq!(result, EnterpriseProviderEnforcementDecision::Rejected);
    }

    #[test]
    fn valid_provider_attestation_passes_provider_gate() {
        let (_dir, store) = setup_store();
        let provider_policy = provider_policy();
        let attestation = provider_attestation();
        let enforcer = EnterpriseRecoveryEnforcer::new(&store);
        let result = enforcer
            .check_enterprise_provider(
                &request(),
                Some(&decision()),
                Some(&provider_policy),
                Some(&attestation),
                Some(&authority_policy()),
            )
            .unwrap();
        assert_eq!(result, EnterpriseProviderEnforcementDecision::Allowed);
    }

    #[test]
    fn enterprise_provider_metadata_is_included_in_p4c_signed_canonical_payload() {
        let (dir, store) = setup_store();
        env::set_var("TUFF_CSE_WINFS_ALLOW_DEV_AUDIT_SIGNER", "1");
        let signer = DevAuditSigner::new("provider-key-1".to_string()).unwrap();
        store
            .save_audit_public_key(&signer.public_key_record())
            .unwrap();

        let record = OperationJournalRecord {
            seq: 1,
            phase: operation_journal::OperationJournalPhase::Commit,
            operation_id: "OP-1".to_string(),
            kind: OperationKind::Recover,
            volume: "D:".to_string(),
            requested_by: "user".to_string(),
            result_status: OperationStatus::Accepted,
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
            enterprise_provider_health: Some(EnterpriseProviderHealth::OfflineImported),
            enterprise_provider_attestation_hash: Some(
                provider_attestation()
                    .attestation_hash
                    .as_ref()
                    .unwrap()
                    .0
                    .clone(),
            ),
            enterprise_recovery_status: Some(EnterpriseRecoveryStatus::Approved),
            enterprise_recovery_enforcement_status: Some(
                tuff_cse_winfs::enterprise_recovery_enforcement::EnterpriseRecoveryEnforcementDecision::Allowed,
            ),
            enterprise_recovery_rejection_reason: None,
            enterprise_provider_enforcement_status: Some(
                EnterpriseProviderEnforcementDecision::Allowed,
            ),
            enterprise_provider_rejection_reason: None,
            approval_status: None,
            recovery_reason: None,
            reason: "test".to_string(),
            timestamp: 1,
            record_hash: None,
            previous_record_hash: None,
            chain_hash: None,
            signing_key_id: None,
            signature_algorithm: None,
            signature: None,
            signed_at: None,
            ..Default::default()
        };
        operation_journal::append_signed_record(
            store.root_path(),
            &BindingStore::volume_hash("D:"),
            record,
            &[0u8; 32],
            &signer,
        )
        .unwrap();
        let records = operation_journal::read_journal_records(
            store.root_path(),
            &BindingStore::volume_hash("D:"),
        )
        .unwrap();
        let mut public_keys = std::collections::HashMap::new();
        public_keys.insert("provider-key-1".to_string(), signer.public_key_record());
        assert!(audit_chain::verify_journal_chain(&records, &public_keys).is_ok());
        assert!(dir.path().exists());
    }

    #[test]
    fn tampering_enterprise_provider_metadata_causes_p4c_verify_failure() {
        let (_dir, store) = setup_store();
        env::set_var("TUFF_CSE_WINFS_ALLOW_DEV_AUDIT_SIGNER", "1");
        let signer = DevAuditSigner::new("provider-key-2".to_string()).unwrap();
        store
            .save_audit_public_key(&signer.public_key_record())
            .unwrap();

        let record = OperationJournalRecord {
            seq: 1,
            phase: operation_journal::OperationJournalPhase::Commit,
            operation_id: "OP-2".to_string(),
            kind: OperationKind::Recover,
            volume: "D:".to_string(),
            requested_by: "user".to_string(),
            result_status: OperationStatus::Accepted,
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
            enterprise_provider_health: Some(EnterpriseProviderHealth::OfflineImported),
            enterprise_provider_attestation_hash: Some(
                provider_attestation()
                    .attestation_hash
                    .as_ref()
                    .unwrap()
                    .0
                    .clone(),
            ),
            enterprise_recovery_status: Some(EnterpriseRecoveryStatus::Approved),
            enterprise_recovery_enforcement_status: Some(
                tuff_cse_winfs::enterprise_recovery_enforcement::EnterpriseRecoveryEnforcementDecision::Allowed,
            ),
            enterprise_recovery_rejection_reason: None,
            enterprise_provider_enforcement_status: Some(
                EnterpriseProviderEnforcementDecision::Allowed,
            ),
            enterprise_provider_rejection_reason: None,
            approval_status: None,
            recovery_reason: None,
            reason: "test".to_string(),
            timestamp: 1,
            record_hash: None,
            previous_record_hash: None,
            chain_hash: None,
            signing_key_id: None,
            signature_algorithm: None,
            signature: None,
            signed_at: None,
            ..Default::default()
        };
        operation_journal::append_signed_record(
            store.root_path(),
            &BindingStore::volume_hash("D:"),
            record,
            &[0u8; 32],
            &signer,
        )
        .unwrap();
        let mut records = operation_journal::read_journal_records(
            store.root_path(),
            &BindingStore::volume_hash("D:"),
        )
        .unwrap();
        records[0].enterprise_provider_policy_id = Some("EP-TAMPERED".to_string());
        let mut public_keys = std::collections::HashMap::new();
        public_keys.insert("provider-key-2".to_string(), signer.public_key_record());
        assert!(audit_chain::verify_journal_chain(&records, &public_keys).is_err());
    }

    #[test]
    fn enterprise_provider_cli_import_status_and_evaluate_work() {
        let (_dir, store) = setup_store();
        let provider_policy_json = serde_json::to_string(&provider_policy()).unwrap();
        let attestation_json = serde_json::to_string(&provider_attestation()).unwrap();
        let policy_path = store.root_path().join("provider-policy.json");
        let attestation_path = store.root_path().join("provider-attestation.json");
        fs::write(&policy_path, provider_policy_json).unwrap();
        fs::write(&attestation_path, attestation_json).unwrap();

        let import = run_cli(
            &[
                "enterprise-provider",
                "import",
                "--policy",
                policy_path.to_str().unwrap(),
                "--json",
            ],
            store.root_path(),
        );
        assert!(import.status.success());

        let import_attestation = run_cli(
            &[
                "enterprise-provider",
                "import-attestation",
                "--attestation",
                attestation_path.to_str().unwrap(),
                "--json",
            ],
            store.root_path(),
        );
        assert!(import_attestation.status.success());

        let status = run_cli(
            &[
                "enterprise-provider",
                "status",
                "--enterprise-provider",
                "EP-001",
                "--json",
            ],
            store.root_path(),
        );
        assert!(status.status.success());

        let evaluate = run_cli(
            &[
                "enterprise-provider",
                "evaluate",
                "--enterprise-provider",
                "EP-001",
                "--operation",
                "recover",
                "--volume",
                "D:",
                "--json",
            ],
            store.root_path(),
        );
        assert!(evaluate.status.success());
    }
}
