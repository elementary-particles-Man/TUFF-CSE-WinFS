#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::process::Command;
    use tempfile::tempdir;
    use tuff_cse_winfs::binding_store::BindingStore;
    use tuff_cse_winfs::enterprise_authority::{
        normalize_enterprise_authority_policy, EnterpriseAuthorityFingerprint,
        EnterpriseAuthorityPolicy, EnterpriseAuthorityPolicyId, EnterpriseAuthorityProviderKind,
    };
    use tuff_cse_winfs::enterprise_quorum::{
        evaluate_quorum_decision, normalize_enterprise_quorum_policy, EnterpriseQuorumEvaluation,
        EnterpriseQuorumMemberFingerprint, EnterpriseQuorumPolicy, EnterpriseQuorumPolicyId,
        EnterpriseQuorumThreshold, QuorumRule,
    };
    use tuff_cse_winfs::enterprise_recovery::{
        build_enterprise_recovery_decision, compute_enterprise_recovery_decision_hash,
        EnterpriseRecoveryDecision, EnterpriseRecoveryDecisionId, EnterpriseRecoveryRequest,
        EnterpriseRecoveryRequestId, EnterpriseRecoverySourceKind, EnterpriseRecoveryStatus,
    };
    use tuff_cse_winfs::enterprise_recovery_enforcement::{
        EnterpriseRecoveryEnforcementDecision, EnterpriseRecoveryEnforcer,
    };
    use tuff_cse_winfs::operations::OperationKind;
    use tuff_cse_winfs::{
        audit_chain,
        audit_signing::AuditSigner,
        audit_signing::DevAuditSigner,
        domain_approval::{DomainApprovalDecision, DomainApprovalStatus},
        domain_approval_enforcement::DomainApprovalEnforcer,
        domain_policy::{DomainPolicy, DomainPolicySourceKind},
        domain_principal::DomainAuthorityFingerprint,
        domain_recovery::{
            DomainRecoveryDecision, DomainRecoveryRequest, DomainRecoveryWorkflowState,
        },
        domain_recovery_enforcement::DomainRecoveryEnforcer,
        local_policy::LocalPolicy,
        operation_journal::{self, OperationJournalRecord},
        operations::{execute_recover_operation, OperationRequest, OperationStatus},
        volume_state::{VolumeBindingState, VolumeRuntimeState},
    };

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
            source_kind: EnterpriseRecoverySourceKind::ImportedOfflineDecision,
            created_at: 1,
        }
    }

    fn decision() -> EnterpriseRecoveryDecision {
        build_enterprise_recovery_decision(
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
        )
    }

    fn cli_path() -> String {
        env::var("CARGO_BIN_EXE_tuff-cse-winfsctl").unwrap()
    }

    fn run_cli(
        args: &[&str],
        store_root: &std::path::Path,
        allow_dev: bool,
    ) -> std::process::Output {
        let mut cmd = Command::new(cli_path());
        cmd.args(args).arg("--store-root").arg(store_root);
        if allow_dev {
            cmd.env("TUFF_CSE_WINFS_ALLOW_DEV_ENTERPRISE_RECOVERY", "1");
        }
        cmd.output().unwrap()
    }

    #[test]
    fn enterprise_authority_policy_persists_only_ids_fingerprints_and_hashes() {
        let (dir, store) = setup_store();
        let policy = authority_policy();
        store.save_enterprise_authority_policy(&policy).unwrap();
        let path = dir.path().join("META/enterprise-authority/EA-001.json");
        let json = fs::read_to_string(path).unwrap();
        assert!(json.contains("EA-001"));
        assert!(json.contains("AUTH-FP-001"));
        assert!(json.contains(&policy.policy_hash.as_ref().unwrap().0));
        assert!(!json.contains("raw authority"));
    }

    #[test]
    fn enterprise_quorum_policy_rejects_threshold_greater_than_members() {
        let policy = EnterpriseQuorumPolicy {
            policy_id: EnterpriseQuorumPolicyId("EQ-BAD".to_string()),
            enterprise_authority_policy_id: EnterpriseAuthorityPolicyId("EA-001".to_string()),
            rule: QuorumRule::Threshold,
            threshold: EnterpriseQuorumThreshold(2),
            members: vec![EnterpriseQuorumMemberFingerprint("MEM-001".to_string())],
            policy_hash: None,
            created_at: 1,
        };
        assert!(normalize_enterprise_quorum_policy(policy).is_err());
    }

    #[test]
    fn enterprise_quorum_policy_rejects_duplicate_members() {
        let policy = EnterpriseQuorumPolicy {
            policy_id: EnterpriseQuorumPolicyId("EQ-BAD".to_string()),
            enterprise_authority_policy_id: EnterpriseAuthorityPolicyId("EA-001".to_string()),
            rule: QuorumRule::Threshold,
            threshold: EnterpriseQuorumThreshold(1),
            members: vec![
                EnterpriseQuorumMemberFingerprint("MEM-001".to_string()),
                EnterpriseQuorumMemberFingerprint("MEM-001".to_string()),
            ],
            policy_hash: None,
            created_at: 1,
        };
        assert!(normalize_enterprise_quorum_policy(policy).is_err());
    }

    #[test]
    fn enterprise_recovery_decision_persists_only_fingerprints_ids_and_hashes() {
        let (dir, store) = setup_store();
        let decision = decision();
        store.save_enterprise_recovery_decision(&decision).unwrap();
        let path = dir
            .path()
            .join("JRN/enterprise-recovery/decisions/ERD-001.json");
        let json = fs::read_to_string(path).unwrap();
        assert!(json.contains("ERD-001"));
        assert!(json.contains("EA-001"));
        assert!(json.contains("EQ-001"));
        assert!(!json.contains("KMS secret"));
        assert!(!json.contains("HSM secret"));
        let loaded = store
            .load_enterprise_recovery_decision("ERD-001")
            .unwrap()
            .unwrap();
        assert_eq!(
            loaded.decision_hash,
            compute_enterprise_recovery_decision_hash(&loaded)
        );
    }

    #[test]
    fn dev_enterprise_recovery_approval_is_rejected_without_env_gate() {
        let (_dir, store) = setup_store();
        store
            .save_enterprise_authority_policy(&authority_policy())
            .unwrap();
        store
            .save_enterprise_quorum_policy(&quorum_policy())
            .unwrap();
        store.save_enterprise_recovery_request(&request()).unwrap();

        env::remove_var("TUFF_CSE_WINFS_ALLOW_DEV_ENTERPRISE_RECOVERY");
        let output = run_cli(
            &[
                "enterprise-recovery",
                "dev-approve",
                "--request-id",
                "ERQ-001",
                "--json",
            ],
            store.root_path(),
            false,
        );
        assert!(!output.status.success());
    }

    #[test]
    fn dev_enterprise_recovery_approval_succeeds_with_explicit_env_gate() {
        let (_dir, store) = setup_store();
        store
            .save_enterprise_authority_policy(&authority_policy())
            .unwrap();
        store
            .save_enterprise_quorum_policy(&quorum_policy())
            .unwrap();
        store.save_enterprise_recovery_request(&request()).unwrap();

        let output = run_cli(
            &[
                "enterprise-recovery",
                "dev-approve",
                "--request-id",
                "ERQ-001",
                "--json",
            ],
            store.root_path(),
            true,
        );
        assert!(output.status.success());
        let decision: EnterpriseRecoveryDecision = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(decision.status, EnterpriseRecoveryStatus::Approved);
    }

    #[test]
    fn valid_enterprise_recovery_decision_passes_enterprise_gate() {
        let (dir, store) = setup_store();
        let auth = authority_policy();
        let quorum = quorum_policy();
        let request = request();
        let decision = decision();
        store.save_enterprise_authority_policy(&auth).unwrap();
        store.save_enterprise_quorum_policy(&quorum).unwrap();
        store.save_enterprise_recovery_request(&request).unwrap();
        store.save_enterprise_recovery_decision(&decision).unwrap();
        let enforcer = EnterpriseRecoveryEnforcer::new(&store);
        let result = enforcer
            .check_enterprise_recovery(&request, Some(&decision), Some(&auth), Some(&quorum))
            .unwrap();
        assert_eq!(result, EnterpriseRecoveryEnforcementDecision::Allowed);
        assert!(dir.path().exists());
    }

    #[test]
    fn missing_enterprise_recovery_decision_rejects_required_enterprise_gate() {
        let (_dir, store) = setup_store();
        let auth = authority_policy();
        let quorum = quorum_policy();
        let request = request();
        let enforcer = EnterpriseRecoveryEnforcer::new(&store);
        let result = enforcer
            .check_enterprise_recovery(&request, None, Some(&auth), Some(&quorum))
            .unwrap();
        assert_eq!(result, EnterpriseRecoveryEnforcementDecision::Rejected);
    }

    #[test]
    fn denied_enterprise_recovery_decision_rejects_operation() {
        let (_dir, store) = setup_store();
        let auth = authority_policy();
        let quorum = quorum_policy();
        let request = request();
        let mut denied = decision();
        denied.status = EnterpriseRecoveryStatus::Denied;
        denied.decision_hash = compute_enterprise_recovery_decision_hash(&denied);
        let enforcer = EnterpriseRecoveryEnforcer::new(&store);
        let result = enforcer
            .check_enterprise_recovery(&request, Some(&denied), Some(&auth), Some(&quorum))
            .unwrap();
        assert_eq!(result, EnterpriseRecoveryEnforcementDecision::Rejected);
    }

    #[test]
    fn expired_enterprise_recovery_decision_rejects_operation() {
        let (_dir, store) = setup_store();
        let auth = authority_policy();
        let quorum = quorum_policy();
        let request = request();
        let mut expired = decision();
        expired.valid_until = 0;
        expired.decision_hash = compute_enterprise_recovery_decision_hash(&expired);
        let enforcer = EnterpriseRecoveryEnforcer::new(&store);
        let result = enforcer
            .check_enterprise_recovery(&request, Some(&expired), Some(&auth), Some(&quorum))
            .unwrap();
        assert_eq!(result, EnterpriseRecoveryEnforcementDecision::Rejected);
    }

    #[test]
    fn consumed_enterprise_recovery_decision_rejects_second_use() {
        let (dir, store) = setup_store();
        let auth = authority_policy();
        let quorum = quorum_policy();
        let request = request();
        let mut used = decision();
        used.consumed_at = Some(1);
        used.decision_hash = compute_enterprise_recovery_decision_hash(&used);
        store.save_enterprise_authority_policy(&auth).unwrap();
        store.save_enterprise_quorum_policy(&quorum).unwrap();
        store.save_enterprise_recovery_decision(&used).unwrap();
        assert!(store.mark_enterprise_recovery_consumed("ERD-001").is_ok());
        let loaded = store
            .load_enterprise_recovery_decision("ERD-001")
            .unwrap()
            .unwrap();
        assert!(loaded.is_consumed());
        let enforcer = EnterpriseRecoveryEnforcer::new(&store);
        let result = enforcer
            .check_enterprise_recovery(&request, Some(&loaded), Some(&auth), Some(&quorum))
            .unwrap();
        assert_eq!(result, EnterpriseRecoveryEnforcementDecision::Rejected);
        assert!(dir.path().exists());
    }

    #[test]
    fn operation_mismatch_rejects_enterprise_recovery_decision() {
        let (_dir, store) = setup_store();
        let auth = authority_policy();
        let quorum = quorum_policy();
        let mut request = request();
        request.operation_kind = OperationKind::Rebind;
        let enforcer = EnterpriseRecoveryEnforcer::new(&store);
        let result = enforcer
            .check_enterprise_recovery(&request, Some(&decision()), Some(&auth), Some(&quorum))
            .unwrap();
        assert_eq!(result, EnterpriseRecoveryEnforcementDecision::Rejected);
    }

    #[test]
    fn volume_mismatch_rejects_enterprise_recovery_decision() {
        let (_dir, store) = setup_store();
        let auth = authority_policy();
        let quorum = quorum_policy();
        let mut request = request();
        request.volume_hash = "other".to_string();
        let enforcer = EnterpriseRecoveryEnforcer::new(&store);
        let result = enforcer
            .check_enterprise_recovery(&request, Some(&decision()), Some(&auth), Some(&quorum))
            .unwrap();
        assert_eq!(result, EnterpriseRecoveryEnforcementDecision::Rejected);
    }

    #[test]
    fn domain_recovery_mismatch_rejects_enterprise_recovery_decision() {
        let (_dir, store) = setup_store();
        let auth = authority_policy();
        let quorum = quorum_policy();
        let mut decision = decision();
        decision.domain_recovery_request_id = "WRONG".to_string();
        decision.decision_hash = compute_enterprise_recovery_decision_hash(&decision);
        let enforcer = EnterpriseRecoveryEnforcer::new(&store);
        let result = enforcer
            .check_enterprise_recovery(&request(), Some(&decision), Some(&auth), Some(&quorum))
            .unwrap();
        assert_eq!(result, EnterpriseRecoveryEnforcementDecision::Rejected);
    }

    #[test]
    fn authority_policy_mismatch_rejects_enterprise_recovery_decision() {
        let (_dir, store) = setup_store();
        let auth = authority_policy();
        let mut request = request();
        request.enterprise_authority_policy_id =
            EnterpriseAuthorityPolicyId("EA-OTHER".to_string());
        let quorum = quorum_policy();
        let enforcer = EnterpriseRecoveryEnforcer::new(&store);
        let result = enforcer
            .check_enterprise_recovery(&request, Some(&decision()), Some(&auth), Some(&quorum))
            .unwrap();
        assert_eq!(result, EnterpriseRecoveryEnforcementDecision::Rejected);
    }

    #[test]
    fn quorum_policy_mismatch_rejects_enterprise_recovery_decision() {
        let (_dir, store) = setup_store();
        let auth = authority_policy();
        let mut request = request();
        request.enterprise_quorum_policy_id = EnterpriseQuorumPolicyId("EQ-OTHER".to_string());
        let quorum = quorum_policy();
        let enforcer = EnterpriseRecoveryEnforcer::new(&store);
        let result = enforcer
            .check_enterprise_recovery(&request, Some(&decision()), Some(&auth), Some(&quorum))
            .unwrap();
        assert_eq!(result, EnterpriseRecoveryEnforcementDecision::Rejected);
    }

    #[test]
    fn quorum_not_met_rejects_enterprise_recovery_decision() {
        let (_dir, store) = setup_store();
        let auth = authority_policy();
        let quorum = normalize_enterprise_quorum_policy(EnterpriseQuorumPolicy {
            policy_id: EnterpriseQuorumPolicyId("EQ-002".to_string()),
            enterprise_authority_policy_id: EnterpriseAuthorityPolicyId("EA-001".to_string()),
            rule: QuorumRule::Threshold,
            threshold: EnterpriseQuorumThreshold(2),
            members: vec![
                EnterpriseQuorumMemberFingerprint("MEM-001".to_string()),
                EnterpriseQuorumMemberFingerprint("MEM-002".to_string()),
            ],
            policy_hash: None,
            created_at: 1,
        })
        .unwrap();
        let mut request = request();
        request.enterprise_quorum_policy_id = quorum.policy_id.clone();
        let decision = build_enterprise_recovery_decision(
            EnterpriseRecoveryDecisionId("ERD-002".to_string()),
            OperationKind::Recover,
            request.volume_hash.clone(),
            request.domain_recovery_request_id.clone(),
            request.domain_recovery_package_id.clone(),
            request.domain_recovery_decision_id.clone(),
            request.enterprise_authority_policy_id.clone(),
            quorum.policy_id.clone(),
            vec![EnterpriseQuorumMemberFingerprint("MEM-001".to_string())],
            1,
            u64::MAX,
            EnterpriseRecoveryStatus::Approved,
            EnterpriseRecoverySourceKind::ImportedOfflineDecision,
        );
        let enforcer = EnterpriseRecoveryEnforcer::new(&store);
        let result = enforcer
            .check_enterprise_recovery(&request, Some(&decision), Some(&auth), Some(&quorum))
            .unwrap();
        assert_eq!(result, EnterpriseRecoveryEnforcementDecision::Rejected);
    }

    #[test]
    fn enterprise_recovery_does_not_bypass_p5c_domain_recovery() {
        let (_dir, store) = setup_store();
        let request = DomainRecoveryRequest {
            request_id: "DRQ-1".to_string(),
            operation_kind: OperationKind::Recover,
            source_volume_hash: "vol".to_string(),
            target_volume_hash: None,
            host_fingerprint: None,
            domain_policy_id: "DP-1".to_string(),
            group_policy_mapping_id: "GM-1".to_string(),
            offline_snapshot_id: None,
            domain_authority_fingerprint: DomainAuthorityFingerprint("DA-1".to_string()),
            created_at: 1,
        };
        let enforcer = DomainRecoveryEnforcer::new(&store);
        assert!(matches!(
            enforcer
                .check_recovery_workflow(None, &request, OperationKind::Recover)
                .unwrap(),
            tuff_cse_winfs::domain_recovery_enforcement::DomainRecoveryEnforcementDecision::Rejected
        ));
    }

    #[test]
    fn enterprise_recovery_does_not_bypass_p5b_domain_approval() {
        let (_dir, store) = setup_store();
        let request = DomainApprovalDecision {
            request_id: "DREQ-1".to_string(),
            decision_id: "DDEC-1".to_string(),
            operation_kind: OperationKind::Recover,
            volume_hash: "vol".to_string(),
            domain_policy_id: "DP-1".to_string(),
            group_policy_mapping_id: "GM-1".to_string(),
            offline_snapshot_id: None,
            domain_authority_fingerprint: DomainAuthorityFingerprint("DA-1".to_string()),
            approver_principal_fingerprint:
                tuff_cse_winfs::domain_principal::DomainPrincipalFingerprint("P-1".to_string()),
            approver_group_fingerprint: None,
            status: DomainApprovalStatus::Denied,
            expires_at: 9_999_999,
            consumed_at: None,
            decision_hash: vec![1],
            source_kind:
                tuff_cse_winfs::domain_approval::DomainApprovalSourceKind::ImportedOfflineDecision,
        };
        let approval_request = tuff_cse_winfs::domain_approval::DomainApprovalRequest {
            request_id: "DREQ-1".to_string(),
            operation_kind: OperationKind::Recover,
            volume_hash: "vol".to_string(),
            domain_policy_id: "DP-1".to_string(),
            group_policy_mapping_id: "GM-1".to_string(),
            offline_snapshot_id: None,
            domain_authority_fingerprint: DomainAuthorityFingerprint("DA-1".to_string()),
            requester_principal_fingerprint:
                tuff_cse_winfs::domain_principal::DomainPrincipalFingerprint("P-1".to_string()),
            created_at: 1,
        };
        let enforcer = DomainApprovalEnforcer::new(&store);
        assert!(matches!(
            enforcer
                .check_required_domain_approval(Some(&request), OperationKind::Recover, "vol", &DomainPolicy {
                    domain_policy_id: "DP-1".to_string(),
                    domain_authority_fingerprint: DomainAuthorityFingerprint("DA-1".to_string()),
                    source_kind: DomainPolicySourceKind::ImportedGpoSnapshot,
                    created_at: 1,
                }, None)
                .unwrap(),
            tuff_cse_winfs::domain_approval_enforcement::DomainApprovalEnforcementDecision::Rejected
        ));
        let _ = approval_request;
    }

    #[test]
    fn enterprise_recovery_does_not_bypass_p4b_local_approval() {
        let (dir, store) = setup_store();
        store
            .save_enterprise_authority_policy(&authority_policy())
            .unwrap();
        store
            .save_enterprise_quorum_policy(&quorum_policy())
            .unwrap();
        store.save_enterprise_recovery_request(&request()).unwrap();
        store
            .save_enterprise_recovery_decision(&decision())
            .unwrap();
        let mut state = VolumeRuntimeState::new();
        state.current = VolumeBindingState::BoundLocked;
        store.save_volume_state("D:", &state).unwrap();

        let local_policy = LocalPolicy::default();
        let result = execute_recover_operation(
            OperationRequest {
                operation_id: "OP-1".to_string(),
                kind: OperationKind::Recover,
                volume: "D:".to_string(),
                requested_by: "user".to_string(),
                policy_id: "POL-1".to_string(),
                timestamp: 1,
                approval_id: None,
                enterprise_authority_policy_id: Some("EA-001".to_string()),
                enterprise_quorum_policy_id: Some("EQ-001".to_string()),
                enterprise_recovery_decision_id: Some("ERD-001".to_string()),
            },
            &tuff_cse_winfs::managed_policy::ManagedPolicy::default(),
            &tuff_cse_winfs::recovery_key::default_recovery_policy(),
            &store,
            "RK-FP-001".to_string(),
            "LOST_HOST".to_string(),
            &local_policy,
        )
        .unwrap();
        assert_eq!(result.status, OperationStatus::Rejected);
        assert!(dir.path().exists());
    }

    #[test]
    fn enterprise_recovery_does_not_bypass_p3c_manual_confirmation_token() {
        let (dir, store) = setup_store();
        let request = OperationRequest {
            operation_id: "OP-1".to_string(),
            kind: OperationKind::ManualComplete,
            volume: "D:".to_string(),
            requested_by: "user".to_string(),
            policy_id: "POL-1".to_string(),
            timestamp: 1,
            approval_id: None,
            enterprise_authority_policy_id: None,
            enterprise_quorum_policy_id: None,
            enterprise_recovery_decision_id: None,
        };
        let local_policy = LocalPolicy::default();
        let result = tuff_cse_winfs::operations::execute_manual_flow_operation(
            request,
            &store,
            tuff_cse_winfs::manual_flow::ManualFlowKind::RecoverComplete,
            "PLAN-1".to_string(),
            "WRONG".to_string(),
            "REASON".to_string(),
            &local_policy,
        )
        .unwrap();
        assert_eq!(result.status, OperationStatus::Rejected);
        assert!(dir.path().exists());
    }

    #[test]
    fn enterprise_metadata_is_included_in_p4c_signed_canonical_payload() {
        let (dir, store) = setup_store();
        env::set_var("TUFF_CSE_WINFS_ALLOW_DEV_AUDIT_SIGNER", "1");
        let signer = DevAuditSigner::new("key-1".to_string()).unwrap();
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
            enterprise_recovery_status: Some(EnterpriseRecoveryStatus::Approved),
            enterprise_recovery_enforcement_status: Some(
                EnterpriseRecoveryEnforcementDecision::Allowed,
            ),
            enterprise_recovery_rejection_reason: None,
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
        public_keys.insert("key-1".to_string(), signer.public_key_record());
        assert!(audit_chain::verify_journal_chain(&records, &public_keys).is_ok());
        assert!(dir.path().exists());
    }

    #[test]
    fn tampering_enterprise_recovery_status_causes_p4c_verify_failure() {
        let (dir, store) = setup_store();
        env::set_var("TUFF_CSE_WINFS_ALLOW_DEV_AUDIT_SIGNER", "1");
        let signer = DevAuditSigner::new("key-2".to_string()).unwrap();
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
            enterprise_recovery_status: Some(EnterpriseRecoveryStatus::Approved),
            enterprise_recovery_enforcement_status: Some(
                EnterpriseRecoveryEnforcementDecision::Allowed,
            ),
            enterprise_recovery_rejection_reason: None,
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
        records[0].enterprise_recovery_status = Some(EnterpriseRecoveryStatus::Denied);
        let mut public_keys = std::collections::HashMap::new();
        public_keys.insert("key-2".to_string(), signer.public_key_record());
        assert!(audit_chain::verify_journal_chain(&records, &public_keys).is_err());
        assert!(dir.path().exists());
    }

    #[test]
    fn tampering_enterprise_quorum_policy_id_causes_p4c_verify_failure() {
        let (dir, store) = setup_store();
        env::set_var("TUFF_CSE_WINFS_ALLOW_DEV_AUDIT_SIGNER", "1");
        let signer = DevAuditSigner::new("key-3".to_string()).unwrap();
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
            enterprise_recovery_status: Some(EnterpriseRecoveryStatus::Approved),
            enterprise_recovery_enforcement_status: Some(
                EnterpriseRecoveryEnforcementDecision::Allowed,
            ),
            enterprise_recovery_rejection_reason: None,
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
        records[0].enterprise_quorum_policy_id = Some("EQ-TAMPERED".to_string());
        let mut public_keys = std::collections::HashMap::new();
        public_keys.insert("key-3".to_string(), signer.public_key_record());
        assert!(audit_chain::verify_journal_chain(&records, &public_keys).is_err());
        assert!(dir.path().exists());
    }

    #[test]
    fn raw_authority_raw_principal_kms_secret_hsm_secret_key_material_are_not_present_in_meta_or_jrn(
    ) {
        let (dir, store) = setup_store();
        store
            .save_enterprise_authority_policy(&authority_policy())
            .unwrap();
        store
            .save_enterprise_quorum_policy(&quorum_policy())
            .unwrap();
        store.save_enterprise_recovery_request(&request()).unwrap();
        store
            .save_enterprise_recovery_decision(&decision())
            .unwrap();
        let mut secrets = String::new();
        for path in [
            dir.path().join("META/enterprise-authority/EA-001.json"),
            dir.path().join("META/enterprise-quorum/EQ-001.json"),
            dir.path()
                .join("JRN/enterprise-recovery/requests/ERQ-001.json"),
            dir.path()
                .join("JRN/enterprise-recovery/decisions/ERD-001.json"),
        ] {
            secrets.push_str(&fs::read_to_string(path).unwrap());
        }
        for needle in [
            "raw authority",
            "raw principal",
            "KMS secret",
            "HSM secret",
            "key material",
            "private key",
        ] {
            assert!(!secrets.contains(needle));
        }
    }

    #[test]
    fn p4c_audit_signing_verify_passes_after_enterprise_recovery_workflow_records() {
        let (_dir, store) = setup_store();
        env::set_var("TUFF_CSE_WINFS_ALLOW_DEV_AUDIT_SIGNER", "1");
        let signer = DevAuditSigner::new("key-4".to_string()).unwrap();
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
            enterprise_recovery_status: Some(EnterpriseRecoveryStatus::Approved),
            enterprise_recovery_enforcement_status: Some(
                EnterpriseRecoveryEnforcementDecision::Allowed,
            ),
            enterprise_recovery_rejection_reason: None,
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
        public_keys.insert("key-4".to_string(), signer.public_key_record());
        assert!(audit_chain::verify_journal_chain(&records, &public_keys).is_ok());
    }
}
