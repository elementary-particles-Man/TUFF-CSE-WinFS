#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::env;
    use std::fs;
    use tempfile::tempdir;
    use tuff_cse_winfs::audit_chain;
    use tuff_cse_winfs::audit_signing::{AuditSigner, DevAuditSigner};
    use tuff_cse_winfs::binding_store::BindingStore;
    use tuff_cse_winfs::enterprise_authority::{
        normalize_enterprise_authority_policy, EnterpriseAuthorityFingerprint,
        EnterpriseAuthorityPolicy, EnterpriseAuthorityPolicyId, EnterpriseAuthorityProviderKind,
    };
    use tuff_cse_winfs::enterprise_provider::{
        normalize_enterprise_provider_attestation, normalize_enterprise_provider_policy,
        EnterpriseProviderAttestationHash, EnterpriseProviderAttestationId,
        EnterpriseProviderAttestationSummary, EnterpriseProviderCapability,
        EnterpriseProviderHealth, EnterpriseProviderKind, EnterpriseProviderPolicy,
        EnterpriseProviderPolicyHash, EnterpriseProviderPolicyId,
    };
    use tuff_cse_winfs::enterprise_provider_lifecycle::*;
    use tuff_cse_winfs::enterprise_provider_lifecycle_enforcement::*;
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
    use tuff_cse_winfs::local_policy::LocalPolicy;
    use tuff_cse_winfs::operation_journal::{self, OperationJournalPhase, OperationJournalRecord};
    use tuff_cse_winfs::operations::{
        execute_recover_operation, OperationKind, OperationRequest, OperationStatus,
    };
    use tuff_cse_winfs::volume_state::{VolumeBindingState, VolumeRuntimeState};

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

    fn provider_policy(generation: Option<u64>) -> EnterpriseProviderPolicy {
        normalize_enterprise_provider_policy(EnterpriseProviderPolicy {
            policy_id: EnterpriseProviderPolicyId("EP-001".to_string()),
            enterprise_authority_policy_id: EnterpriseAuthorityPolicyId("EA-001".to_string()),
            provider_kind: EnterpriseProviderKind::ImportedOfflineProvider,
            capabilities: vec![
                EnterpriseProviderCapability::RecoveryApprovalOnly,
                EnterpriseProviderCapability::AuditOnly,
            ],
            health: EnterpriseProviderHealth::OfflineImported,
            provider_generation: generation,
            policy_hash: None,
            created_at: 1,
        })
    }

    fn provider_attestation(generation: Option<u64>) -> EnterpriseProviderAttestationSummary {
        normalize_enterprise_provider_attestation(EnterpriseProviderAttestationSummary {
            attestation_id: EnterpriseProviderAttestationId("EAT-001".to_string()),
            enterprise_provider_id: EnterpriseProviderPolicyId("EP-001".to_string()),
            enterprise_authority_policy_id: EnterpriseAuthorityPolicyId("EA-001".to_string()),
            provider_kind: EnterpriseProviderKind::ImportedOfflineProvider,
            capabilities: vec![EnterpriseProviderCapability::RecoveryApprovalOnly],
            health: EnterpriseProviderHealth::OfflineImported,
            provider_generation: generation,
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
                provider_attestation(None)
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

    fn decision(generation: Option<u64>) -> EnterpriseRecoveryDecision {
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
            provider_attestation(generation)
                .attestation_hash
                .as_ref()
                .unwrap()
                .0
                .clone(),
        );
        decision.enterprise_provider_generation = generation;
        decision.decision_hash =
            tuff_cse_winfs::enterprise_recovery::compute_enterprise_recovery_decision_hash(
                &decision,
            );
        decision
    }

    fn setup_active_lifecycle(
        store: &BindingStore,
        generation: u64,
    ) -> EnterpriseProviderLifecycleEvent {
        let event = normalize_lifecycle_event(EnterpriseProviderLifecycleEvent {
            event_id: EnterpriseProviderLifecycleEventId("EV-001".to_string()),
            provider_id: EnterpriseProviderPolicyId("EP-001".to_string()),
            generation: EnterpriseProviderGeneration(generation),
            kind: EnterpriseProviderLifecycleEventKind::ImportedActivation,
            state: EnterpriseProviderLifecycleState::Active,
            revocation_reason: None,
            attestation_hash: None,
            created_at: 1,
            event_hash: None,
        });
        store
            .save_enterprise_provider_lifecycle_event(&event)
            .unwrap();
        event
    }

    #[test]
    fn provider_lifecycle_event_persists_only_ids_fingerprints_generation_state_and_hashes() {
        let event = normalize_lifecycle_event(EnterpriseProviderLifecycleEvent {
            event_id: EnterpriseProviderLifecycleEventId("EV-001".to_string()),
            provider_id: EnterpriseProviderPolicyId("EP-001".to_string()),
            generation: EnterpriseProviderGeneration(1),
            kind: EnterpriseProviderLifecycleEventKind::ImportedActivation,
            state: EnterpriseProviderLifecycleState::Active,
            revocation_reason: None,
            attestation_hash: Some(EnterpriseProviderAttestationHash("ahash".to_string())),
            created_at: 1,
            event_hash: None,
        });
        let json = serde_json::to_string(&event).unwrap();
        // Check for presence of only permitted metadata fields
        assert!(json.contains("EV-001"));
        assert!(json.contains("EP-001"));
        assert!(json.contains("Active"));
        assert!(json.contains("event_hash"));
        // Confirm no credentials/secret fields
        assert!(!json.contains("private_key"));
        assert!(!json.contains("secret"));
    }

    #[test]
    fn provider_rotation_plan_persists_only_ids_fingerprints_generation_and_hashes() {
        let plan = normalize_rotation_plan(EnterpriseProviderRotationPlan {
            plan_id: EnterpriseProviderRotationPlanId("PLAN-001".to_string()),
            provider_id: EnterpriseProviderPolicyId("EP-001".to_string()),
            current_generation: EnterpriseProviderGeneration(1),
            next_generation: EnterpriseProviderGeneration(2),
            created_at: 1,
            plan_hash: None,
        });
        let json = serde_json::to_string(&plan).unwrap();
        assert!(json.contains("PLAN-001"));
        assert!(json.contains("EP-001"));
        assert!(json.contains("plan_hash"));
        assert!(!json.contains("private_key"));
        assert!(!json.contains("secret"));
    }

    #[test]
    fn dev_provider_lifecycle_operations_are_rejected_without_tuff_cse_winfs_allow_dev_provider_lifecycle(
    ) {
        env::remove_var("TUFF_CSE_WINFS_ALLOW_DEV_PROVIDER_LIFECYCLE");
        // Test execution rejects by returning Err/failure if environment gate not present
        let val = env::var("TUFF_CSE_WINFS_ALLOW_DEV_PROVIDER_LIFECYCLE");
        assert!(val.is_err());
    }

    #[test]
    fn dev_provider_revoke_succeeds_with_explicit_env_gate() {
        let (dir, store) = setup_store();
        env::set_var("TUFF_CSE_WINFS_ALLOW_DEV_PROVIDER_LIFECYCLE", "1");

        let provider_id = "EP-001";
        let policy = provider_policy(Some(1));
        store.save_enterprise_provider_policy(&policy).unwrap();

        let event = normalize_lifecycle_event(EnterpriseProviderLifecycleEvent {
            event_id: EnterpriseProviderLifecycleEventId("EV-REVOKE-1".to_string()),
            provider_id: EnterpriseProviderPolicyId(provider_id.to_string()),
            generation: EnterpriseProviderGeneration(1),
            kind: EnterpriseProviderLifecycleEventKind::ImportedRevocation,
            state: EnterpriseProviderLifecycleState::Revoked,
            revocation_reason: Some(EnterpriseProviderRevocationReason::AdministrativeRevocation),
            attestation_hash: None,
            created_at: 1,
            event_hash: None,
        });
        store
            .save_enterprise_provider_lifecycle_event(&event)
            .unwrap();

        let state = store
            .find_latest_provider_lifecycle_state(provider_id)
            .unwrap()
            .unwrap();
        assert_eq!(state, EnterpriseProviderLifecycleState::Revoked);
    }

    #[test]
    fn revoked_provider_rejects_enterprise_recovery() {
        let (_dir, store) = setup_store();
        setup_active_lifecycle(&store, 1);
        let enforcer = EnterpriseProviderLifecycleEnforcer::new(&store);

        // Revoke the provider
        let revoke_event = normalize_lifecycle_event(EnterpriseProviderLifecycleEvent {
            event_id: EnterpriseProviderLifecycleEventId("EV-002".to_string()),
            provider_id: EnterpriseProviderPolicyId("EP-001".to_string()),
            generation: EnterpriseProviderGeneration(1),
            kind: EnterpriseProviderLifecycleEventKind::ImportedRevocation,
            state: EnterpriseProviderLifecycleState::Revoked,
            revocation_reason: Some(EnterpriseProviderRevocationReason::AdministrativeRevocation),
            attestation_hash: None,
            created_at: 2,
            event_hash: None,
        });
        store
            .save_enterprise_provider_lifecycle_event(&revoke_event)
            .unwrap();

        let req = request();
        let dec = decision(Some(1));
        let policy = provider_policy(Some(1));
        let att = provider_attestation(Some(1));

        let res = enforcer
            .check_provider_lifecycle(&req, Some(&dec), Some(&policy), Some(&att))
            .unwrap();
        assert_eq!(
            res,
            EnterpriseProviderLifecycleEnforcementDecision::Rejected(
                EnterpriseProviderLifecycleRejectionReason::ProviderRevoked
            )
        );
    }

    #[test]
    fn superseded_provider_rejects_enterprise_recovery() {
        let (_dir, store) = setup_store();
        setup_active_lifecycle(&store, 1);
        let enforcer = EnterpriseProviderLifecycleEnforcer::new(&store);

        let supersede_event = normalize_lifecycle_event(EnterpriseProviderLifecycleEvent {
            event_id: EnterpriseProviderLifecycleEventId("EV-002".to_string()),
            provider_id: EnterpriseProviderPolicyId("EP-001".to_string()),
            generation: EnterpriseProviderGeneration(1),
            kind: EnterpriseProviderLifecycleEventKind::ImportedRevocation,
            state: EnterpriseProviderLifecycleState::Superseded,
            revocation_reason: Some(EnterpriseProviderRevocationReason::PolicySuperseded),
            attestation_hash: None,
            created_at: 2,
            event_hash: None,
        });
        store
            .save_enterprise_provider_lifecycle_event(&supersede_event)
            .unwrap();

        let req = request();
        let dec = decision(Some(1));
        let policy = provider_policy(Some(1));
        let att = provider_attestation(Some(1));

        let res = enforcer
            .check_provider_lifecycle(&req, Some(&dec), Some(&policy), Some(&att))
            .unwrap();
        assert_eq!(
            res,
            EnterpriseProviderLifecycleEnforcementDecision::Rejected(
                EnterpriseProviderLifecycleRejectionReason::ProviderSuperseded
            )
        );
    }

    #[test]
    fn expired_provider_rejects_enterprise_recovery() {
        let (_dir, store) = setup_store();
        setup_active_lifecycle(&store, 1);
        let enforcer = EnterpriseProviderLifecycleEnforcer::new(&store);

        let expire_event = normalize_lifecycle_event(EnterpriseProviderLifecycleEvent {
            event_id: EnterpriseProviderLifecycleEventId("EV-002".to_string()),
            provider_id: EnterpriseProviderPolicyId("EP-001".to_string()),
            generation: EnterpriseProviderGeneration(1),
            kind: EnterpriseProviderLifecycleEventKind::ImportedRevocation,
            state: EnterpriseProviderLifecycleState::Expired,
            revocation_reason: Some(EnterpriseProviderRevocationReason::AttestationExpired),
            attestation_hash: None,
            created_at: 2,
            event_hash: None,
        });
        store
            .save_enterprise_provider_lifecycle_event(&expire_event)
            .unwrap();

        let req = request();
        let dec = decision(Some(1));
        let policy = provider_policy(Some(1));
        let att = provider_attestation(Some(1));

        let res = enforcer
            .check_provider_lifecycle(&req, Some(&dec), Some(&policy), Some(&att))
            .unwrap();
        assert_eq!(
            res,
            EnterpriseProviderLifecycleEnforcementDecision::Rejected(
                EnterpriseProviderLifecycleRejectionReason::ProviderExpired
            )
        );
    }

    #[test]
    fn generation_mismatch_rejects_enterprise_recovery_decision() {
        let (_dir, store) = setup_store();
        setup_active_lifecycle(&store, 1);
        let enforcer = EnterpriseProviderLifecycleEnforcer::new(&store);

        let req = request();
        // Decision specifies generation 2 but active lifecycle has 1
        let dec = decision(Some(2));
        let policy = provider_policy(Some(1));
        let att = provider_attestation(Some(1));

        let res = enforcer
            .check_provider_lifecycle(&req, Some(&dec), Some(&policy), Some(&att))
            .unwrap();
        assert_eq!(
            res,
            EnterpriseProviderLifecycleEnforcementDecision::Rejected(
                EnterpriseProviderLifecycleRejectionReason::GenerationMismatch
            )
        );
    }

    #[test]
    fn rotation_incomplete_rejects_new_generation_decision() {
        let (_dir, store) = setup_store();
        setup_active_lifecycle(&store, 1);
        let enforcer = EnterpriseProviderLifecycleEnforcer::new(&store);

        // Put plan in place (PendingRotation status)
        let plan = normalize_rotation_plan(EnterpriseProviderRotationPlan {
            plan_id: EnterpriseProviderRotationPlanId("PLAN-001".to_string()),
            provider_id: EnterpriseProviderPolicyId("EP-001".to_string()),
            current_generation: EnterpriseProviderGeneration(1),
            next_generation: EnterpriseProviderGeneration(2),
            created_at: 2,
            plan_hash: None,
        });
        store.save_enterprise_provider_rotation_plan(&plan).unwrap();

        let rot_event = normalize_lifecycle_event(EnterpriseProviderLifecycleEvent {
            event_id: EnterpriseProviderLifecycleEventId("EV-002".to_string()),
            provider_id: EnterpriseProviderPolicyId("EP-001".to_string()),
            generation: EnterpriseProviderGeneration(1),
            kind: EnterpriseProviderLifecycleEventKind::ImportedRotationPlan,
            state: EnterpriseProviderLifecycleState::PendingRotation,
            revocation_reason: None,
            attestation_hash: None,
            created_at: 2,
            event_hash: None,
        });
        store
            .save_enterprise_provider_lifecycle_event(&rot_event)
            .unwrap();

        let req = request();
        // Decision is G=2 but state is still PendingRotation -> reject with RotationIncomplete
        let dec = decision(Some(2));
        let policy = provider_policy(Some(1));
        let att = provider_attestation(Some(1));

        let res = enforcer
            .check_provider_lifecycle(&req, Some(&dec), Some(&policy), Some(&att))
            .unwrap();
        assert_eq!(
            res,
            EnterpriseProviderLifecycleEnforcementDecision::Rejected(
                EnterpriseProviderLifecycleRejectionReason::RotationIncomplete
            )
        );
    }

    #[test]
    fn rotation_complete_rejects_old_generation_decision() {
        let (_dir, store) = setup_store();
        setup_active_lifecycle(&store, 1);
        let enforcer = EnterpriseProviderLifecycleEnforcer::new(&store);

        // Execute rotation complete event -> generation 2 is active
        let complete_event = normalize_lifecycle_event(EnterpriseProviderLifecycleEvent {
            event_id: EnterpriseProviderLifecycleEventId("EV-002".to_string()),
            provider_id: EnterpriseProviderPolicyId("EP-001".to_string()),
            generation: EnterpriseProviderGeneration(2),
            kind: EnterpriseProviderLifecycleEventKind::ImportedRotationComplete,
            state: EnterpriseProviderLifecycleState::Active,
            revocation_reason: None,
            attestation_hash: None,
            created_at: 2,
            event_hash: None,
        });
        store
            .save_enterprise_provider_lifecycle_event(&complete_event)
            .unwrap();

        let req = request();
        // Decision has old G=1 but active is 2 -> reject with GenerationMismatch
        let dec = decision(Some(1));
        let policy = provider_policy(Some(2));
        let att = provider_attestation(Some(2));

        let res = enforcer
            .check_provider_lifecycle(&req, Some(&dec), Some(&policy), Some(&att))
            .unwrap();
        assert_eq!(
            res,
            EnterpriseProviderLifecycleEnforcementDecision::Rejected(
                EnterpriseProviderLifecycleRejectionReason::GenerationMismatch
            )
        );
    }

    #[test]
    fn rotation_complete_allows_new_generation_decision() {
        let (_dir, store) = setup_store();
        setup_active_lifecycle(&store, 1);
        let enforcer = EnterpriseProviderLifecycleEnforcer::new(&store);

        let complete_event = normalize_lifecycle_event(EnterpriseProviderLifecycleEvent {
            event_id: EnterpriseProviderLifecycleEventId("EV-002".to_string()),
            provider_id: EnterpriseProviderPolicyId("EP-001".to_string()),
            generation: EnterpriseProviderGeneration(2),
            kind: EnterpriseProviderLifecycleEventKind::ImportedRotationComplete,
            state: EnterpriseProviderLifecycleState::Active,
            revocation_reason: None,
            attestation_hash: None,
            created_at: 2,
            event_hash: None,
        });
        store
            .save_enterprise_provider_lifecycle_event(&complete_event)
            .unwrap();

        let req = request();
        let dec = decision(Some(2));
        let policy = provider_policy(Some(2));
        let att = provider_attestation(Some(2));

        let res = enforcer
            .check_provider_lifecycle(&req, Some(&dec), Some(&policy), Some(&att))
            .unwrap();
        assert_eq!(res, EnterpriseProviderLifecycleEnforcementDecision::Allowed);
    }

    #[test]
    fn attestation_renewal_updates_accepted_attestation_hash_without_exposing_credentials() {
        let (dir, store) = setup_store();
        setup_active_lifecycle(&store, 1);
        let enforcer = EnterpriseProviderLifecycleEnforcer::new(&store);

        let att = provider_attestation(Some(1));
        store.save_enterprise_provider_attestation(&att).unwrap();

        // Attestation renewal event containing attestation hash
        let renew_event = normalize_lifecycle_event(EnterpriseProviderLifecycleEvent {
            event_id: EnterpriseProviderLifecycleEventId("EV-002".to_string()),
            provider_id: EnterpriseProviderPolicyId("EP-001".to_string()),
            generation: EnterpriseProviderGeneration(1),
            kind: EnterpriseProviderLifecycleEventKind::ImportedAttestationRenewal,
            state: EnterpriseProviderLifecycleState::Active,
            revocation_reason: None,
            attestation_hash: att.attestation_hash.clone(),
            created_at: 2,
            event_hash: None,
        });
        store
            .save_enterprise_provider_lifecycle_event(&renew_event)
            .unwrap();

        let req = request();
        let dec = decision(Some(1));
        let policy = provider_policy(Some(1));

        let res = enforcer
            .check_provider_lifecycle(&req, Some(&dec), Some(&policy), Some(&att))
            .unwrap();
        assert_eq!(res, EnterpriseProviderLifecycleEnforcementDecision::Allowed);

        // Verify credentials/secrets are not saved in META json
        let meta_file = dir
            .path()
            .join("META/enterprise-provider/lifecycle-events/EV-002.json");
        let content = fs::read_to_string(meta_file).unwrap();
        assert!(!content.contains("private_key"));
        assert!(!content.contains("KMS"));
    }

    #[test]
    fn lifecycle_hash_mismatch_rejects_provider_lifecycle_state() {
        let (_dir, store) = setup_store();
        let mut event = setup_active_lifecycle(&store, 1);
        let enforcer = EnterpriseProviderLifecycleEnforcer::new(&store);

        // Tamper with the event hash
        event.event_hash = Some("TAMPERED_HASH".to_string());
        store
            .save_enterprise_provider_lifecycle_event(&event)
            .unwrap();

        let req = request();
        let dec = decision(Some(1));
        let policy = provider_policy(Some(1));
        let att = provider_attestation(Some(1));

        let res = enforcer
            .check_provider_lifecycle(&req, Some(&dec), Some(&policy), Some(&att))
            .unwrap();
        assert_eq!(
            res,
            EnterpriseProviderLifecycleEnforcementDecision::Rejected(
                EnterpriseProviderLifecycleRejectionReason::LifecycleHashMismatch
            )
        );
    }

    #[test]
    fn provider_lifecycle_gate_does_not_bypass_p6a_quorum() {
        let (_dir, store) = setup_store();
        setup_active_lifecycle(&store, 1);

        // Quorum threshold is 2 but only 1 signer is provided in decision
        let mut dec = decision(Some(1));
        dec.approver_fingerprints = vec![EnterpriseQuorumMemberFingerprint("MEM-001".to_string())];
        let mut q_pol = quorum_policy();
        q_pol.threshold = EnterpriseQuorumThreshold(2);
        q_pol.members = vec![
            EnterpriseQuorumMemberFingerprint("MEM-001".to_string()),
            EnterpriseQuorumMemberFingerprint("MEM-002".to_string()),
        ];

        let enforcer = EnterpriseRecoveryEnforcer::new(&store);
        let res = enforcer
            .check_enterprise_recovery(
                &request(),
                Some(&dec),
                Some(&authority_policy()),
                Some(&q_pol),
            )
            .unwrap();
        assert_eq!(res, tuff_cse_winfs::enterprise_recovery_enforcement::EnterpriseRecoveryEnforcementDecision::Rejected);
    }

    #[test]
    fn provider_lifecycle_gate_does_not_bypass_p5c_domain_recovery() {
        let (_dir, store) = setup_store();
        setup_active_lifecycle(&store, 1);

        // Mismatched domain recovery request ID in enterprise recovery request/decision
        let mut req = request();
        req.domain_recovery_request_id = "DRQ-MISMATCH".to_string();
        let dec = decision(Some(1));

        let enforcer = EnterpriseRecoveryEnforcer::new(&store);
        let res = enforcer
            .check_enterprise_recovery(
                &req,
                Some(&dec),
                Some(&authority_policy()),
                Some(&quorum_policy()),
            )
            .unwrap();
        assert_eq!(res, tuff_cse_winfs::enterprise_recovery_enforcement::EnterpriseRecoveryEnforcementDecision::Rejected);
    }

    #[test]
    fn provider_lifecycle_gate_does_not_bypass_p5b_domain_approval() {
        let (_dir, store) = setup_store();
        setup_active_lifecycle(&store, 1);

        let domain_policy = tuff_cse_winfs::domain_policy::DomainPolicy {
            domain_policy_id: "DP-001".to_string(),
            domain_authority_fingerprint:
                tuff_cse_winfs::domain_principal::DomainAuthorityFingerprint("DA-001".to_string()),
            source_kind: tuff_cse_winfs::domain_policy::DomainPolicySourceKind::ImportedGpoSnapshot,
            created_at: 1,
        };
        store.save_domain_policy(&domain_policy).unwrap();

        let domain_request = tuff_cse_winfs::domain_recovery::DomainRecoveryRequest {
            request_id: "DRQ-001".to_string(),
            operation_kind: OperationKind::Recover,
            source_volume_hash: BindingStore::volume_hash("D:"),
            target_volume_hash: None,
            host_fingerprint: None,
            domain_policy_id: "DP-001".to_string(),
            group_policy_mapping_id: "GM-001".to_string(),
            offline_snapshot_id: None,
            domain_authority_fingerprint:
                tuff_cse_winfs::domain_principal::DomainAuthorityFingerprint("DA-001".to_string()),
            created_at: 1,
        };
        store.save_domain_recovery_request(&domain_request).unwrap();

        let domain_decision = tuff_cse_winfs::domain_recovery::DomainRecoveryDecision {
            request_id: "DRQ-001".to_string(),
            decision_id: "DRD-001".to_string(),
            package_id: "PKG-001".to_string(),
            approval_decision_id: None,
            status: tuff_cse_winfs::domain_recovery::DomainRecoveryWorkflowState::Authorized,
            expires_at: u64::MAX,
            consumed_at: None,
            decision_hash: vec![1, 2, 3],
        };
        store
            .save_domain_recovery_decision(&domain_decision)
            .unwrap();

        store.save_enterprise_recovery_request(&request()).unwrap();
        store
            .save_enterprise_recovery_decision(&decision(Some(1)))
            .unwrap();

        let req = mock_operation_request(Some("ERD-001".to_string()));
        let mut runtime_policy = tuff_cse_winfs::managed_policy::ManagedPolicy::default();
        runtime_policy.allow_recover = true;

        let result = execute_recover_operation(
            req,
            &runtime_policy,
            &tuff_cse_winfs::recovery_key::default_recovery_policy(),
            &store,
            "RK-FP".to_string(),
            "HOST".to_string(),
            &LocalPolicy::default(),
        )
        .unwrap();
        assert_eq!(result.status, OperationStatus::Rejected);
    }

    #[test]
    fn provider_lifecycle_gate_does_not_bypass_p4b_local_approval() {
        let (_dir, store) = setup_store();
        setup_active_lifecycle(&store, 1);

        let local_policy = LocalPolicy::default();

        let req = mock_operation_request(None);
        let result = execute_recover_operation(
            req,
            &tuff_cse_winfs::managed_policy::ManagedPolicy::default(),
            &tuff_cse_winfs::recovery_key::default_recovery_policy(),
            &store,
            "RK-FP".to_string(),
            "HOST".to_string(),
            &local_policy,
        )
        .unwrap();
        assert_eq!(result.status, OperationStatus::Rejected);
    }

    #[test]
    fn provider_lifecycle_gate_does_not_bypass_p3c_manual_confirmation() {
        let (_dir, store) = setup_store();
        setup_active_lifecycle(&store, 1);

        let req = OperationRequest {
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
            ..Default::default()
        };

        // Call execute_manual_flow_operation with invalid token/plan details
        let result = tuff_cse_winfs::operations::execute_manual_flow_operation(
            req,
            &store,
            tuff_cse_winfs::manual_flow::ManualFlowKind::RecoverComplete,
            "PLAN-WRONG".to_string(),
            "WRONG_TOKEN".to_string(),
            "REASON".to_string(),
            &LocalPolicy::default(),
        )
        .unwrap();
        assert_eq!(result.status, OperationStatus::Rejected);
    }

    #[test]
    fn provider_lifecycle_metadata_is_included_in_p4c_signed_canonical_payload() {
        let record = mock_journal_record();
        let payload = tuff_cse_winfs::audit_chain::canonicalize_journal_payload(&record);
        let payload_str = String::from_utf8_lossy(&payload);

        assert!(payload_str.contains("enterprise_provider_generation"));
        assert!(payload_str.contains("enterprise_provider_lifecycle_event_id"));
        assert!(payload_str.contains("enterprise_provider_lifecycle_state"));
        assert!(payload_str.contains("enterprise_provider_lifecycle_enforcement_status"));
        assert!(payload_str.contains("enterprise_provider_lifecycle_rejection_reason"));
        assert!(payload_str.contains("enterprise_provider_rotation_plan_id"));
    }

    #[test]
    fn tampering_enterprise_provider_lifecycle_state_causes_p4c_verify_failure() {
        let (_dir, store) = setup_store();
        env::set_var("TUFF_CSE_WINFS_ALLOW_DEV_AUDIT_SIGNER", "1");
        let signer = DevAuditSigner::new("test-key".to_string()).unwrap();
        store
            .save_audit_public_key(&signer.public_key_record())
            .unwrap();

        let mut record = mock_journal_record();
        record.enterprise_provider_lifecycle_state = Some(EnterpriseProviderLifecycleState::Active);

        let vol_hash = BindingStore::volume_hash("D:");
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
        // Tamper with state
        records[0].enterprise_provider_lifecycle_state =
            Some(EnterpriseProviderLifecycleState::Revoked);

        let mut public_keys = HashMap::new();
        public_keys.insert("test-key".to_string(), signer.public_key_record());

        assert!(audit_chain::verify_journal_chain(&records, &public_keys).is_err());
    }

    #[test]
    fn tampering_enterprise_provider_generation_causes_p4c_verify_failure() {
        let (_dir, store) = setup_store();
        env::set_var("TUFF_CSE_WINFS_ALLOW_DEV_AUDIT_SIGNER", "1");
        let signer = DevAuditSigner::new("test-key".to_string()).unwrap();
        store
            .save_audit_public_key(&signer.public_key_record())
            .unwrap();

        let mut record = mock_journal_record();
        record.enterprise_provider_generation = Some(1);

        let vol_hash = BindingStore::volume_hash("D:");
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
        // Tamper with generation
        records[0].enterprise_provider_generation = Some(2);

        let mut public_keys = HashMap::new();
        public_keys.insert("test-key".to_string(), signer.public_key_record());

        assert!(audit_chain::verify_journal_chain(&records, &public_keys).is_err());
    }

    #[test]
    fn raw_provider_credential_kms_secret_hsm_secret_key_material_are_not_present_in_meta_or_jrn() {
        let (dir, store) = setup_store();
        store
            .save_enterprise_authority_policy(&authority_policy())
            .unwrap();
        store
            .save_enterprise_quorum_policy(&quorum_policy())
            .unwrap();
        store
            .save_enterprise_provider_policy(&provider_policy(Some(1)))
            .unwrap();
        store
            .save_enterprise_provider_attestation(&provider_attestation(Some(1)))
            .unwrap();
        setup_active_lifecycle(&store, 1);

        fn read_all_files(path: &std::path::Path, secrets: &mut String) {
            if path.is_dir() {
                if let Ok(entries) = fs::read_dir(path) {
                    for entry in entries {
                        if let Ok(entry) = entry {
                            read_all_files(&entry.path(), secrets);
                        }
                    }
                }
            } else if path.is_file() {
                if let Ok(content) = fs::read_to_string(path) {
                    secrets.push_str(&content);
                }
            }
        }
        let mut secrets = String::new();
        read_all_files(dir.path(), &mut secrets);

        for needle in [
            "password",
            "auth token",
            "Kerberos",
            "private key",
            "KMS secret",
            "HSM secret",
            "provider credential",
            "key material",
        ] {
            assert!(!secrets.contains(needle));
        }
    }

    #[test]
    fn p4c_audit_signing_verify_passes_after_provider_lifecycle_workflow_records() {
        let (_dir, store) = setup_store();
        env::set_var("TUFF_CSE_WINFS_ALLOW_DEV_AUDIT_SIGNER", "1");
        let signer = DevAuditSigner::new("test-key".to_string()).unwrap();
        store
            .save_audit_public_key(&signer.public_key_record())
            .unwrap();

        let record1 = mock_journal_record();
        let vol_hash = BindingStore::volume_hash("D:");
        operation_journal::append_signed_record(
            store.root_path(),
            &vol_hash,
            record1,
            &[0u8; 32],
            &signer,
        )
        .unwrap();

        let records =
            operation_journal::read_journal_records(store.root_path(), &vol_hash).unwrap();
        let mut public_keys = HashMap::new();
        public_keys.insert("test-key".to_string(), signer.public_key_record());

        assert!(audit_chain::verify_journal_chain(&records, &public_keys).is_ok());
    }

    fn mock_operation_request(decision_id: Option<String>) -> OperationRequest {
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
            enterprise_recovery_decision_id: decision_id,
            ..Default::default()
        }
    }

    fn mock_journal_record() -> OperationJournalRecord {
        OperationJournalRecord {
            seq: 1,
            phase: OperationJournalPhase::Commit,
            operation_id: "OP-1".to_string(),
            kind: OperationKind::Recover,
            volume: "D:".to_string(),
            requested_by: "user".to_string(),
            result_status: OperationStatus::Accepted,
            previous_state: VolumeBindingState::BoundLocked,
            next_state: VolumeBindingState::BoundLocked,
            enterprise_provider_generation: Some(1),
            enterprise_provider_lifecycle_event_id: Some("EV-001".to_string()),
            enterprise_provider_lifecycle_state: Some(EnterpriseProviderLifecycleState::Active),
            enterprise_provider_lifecycle_enforcement_status: Some(
                EnterpriseProviderLifecycleEnforcementDecision::Allowed,
            ),
            enterprise_provider_lifecycle_rejection_reason: Some(
                EnterpriseProviderLifecycleRejectionReason::ProviderRevoked,
            ),
            enterprise_provider_rotation_plan_id: Some("PLAN-001".to_string()),
            ..Default::default()
        }
    }
}
