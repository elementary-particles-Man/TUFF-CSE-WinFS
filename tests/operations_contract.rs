#[cfg(test)]
mod tests {
    use tuff_cse_winfs::managed_policy::ManagedPolicy;
    use tuff_cse_winfs::operations::{
        execute_operation, OperationKind, OperationRequest, OperationStatus,
    };
    use tuff_cse_winfs::volume_state::{VolumeBindingState, VolumeRuntimeState};

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
    fn test_default_managed_policy_allows_standard_ops() {
        let policy = ManagedPolicy::default();
        assert!(policy.allow_status);
        assert!(policy.allow_bind);
        assert!(policy.allow_unlock);
        assert!(policy.allow_lock);
        assert!(policy.allow_eject);
    }

    #[test]
    fn test_default_managed_policy_rejects_reserved_ops() {
        let mut policy = ManagedPolicy::default();
        policy.allow_status = false;
        let mut state = VolumeRuntimeState::new();

        let result = execute_operation(
            mock_request(OperationKind::Status, None),
            &policy,
            &mut state,
        )
        .unwrap();
        assert_eq!(result.status, OperationStatus::Rejected);
    }

    #[test]
    fn test_bind_transition() {
        let policy = ManagedPolicy::default();
        let mut state = VolumeRuntimeState::new();

        let result =
            execute_operation(mock_request(OperationKind::Bind, None), &policy, &mut state)
                .unwrap();
        assert_eq!(result.status, OperationStatus::PendingBindingPhase);
        assert_eq!(result.next_state, VolumeBindingState::BoundLocked);
        assert_eq!(state.current, VolumeBindingState::BoundLocked);
    }

    #[test]
    fn test_unlock_transition() {
        let policy = ManagedPolicy::default();
        let mut state = VolumeRuntimeState::new();
        state.current = VolumeBindingState::BoundLocked;

        let result = execute_operation(
            mock_request(OperationKind::Unlock, None),
            &policy,
            &mut state,
        )
        .unwrap();
        assert_eq!(result.status, OperationStatus::PendingCryptoPhase);
        assert_eq!(result.next_state, VolumeBindingState::Unlocked);
        assert_eq!(state.current, VolumeBindingState::Unlocked);
    }

    #[test]
    fn test_lock_transition() {
        let policy = ManagedPolicy::default();
        let mut state = VolumeRuntimeState::new();
        state.current = VolumeBindingState::Unlocked;

        let result =
            execute_operation(mock_request(OperationKind::Lock, None), &policy, &mut state)
                .unwrap();
        assert_eq!(result.status, OperationStatus::PendingDriverPhase);
        assert_eq!(result.next_state, VolumeBindingState::Locked);
        assert_eq!(state.current, VolumeBindingState::Locked);
    }

    #[test]
    fn test_eject_transition() {
        let policy = ManagedPolicy::default();
        let mut state = VolumeRuntimeState::new();
        state.current = VolumeBindingState::Locked;

        let result = execute_operation(
            mock_request(OperationKind::Eject, None),
            &policy,
            &mut state,
        )
        .unwrap();
        assert_eq!(result.status, OperationStatus::PendingDriverPhase);
        assert_eq!(result.next_state, VolumeBindingState::CleanRemoved);
        assert_eq!(state.current, VolumeBindingState::CleanRemoved);
    }

    #[test]
    fn test_export_returns_accepted_in_p3a() {
        let mut policy = ManagedPolicy::default();
        policy.allow_export = true;
        let mut state = VolumeRuntimeState::new();

        let result = execute_operation(
            mock_request(OperationKind::Export, None),
            &policy,
            &mut state,
        )
        .unwrap();
        assert_eq!(result.status, OperationStatus::Accepted);
    }

    #[test]
    fn test_rebind_returns_accepted_in_p3b() {
        let mut policy = ManagedPolicy::default();
        policy.allow_rebind = true;
        let mut state = VolumeRuntimeState::new();

        let result = execute_operation(
            mock_request(OperationKind::Rebind, None),
            &policy,
            &mut state,
        )
        .unwrap();
        assert_eq!(result.status, OperationStatus::Accepted);
    }

    #[test]
    fn test_recover_returns_accepted_in_p3b() {
        let mut policy = ManagedPolicy::default();
        policy.allow_recover = true;
        let mut state = VolumeRuntimeState::new();

        let result = execute_operation(
            mock_request(OperationKind::Recover, None),
            &policy,
            &mut state,
        )
        .unwrap();
        assert_eq!(result.status, OperationStatus::Accepted);
    }

    #[test]
    fn test_no_secrets_in_json() {
        let req = mock_request(OperationKind::Bind, None);
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("basekey"));
        assert!(!json.contains("MK"));
        assert!(!json.contains("TK"));
        assert!(!json.contains("PK"));
    }

    #[test]
    fn test_operation_kind_serializes() {
        let kind = OperationKind::Bind;
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, "\"Bind\"");
    }

    #[test]
    fn test_local_approval_status_serializes() {
        use tuff_cse_winfs::local_approval::LocalApprovalStatus;
        let status = LocalApprovalStatus::Requested;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"Requested\"");
    }

    #[test]
    fn test_local_operation_class_serializes() {
        use tuff_cse_winfs::local_policy::LocalOperationClass;
        let class = LocalOperationClass::Export;
        let json = serde_json::to_string(&class).unwrap();
        assert_eq!(json, "\"Export\"");
    }

    #[test]
    fn test_operation_kind_deserializes() {
        let json = "\"Bind\"";
        let deserialized: OperationKind = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, OperationKind::Bind);
    }

    #[test]
    fn test_enterprise_authority_policy_serializes() {
        use tuff_cse_winfs::enterprise_authority::{
            EnterpriseAuthorityFingerprint, EnterpriseAuthorityPolicy,
            EnterpriseAuthorityPolicyHash, EnterpriseAuthorityPolicyId,
            EnterpriseAuthorityProviderKind,
        };

        let policy = EnterpriseAuthorityPolicy {
            policy_id: EnterpriseAuthorityPolicyId("EA-001".to_string()),
            authority_fingerprint: EnterpriseAuthorityFingerprint("AUTH-FP".to_string()),
            provider_kind: EnterpriseAuthorityProviderKind::ImportedOfflineAuthority,
            policy_hash: Some(EnterpriseAuthorityPolicyHash("hash".to_string())),
            created_at: 1,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let decoded: EnterpriseAuthorityPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.policy_id.0, "EA-001");
    }

    #[test]
    fn test_enterprise_quorum_policy_serializes() {
        use tuff_cse_winfs::enterprise_authority::EnterpriseAuthorityPolicyId;
        use tuff_cse_winfs::enterprise_quorum::{
            EnterpriseQuorumMemberFingerprint, EnterpriseQuorumPolicy, EnterpriseQuorumPolicyHash,
            EnterpriseQuorumPolicyId, EnterpriseQuorumThreshold, QuorumRule,
        };

        let policy = EnterpriseQuorumPolicy {
            policy_id: EnterpriseQuorumPolicyId("EQ-001".to_string()),
            enterprise_authority_policy_id: EnterpriseAuthorityPolicyId("EA-001".to_string()),
            rule: QuorumRule::Threshold,
            threshold: EnterpriseQuorumThreshold(1),
            members: vec![EnterpriseQuorumMemberFingerprint("FP-1".to_string())],
            policy_hash: Some(EnterpriseQuorumPolicyHash("hash".to_string())),
            created_at: 1,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let decoded: EnterpriseQuorumPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.policy_id.0, "EQ-001");
    }

    #[test]
    fn test_enterprise_provider_policy_and_attestation_serializes() {
        use tuff_cse_winfs::enterprise_authority::EnterpriseAuthorityPolicyId;
        use tuff_cse_winfs::enterprise_provider::{
            EnterpriseProviderAttestationHash, EnterpriseProviderAttestationId,
            EnterpriseProviderAttestationSummary, EnterpriseProviderCapability,
            EnterpriseProviderHealth, EnterpriseProviderKind, EnterpriseProviderPolicy,
            EnterpriseProviderPolicyHash, EnterpriseProviderPolicyId,
        };

        let policy = EnterpriseProviderPolicy {
            policy_id: EnterpriseProviderPolicyId("EP-001".to_string()),
            enterprise_authority_policy_id: EnterpriseAuthorityPolicyId("EA-001".to_string()),
            provider_kind: EnterpriseProviderKind::ImportedOfflineProvider,
            capabilities: vec![EnterpriseProviderCapability::RecoveryApprovalOnly],
            health: EnterpriseProviderHealth::OfflineImported,
            policy_hash: Some(EnterpriseProviderPolicyHash("hash".to_string())),
            created_at: 1,
        };
        let attestation = EnterpriseProviderAttestationSummary {
            attestation_id: EnterpriseProviderAttestationId("EAT-001".to_string()),
            enterprise_provider_id: EnterpriseProviderPolicyId("EP-001".to_string()),
            enterprise_authority_policy_id: EnterpriseAuthorityPolicyId("EA-001".to_string()),
            provider_kind: EnterpriseProviderKind::ImportedOfflineProvider,
            capabilities: vec![EnterpriseProviderCapability::RecoveryApprovalOnly],
            health: EnterpriseProviderHealth::OfflineImported,
            valid_from: 1,
            valid_until: 2,
            revoked_at: None,
            attestation_hash: Some(EnterpriseProviderAttestationHash("ahash".to_string())),
            created_at: 1,
        };
        let policy_json = serde_json::to_string(&policy).unwrap();
        let attestation_json = serde_json::to_string(&attestation).unwrap();
        let decoded_policy: EnterpriseProviderPolicy = serde_json::from_str(&policy_json).unwrap();
        let decoded_attestation: EnterpriseProviderAttestationSummary =
            serde_json::from_str(&attestation_json).unwrap();
        assert_eq!(decoded_policy.policy_id.0, "EP-001");
        assert_eq!(decoded_attestation.attestation_id.0, "EAT-001");
    }

    #[test]
    fn test_enterprise_recovery_request_and_decision_serializes() {
        use tuff_cse_winfs::enterprise_authority::EnterpriseAuthorityPolicyId;
        use tuff_cse_winfs::enterprise_quorum::{
            EnterpriseQuorumMemberFingerprint, EnterpriseQuorumPolicyId,
        };
        use tuff_cse_winfs::enterprise_recovery::{
            build_enterprise_recovery_decision, EnterpriseRecoveryDecisionId,
            EnterpriseRecoveryRequest, EnterpriseRecoveryRequestId, EnterpriseRecoverySourceKind,
            EnterpriseRecoveryStatus,
        };

        let request = EnterpriseRecoveryRequest {
            request_id: EnterpriseRecoveryRequestId("ERQ-1".to_string()),
            operation_kind: OperationKind::Recover,
            volume_hash: "vol".to_string(),
            domain_recovery_request_id: "drq".to_string(),
            domain_recovery_package_id: "dpk".to_string(),
            domain_recovery_decision_id: "ddc".to_string(),
            enterprise_authority_policy_id: EnterpriseAuthorityPolicyId("EA-1".to_string()),
            enterprise_quorum_policy_id: EnterpriseQuorumPolicyId("EQ-1".to_string()),
            enterprise_provider_id: Some("EP-1".to_string()),
            provider_attestation_hash: Some("AH-1".to_string()),
            source_kind: EnterpriseRecoverySourceKind::ImportedOfflineDecision,
            created_at: 1,
        };
        let json = serde_json::to_string(&request).unwrap();
        let decoded: EnterpriseRecoveryRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.request_id.0, "ERQ-1");

        let decision = build_enterprise_recovery_decision(
            EnterpriseRecoveryDecisionId("ERD-1".to_string()),
            OperationKind::Recover,
            "vol".to_string(),
            "drq".to_string(),
            "dpk".to_string(),
            "ddc".to_string(),
            EnterpriseAuthorityPolicyId("EA-1".to_string()),
            EnterpriseQuorumPolicyId("EQ-1".to_string()),
            vec![EnterpriseQuorumMemberFingerprint("FP-1".to_string())],
            1,
            2,
            EnterpriseRecoveryStatus::Approved,
            EnterpriseRecoverySourceKind::DevGeneratedDecision,
        );
        let mut decision = decision;
        decision.enterprise_provider_id = Some("EP-1".to_string());
        decision.provider_attestation_hash = Some("AH-1".to_string());
        decision.decision_hash =
            tuff_cse_winfs::enterprise_recovery::compute_enterprise_recovery_decision_hash(
                &decision,
            );
        let json = serde_json::to_string(&decision).unwrap();
        let decoded: tuff_cse_winfs::enterprise_recovery::EnterpriseRecoveryDecision =
            serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.decision_id.0, "ERD-1");
    }

    #[test]
    fn test_enterprise_recovery_status_serializes() {
        use tuff_cse_winfs::enterprise_recovery::EnterpriseRecoveryStatus;
        let json = serde_json::to_string(&EnterpriseRecoveryStatus::Approved).unwrap();
        assert_eq!(json, "\"Approved\"");
    }

    #[test]
    fn test_operation_journal_record_enterprise_fields_serializes() {
        use tuff_cse_winfs::enterprise_provider::EnterpriseProviderHealth;
        use tuff_cse_winfs::enterprise_provider_enforcement::{
            EnterpriseProviderEnforcementDecision, EnterpriseProviderRejectionReason,
        };
        use tuff_cse_winfs::enterprise_recovery::EnterpriseRecoveryStatus;
        use tuff_cse_winfs::enterprise_recovery_enforcement::{
            EnterpriseRecoveryEnforcementDecision, EnterpriseRecoveryRejectionReason,
        };
        use tuff_cse_winfs::operation_journal::{OperationJournalPhase, OperationJournalRecord};
        use tuff_cse_winfs::volume_state::VolumeBindingState;

        let record = OperationJournalRecord {
            seq: 1,
            phase: OperationJournalPhase::Commit,
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
            enterprise_authority_policy_id: Some("EA-1".to_string()),
            enterprise_quorum_policy_id: Some("EQ-1".to_string()),
            enterprise_recovery_request_id: Some("ERQ-1".to_string()),
            enterprise_recovery_decision_id: Some("ERD-1".to_string()),
            enterprise_provider_policy_id: Some("EP-1".to_string()),
            enterprise_provider_attestation_id: Some("EAT-1".to_string()),
            enterprise_provider_kind: Some(
                tuff_cse_winfs::enterprise_provider::EnterpriseProviderKind::ImportedOfflineProvider,
            ),
            enterprise_provider_health: Some(EnterpriseProviderHealth::OfflineImported),
            enterprise_provider_attestation_hash: Some("AH-1".to_string()),
            enterprise_recovery_status: Some(EnterpriseRecoveryStatus::Approved),
            enterprise_recovery_enforcement_status: Some(
                EnterpriseRecoveryEnforcementDecision::Allowed,
            ),
            enterprise_recovery_rejection_reason: None,
            enterprise_provider_enforcement_status: Some(
                EnterpriseProviderEnforcementDecision::Allowed,
            ),
            enterprise_provider_rejection_reason: Some(
                EnterpriseProviderRejectionReason::ReservedLiveProvider,
            ),
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
        let json = serde_json::to_string(&record).unwrap();
        let decoded: OperationJournalRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(
            decoded.enterprise_provider_policy_id.as_deref(),
            Some("EP-1")
        );
    }
}
