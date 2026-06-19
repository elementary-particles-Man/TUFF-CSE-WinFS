#[cfg(test)]
mod tests {
    use tempfile::tempdir;
    use tuff_cse_winfs::binding_store::BindingStore;
    use tuff_cse_winfs::domain_principal::DomainAuthorityFingerprint;
    use tuff_cse_winfs::domain_recovery::{
        DomainRecoveryDecision, DomainRecoveryRequest, DomainRecoveryWorkflowState,
    };
    use tuff_cse_winfs::domain_recovery_enforcement::DomainRecoveryEnforcer;
    use tuff_cse_winfs::enterprise_authority::{
        normalize_enterprise_authority_policy, EnterpriseAuthorityFingerprint,
        EnterpriseAuthorityPolicy, EnterpriseAuthorityPolicyId, EnterpriseAuthorityProviderKind,
    };
    use tuff_cse_winfs::enterprise_quorum::{
        normalize_enterprise_quorum_policy, EnterpriseQuorumMemberFingerprint,
        EnterpriseQuorumPolicy, EnterpriseQuorumPolicyId, EnterpriseQuorumThreshold, QuorumRule,
    };
    use tuff_cse_winfs::enterprise_recovery::{
        build_enterprise_recovery_decision, EnterpriseRecoveryDecisionId,
        EnterpriseRecoveryRequest, EnterpriseRecoveryRequestId, EnterpriseRecoverySourceKind,
        EnterpriseRecoveryStatus,
    };
    use tuff_cse_winfs::enterprise_recovery_enforcement::EnterpriseRecoveryEnforcer;
    use tuff_cse_winfs::operations::OperationKind;

    fn setup_store() -> (tempfile::TempDir, BindingStore) {
        let dir = tempdir().unwrap();
        let store = BindingStore::open_at(dir.path()).unwrap();
        (dir, store)
    }

    #[test]
    fn test_p5c_domain_recovery_workflow_remains_intact_after_p6a() {
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
        let decision = DomainRecoveryDecision {
            request_id: request.request_id.clone(),
            decision_id: "DRD-1".to_string(),
            package_id: "PKG-1".to_string(),
            approval_decision_id: None,
            status: DomainRecoveryWorkflowState::Authorized,
            expires_at: u64::MAX,
            consumed_at: None,
            decision_hash: vec![1, 2, 3],
        };

        let enforcer = DomainRecoveryEnforcer::new(&store);
        let result = enforcer
            .check_recovery_workflow(Some(&decision), &request, OperationKind::Recover)
            .unwrap();
        assert!(matches!(result, tuff_cse_winfs::domain_recovery_enforcement::DomainRecoveryEnforcementDecision::Allowed | tuff_cse_winfs::domain_recovery_enforcement::DomainRecoveryEnforcementDecision::NotRequired));
    }

    #[test]
    fn test_domain_recovery_is_still_required_before_enterprise_recovery_when_policy_requires_it() {
        let (_dir, store) = setup_store();

        let authority_policy = normalize_enterprise_authority_policy(EnterpriseAuthorityPolicy {
            policy_id: EnterpriseAuthorityPolicyId("EA-1".to_string()),
            authority_fingerprint: EnterpriseAuthorityFingerprint("AUTH-FP".to_string()),
            provider_kind: EnterpriseAuthorityProviderKind::ImportedOfflineAuthority,
            policy_hash: None,
            created_at: 1,
        });
        let quorum_policy = normalize_enterprise_quorum_policy(EnterpriseQuorumPolicy {
            policy_id: EnterpriseQuorumPolicyId("EQ-1".to_string()),
            enterprise_authority_policy_id: authority_policy.policy_id.clone(),
            rule: QuorumRule::Threshold,
            threshold: EnterpriseQuorumThreshold(1),
            members: vec![EnterpriseQuorumMemberFingerprint("MEM-1".to_string())],
            policy_hash: None,
            created_at: 1,
        })
        .unwrap();
        store
            .save_enterprise_authority_policy(&authority_policy)
            .unwrap();
        store.save_enterprise_quorum_policy(&quorum_policy).unwrap();

        let request = EnterpriseRecoveryRequest {
            request_id: EnterpriseRecoveryRequestId("ERQ-1".to_string()),
            operation_kind: OperationKind::Recover,
            volume_hash: "vol".to_string(),
            domain_recovery_request_id: "DRQ-1".to_string(),
            domain_recovery_package_id: "PKG-1".to_string(),
            domain_recovery_decision_id: "DRD-1".to_string(),
            enterprise_authority_policy_id: authority_policy.policy_id.clone(),
            enterprise_quorum_policy_id: quorum_policy.policy_id.clone(),
            source_kind: EnterpriseRecoverySourceKind::ImportedOfflineDecision,
            created_at: 1,
        };
        let decision = build_enterprise_recovery_decision(
            EnterpriseRecoveryDecisionId("ERD-1".to_string()),
            OperationKind::Recover,
            "vol".to_string(),
            "WRONG-REQ".to_string(),
            "WRONG-PKG".to_string(),
            "WRONG-DEC".to_string(),
            authority_policy.policy_id.clone(),
            quorum_policy.policy_id.clone(),
            vec![EnterpriseQuorumMemberFingerprint("MEM-1".to_string())],
            1,
            9999,
            EnterpriseRecoveryStatus::Approved,
            EnterpriseRecoverySourceKind::ImportedOfflineDecision,
        );

        let enforcer = EnterpriseRecoveryEnforcer::new(&store);
        let result = enforcer
            .check_enterprise_recovery(
                &request,
                Some(&decision),
                Some(&authority_policy),
                Some(&quorum_policy),
            )
            .unwrap();
        assert_eq!(
            result,
            tuff_cse_winfs::enterprise_recovery_enforcement::EnterpriseRecoveryEnforcementDecision::Rejected
        );
    }
}
