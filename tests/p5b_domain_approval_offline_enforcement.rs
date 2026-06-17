use tuff_cse_winfs::domain_approval::{DomainApprovalRequest, DomainApprovalStatus, DomainApprovalSourceKind, DomainApprovalDecision};
use tuff_cse_winfs::domain_principal::{DomainAuthorityFingerprint, DomainPrincipalFingerprint, DomainGroupFingerprint};
use tuff_cse_winfs::operations::OperationKind;
use tuff_cse_winfs::domain_policy::{DomainPolicy, DomainPolicySourceKind, DomainPolicyEffect, DomainOperationPolicy};
use tuff_cse_winfs::domain_approval_enforcement::{DomainApprovalEnforcer, DomainApprovalEnforcementDecision};
use tuff_cse_winfs::binding_store::BindingStore;
use tempfile::tempdir;

#[test]
fn test_domain_approval_request_persists_only_fingerprints() {
    let req = DomainApprovalRequest {
        request_id: "req-1".to_string(),
        operation_kind: OperationKind::Export,
        volume_hash: "vol-hash".to_string(),
        domain_policy_id: "policy-1".to_string(),
        group_policy_mapping_id: "mapping-1".to_string(),
        offline_snapshot_id: None,
        domain_authority_fingerprint: DomainAuthorityFingerprint("auth-fp".to_string()),
        requester_principal_fingerprint: DomainPrincipalFingerprint("req-fp".to_string()),
        created_at: 0,
    };
    let serialized = serde_json::to_string(&req).unwrap();
    assert!(!serialized.contains("SID"));
    assert!(!serialized.contains("UPN"));
    assert!(serialized.contains("auth-fp"));
}

#[test]
fn test_domain_approval_enforcer_accepts_valid_decision() {
    let dir = tempdir().unwrap();
    let store = BindingStore::open_at(dir.path()).unwrap();
    let enforcer = DomainApprovalEnforcer::new(&store);

    let decision = DomainApprovalDecision {
        request_id: "req-1".to_string(),
        decision_id: "dec-1".to_string(),
        operation_kind: OperationKind::Export,
        volume_hash: "vol-hash".to_string(),
        domain_policy_id: "policy-1".to_string(),
        group_policy_mapping_id: "mapping-1".to_string(),
        offline_snapshot_id: None,
        domain_authority_fingerprint: DomainAuthorityFingerprint("auth-fp".to_string()),
        approver_principal_fingerprint: DomainPrincipalFingerprint("approver-fp".to_string()),
        approver_group_fingerprint: None,
        status: DomainApprovalStatus::Approved,
        expires_at: 9999999999,
        consumed_at: None,
        decision_hash: vec![0],
        source_kind: DomainApprovalSourceKind::ImportedOfflineDecision,
    };
    store.save_domain_approval_decision(&decision).unwrap();

    let policy = DomainPolicy {
        domain_policy_id: "policy-1".to_string(),
        domain_authority_fingerprint: DomainAuthorityFingerprint("auth-fp".to_string()),
        source_kind: DomainPolicySourceKind::ImportedGpoSnapshot,
        created_at: 0,
    };

    let result = enforcer.check_required_domain_approval(
        Some(&decision),
        OperationKind::Export,
        "vol-hash",
        &policy,
        None,
    ).unwrap();

    assert_eq!(result, DomainApprovalEnforcementDecision::Allowed);
}
