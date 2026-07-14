#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use tempfile::tempdir;
    use tuff_cse_winfs::audit_chain;
    use tuff_cse_winfs::audit_signing::{AuditSigner, DevAuditSigner};
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
    use tuff_cse_winfs::enterprise_provider::{
        normalize_enterprise_provider_attestation, normalize_enterprise_provider_policy,
        EnterpriseProviderAttestationId, EnterpriseProviderAttestationSummary,
        EnterpriseProviderCapability, EnterpriseProviderHealth, EnterpriseProviderKind,
        EnterpriseProviderPolicy, EnterpriseProviderPolicyId,
    };
    use tuff_cse_winfs::enterprise_provider_enforcement::EnterpriseProviderEnforcer;
    use tuff_cse_winfs::enterprise_provider_lifecycle::{
        normalize_lifecycle_event, EnterpriseProviderGeneration, EnterpriseProviderLifecycleEvent,
        EnterpriseProviderLifecycleEventId, EnterpriseProviderLifecycleEventKind,
        EnterpriseProviderLifecycleState,
    };
    use tuff_cse_winfs::enterprise_provider_lifecycle_enforcement::{
        EnterpriseProviderLifecycleEnforcementDecision, EnterpriseProviderLifecycleEnforcer,
    };
    use tuff_cse_winfs::enterprise_quorum::{
        normalize_enterprise_quorum_policy, EnterpriseQuorumMemberFingerprint,
        EnterpriseQuorumPolicy, EnterpriseQuorumPolicyId, EnterpriseQuorumThreshold, QuorumRule,
    };
    use tuff_cse_winfs::enterprise_recovery::{
        build_enterprise_recovery_decision, compute_enterprise_recovery_decision_hash,
        EnterpriseRecoveryDecision, EnterpriseRecoveryDecisionId, EnterpriseRecoveryRequest,
        EnterpriseRecoveryRequestId, EnterpriseRecoverySourceKind, EnterpriseRecoveryStatus,
    };
    use tuff_cse_winfs::enterprise_recovery_enforcement::{
        EnterpriseRecoveryEnforcementDecision, EnterpriseRecoveryEnforcer,
    };
    use tuff_cse_winfs::operation_journal::{self, OperationJournalPhase, OperationJournalRecord};
    use tuff_cse_winfs::operations::{
        execute_operation, OperationKind, OperationRequest, OperationStatus,
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

    fn domain_recovery_request() -> DomainRecoveryRequest {
        DomainRecoveryRequest {
            request_id: "DRQ-001".to_string(),
            operation_kind: OperationKind::Recover,
            source_volume_hash: BindingStore::volume_hash("D:"),
            target_volume_hash: None,
            host_fingerprint: None,
            domain_policy_id: "DP-001".to_string(),
            group_policy_mapping_id: "GM-001".to_string(),
            offline_snapshot_id: None,
            domain_authority_fingerprint: DomainAuthorityFingerprint("DA-001".to_string()),
            created_at: 1,
        }
    }

    fn domain_recovery_decision() -> DomainRecoveryDecision {
        DomainRecoveryDecision {
            request_id: "DRQ-001".to_string(),
            decision_id: "DRD-001".to_string(),
            package_id: "DRP-001".to_string(),
            approval_decision_id: Some("DAP-001".to_string()),
            status: DomainRecoveryWorkflowState::Authorized,
            expires_at: u64::MAX,
            consumed_at: None,
            decision_hash: vec![1, 2, 3],
        }
    }

    fn enterprise_recovery_request(
        provider_id: &str,
        attestation_hash: &str,
    ) -> EnterpriseRecoveryRequest {
        EnterpriseRecoveryRequest {
            request_id: EnterpriseRecoveryRequestId("ERQ-001".to_string()),
            operation_kind: OperationKind::Recover,
            volume_hash: BindingStore::volume_hash("D:"),
            domain_recovery_request_id: "DRQ-001".to_string(),
            domain_recovery_package_id: "DRP-001".to_string(),
            domain_recovery_decision_id: "DRD-001".to_string(),
            enterprise_authority_policy_id: EnterpriseAuthorityPolicyId("EA-001".to_string()),
            enterprise_quorum_policy_id: EnterpriseQuorumPolicyId("EQ-001".to_string()),
            enterprise_provider_id: Some(provider_id.to_string()),
            provider_attestation_hash: Some(attestation_hash.to_string()),
            source_kind: EnterpriseRecoverySourceKind::ImportedOfflineDecision,
            created_at: 1,
        }
    }

    fn enterprise_recovery_decision(
        provider_id: &str,
        generation: Option<u64>,
    ) -> EnterpriseRecoveryDecision {
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
        decision.enterprise_provider_id = Some(provider_id.to_string());
        decision.enterprise_provider_generation = generation;
        decision.provider_attestation_hash = Some(
            provider_attestation(generation)
                .attestation_hash
                .as_ref()
                .unwrap()
                .0
                .clone(),
        );
        decision.decision_hash = compute_enterprise_recovery_decision_hash(&decision);
        decision
    }

    fn cli_path(name: &str) -> String {
        env::var(format!("CARGO_BIN_EXE_{}", name)).unwrap()
    }

    fn read_all_text_files(path: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if path.is_file() {
            out.push(path.to_path_buf());
            return out;
        }
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let entry_path = entry.path();
                if entry_path.is_dir() {
                    out.extend(read_all_text_files(&entry_path));
                } else {
                    out.push(entry_path);
                }
            }
        }
        out
    }

    fn assert_no_forbidden_strings(root: &Path, needles: &[&str]) {
        for file in read_all_text_files(root) {
            if let Ok(text) = fs::read_to_string(&file) {
                for needle in needles {
                    assert!(
                        !text.contains(needle),
                        "forbidden string `{}` found in {}",
                        needle,
                        file.display()
                    );
                }
            }
        }
    }

    #[test]
    fn rc_constants_and_status_output_are_fixed() {
        assert_eq!(tuff_cse_winfs::V1_RC_PHASE, "P6Z");
        assert_eq!(
            tuff_cse_winfs::V1_RC_COMPLETED_PHASES.first().copied(),
            Some("P1A")
        );
        assert!(tuff_cse_winfs::V1_RC_COMPLETED_PHASES.contains(&"P6C"));
        assert!(tuff_cse_winfs::V1_RC_RESERVED_LIVE_INTEGRATIONS.contains(&"live KMS"));
        assert!(tuff_cse_winfs::V1_RC_FORBIDDEN_BOUNDARIES.contains(&"RAW"));

        let output = Command::new(cli_path("tuff-cse-winfsctl"))
            .arg("rc-status")
            .output()
            .unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("v1 boundary phase: P6Z"));
        assert!(stdout.contains("main-independent build info"));
        assert!(stdout.contains("completed phases: P1A"));
        assert!(stdout.contains("reserved live integrations: live KMS"));
    }

    #[test]
    fn representative_flow_from_p1c_to_p6c_remains_closed() {
        env::set_var("TUFF_CSE_WINFS_ALLOW_DEV_AUDIT_SIGNER", "1");
        let (dir, store) = setup_store();
        let signer = DevAuditSigner::new("rc-test-key".to_string()).unwrap();
        store
            .save_audit_public_key(&signer.public_key_record())
            .unwrap();

        let authority = authority_policy();
        let quorum = quorum_policy();
        let provider = provider_policy(Some(1));
        let attestation = provider_attestation(Some(1));
        store.save_enterprise_authority_policy(&authority).unwrap();
        store.save_enterprise_quorum_policy(&quorum).unwrap();
        store.save_enterprise_provider_policy(&provider).unwrap();
        store
            .save_enterprise_provider_attestation(&attestation)
            .unwrap();

        let domain_request = domain_recovery_request();
        let domain_decision = domain_recovery_decision();
        let domain_enforcer = DomainRecoveryEnforcer::new(&store);
        let domain_result = domain_enforcer
            .check_recovery_workflow(
                Some(&domain_decision),
                &domain_request,
                OperationKind::Recover,
            )
            .unwrap();
        assert!(matches!(
            domain_result,
            tuff_cse_winfs::domain_recovery_enforcement::DomainRecoveryEnforcementDecision::Allowed
                | tuff_cse_winfs::domain_recovery_enforcement::DomainRecoveryEnforcementDecision::NotRequired
        ));

        let enterprise_request = enterprise_recovery_request(
            "EP-001",
            attestation.attestation_hash.as_ref().unwrap().0.as_str(),
        );
        let enterprise_decision = enterprise_recovery_decision("EP-001", Some(1));
        let enterprise_enforcer = EnterpriseRecoveryEnforcer::new(&store);
        let enterprise_result = enterprise_enforcer
            .check_enterprise_recovery(
                &enterprise_request,
                Some(&enterprise_decision),
                Some(&authority),
                Some(&quorum),
            )
            .unwrap();
        assert_eq!(
            enterprise_result,
            EnterpriseRecoveryEnforcementDecision::Allowed
        );

        let provider_enforcer = EnterpriseProviderEnforcer::new(&store);
        let provider_result = provider_enforcer
            .check_enterprise_provider(
                &enterprise_request,
                Some(&enterprise_decision),
                Some(&provider),
                Some(&attestation),
                Some(&authority),
            )
            .unwrap();
        assert_eq!(provider_result, tuff_cse_winfs::enterprise_provider_enforcement::EnterpriseProviderEnforcementDecision::Allowed);

        let active_event = normalize_lifecycle_event(EnterpriseProviderLifecycleEvent {
            event_id: EnterpriseProviderLifecycleEventId("EV-001".to_string()),
            provider_id: EnterpriseProviderPolicyId("EP-001".to_string()),
            generation: EnterpriseProviderGeneration(1),
            kind: EnterpriseProviderLifecycleEventKind::ImportedActivation,
            state: EnterpriseProviderLifecycleState::Active,
            revocation_reason: None,
            attestation_hash: attestation.attestation_hash.clone(),
            created_at: 1,
            event_hash: None,
        });
        store
            .save_enterprise_provider_lifecycle_event(&active_event)
            .unwrap();

        let lifecycle_enforcer = EnterpriseProviderLifecycleEnforcer::new(&store);
        let lifecycle_result = lifecycle_enforcer
            .check_provider_lifecycle(
                &enterprise_request,
                Some(&enterprise_decision),
                Some(&provider),
                Some(&attestation),
            )
            .unwrap();
        assert_eq!(
            lifecycle_result,
            EnterpriseProviderLifecycleEnforcementDecision::Allowed
        );

        let recovered = execute_operation(
            OperationRequest {
                operation_id: "OP-RECOVER-001".to_string(),
                kind: OperationKind::Status,
                volume: "D:".to_string(),
                requested_by: "test-user".to_string(),
                policy_id: "test-policy".to_string(),
                timestamp: 1,
                approval_id: Some("APP-001".to_string()),
                enterprise_authority_policy_id: Some(authority.policy_id.0.clone()),
                enterprise_quorum_policy_id: Some(quorum.policy_id.0.clone()),
                enterprise_recovery_decision_id: Some(enterprise_decision.decision_id.0.clone()),
                enterprise_provider_generation: Some(1),
                enterprise_provider_lifecycle_event_id: Some("EV-001".to_string()),
            },
            &tuff_cse_winfs::managed_policy::ManagedPolicy::default(),
            &mut VolumeRuntimeState::new(),
        )
        .unwrap();
        assert_eq!(recovered.status, OperationStatus::Accepted);

        let journal_record = OperationJournalRecord {
            seq: 1,
            phase: OperationJournalPhase::Commit,
            operation_id: "OP-RECOVER-001".to_string(),
            kind: OperationKind::Recover,
            volume: "D:".to_string(),
            requested_by: "test-user".to_string(),
            result_status: OperationStatus::Accepted,
            previous_state: VolumeBindingState::BoundLocked,
            next_state: VolumeBindingState::BoundLocked,
            descriptor_id: None,
            plan_id: None,
            session_id: None,
            manual_flow_id: None,
            approval_id: Some("APP-001".to_string()),
            decision_id: Some("ERD-001".to_string()),
            enterprise_authority_policy_id: Some(authority.policy_id.0.clone()),
            enterprise_quorum_policy_id: Some(quorum.policy_id.0.clone()),
            enterprise_recovery_request_id: Some("ERQ-001".to_string()),
            enterprise_recovery_decision_id: Some(enterprise_decision.decision_id.0.clone()),
            enterprise_provider_policy_id: Some(provider.policy_id.0.clone()),
            enterprise_provider_attestation_id: Some(attestation.attestation_id.0.clone()),
            enterprise_provider_kind: Some(provider.provider_kind),
            enterprise_provider_health: Some(provider.health),
            enterprise_provider_attestation_hash: attestation
                .attestation_hash
                .as_ref()
                .map(|hash| hash.0.clone()),
            enterprise_recovery_status: Some(EnterpriseRecoveryStatus::Approved),
            enterprise_recovery_enforcement_status: Some(EnterpriseRecoveryEnforcementDecision::Allowed),
            enterprise_recovery_rejection_reason: None,
            enterprise_provider_enforcement_status: Some(
                tuff_cse_winfs::enterprise_provider_enforcement::EnterpriseProviderEnforcementDecision::Allowed,
            ),
            enterprise_provider_rejection_reason: None,
            enterprise_provider_lifecycle_event_id: Some("EV-001".to_string()),
            enterprise_provider_generation: Some(1),
            enterprise_provider_lifecycle_state: Some(EnterpriseProviderLifecycleState::Active),
            enterprise_provider_lifecycle_enforcement_status: Some(
                EnterpriseProviderLifecycleEnforcementDecision::Allowed,
            ),
            enterprise_provider_lifecycle_rejection_reason: None,
            enterprise_provider_rotation_plan_id: Some("PLAN-001".to_string()),
            approval_status: Some("Approved".to_string()),
            recovery_reason: Some("Authorized".to_string()),
            reason: "closed boundary".to_string(),
            timestamp: 1,
            record_hash: None,
            previous_record_hash: None,
            chain_hash: None,
            signing_key_id: None,
            signature_algorithm: None,
            signature: None,
            signed_at: None,
        };
        let payload = audit_chain::canonicalize_journal_payload(&journal_record);
        let payload_str = String::from_utf8(payload).unwrap();
        assert!(payload_str.contains("enterprise_provider_generation"));
        assert!(payload_str.contains("enterprise_provider_lifecycle_event_id"));
        assert!(payload_str.contains("enterprise_provider_lifecycle_state"));
        assert!(payload_str.contains("enterprise_provider_lifecycle_enforcement_status"));
        assert!(payload_str.contains("enterprise_provider_rotation_plan_id"));

        let store_root = dir.path();
        operation_journal::append_signed_record(
            store_root,
            &BindingStore::volume_hash("D:"),
            journal_record.clone(),
            &[0u8; 32],
            &signer,
        )
        .unwrap();

        let records =
            operation_journal::read_journal_records(store_root, &BindingStore::volume_hash("D:"))
                .unwrap();
        assert_eq!(records.len(), 1);

        let mut tampered = records.clone();
        tampered[0].record_hash = Some(vec![0u8; 32]);
        let mut public_keys = HashMap::new();
        public_keys.insert("rc-test-key".to_string(), signer.public_key_record());
        assert!(audit_chain::verify_journal_chain(&tampered, &public_keys).is_err());

        let mut tampered = records.clone();
        tampered[0].enterprise_provider_generation = Some(2);
        assert!(audit_chain::verify_journal_chain(&tampered, &public_keys).is_err());

        let mut tampered = records.clone();
        tampered[0].enterprise_provider_lifecycle_state =
            Some(EnterpriseProviderLifecycleState::Revoked);
        assert!(audit_chain::verify_journal_chain(&tampered, &public_keys).is_err());

        let mut tampered = records.clone();
        tampered[0].enterprise_provider_rotation_plan_id = Some("PLAN-ALT".to_string());
        assert!(audit_chain::verify_journal_chain(&tampered, &public_keys).is_err());

        assert_no_forbidden_strings(
            store_root,
            &[
                "password",
                "auth token",
                "Kerberos",
                "LDAP bind",
                "raw SID",
                "raw account",
                "raw UPN",
                "raw group",
                "raw domain",
                "basekey",
                "MK",
                "TK",
                "PK",
                "private key",
                "KMS secret",
                "HSM secret",
                "provider credential",
                "raw TPM",
            ],
        );

        assert_no_forbidden_strings(
            store_root,
            &[
                "live KMS",
                "live HSM",
                "PKCS#11 connect",
                "Cloud KMS SDK",
                "domain controller",
                "LSASS",
                "pnputil",
                "raw LBA",
                "partition resize",
                "AnchorProvider",
            ],
        );
    }

    #[test]
    fn v1_rc_installer_dry_run_and_verify_pass() {
        let setup = cli_path("TuffCseWinFsSetup");
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let policy = repo_root.join("examples/cse-install-policy.example.json");
        let driver_package = repo_root.join("driver/windows");

        let output = Command::new(&setup)
            .args([
                "install",
                "--policy",
                policy.to_str().unwrap(),
                "--driver-package",
                driver_package.to_str().unwrap(),
                "--dry-run",
            ])
            .output()
            .unwrap();
        assert!(output.status.success());

        let output = Command::new(&setup)
            .args(["verify", "--policy", policy.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(output.status.success());
    }

    #[test]
    fn v1_rc_gate_keeps_non_p8a_live_integrations_closed() {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let src_root = repo_root.join("src");
        assert_no_forbidden_strings(
            &src_root,
            &[
                "CloudKmsClient",
                "Pkcs11Session",
                "AnchorProvider",
                "RawLba",
                "partition resize",
                "KmsSecret",
                "HsmSecret",
            ],
        );

        let driver_source = fs::read_to_string(src_root.join("driver.rs")).unwrap();
        let install_source = fs::read_to_string(src_root.join("install.rs")).unwrap();
        assert!(driver_source.contains("pnputil.exe"));
        assert!(install_source.contains("live_driver_install"));
        assert!(install_source.contains("install_driver_package_live"));
        assert_eq!(tuff_cse_winfs::P8A_LIVE_DRIVER_INSTALL_PHASE, "P8A");
    }
}
