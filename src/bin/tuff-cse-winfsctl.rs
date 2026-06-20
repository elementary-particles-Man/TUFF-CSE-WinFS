use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tuff_cse_winfs::audit_chain;
use tuff_cse_winfs::audit_signing::{self, AuditSigner, DevAuditSigner};
use tuff_cse_winfs::binding::{self, BindingInputSnapshot};
use tuff_cse_winfs::binding_policy;
use tuff_cse_winfs::binding_store::BindingStore;
use tuff_cse_winfs::enterprise_authority::{self, EnterpriseAuthorityPolicy};
use tuff_cse_winfs::enterprise_provider::{
    self, EnterpriseProviderAttestationSummary, EnterpriseProviderPolicy,
};
use tuff_cse_winfs::enterprise_provider_enforcement::{
    EnterpriseProviderEnforcementDecision, EnterpriseProviderEnforcer,
};
use tuff_cse_winfs::enterprise_quorum::{self, EnterpriseQuorumPolicy};
use tuff_cse_winfs::enterprise_recovery::{
    self, EnterpriseRecoveryDecision, EnterpriseRecoveryRequest, EnterpriseRecoverySourceKind,
    EnterpriseRecoveryStatus,
};
use tuff_cse_winfs::enterprise_recovery_enforcement::{
    EnterpriseRecoveryEnforcementDecision, EnterpriseRecoveryEnforcer,
};
use tuff_cse_winfs::export_manifest::ExportRecipient;
use tuff_cse_winfs::export_policy;
use tuff_cse_winfs::key_material;
use tuff_cse_winfs::local_approval;
use tuff_cse_winfs::local_policy::{self, LocalOperationClass};
use tuff_cse_winfs::local_principal;
use tuff_cse_winfs::managed_policy::{self, ManagedPolicy};
use tuff_cse_winfs::manual_flow::ManualFlowKind;
use tuff_cse_winfs::operation_journal::{self};
use tuff_cse_winfs::operations::{self, OperationKind, OperationRequest};
use tuff_cse_winfs::rebind_model;
use tuff_cse_winfs::recovery_key;

#[derive(Parser)]
#[command(name = "tuff-cse-winfsctl")]
#[command(about = "TUFF-CSE-WinFS v1 Management CUI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Display the management status of the target volume
    Status {
        #[arg(short, long)]
        volume: String,
        #[arg(short, long)]
        policy: Option<PathBuf>,
        #[arg(short, long)]
        json: bool,
        #[arg(long)]
        recover_stale: bool,
        #[arg(long, hide = true)]
        store_root: Option<PathBuf>,
    },
    /// Bind a volume for management
    Bind {
        #[arg(short, long)]
        volume: String,
        #[arg(short, long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        binding_policy: Option<PathBuf>,
        #[arg(long)]
        plan_only: bool,
        #[arg(long)]
        json: bool,
        #[arg(long, hide = true)]
        store_root: Option<PathBuf>,
    },
    /// Unlock a volume for in-place usage
    Unlock {
        #[arg(short, long)]
        volume: String,
        #[arg(short, long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        local_policy: Option<PathBuf>,
        #[arg(long)]
        approval_id: Option<String>,
        #[arg(long, hide = true)]
        store_root: Option<PathBuf>,
    },
    /// Lock a currently used volume
    Lock {
        #[arg(short, long)]
        volume: String,
        #[arg(short, long)]
        policy: Option<PathBuf>,
        #[arg(long, hide = true)]
        store_root: Option<PathBuf>,
    },
    /// Safely eject a volume
    Eject {
        #[arg(short, long)]
        volume: String,
        #[arg(short, long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        local_policy: Option<PathBuf>,
        #[arg(long)]
        approval_id: Option<String>,
        #[arg(long, hide = true)]
        store_root: Option<PathBuf>,
    },
    /// Read the operation journal for a volume
    Audit {
        #[arg(short, long)]
        volume: String,
        #[arg(short, long)]
        policy: Option<PathBuf>,
        #[arg(short, long)]
        json: bool,
        #[arg(long, hide = true)]
        store_root: Option<PathBuf>,
    },
    /// Reseal for external transfer
    Export {
        #[arg(short, long)]
        volume: String,
        #[arg(long)]
        recipient: Option<String>,
        #[arg(long)]
        recipient_key_fp: Option<String>,
        #[arg(long)]
        export_policy: Option<PathBuf>,
        #[arg(long)]
        local_policy: Option<PathBuf>,
        #[arg(long)]
        approval_id: Option<String>,
        #[arg(long)]
        manifest_out: Option<PathBuf>,
        #[arg(long, hide = true)]
        store_root: Option<PathBuf>,
        #[arg(short, long)]
        json: bool,
        #[arg(long)]
        require_manual_confirmation: bool,
        #[arg(long)]
        complete_plan: Option<String>,
        #[arg(long)]
        cancel_plan: Option<String>,
        #[arg(long)]
        confirm: Option<String>,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Transfer ownership boundary
    Rebind {
        #[arg(short, long)]
        volume: String,
        #[arg(long)]
        new_host_fp: Option<String>,
        #[arg(long)]
        new_host_label: Option<String>,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long)]
        rebind_policy: Option<PathBuf>,
        #[arg(long)]
        local_policy: Option<PathBuf>,
        #[arg(long)]
        approval_id: Option<String>,
        #[arg(long)]
        manifest_out: Option<PathBuf>,
        #[arg(long, hide = true)]
        store_root: Option<PathBuf>,
        #[arg(short, long)]
        json: bool,
        #[arg(long)]
        complete_plan: Option<String>,
        #[arg(long)]
        cancel_plan: Option<String>,
        #[arg(long)]
        confirm: Option<String>,
    },
    /// Recover a volume
    Recover {
        #[arg(short, long)]
        volume: String,
        #[arg(long)]
        recovery_key_fp: Option<String>,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long)]
        recovery_policy: Option<PathBuf>,
        #[arg(long)]
        local_policy: Option<PathBuf>,
        #[arg(long)]
        approval_id: Option<String>,
        #[arg(long)]
        plan_out: Option<PathBuf>,
        #[arg(long, hide = true)]
        store_root: Option<PathBuf>,
        #[arg(short, long)]
        json: bool,
        #[arg(long)]
        complete_plan: Option<String>,
        #[arg(long)]
        cancel_plan: Option<String>,
        #[arg(long)]
        confirm: Option<String>,
    },
    /// Approval management
    Approval {
        #[command(subcommand)]
        sub: ApprovalCommands,
    },
    /// Enterprise authority management
    EnterpriseAuthority {
        #[command(subcommand)]
        sub: EnterpriseAuthorityCommands,
    },
    /// Enterprise quorum management
    EnterpriseQuorum {
        #[command(subcommand)]
        sub: EnterpriseQuorumCommands,
    },
    /// Enterprise provider management
    EnterpriseProvider {
        #[command(subcommand)]
        sub: EnterpriseProviderCommands,
    },
    /// Enterprise recovery management
    EnterpriseRecovery {
        #[command(subcommand)]
        sub: EnterpriseRecoveryCommands,
    },
    /// Audit signing management
    AuditSigning {
        #[command(subcommand)]
        sub: AuditSigningCommands,
    },
}

#[derive(Subcommand)]
enum AuditSigningCommands {
    /// Initialize audit signing key
    Init {
        #[arg(short, long)]
        volume: String,
        #[arg(long, hide = true)]
        store_root: Option<PathBuf>,
    },
    /// Check audit signing status
    Status {
        #[arg(short, long)]
        volume: String,
        #[arg(long, hide = true)]
        store_root: Option<PathBuf>,
    },
    /// Verify audit journal
    Verify {
        #[arg(short, long)]
        volume: String,
        #[arg(long, hide = true)]
        store_root: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ApprovalCommands {
    /// Request a local administrator approval
    Request {
        #[arg(long)]
        operation: String, // e.g. export, recover, rebind, unlock, eject
        #[arg(long)]
        volume: Option<String>,
        #[arg(long)]
        target_plan: Option<String>,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        principal_fp: Option<String>,
        #[arg(long)]
        local_policy: Option<PathBuf>,
        #[arg(long, hide = true)]
        store_root: Option<PathBuf>,
        #[arg(short, long)]
        json: bool,
    },
    /// Approve a pending request
    Approve {
        #[arg(long)]
        approval_id: String,
        #[arg(long)]
        reason: String,
        #[arg(long, hide = true)]
        store_root: Option<PathBuf>,
        #[arg(short, long)]
        json: bool,
        #[arg(long)]
        dev_approver_fingerprint: Option<String>,
    },
    /// Deny a pending request
    Deny {
        #[arg(long)]
        approval_id: String,
        #[arg(long)]
        reason: String,
        #[arg(long, hide = true)]
        store_root: Option<PathBuf>,
        #[arg(short, long)]
        json: bool,
        #[arg(long)]
        dev_approver_fingerprint: Option<String>,
    },
    /// Check the status of an approval request
    Status {
        #[arg(long)]
        approval_id: String,
        #[arg(long, hide = true)]
        store_root: Option<PathBuf>,
        #[arg(short, long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum EnterpriseAuthorityCommands {
    Import {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long, hide = true)]
        store_root: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    Status {
        #[arg(long)]
        policy_id: Option<String>,
        #[arg(long, hide = true)]
        store_root: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    Evaluate {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long, hide = true)]
        store_root: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum EnterpriseQuorumCommands {
    Import {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long, hide = true)]
        store_root: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    Status {
        #[arg(long)]
        policy_id: Option<String>,
        #[arg(long, hide = true)]
        store_root: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    Evaluate {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long, hide = true)]
        store_root: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum EnterpriseProviderCommands {
    Import {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long, hide = true)]
        store_root: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    ImportAttestation {
        #[arg(long)]
        attestation: PathBuf,
        #[arg(long, hide = true)]
        store_root: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    Status {
        #[arg(long = "enterprise-provider")]
        enterprise_provider: Option<String>,
        #[arg(long = "enterprise-provider-attestation")]
        enterprise_provider_attestation: Option<String>,
        #[arg(long, hide = true)]
        store_root: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    Evaluate {
        #[arg(long = "enterprise-provider")]
        enterprise_provider: String,
        #[arg(long)]
        operation: String,
        #[arg(long)]
        volume: String,
        #[arg(long, hide = true)]
        store_root: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum EnterpriseRecoveryCommands {
    Request {
        #[arg(long)]
        operation: String,
        #[arg(long)]
        volume: String,
        #[arg(long)]
        domain_recovery_request_id: Option<String>,
        #[arg(long)]
        domain_recovery_package_id: Option<String>,
        #[arg(long)]
        domain_recovery_decision_id: Option<String>,
        #[arg(long)]
        enterprise_authority_policy_id: Option<String>,
        #[arg(long)]
        enterprise_quorum_policy_id: Option<String>,
        #[arg(long, hide = true)]
        store_root: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    ImportDecision {
        #[arg(long)]
        decision: PathBuf,
        #[arg(long, hide = true)]
        store_root: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    DevApprove {
        #[arg(long)]
        request_id: String,
        #[arg(long, hide = true)]
        store_root: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    DevDeny {
        #[arg(long)]
        request_id: String,
        #[arg(long, hide = true)]
        store_root: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    Status {
        #[arg(long = "enterprise-recovery-decision")]
        enterprise_recovery_decision: Option<String>,
        #[arg(long)]
        request_id: Option<String>,
        #[arg(long, hide = true)]
        store_root: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    Evaluate {
        #[arg(long)]
        operation: String,
        #[arg(long)]
        volume: String,
        #[arg(long = "enterprise-recovery-decision")]
        enterprise_recovery_decision: String,
        #[arg(long, hide = true)]
        store_root: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

fn load_policy_or_default(path: Option<PathBuf>) -> Result<ManagedPolicy> {
    match path {
        Some(p) => managed_policy::load_managed_policy(p),
        None => Ok(managed_policy::default_local_policy()),
    }
}

fn open_store(store_root: Option<PathBuf>) -> Result<BindingStore> {
    match store_root {
        Some(path) => BindingStore::open_at(&path),
        None => BindingStore::open_default(),
    }
}

fn handle_operation(
    kind: OperationKind,
    volume: String,
    policy_path: Option<PathBuf>,
    local_policy_path: Option<PathBuf>,
    approval_id: Option<String>,
    store_root: Option<PathBuf>,
) -> Result<()> {
    let policy = load_policy_or_default(policy_path)?;
    let local_policy = match local_policy_path {
        Some(p) => Some(local_policy::load_local_policy(p)?),
        None => None,
    };
    let store = open_store(store_root)?;

    let request = OperationRequest {
        operation_id: format!(
            "OP-{}-{}",
            kind as u32,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        ),
        kind,
        volume: volume.clone(),
        requested_by: "Admin".to_string(), // Mock
        policy_id: policy.policy_id.clone(),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        approval_id,
        enterprise_authority_policy_id: None,
        enterprise_quorum_policy_id: None,
        enterprise_recovery_decision_id: None,
    };

    let result =
        operations::execute_managed_operation(request, &policy, &store, local_policy.as_ref())?;

    println!("Operation: {:?}", kind);
    println!("Status: {:?}", result.status);
    println!("Reason: {}", result.reason);
    println!(
        "Transition: {:?} -> {:?}",
        result.previous_state, result.next_state
    );

    Ok(())
}

fn handle_audit(
    volume: String,
    policy_path: Option<PathBuf>,
    json: bool,
    store_root: Option<PathBuf>,
) -> Result<()> {
    let policy = load_policy_or_default(policy_path)?;
    let store = open_store(store_root)?;

    if !policy.allow_audit {
        println!("Audit is denied by policy.");
        return Ok(());
    }

    let dummy_hash = BindingStore::volume_hash(&volume);

    match operation_journal::read_journal_records(store.root_path(), &dummy_hash) {
        Ok(records) => {
            if json {
                for record in records {
                    println!("{}", serde_json::to_string(&record)?);
                }
            } else {
                println!("Audit Journal for Volume: {}", volume);
                for record in records {
                    println!(
                        "[{}] [{:?}] OP: {:?}, Status: {:?}, Reason: {}",
                        record.timestamp,
                        record.phase,
                        record.kind,
                        record.result_status,
                        record.reason
                    );
                }
            }
        }
        Err(_) => {
            println!(
                "No journal found or error reading journal for volume: {}",
                volume
            );
        }
    }

    Ok(())
}

fn handle_export(
    volume: String,
    recipient_id: Option<String>,
    recipient_key_fp: Option<String>,
    export_policy_path: Option<PathBuf>,
    _local_policy_path: Option<PathBuf>,
    approval_id: Option<String>,
    manifest_out: Option<PathBuf>,
    store_root: Option<PathBuf>,
    json: bool,
    require_manual_confirmation: bool,
    complete_plan: Option<String>,
    cancel_plan: Option<String>,
    confirm: Option<String>,
    reason_code: Option<String>,
) -> Result<()> {
    let policy = load_policy_or_default(None)?;
    let local_policy = match _local_policy_path {
        Some(p) => local_policy::load_local_policy(p)?,
        None => local_policy::default_local_policy(),
    };
    let store = open_store(store_root)?;

    if let Some(target_plan_id) = complete_plan {
        let request = OperationRequest {
            operation_id: format!(
                "OP-MCOMPLETE-{}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            ),
            kind: OperationKind::ManualComplete,
            volume,
            requested_by: "Admin".to_string(),
            policy_id: "MANUAL-FLOW".to_string(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            approval_id,
            enterprise_authority_policy_id: None,
            enterprise_quorum_policy_id: None,
            enterprise_recovery_decision_id: None,
        };
        let result = operations::execute_manual_flow_operation(
            request,
            &store,
            ManualFlowKind::ExportComplete,
            target_plan_id,
            confirm.unwrap_or_default(),
            reason_code.unwrap_or_default(),
            &local_policy,
        )?;
        println!("Status: {:?}", result.status);
        println!("Reason: {}", result.reason);
        return Ok(());
    }

    if let Some(target_plan_id) = cancel_plan {
        let request = OperationRequest {
            operation_id: format!(
                "OP-MCANCEL-{}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            ),
            kind: OperationKind::ManualCancel,
            volume,
            requested_by: "Admin".to_string(),
            policy_id: "MANUAL-FLOW".to_string(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            approval_id,
            enterprise_authority_policy_id: None,
            enterprise_quorum_policy_id: None,
            enterprise_recovery_decision_id: None,
        };
        let result = operations::execute_manual_flow_operation(
            request,
            &store,
            ManualFlowKind::ExportCancel,
            target_plan_id,
            confirm.unwrap_or_default(),
            reason_code.unwrap_or_default(),
            &local_policy,
        )?;
        println!("Status: {:?}", result.status);
        println!("Reason: {}", result.reason);
        return Ok(());
    }

    let rid = recipient_id.ok_or_else(|| anyhow!("recipient required"))?;
    let rkfp = recipient_key_fp.ok_or_else(|| anyhow!("recipient-key-fp required"))?;

    let export_policy = match export_policy_path {
        Some(p) => export_policy::load_export_policy(p)?,
        None => export_policy::default_manifest_only_policy(),
    };

    let recipient = ExportRecipient {
        recipient_id: rid,
        recipient_key_fingerprint: rkfp,
        recipient_org_hint: None,
    };

    let request = OperationRequest {
        operation_id: format!(
            "OP-EXPORT-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        ),
        kind: OperationKind::Export,
        volume: volume.clone(),
        requested_by: "Admin".to_string(),
        policy_id: export_policy.policy_id.clone(),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        approval_id,
        enterprise_authority_policy_id: None,
        enterprise_quorum_policy_id: None,
        enterprise_recovery_decision_id: None,
    };

    let result = operations::execute_export_operation(
        request,
        &policy,
        &export_policy,
        &store,
        recipient,
        require_manual_confirmation,
        &local_policy,
    )?;

    if json {
        println!("{}", serde_json::to_string(&result)?);
    } else {
        println!("Operation: Export");
        println!("Status: {:?}", result.status);
        println!("Reason: {}", result.reason);
    }

    if let Some(out_path) = manifest_out {
        let export_id = result.reason.split(": ").nth(1).unwrap_or("");
        if let Some(manifest) =
            store.load_export_manifest(export_id.trim_start_matches("MANIFEST-"))?
        {
            let file = std::fs::File::create(out_path)?;
            serde_json::to_writer_pretty(file, &manifest)?;
            println!("Manifest copied to specified output path.");
        }
    }

    Ok(())
}

fn handle_recover(
    volume: String,
    recovery_key_fp: Option<String>,
    reason: Option<String>,
    recovery_policy_path: Option<PathBuf>,
    local_policy_path: Option<PathBuf>,
    approval_id: Option<String>,
    plan_out: Option<PathBuf>,
    store_root: Option<PathBuf>,
    json: bool,
    complete_plan: Option<String>,
    _cancel_plan: Option<String>,
    confirm: Option<String>,
) -> Result<()> {
    let policy = load_policy_or_default(None)?;
    let local_policy = match local_policy_path {
        Some(p) => local_policy::load_local_policy(p)?,
        None => local_policy::default_local_policy(),
    };
    let store = open_store(store_root)?;

    if let Some(target_plan_id) = complete_plan {
        let request = OperationRequest {
            operation_id: format!(
                "OP-RECOVER-COMPLETE-{}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            ),
            kind: OperationKind::ManualComplete,
            volume,
            requested_by: "Admin".to_string(),
            policy_id: "MANUAL-FLOW".to_string(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            approval_id,
            enterprise_authority_policy_id: None,
            enterprise_quorum_policy_id: None,
            enterprise_recovery_decision_id: None,
        };
        let result = operations::execute_manual_flow_operation(
            request,
            &store,
            ManualFlowKind::RecoverComplete,
            target_plan_id,
            confirm.unwrap_or_default(),
            "RECOVERY_CONFIRMED".to_string(),
            &local_policy,
        )?;
        println!("Status: {:?}", result.status);
        println!("Reason: {}", result.reason);
        return Ok(());
    }

    let fp = recovery_key_fp.ok_or_else(|| anyhow!("recovery-key-fp required"))?;
    let rsn = reason.ok_or_else(|| anyhow!("reason required"))?;

    let recovery_policy = match recovery_policy_path {
        Some(p) => recovery_key::load_recovery_policy(p)?,
        None => recovery_key::default_recovery_policy(),
    };

    let request = OperationRequest {
        operation_id: format!(
            "OP-RECOVER-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        ),
        kind: OperationKind::Recover,
        volume: volume.clone(),
        requested_by: "Admin".to_string(),
        policy_id: recovery_policy.policy_id.clone(),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        approval_id,
        enterprise_authority_policy_id: None,
        enterprise_quorum_policy_id: None,
        enterprise_recovery_decision_id: None,
    };

    let result = operations::execute_recover_operation(
        request,
        &policy,
        &recovery_policy,
        &store,
        fp,
        rsn,
        &local_policy,
    )?;

    if json {
        println!("{}", serde_json::to_string(&result)?);
    } else {
        println!("Operation: Recover");
        println!("Status: {:?}", result.status);
        println!("Reason: {}", result.reason);
    }

    if let Some(out_path) = plan_out {
        let plan_id = result.reason.split(": ").nth(1).unwrap_or("");
        if let Some(plan) = store.load_recovery_plan(plan_id)? {
            let file = std::fs::File::create(out_path)?;
            serde_json::to_writer_pretty(file, &plan)?;
            println!("Recovery plan copied to specified output path.");
        }
    }

    Ok(())
}

fn handle_rebind(
    volume: String,
    new_host_fp: Option<String>,
    new_host_label: Option<String>,
    reason: Option<String>,
    rebind_policy_path: Option<PathBuf>,
    local_policy_path: Option<PathBuf>,
    approval_id: Option<String>,
    manifest_out: Option<PathBuf>,
    store_root: Option<PathBuf>,
    json: bool,
    complete_plan: Option<String>,
    _cancel_plan: Option<String>,
    confirm: Option<String>,
) -> Result<()> {
    let policy = load_policy_or_default(None)?;
    let local_policy = match local_policy_path {
        Some(p) => local_policy::load_local_policy(p)?,
        None => local_policy::default_local_policy(),
    };
    let store = open_store(store_root)?;

    if let Some(target_plan_id) = complete_plan {
        let request = OperationRequest {
            operation_id: format!(
                "OP-REBIND-COMPLETE-{}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            ),
            kind: OperationKind::ManualComplete,
            volume,
            requested_by: "Admin".to_string(),
            policy_id: "MANUAL-FLOW".to_string(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            approval_id,
            enterprise_authority_policy_id: None,
            enterprise_quorum_policy_id: None,
            enterprise_recovery_decision_id: None,
        };
        let result = operations::execute_manual_flow_operation(
            request,
            &store,
            ManualFlowKind::RebindComplete,
            target_plan_id,
            confirm.unwrap_or_default(),
            "REBIND_CONFIRMED".to_string(),
            &local_policy,
        )?;
        println!("Status: {:?}", result.status);
        println!("Reason: {}", result.reason);
        return Ok(());
    }

    let fp = new_host_fp.ok_or_else(|| anyhow!("new-host-fp required"))?;
    let rsn = reason.ok_or_else(|| anyhow!("reason required"))?;

    let rebind_policy = match rebind_policy_path {
        Some(p) => rebind_model::load_rebind_policy(p)?,
        None => rebind_model::default_rebind_policy(),
    };

    let request = OperationRequest {
        operation_id: format!(
            "OP-REBIND-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        ),
        kind: OperationKind::Rebind,
        volume: volume.clone(),
        requested_by: "Admin".to_string(),
        policy_id: rebind_policy.policy_id.clone(),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        approval_id,
        enterprise_authority_policy_id: None,
        enterprise_quorum_policy_id: None,
        enterprise_recovery_decision_id: None,
    };

    let result = operations::execute_rebind_operation(
        request,
        &policy,
        &rebind_policy,
        &store,
        fp,
        new_host_label,
        rsn,
        &local_policy,
    )?;

    if json {
        println!("{}", serde_json::to_string(&result)?);
    } else {
        println!("Operation: Rebind");
        println!("Status: {:?}", result.status);
        println!("Reason: {}", result.reason);
    }

    if let Some(out_path) = manifest_out {
        let rebind_id = result.reason.split(": ").nth(1).unwrap_or("");
        if let Some(manifest) = store.load_rebind_manifest(rebind_id)? {
            let file = std::fs::File::create(out_path)?;
            serde_json::to_writer_pretty(file, &manifest)?;
            println!("Rebind manifest copied to specified output path.");
        }
    }

    Ok(())
}

fn handle_audit_signing(
    sub: &AuditSigningCommands,
    volume: String,
    store_root: Option<PathBuf>,
) -> Result<()> {
    let store = open_store(store_root)?;
    match sub {
        AuditSigningCommands::Init { .. } => {
            let signer = DevAuditSigner::new(format!("DEV-SIGNER-{}", volume))?;
            store.save_audit_public_key(&signer.public_key_record())?;
            println!("Audit signing key initialized: {}", signer.key_id().0);
        }
        AuditSigningCommands::Status { .. } => {
            // ... load and print status ...
            println!("Status check not fully implemented in skeleton");
        }
        AuditSigningCommands::Verify { volume, .. } => {
            let records = operation_journal::read_journal_records(
                store.root_path(),
                &BindingStore::volume_hash(volume),
            )?;
            // ... verification logic ...
            println!("Verification check not fully implemented in skeleton");
        }
    }
    Ok(())
}

fn handle_approval(sub: ApprovalCommands) -> Result<()> {
    // ... approval logic ...
    Ok(())
}

fn handle_enterprise_authority(sub: EnterpriseAuthorityCommands) -> Result<()> {
    match sub {
        EnterpriseAuthorityCommands::Import {
            policy,
            store_root,
            json,
        } => {
            let store = open_store(store_root)?;
            let file = std::fs::File::open(policy)?;
            let policy: EnterpriseAuthorityPolicy = serde_json::from_reader(file)?;
            let policy = enterprise_authority::normalize_enterprise_authority_policy(policy);
            store.save_enterprise_authority_policy(&policy)?;
            if json {
                println!("{}", serde_json::to_string(&policy)?);
            } else {
                println!(
                    "Enterprise authority policy imported: {}",
                    policy.policy_id.0
                );
            }
        }
        EnterpriseAuthorityCommands::Status {
            policy_id,
            store_root,
            json,
        } => {
            let store = open_store(store_root)?;
            if let Some(policy_id) = policy_id {
                if let Some(policy) = store.load_enterprise_authority_policy(&policy_id)? {
                    if json {
                        println!("{}", serde_json::to_string(&policy)?);
                    } else {
                        println!("Enterprise authority policy: {}", policy.policy_id.0);
                        println!(
                            "Hash: {}",
                            policy
                                .policy_hash
                                .as_ref()
                                .map(|h| h.0.as_str())
                                .unwrap_or("")
                        );
                    }
                }
            } else {
                let policies = store.list_enterprise_authority_policies()?;
                if json {
                    println!("{}", serde_json::to_string(&policies)?);
                } else {
                    println!("Enterprise authority policies: {}", policies.len());
                }
            }
        }
        EnterpriseAuthorityCommands::Evaluate {
            policy,
            store_root,
            json,
        } => {
            let store = open_store(store_root)?;
            let file = std::fs::File::open(policy)?;
            let policy: EnterpriseAuthorityPolicy = serde_json::from_reader(file)?;
            let policy = enterprise_authority::normalize_enterprise_authority_policy(policy);
            let output = serde_json::json!({
                "policy_id": policy.policy_id.0,
                "authority_fingerprint": policy.authority_fingerprint.0,
                "provider_kind": policy.provider_kind,
                "policy_hash": policy.policy_hash.as_ref().map(|h| h.0.clone()).unwrap_or_default(),
                "created_at": policy.created_at,
                "store_root": store.root_path(),
            });
            if json {
                println!("{}", serde_json::to_string(&output)?);
            } else {
                println!(
                    "Enterprise authority policy validated: {}",
                    policy.policy_id.0
                );
            }
        }
    }
    Ok(())
}

fn handle_enterprise_quorum(sub: EnterpriseQuorumCommands) -> Result<()> {
    match sub {
        EnterpriseQuorumCommands::Import {
            policy,
            store_root,
            json,
        } => {
            let store = open_store(store_root)?;
            let file = std::fs::File::open(policy)?;
            let policy: EnterpriseQuorumPolicy = serde_json::from_reader(file)?;
            let policy = enterprise_quorum::normalize_enterprise_quorum_policy(policy)?;
            store.save_enterprise_quorum_policy(&policy)?;
            if json {
                println!("{}", serde_json::to_string(&policy)?);
            } else {
                println!("Enterprise quorum policy imported: {}", policy.policy_id.0);
            }
        }
        EnterpriseQuorumCommands::Status {
            policy_id,
            store_root,
            json,
        } => {
            let store = open_store(store_root)?;
            if let Some(policy_id) = policy_id {
                if let Some(policy) = store.load_enterprise_quorum_policy(&policy_id)? {
                    if json {
                        println!("{}", serde_json::to_string(&policy)?);
                    } else {
                        println!("Enterprise quorum policy: {}", policy.policy_id.0);
                    }
                }
            } else {
                let policies = store.list_enterprise_quorum_policies()?;
                if json {
                    println!("{}", serde_json::to_string(&policies)?);
                } else {
                    println!("Enterprise quorum policies: {}", policies.len());
                }
            }
        }
        EnterpriseQuorumCommands::Evaluate {
            policy,
            store_root,
            json,
        } => {
            let store = open_store(store_root)?;
            let file = std::fs::File::open(policy)?;
            let policy: EnterpriseQuorumPolicy = serde_json::from_reader(file)?;
            let policy = enterprise_quorum::normalize_enterprise_quorum_policy(policy)?;
            let evaluation = enterprise_quorum::evaluate_quorum_decision(&policy, &policy.members)?;
            let output = serde_json::json!({
                "policy_id": policy.policy_id.0,
                "authority_policy_id": policy.enterprise_authority_policy_id.0,
                "threshold": policy.threshold.0,
                "evaluation": evaluation,
                "store_root": store.root_path(),
            });
            if json {
                println!("{}", serde_json::to_string(&output)?);
            } else {
                println!("Enterprise quorum policy validated: {}", policy.policy_id.0);
            }
        }
    }
    Ok(())
}

fn handle_enterprise_provider(sub: EnterpriseProviderCommands) -> Result<()> {
    match sub {
        EnterpriseProviderCommands::Import {
            policy,
            store_root,
            json,
        } => {
            let store = open_store(store_root)?;
            let file = std::fs::File::open(policy)?;
            let policy: EnterpriseProviderPolicy = serde_json::from_reader(file)?;
            let policy = enterprise_provider::normalize_enterprise_provider_policy(policy);
            store.save_enterprise_provider_policy(&policy)?;
            if json {
                println!("{}", serde_json::to_string(&policy)?);
            } else {
                println!(
                    "Enterprise provider policy imported: {}",
                    policy.policy_id.0
                );
            }
        }
        EnterpriseProviderCommands::ImportAttestation {
            attestation,
            store_root,
            json,
        } => {
            let store = open_store(store_root)?;
            let file = std::fs::File::open(attestation)?;
            let attestation: EnterpriseProviderAttestationSummary = serde_json::from_reader(file)?;
            let attestation =
                enterprise_provider::normalize_enterprise_provider_attestation(attestation);
            store.save_enterprise_provider_attestation(&attestation)?;
            if json {
                println!("{}", serde_json::to_string(&attestation)?);
            } else {
                println!(
                    "Enterprise provider attestation imported: {}",
                    attestation.attestation_id.0
                );
            }
        }
        EnterpriseProviderCommands::Status {
            enterprise_provider,
            enterprise_provider_attestation,
            store_root,
            json,
        } => {
            let store = open_store(store_root)?;
            if let Some(ref provider_id) = enterprise_provider {
                if let Some(policy) = store.load_enterprise_provider_policy(&provider_id)? {
                    if json {
                        println!("{}", serde_json::to_string(&policy)?);
                    } else {
                        println!("Enterprise provider policy: {}", policy.policy_id.0);
                        println!(
                            "Hash: {}",
                            policy
                                .policy_hash
                                .as_ref()
                                .map(|hash| hash.0.as_str())
                                .unwrap_or("")
                        );
                    }
                }
            }
            if let Some(ref attestation_id) = enterprise_provider_attestation {
                if let Some(attestation) =
                    store.load_enterprise_provider_attestation(&attestation_id)?
                {
                    if json {
                        println!("{}", serde_json::to_string(&attestation)?);
                    } else {
                        println!(
                            "Enterprise provider attestation: {}",
                            attestation.attestation_id.0
                        );
                        println!(
                            "Hash: {}",
                            attestation
                                .attestation_hash
                                .as_ref()
                                .map(|hash| hash.0.as_str())
                                .unwrap_or("")
                        );
                    }
                }
            }
            if enterprise_provider.is_none() && enterprise_provider_attestation.is_none() {
                let policies = store.list_enterprise_provider_policies()?;
                if json {
                    println!("{}", serde_json::to_string(&policies)?);
                } else {
                    println!("Enterprise provider policies: {}", policies.len());
                }
            }
        }
        EnterpriseProviderCommands::Evaluate {
            enterprise_provider,
            operation,
            volume,
            store_root,
            json,
        } => {
            let store = open_store(store_root)?;
            let provider_policy = store
                .load_enterprise_provider_policy(&enterprise_provider)?
                .ok_or_else(|| anyhow!("enterprise provider policy not found"))?;
            let attestation = store
                .find_valid_enterprise_provider_attestation_summary(&enterprise_provider, None)?
                .ok_or_else(|| anyhow!("enterprise provider attestation not found"))?;
            let authority_policy = store.load_enterprise_authority_policy(
                &provider_policy.enterprise_authority_policy_id.0,
            )?;
            let request = EnterpriseRecoveryRequest {
                request_id: enterprise_recovery::EnterpriseRecoveryRequestId(format!(
                    "ERQ-EP-{}",
                    BindingStore::volume_hash(&volume)
                )),
                operation_kind: parse_operation_kind(&operation)?,
                volume_hash: BindingStore::volume_hash(&volume),
                domain_recovery_request_id: format!(
                    "DR-REQ-{}",
                    BindingStore::volume_hash(&volume)
                ),
                domain_recovery_package_id: format!(
                    "DR-PKG-{}",
                    BindingStore::volume_hash(&volume)
                ),
                domain_recovery_decision_id: format!(
                    "DR-DEC-{}",
                    BindingStore::volume_hash(&volume)
                ),
                enterprise_authority_policy_id: provider_policy
                    .enterprise_authority_policy_id
                    .clone(),
                enterprise_quorum_policy_id: enterprise_quorum::EnterpriseQuorumPolicyId(format!(
                    "EQ-EP-{}",
                    provider_policy.policy_id.0
                )),
                enterprise_provider_id: Some(provider_policy.policy_id.0.clone()),
                provider_attestation_hash: attestation
                    .attestation_hash
                    .as_ref()
                    .map(|hash| hash.0.clone()),
                source_kind:
                    enterprise_recovery::EnterpriseRecoverySourceKind::ImportedOfflineDecision,
                created_at: attestation.created_at,
            };
            let enforcer = EnterpriseRecoveryEnforcer::new(&store);
            let decision = enforcer.check_enterprise_provider(
                &request,
                None,
                Some(&provider_policy),
                Some(&attestation),
                authority_policy.as_ref(),
            )?;
            let required_capability =
                enterprise_provider::required_provider_capability_for_operation(
                    parse_operation_kind(&operation)?,
                );
            let output = serde_json::json!({
                "provider_id": provider_policy.policy_id.0,
                "attestation_id": attestation.attestation_id.0,
                "required_capability": required_capability,
                "decision": decision,
                "operation": operation,
                "volume": volume,
            });
            if json {
                println!("{}", serde_json::to_string(&output)?);
            } else {
                println!("Enterprise provider evaluation: {:?}", decision);
            }
        }
    }
    Ok(())
}

fn parse_operation_kind(name: &str) -> Result<OperationKind> {
    match name.to_ascii_lowercase().as_str() {
        "recover" => Ok(OperationKind::Recover),
        "rebind" => Ok(OperationKind::Rebind),
        "export" => Ok(OperationKind::Export),
        "bind" => Ok(OperationKind::Bind),
        "unlock" => Ok(OperationKind::Unlock),
        "lock" => Ok(OperationKind::Lock),
        "eject" => Ok(OperationKind::Eject),
        "status" => Ok(OperationKind::Status),
        "audit" => Ok(OperationKind::Audit),
        _ => Err(anyhow!("unsupported operation kind")),
    }
}

fn default_enterprise_policy_id(prefix: &str, volume: &str) -> String {
    format!("{}-{}", prefix, BindingStore::volume_hash(volume))
}

fn build_enterprise_recovery_request(
    operation: String,
    volume: String,
    domain_recovery_request_id: Option<String>,
    domain_recovery_package_id: Option<String>,
    domain_recovery_decision_id: Option<String>,
    enterprise_authority_policy_id: Option<String>,
    enterprise_quorum_policy_id: Option<String>,
    store: &BindingStore,
) -> Result<EnterpriseRecoveryRequest> {
    let op = parse_operation_kind(&operation)?;
    let vol_hash = BindingStore::volume_hash(&volume);
    let authority_policy_id = enterprise_authority_policy_id.unwrap_or_else(|| {
        store
            .list_enterprise_authority_policies()
            .ok()
            .and_then(|mut policies| policies.pop().map(|p| p.policy_id.0))
            .unwrap_or_else(|| default_enterprise_policy_id("EA", &volume))
    });
    let quorum_policy_id = enterprise_quorum_policy_id.unwrap_or_else(|| {
        store
            .list_enterprise_quorum_policies()
            .ok()
            .and_then(|mut policies| policies.pop().map(|p| p.policy_id.0))
            .unwrap_or_else(|| default_enterprise_policy_id("EQ", &volume))
    });
    let provider_policy_id = store
        .list_enterprise_provider_policies()
        .ok()
        .and_then(|policies| policies.into_iter().max_by_key(|policy| policy.created_at))
        .map(|policy| policy.policy_id.0);
    let provider_attestation_hash = provider_policy_id.as_ref().and_then(|provider_id| {
        store
            .find_valid_enterprise_provider_attestation_summary(provider_id, None)
            .ok()
            .flatten()
            .and_then(|attestation| attestation.attestation_hash.map(|hash| hash.0))
    });
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    Ok(EnterpriseRecoveryRequest {
        request_id: enterprise_recovery::EnterpriseRecoveryRequestId(format!(
            "ERQ-{}-{}",
            op as u32, now
        )),
        operation_kind: op,
        volume_hash: vol_hash.clone(),
        domain_recovery_request_id: domain_recovery_request_id
            .unwrap_or_else(|| format!("DR-REQ-{}", vol_hash)),
        domain_recovery_package_id: domain_recovery_package_id
            .unwrap_or_else(|| format!("DR-PKG-{}", vol_hash)),
        domain_recovery_decision_id: domain_recovery_decision_id
            .unwrap_or_else(|| format!("DR-DEC-{}", vol_hash)),
        enterprise_authority_policy_id: enterprise_authority::EnterpriseAuthorityPolicyId(
            authority_policy_id,
        ),
        enterprise_quorum_policy_id: enterprise_quorum::EnterpriseQuorumPolicyId(quorum_policy_id),
        enterprise_provider_id: provider_policy_id,
        provider_attestation_hash,
        source_kind: EnterpriseRecoverySourceKind::ImportedOfflineDecision,
        created_at: now,
    })
}

fn handle_enterprise_recovery(sub: EnterpriseRecoveryCommands) -> Result<()> {
    match sub {
        EnterpriseRecoveryCommands::Request {
            operation,
            volume,
            domain_recovery_request_id,
            domain_recovery_package_id,
            domain_recovery_decision_id,
            enterprise_authority_policy_id,
            enterprise_quorum_policy_id,
            store_root,
            json,
        } => {
            let store = open_store(store_root)?;
            let request = build_enterprise_recovery_request(
                operation,
                volume,
                domain_recovery_request_id,
                domain_recovery_package_id,
                domain_recovery_decision_id,
                enterprise_authority_policy_id,
                enterprise_quorum_policy_id,
                &store,
            )?;
            store.save_enterprise_recovery_request(&request)?;
            if json {
                println!("{}", serde_json::to_string(&request)?);
            } else {
                println!("Enterprise recovery request: {}", request.request_id.0);
            }
        }
        EnterpriseRecoveryCommands::ImportDecision {
            decision,
            store_root,
            json,
        } => {
            let store = open_store(store_root)?;
            let file = std::fs::File::open(decision)?;
            let mut decision: EnterpriseRecoveryDecision = serde_json::from_reader(file)?;
            decision.decision_hash =
                enterprise_recovery::compute_enterprise_recovery_decision_hash(&decision);
            store.save_enterprise_recovery_decision(&decision)?;
            if json {
                println!("{}", serde_json::to_string(&decision)?);
            } else {
                println!(
                    "Enterprise recovery decision imported: {}",
                    decision.decision_id.0
                );
            }
        }
        EnterpriseRecoveryCommands::DevApprove {
            request_id,
            store_root,
            json,
        } => {
            if std::env::var("TUFF_CSE_WINFS_ALLOW_DEV_ENTERPRISE_RECOVERY")
                .ok()
                .as_deref()
                != Some("1")
            {
                return Err(anyhow!(
                    "TUFF_CSE_WINFS_ALLOW_DEV_ENTERPRISE_RECOVERY=1 is required"
                ));
            }
            let store = open_store(store_root)?;
            let request = store
                .load_enterprise_recovery_request(&request_id)?
                .ok_or_else(|| anyhow!("enterprise recovery request not found"))?;
            let authority_policy = store
                .load_enterprise_authority_policy(&request.enterprise_authority_policy_id.0)?
                .ok_or_else(|| anyhow!("enterprise authority policy not found"))?;
            let quorum_policy = store
                .load_enterprise_quorum_policy(&request.enterprise_quorum_policy_id.0)?
                .ok_or_else(|| anyhow!("enterprise quorum policy not found"))?;
            let approvers = quorum_policy
                .members
                .iter()
                .take(quorum_policy.threshold.0 as usize)
                .cloned()
                .collect::<Vec<_>>();
            let mut decision = enterprise_recovery::build_enterprise_recovery_decision(
                enterprise_recovery::EnterpriseRecoveryDecisionId(format!(
                    "ERD-{}",
                    request.request_id.0
                )),
                request.operation_kind,
                request.volume_hash.clone(),
                request.domain_recovery_request_id.clone(),
                request.domain_recovery_package_id.clone(),
                request.domain_recovery_decision_id.clone(),
                authority_policy.policy_id,
                quorum_policy.policy_id,
                approvers,
                request.created_at,
                request.created_at + 3600,
                EnterpriseRecoveryStatus::Approved,
                EnterpriseRecoverySourceKind::DevGeneratedDecision,
            );
            decision.enterprise_provider_id = request.enterprise_provider_id.clone();
            decision.provider_attestation_hash = request.provider_attestation_hash.clone();
            decision.decision_hash =
                enterprise_recovery::compute_enterprise_recovery_decision_hash(&decision);
            store.save_enterprise_recovery_decision(&decision)?;
            if json {
                println!("{}", serde_json::to_string(&decision)?);
            } else {
                println!(
                    "Enterprise recovery decision approved: {}",
                    decision.decision_id.0
                );
            }
        }
        EnterpriseRecoveryCommands::DevDeny {
            request_id,
            store_root,
            json,
        } => {
            if std::env::var("TUFF_CSE_WINFS_ALLOW_DEV_ENTERPRISE_RECOVERY")
                .ok()
                .as_deref()
                != Some("1")
            {
                return Err(anyhow!(
                    "TUFF_CSE_WINFS_ALLOW_DEV_ENTERPRISE_RECOVERY=1 is required"
                ));
            }
            let store = open_store(store_root)?;
            let request = store
                .load_enterprise_recovery_request(&request_id)?
                .ok_or_else(|| anyhow!("enterprise recovery request not found"))?;
            let mut decision = enterprise_recovery::build_enterprise_recovery_decision(
                enterprise_recovery::EnterpriseRecoveryDecisionId(format!(
                    "ERD-{}",
                    request.request_id.0
                )),
                request.operation_kind,
                request.volume_hash.clone(),
                request.domain_recovery_request_id.clone(),
                request.domain_recovery_package_id.clone(),
                request.domain_recovery_decision_id.clone(),
                request.enterprise_authority_policy_id.clone(),
                request.enterprise_quorum_policy_id.clone(),
                Vec::new(),
                request.created_at,
                request.created_at + 3600,
                EnterpriseRecoveryStatus::Denied,
                EnterpriseRecoverySourceKind::DevGeneratedDecision,
            );
            decision.enterprise_provider_id = request.enterprise_provider_id.clone();
            decision.provider_attestation_hash = request.provider_attestation_hash.clone();
            decision.decision_hash =
                enterprise_recovery::compute_enterprise_recovery_decision_hash(&decision);
            store.save_enterprise_recovery_decision(&decision)?;
            if json {
                println!("{}", serde_json::to_string(&decision)?);
            } else {
                println!(
                    "Enterprise recovery decision denied: {}",
                    decision.decision_id.0
                );
            }
        }
        EnterpriseRecoveryCommands::Status {
            enterprise_recovery_decision,
            request_id,
            store_root,
            json,
        } => {
            let store = open_store(store_root)?;
            if let Some(decision_id) = enterprise_recovery_decision {
                if let Some(decision) = store.load_enterprise_recovery_decision(&decision_id)? {
                    if json {
                        println!("{}", serde_json::to_string(&decision)?);
                    } else {
                        println!("Enterprise recovery decision: {}", decision.decision_id.0);
                        println!("Status: {:?}", decision.status);
                    }
                }
            } else if let Some(request_id) = request_id {
                if let Some(request) = store.load_enterprise_recovery_request(&request_id)? {
                    if json {
                        println!("{}", serde_json::to_string(&request)?);
                    } else {
                        println!("Enterprise recovery request: {}", request.request_id.0);
                    }
                }
            }
        }
        EnterpriseRecoveryCommands::Evaluate {
            operation,
            volume,
            enterprise_recovery_decision,
            store_root,
            json,
        } => {
            let store = open_store(store_root)?;
            let decision = store
                .load_enterprise_recovery_decision(&enterprise_recovery_decision)?
                .ok_or_else(|| anyhow!("enterprise recovery decision not found"))?;
            let request = EnterpriseRecoveryRequest {
                request_id: enterprise_recovery::EnterpriseRecoveryRequestId(format!(
                    "ERQ-{}",
                    decision.decision_id.0
                )),
                operation_kind: parse_operation_kind(&operation)?,
                volume_hash: BindingStore::volume_hash(&volume),
                domain_recovery_request_id: decision.domain_recovery_request_id.clone(),
                domain_recovery_package_id: decision.domain_recovery_package_id.clone(),
                domain_recovery_decision_id: decision.domain_recovery_decision_id.clone(),
                enterprise_authority_policy_id: decision.enterprise_authority_policy_id.clone(),
                enterprise_quorum_policy_id: decision.enterprise_quorum_policy_id.clone(),
                enterprise_provider_id: decision.enterprise_provider_id.clone(),
                provider_attestation_hash: decision.provider_attestation_hash.clone(),
                source_kind: decision.source_kind,
                created_at: decision.valid_from,
            };
            let authority_policy = store
                .load_enterprise_authority_policy(&request.enterprise_authority_policy_id.0)?
                .ok_or_else(|| anyhow!("enterprise authority policy not found"))?;
            let quorum_policy = store
                .load_enterprise_quorum_policy(&request.enterprise_quorum_policy_id.0)?
                .ok_or_else(|| anyhow!("enterprise quorum policy not found"))?;
            let enforcer = EnterpriseRecoveryEnforcer::new(&store);
            let enforcement = enforcer.check_enterprise_recovery(
                &request,
                Some(&decision),
                Some(&authority_policy),
                Some(&quorum_policy),
            )?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&serde_json::json!({
                        "decision_id": decision.decision_id.0,
                        "enforcement": enforcement,
                        "status": decision.status,
                    }))?
                );
            } else {
                println!("Enterprise recovery evaluation: {:?}", enforcement);
            }
        }
    }
    Ok(())
}

fn handle_bind_plan_only(
    volume: String,
    binding_policy_path: Option<PathBuf>,
    json: bool,
) -> Result<()> {
    let policy = match binding_policy_path {
        Some(p) => binding_policy::load_binding_policy(p)?,
        None => binding_policy::default_single_host_local_policy(),
    };

    let input = BindingInputSnapshot {
        raw_tpm_identity: Some("MOCK_TPM_EK_PUB".to_string()),
        raw_host_id: Some("MOCK_HOST_UUID".to_string()),
        raw_device_uuid: Some("MOCK_DEVICE_UUID".to_string()),
        raw_volume_serial: Some("MOCK_VOL_SERIAL".to_string()),
        raw_policy_material: Some("MOCK_POLICY_MATERIAL".to_string()),
        installer_entropy_bytes: Some(vec![1, 2, 3, 4]),
    };

    let global_salt = "SYSTEM_UNIQUE_SALT_STUB";
    let descriptor = binding::build_binding_descriptor(&policy, &input, &volume, global_salt)?;
    let plan = key_material::build_key_derivation_plan(&descriptor, &policy)?;

    if json {
        let out = serde_json::json!({
            "descriptor": descriptor,
            "plan": plan
        });
        println!("{}", serde_json::to_string(&out)?);
    } else {
        println!("--- Binding Descriptor ---");
        println!("Descriptor ID: {}", descriptor.descriptor_id);
        println!("Volume: {}", descriptor.volume);
        println!("Fingerprints:");
        for fp in descriptor.material_fingerprints {
            println!("  - {:?}: {}", fp.kind, fp.fingerprint);
        }
        println!("--- Key Derivation Plan ---");
        println!("Plan ID: {}", plan.plan_id);
        println!("Algorithm Suite: {}", plan.algorithm_suite);
    }

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status {
            volume,
            policy,
            json,
            recover_stale,
            store_root,
        } => {
            // ...
            handle_operation(
                OperationKind::Status,
                volume,
                policy,
                None,
                None,
                store_root,
            )?;
        }
        Commands::Bind {
            volume,
            policy,
            binding_policy,
            plan_only,
            json,
            store_root,
        } => {
            if plan_only {
                handle_bind_plan_only(volume, binding_policy, json)?;
            } else {
                handle_operation(OperationKind::Bind, volume, policy, None, None, store_root)?;
            }
        }
        Commands::Unlock {
            volume,
            policy,
            local_policy,
            approval_id,
            store_root,
        } => {
            handle_operation(
                OperationKind::Unlock,
                volume,
                policy,
                local_policy,
                approval_id,
                store_root,
            )?;
        }
        Commands::Lock {
            volume,
            policy,
            store_root,
        } => {
            handle_operation(OperationKind::Lock, volume, policy, None, None, store_root)?;
        }
        Commands::Eject {
            volume,
            policy,
            local_policy,
            approval_id,
            store_root,
        } => {
            handle_operation(
                OperationKind::Eject,
                volume,
                policy,
                local_policy,
                approval_id,
                store_root,
            )?;
        }
        Commands::Audit {
            volume,
            policy,
            json,
            store_root,
        } => {
            handle_audit(volume, policy, json, store_root)?;
        }
        Commands::Export {
            volume,
            recipient,
            recipient_key_fp,
            export_policy,
            local_policy,
            approval_id,
            manifest_out,
            store_root,
            json,
            require_manual_confirmation,
            complete_plan,
            cancel_plan,
            confirm,
            reason,
        } => {
            handle_export(
                volume,
                recipient,
                recipient_key_fp,
                export_policy,
                local_policy,
                approval_id,
                manifest_out,
                store_root,
                json,
                require_manual_confirmation,
                complete_plan,
                cancel_plan,
                confirm,
                reason,
            )?;
        }
        Commands::Rebind {
            volume,
            new_host_fp,
            new_host_label,
            reason,
            rebind_policy,
            local_policy,
            approval_id,
            manifest_out,
            store_root,
            json,
            complete_plan,
            cancel_plan,
            confirm,
        } => {
            handle_rebind(
                volume,
                new_host_fp,
                new_host_label,
                reason,
                rebind_policy,
                local_policy,
                approval_id,
                manifest_out,
                store_root,
                json,
                complete_plan,
                cancel_plan,
                confirm,
            )?;
        }
        Commands::Recover {
            volume,
            recovery_key_fp,
            reason,
            recovery_policy,
            local_policy,
            approval_id,
            plan_out,
            store_root,
            json,
            complete_plan,
            cancel_plan,
            confirm,
        } => {
            handle_recover(
                volume,
                recovery_key_fp,
                reason,
                recovery_policy,
                local_policy,
                approval_id,
                plan_out,
                store_root,
                json,
                complete_plan,
                cancel_plan,
                confirm,
            )?;
        }
        Commands::Approval { sub } => handle_approval(sub)?,
        Commands::EnterpriseAuthority { sub } => handle_enterprise_authority(sub)?,
        Commands::EnterpriseQuorum { sub } => handle_enterprise_quorum(sub)?,
        Commands::EnterpriseProvider { sub } => handle_enterprise_provider(sub)?,
        Commands::EnterpriseRecovery { sub } => handle_enterprise_recovery(sub)?,
        Commands::AuditSigning { sub } => match &sub {
            AuditSigningCommands::Init { volume, store_root } => {
                handle_audit_signing(&sub, volume.clone(), store_root.clone())
            }
            AuditSigningCommands::Status { volume, store_root } => {
                handle_audit_signing(&sub, volume.clone(), store_root.clone())
            }
            AuditSigningCommands::Verify { volume, store_root } => {
                handle_audit_signing(&sub, volume.clone(), store_root.clone())
            }
        }?,
    }

    Ok(())
}
