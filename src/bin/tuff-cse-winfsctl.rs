use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tuff_cse_winfs::audit_chain;
use tuff_cse_winfs::audit_signing::{self, AuditSigner, DevAuditSigner};
use tuff_cse_winfs::binding::{self, BindingInputSnapshot};
use tuff_cse_winfs::binding_policy;
use tuff_cse_winfs::binding_store::BindingStore;
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
