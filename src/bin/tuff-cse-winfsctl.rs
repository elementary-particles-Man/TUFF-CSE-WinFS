use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tuff_cse_winfs::layout;
use tuff_cse_winfs::managed_policy::{self, ManagedPolicy};
use tuff_cse_winfs::operation_journal::{self, OperationJournalRecord};
use tuff_cse_winfs::operations::{self, OperationKind, OperationRequest};
use tuff_cse_winfs::volume_state::VolumeRuntimeState;

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
    },
    /// Unlock a volume for in-place usage
    Unlock {
        #[arg(short, long)]
        volume: String,
        #[arg(short, long)]
        policy: Option<PathBuf>,
    },
    /// Lock a currently used volume
    Lock {
        #[arg(short, long)]
        volume: String,
        #[arg(short, long)]
        policy: Option<PathBuf>,
    },
    /// Safely eject a volume
    Eject {
        #[arg(short, long)]
        volume: String,
        #[arg(short, long)]
        policy: Option<PathBuf>,
    },
    /// Read the operation journal for a volume
    Audit {
        #[arg(short, long)]
        volume: String,
        #[arg(short, long)]
        policy: Option<PathBuf>,
        #[arg(short, long)]
        json: bool,
    },
    /// (Reserved) Reseal for external transfer
    Export {
        #[arg(short, long)]
        volume: String,
    },
    /// (Reserved) Transfer ownership boundary
    Rebind {
        #[arg(short, long)]
        volume: String,
    },
    /// (Reserved) Recover a volume
    Recover {
        #[arg(short, long)]
        volume: String,
    },
}

fn load_policy_or_default(path: Option<PathBuf>) -> Result<ManagedPolicy> {
    match path {
        Some(p) => managed_policy::load_managed_policy(p),
        None => Ok(managed_policy::default_local_policy()),
    }
}

// In P1C, we mock the state fetching based on a dummy volume hash
fn mock_get_state(_volume: &str) -> VolumeRuntimeState {
    VolumeRuntimeState::new() // Always returns Unregistered for the skeleton
}

fn handle_operation(
    kind: OperationKind,
    volume: String,
    policy_path: Option<PathBuf>,
) -> Result<()> {
    let policy = load_policy_or_default(policy_path)?;
    let mut state = mock_get_state(&volume); // Skeleton state

    let request = OperationRequest {
        operation_id: format!(
            "OP-{}-{}",
            kind as u32,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        ),
        kind,
        volume: volume.clone(),
        requested_by: "Admin".to_string(), // Mock
        policy_id: policy.policy_id.clone(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    let result = operations::execute_operation(request.clone(), &policy, &mut state)?;

    println!("Operation: {:?}", kind);
    println!("Status: {:?}", result.status);
    println!("Reason: {}", result.reason);
    println!(
        "Transition: {:?} -> {:?}",
        result.previous_state, result.next_state
    );

    // Write to journal
    let root = layout::management_root();
    // Use a dummy hash for the skeleton
    let dummy_hash = format!("{:x}", md5::compute(volume.as_bytes()));

    let record = OperationJournalRecord {
        operation_id: result.operation_id,
        kind: result.kind,
        volume: result.volume,
        requested_by: request.requested_by,
        result_status: result.status,
        reason: result.reason,
        timestamp: result.timestamp,
    };

    // Ignore errors for journal appending in this skeleton if layout doesn't exist
    let _ = operation_journal::append_journal_record(&root, &dummy_hash, &record);

    Ok(())
}

fn handle_audit(volume: String, policy_path: Option<PathBuf>, json: bool) -> Result<()> {
    let policy = load_policy_or_default(policy_path)?;
    if !policy.allow_audit {
        println!("Audit is denied by policy.");
        return Ok(());
    }

    let root = layout::management_root();
    let dummy_hash = format!("{:x}", md5::compute(volume.as_bytes()));

    match operation_journal::read_journal_records(&root, &dummy_hash) {
        Ok(records) => {
            if json {
                for record in records {
                    println!("{}", serde_json::to_string(&record)?);
                }
            } else {
                println!("Audit Journal for Volume: {}", volume);
                for record in records {
                    println!(
                        "[{}] OP: {:?}, Status: {:?}, Reason: {}",
                        record.timestamp, record.kind, record.result_status, record.reason
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

    // Record the audit operation itself
    if policy.audit_status_operations {
        let request = OperationRequest {
            operation_id: format!(
                "OP-AUDIT-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            ),
            kind: OperationKind::Audit,
            volume: volume.clone(),
            requested_by: "Admin".to_string(),
            policy_id: policy.policy_id.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        let mut state = mock_get_state(&volume);
        if let Ok(result) = operations::execute_operation(request.clone(), &policy, &mut state) {
            let record = OperationJournalRecord {
                operation_id: result.operation_id,
                kind: result.kind,
                volume: result.volume,
                requested_by: request.requested_by,
                result_status: result.status,
                reason: result.reason,
                timestamp: result.timestamp,
            };
            let _ = operation_journal::append_journal_record(&root, &dummy_hash, &record);
        }
    }

    Ok(())
}

use tuff_cse_winfs::binding::{self, BindingInputSnapshot};
use tuff_cse_winfs::binding_policy;
use tuff_cse_winfs::key_material;

fn handle_bind_plan_only(
    volume: String,
    binding_policy_path: Option<PathBuf>,
    json: bool,
) -> Result<()> {
    let policy = match binding_policy_path {
        Some(p) => binding_policy::load_binding_policy(p)?,
        None => binding_policy::default_single_host_local_policy(),
    };

    // Mock input snapshot for P2A
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
        } => {
            if json {
                println!(
                    r#"{{"volume": "{}", "status": "Not Implemented in P1C Skeleton"}}"#,
                    volume
                );
            } else {
                handle_operation(OperationKind::Status, volume, policy)?;
            }
        }
        Commands::Bind {
            volume,
            policy,
            binding_policy,
            plan_only,
            json,
        } => {
            if plan_only {
                handle_bind_plan_only(volume, binding_policy, json)?;
            } else {
                handle_operation(OperationKind::Bind, volume, policy)?;
            }
        }
        Commands::Unlock { volume, policy } => {
            handle_operation(OperationKind::Unlock, volume, policy)?
        }
        Commands::Lock { volume, policy } => handle_operation(OperationKind::Lock, volume, policy)?,
        Commands::Eject { volume, policy } => {
            handle_operation(OperationKind::Eject, volume, policy)?
        }
        Commands::Audit {
            volume,
            policy,
            json,
        } => handle_audit(volume, policy, json)?,
        Commands::Export { volume } => {
            println!("Operation: Export on volume {}", volume);
            println!("Status: RESERVED");
            println!("Reason: RESERVED_NOT_IMPLEMENTED");
            println!("Note: Export is for resealing for external transfer, not for unlocking.");
        }
        Commands::Rebind { volume } => {
            println!("Operation: Rebind on volume {}", volume);
            println!("Status: RESERVED");
            println!("Reason: RESERVED_NOT_IMPLEMENTED");
            println!("Note: Rebind transfers ownership boundaries and is distinct from unlock/export/eject.");
        }
        Commands::Recover { volume } => {
            println!("Operation: Recover on volume {}", volume);
            println!("Status: RESERVED");
            println!("Reason: RESERVED_NOT_IMPLEMENTED");
        }
    }

    Ok(())
}
