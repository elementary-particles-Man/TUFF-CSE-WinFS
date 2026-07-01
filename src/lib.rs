pub mod approval_enforcement;
pub mod audit_chain;
pub mod audit_signing;
pub mod binding;
pub mod binding_policy;
pub mod binding_store;
pub mod completion;
pub mod domain_approval;
pub mod domain_approval_enforcement;
pub mod domain_policy;
pub mod domain_principal;
pub mod domain_recovery;
pub mod domain_recovery_enforcement;
pub mod driver;
pub mod enterprise_authority;
pub mod enterprise_provider;
pub mod enterprise_provider_enforcement;
pub mod enterprise_provider_lifecycle;
pub mod enterprise_provider_lifecycle_enforcement;
pub mod enterprise_quorum;
pub mod enterprise_recovery;
pub mod enterprise_recovery_enforcement;
pub mod export_manifest;
pub mod export_policy;
pub mod group_policy_mapping;
pub mod install;
pub mod key_material;
pub mod layout;
pub mod local_approval;
pub mod local_policy;
pub mod local_principal;
pub mod managed_policy;
pub mod manual_flow;
pub mod offline_policy_snapshot;
pub mod operation_journal;
pub mod operations;
pub mod plan_state;
pub mod policy;
pub mod rebind_model;
pub mod recovery;
pub mod recovery_key;
pub mod runtime_session;
pub mod secure_runtime;
pub mod uninstall;
pub mod verify;
pub mod volume;
pub mod volume_state;

pub const V1_RC_PHASE: &str = "P6Z";
pub const V1_RC_BASE_COMMIT: &str = "d8c8f3b90ba9f57d12c498b4f8ace31c1420740a";
pub const V1_RC_COMPLETED_PHASES: &[&str] = &[
    "P1A", "P1B", "P1C", "P2A", "P2B", "P2C", "P3A", "P3B", "P3C", "P4A", "P4B", "P4C", "P5A",
    "P5B", "P5C", "P6A", "P6B", "P6C",
];
pub const V1_RC_RESERVED_LIVE_INTEGRATIONS: &[&str] = &[
    "live KMS",
    "live HSM",
    "Cloud KMS SDK",
    "PKCS#11 live connection",
    "key recovery",
    "CSE encrypted I/O",
    "TPM real API",
    "driver I/O",
];
pub const V1_RC_FORBIDDEN_BOUNDARIES: &[&str] = &[
    "ReFS",
    "RAW",
    "network",
    "system",
    "pagefile",
    "crashdump",
    "hibernation",
    "EFI",
    "MSR",
    "Recovery",
    "OEM",
    "BitLocker conflict",
];
pub const P7A_PUBLIC_INSTALLER_PHASE: &str = "P7A";
pub const P7A_PUBLIC_INSTALLER_BOUNDARY: &str = "Public Windows Installer Package Boundary";
pub const P7A_PUBLIC_INSTALLER_ARTIFACTS: &[&str] = &[
    "portable zip artifact",
    "WiX scaffold",
    "README-FIRST",
    "manifest",
];
pub const P7A_PUBLIC_INSTALLER_RESERVED_ACTIONS: &[&str] = &[
    "driver install",
    "service install",
    "code signing",
    "CSE crypto I/O",
    "TPM live API",
    "KMS/HSM live integration",
];
pub const P7B_PUBLIC_RELEASE_PHASE: &str = "P7B";
pub const P7B_PUBLIC_RELEASE_BOUNDARY: &str =
    "Public Release Artifact Checksum Draft Release Boundary";
pub const P7B_PUBLIC_RELEASE_ARTIFACTS: &[&str] = &[
    "portable zip release artifact",
    "release manifest",
    "SHA256 checksum report",
    "draft release notes",
];
pub const P7B_PUBLIC_RELEASE_RESERVED_ACTIONS: &[&str] = &[
    "GitHub Release publish",
    "driver install",
    "service install",
    "code signing",
    "CSE crypto I/O",
    "TPM live API",
    "KMS/HSM live integration",
];
pub const P7C_DRAFT_RELEASE_PHASE: &str = "P7C";
pub const P7C_DRAFT_RELEASE_BOUNDARY: &str = "RC Tag and Draft GitHub Release Asset Boundary";
pub const P7C_DRAFT_RELEASE_ASSETS: &[&str] = &[
    "public windows installer zip",
    "release manifest",
    "SHA256 checksum report",
    "draft release notes",
];
pub const P7C_DRAFT_RELEASE_RESERVED_ACTIONS: &[&str] = &[
    "GitHub Release publish",
    "tag overwrite",
    "force tag",
    "driver install",
    "service install",
    "code signing",
    "CSE crypto I/O",
    "TPM live API",
    "KMS/HSM live integration",
];
