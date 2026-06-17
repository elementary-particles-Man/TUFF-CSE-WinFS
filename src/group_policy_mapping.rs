use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::domain_principal::DomainGroupFingerprint;
use crate::domain_policy::{DomainOperationPolicy, DomainPolicyEffect};
use crate::operations::OperationKind;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupPolicyMapping {
    pub mapping_id: String,
    pub domain_policy_id: String,
    pub group_mappings: HashMap<DomainGroupFingerprint, HashMap<OperationKind, DomainOperationPolicy>>,
    pub created_at: u64,
}

impl GroupPolicyMapping {
    pub fn resolve_group_policy_effect(
        &self,
        group_fingerprint: &DomainGroupFingerprint,
        operation: OperationKind,
    ) -> Option<DomainOperationPolicy> {
        self.group_mappings
            .get(group_fingerprint)
            .and_then(|op_map| op_map.get(&operation))
            .cloned()
    }
}
