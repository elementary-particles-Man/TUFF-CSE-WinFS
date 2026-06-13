use crate::binding::BindingDescriptor;
use crate::export_manifest::{ExportManifest, ExportPlan};
use crate::key_material::KeyDerivationPlan;
use crate::layout;
use crate::manual_flow::ManualFlowRecord;
use crate::rebind_model::{RebindManifest, RebindPlan};
use crate::recovery_key::{RecoveryKeyDescriptor, RecoveryPlan};
use crate::runtime_session::RuntimeSession;
use crate::volume_state::VolumeRuntimeState;
use anyhow::Result;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

pub struct BindingStore {
    root: PathBuf,
}

impl BindingStore {
    pub fn open_default() -> Result<Self> {
        let root = layout::management_root();
        Self::open_at(&root)
    }

    pub fn open_at(root: &Path) -> Result<Self> {
        let store = Self {
            root: root.to_path_buf(),
        };
        store.ensure_dirs()?;
        Ok(store)
    }

    pub fn root_path(&self) -> &Path {
        &self.root
    }

    fn ensure_dirs(&self) -> Result<()> {
        let dirs = [
            "META/bindings",
            "META/states",
            "META/exports",
            "META/rebind",
            "KEYS/plans",
            "KEYS/export-plans",
            "KEYS/recovery",
            "KEYS/recovery-plans",
            "KEYS/rebind-plans",
            "JRN/runtime",
            "JRN/manual",
            "JRN",
        ];
        for d in dirs {
            let path = self.root.join(d);
            if !path.exists() {
                fs::create_dir_all(&path)?;
            }
        }
        Ok(())
    }

    pub fn volume_hash(volume: &str) -> String {
        format!("{:x}", md5::compute(volume.as_bytes()))
    }

    pub fn save_binding_descriptor(&self, desc: &BindingDescriptor) -> Result<()> {
        let hash = Self::volume_hash(&desc.volume);
        let path = self
            .root
            .join(format!("META/bindings/{}.binding.json", hash));
        let file = File::create(&path)?;
        serde_json::to_writer_pretty(file, desc)?;
        Ok(())
    }

    pub fn load_binding_descriptor(&self, volume: &str) -> Result<Option<BindingDescriptor>> {
        let hash = Self::volume_hash(volume);
        let path = self
            .root
            .join(format!("META/bindings/{}.binding.json", hash));
        if !path.exists() {
            return Ok(None);
        }
        let file = File::open(&path)?;
        let desc = serde_json::from_reader(file)?;
        Ok(Some(desc))
    }

    pub fn save_key_derivation_plan(&self, volume: &str, plan: &KeyDerivationPlan) -> Result<()> {
        let hash = Self::volume_hash(volume);
        let path = self.root.join(format!("KEYS/plans/{}.plan.json", hash));
        let file = File::create(&path)?;
        serde_json::to_writer_pretty(file, plan)?;
        Ok(())
    }

    pub fn load_key_derivation_plan(&self, volume: &str) -> Result<Option<KeyDerivationPlan>> {
        let hash = Self::volume_hash(volume);
        let path = self.root.join(format!("KEYS/plans/{}.plan.json", hash));
        if !path.exists() {
            return Ok(None);
        }
        let file = File::open(&path)?;
        let plan = serde_json::from_reader(file)?;
        Ok(Some(plan))
    }

    pub fn save_volume_state(&self, volume: &str, state: &VolumeRuntimeState) -> Result<()> {
        let hash = Self::volume_hash(volume);
        let path = self.root.join(format!("META/states/{}.state.json", hash));
        let file = File::create(&path)?;
        serde_json::to_writer_pretty(file, state)?;
        Ok(())
    }

    pub fn load_volume_state(&self, volume: &str) -> Result<VolumeRuntimeState> {
        let hash = Self::volume_hash(volume);
        let path = self.root.join(format!("META/states/{}.state.json", hash));
        if !path.exists() {
            return Ok(VolumeRuntimeState::new());
        }
        let file = File::open(&path)?;
        let state = serde_json::from_reader(file)?;
        Ok(state)
    }

    pub fn save_runtime_session(&self, session: &RuntimeSession) -> Result<()> {
        let path = self
            .root
            .join(format!("JRN/runtime/{}.session.json", session.volume_hash));
        let file = File::create(&path)?;
        serde_json::to_writer_pretty(file, session)?;
        Ok(())
    }

    pub fn load_runtime_session(&self, volume_hash: &str) -> Result<Option<RuntimeSession>> {
        let path = self
            .root
            .join(format!("JRN/runtime/{}.session.json", volume_hash));
        if !path.exists() {
            return Ok(None);
        }
        let file = File::open(&path)?;
        let session = serde_json::from_reader(file)?;
        Ok(Some(session))
    }

    pub fn clear_runtime_session(&self, volume_hash: &str) -> Result<()> {
        let path = self
            .root
            .join(format!("JRN/runtime/{}.session.json", volume_hash));
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }

    pub fn save_export_manifest(&self, manifest: &ExportManifest) -> Result<()> {
        let path = self
            .root
            .join(format!("META/exports/{}.manifest.json", manifest.export_id));
        let file = File::create(&path)?;
        serde_json::to_writer_pretty(file, manifest)?;
        Ok(())
    }

    pub fn load_export_manifest(&self, export_id: &str) -> Result<Option<ExportManifest>> {
        let path = self
            .root
            .join(format!("META/exports/{}.manifest.json", export_id));
        if !path.exists() {
            return Ok(None);
        }
        let file = File::open(&path)?;
        let manifest = serde_json::from_reader(file)?;
        Ok(Some(manifest))
    }

    pub fn save_export_plan(&self, plan: &ExportPlan) -> Result<()> {
        let path = self
            .root
            .join(format!("KEYS/export-plans/{}.plan.json", plan.export_id));
        let file = File::create(&path)?;
        serde_json::to_writer_pretty(file, plan)?;
        Ok(())
    }

    pub fn load_export_plan(&self, export_id: &str) -> Result<Option<ExportPlan>> {
        let path = self
            .root
            .join(format!("KEYS/export-plans/{}.plan.json", export_id));
        if !path.exists() {
            return Ok(None);
        }
        let file = File::open(&path)?;
        let plan = serde_json::from_reader(file)?;
        Ok(Some(plan))
    }

    pub fn save_recovery_descriptor(&self, descriptor: &RecoveryKeyDescriptor) -> Result<()> {
        let path = self.root.join(format!(
            "KEYS/recovery/{}.recovery.json",
            descriptor.recovery_id
        ));
        let file = File::create(&path)?;
        serde_json::to_writer_pretty(file, descriptor)?;
        Ok(())
    }

    pub fn load_recovery_descriptor(
        &self,
        recovery_id: &str,
    ) -> Result<Option<RecoveryKeyDescriptor>> {
        let path = self
            .root
            .join(format!("KEYS/recovery/{}.recovery.json", recovery_id));
        if !path.exists() {
            return Ok(None);
        }
        let file = File::open(&path)?;
        let descriptor = serde_json::from_reader(file)?;
        Ok(Some(descriptor))
    }

    pub fn save_recovery_plan(&self, plan: &RecoveryPlan) -> Result<()> {
        let path = self.root.join(format!(
            "KEYS/recovery-plans/{}.plan.json",
            plan.recovery_plan_id
        ));
        let file = File::create(&path)?;
        serde_json::to_writer_pretty(file, plan)?;
        Ok(())
    }

    pub fn load_recovery_plan(&self, recovery_plan_id: &str) -> Result<Option<RecoveryPlan>> {
        let path = self.root.join(format!(
            "KEYS/recovery-plans/{}.plan.json",
            recovery_plan_id
        ));
        if !path.exists() {
            return Ok(None);
        }
        let file = File::open(&path)?;
        let plan = serde_json::from_reader(file)?;
        Ok(Some(plan))
    }

    pub fn save_rebind_plan(&self, plan: &RebindPlan) -> Result<()> {
        let path = self.root.join(format!(
            "KEYS/rebind-plans/{}.plan.json",
            plan.rebind_plan_id
        ));
        let file = File::create(&path)?;
        serde_json::to_writer_pretty(file, plan)?;
        Ok(())
    }

    pub fn load_rebind_plan(&self, rebind_plan_id: &str) -> Result<Option<RebindPlan>> {
        let path = self
            .root
            .join(format!("KEYS/rebind-plans/{}.plan.json", rebind_plan_id));
        if !path.exists() {
            return Ok(None);
        }
        let file = File::open(&path)?;
        let plan = serde_json::from_reader(file)?;
        Ok(Some(plan))
    }

    pub fn save_rebind_manifest(&self, manifest: &RebindManifest) -> Result<()> {
        let path = self
            .root
            .join(format!("META/rebind/{}.manifest.json", manifest.rebind_id));
        let file = File::create(&path)?;
        serde_json::to_writer_pretty(file, manifest)?;
        Ok(())
    }

    pub fn load_rebind_manifest(&self, rebind_id: &str) -> Result<Option<RebindManifest>> {
        let path = self
            .root
            .join(format!("META/rebind/{}.manifest.json", rebind_id));
        if !path.exists() {
            return Ok(None);
        }
        let file = File::open(&path)?;
        let manifest = serde_json::from_reader(file)?;
        Ok(Some(manifest))
    }

    pub fn save_manual_flow_record(&self, record: &ManualFlowRecord) -> Result<()> {
        let path = self
            .root
            .join(format!("JRN/manual/{}.manual.json", record.manual_flow_id));
        let file = File::create(&path)?;
        serde_json::to_writer_pretty(file, record)?;
        Ok(())
    }

    pub fn load_manual_flow_record(
        &self,
        manual_flow_id: &str,
    ) -> Result<Option<ManualFlowRecord>> {
        let path = self
            .root
            .join(format!("JRN/manual/{}.manual.json", manual_flow_id));
        if !path.exists() {
            return Ok(None);
        }
        let file = File::open(&path)?;
        let record = serde_json::from_reader(file)?;
        Ok(Some(record))
    }
}
