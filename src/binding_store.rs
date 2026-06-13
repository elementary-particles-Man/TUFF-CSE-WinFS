use crate::binding::BindingDescriptor;
use crate::export_manifest::{ExportManifest, ExportPlan};
use crate::key_material::KeyDerivationPlan;
use crate::layout;
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
            "KEYS/plans",
            "KEYS/export-plans",
            "JRN/runtime",
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
}
