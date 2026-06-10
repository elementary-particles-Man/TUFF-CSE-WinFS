use anyhow::Result;
use std::fs;
use std::path::PathBuf;

pub fn management_root() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        PathBuf::from("C:\\ProgramData\\TUFF-CSE-WinFS\\devices\\")
    }
    #[cfg(not(target_os = "windows"))]
    {
        let mut path = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        path.push(".tuff-cse-winfs-dev");
        path.push("ProgramData");
        path.push("TUFF-CSE-WinFS");
        path.push("devices");
        path
    }
}

pub fn ensure_layout(root: &PathBuf) -> Result<()> {
    let subdirs = ["BTM", "JRN", "META", "KEYS"];
    for subdir in &subdirs {
        let mut path = root.clone();
        path.push(subdir);
        if !path.exists() {
            fs::create_dir_all(&path)?;
        }
    }
    Ok(())
}
