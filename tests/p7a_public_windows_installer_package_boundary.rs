#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn read(path: impl AsRef<Path>) -> String {
        fs::read_to_string(path).unwrap()
    }

    fn assert_not_contains(text: &str, needle: &str) {
        assert!(
            !text.contains(needle),
            "unexpected forbidden string `{needle}` found"
        );
    }

    #[test]
    fn rc_status_reports_p7a_installer_readiness_without_secrets() {
        assert_eq!(tuff_cse_winfs::V1_RC_PHASE, "P6Z");
        assert_eq!(
            tuff_cse_winfs::V1_RC_BASE_COMMIT,
            "d8c8f3b90ba9f57d12c498b4f8ace31c1420740a"
        );
        assert_eq!(tuff_cse_winfs::P7A_PUBLIC_INSTALLER_PHASE, "P7A");

        let ctl = env::var("CARGO_BIN_EXE_tuff-cse-winfsctl").unwrap();
        let output = Command::new(ctl).arg("rc-status").output().unwrap();
        assert!(output.status.success());

        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            stdout.contains("installer readiness: P7A / Public Windows Installer Package Boundary")
        );
        assert!(stdout.contains("installer artifact boundary: portable zip artifact, WiX scaffold, README-FIRST, manifest"));
        assert!(stdout.contains("installer reserved actions: driver install, service install, code signing, CSE crypto I/O, TPM live API, KMS/HSM live integration"));
        assert_not_contains(&stdout, "password");
        assert_not_contains(&stdout, "auth token");
        assert_not_contains(&stdout, "private key");
    }

    #[test]
    fn installer_files_and_manifest_define_public_package_boundary() {
        let root = repo_root();
        let installer = root.join("installer/windows");
        let readme = read(installer.join("README.md"));
        let manifest = read(installer.join("PACKAGE_MANIFEST.md"));
        let readme_first = read(installer.join("assets/README-FIRST.txt"));
        let license = read(installer.join("assets/LICENSE.rtf"));
        let wxs = read(installer.join("TUFF-CSE-WinFS.wxs"));
        let build_script = read(installer.join("build-installer.ps1"));

        assert!(readme.contains("Public Windows Installer Package Boundary"));
        assert!(manifest.contains("TuffCseWinFsSetup.exe"));
        assert!(manifest.contains("tuff-cse-winfsctl.exe"));
        assert!(readme_first.contains("tuff-cse-winfsctl rc-status"));
        assert!(readme_first.contains(
            "TuffCseWinFsSetup -- install --policy examples/cse-install-policy.example.json --dry-run"
        ));
        assert!(readme_first.contains(
            "TuffCseWinFsSetup -- verify --policy examples/cse-install-policy.example.json"
        ));
        assert!(license.contains("repository license"));
        assert!(wxs.contains("InstallerBinaries"));
        assert!(wxs.contains("InstallerDocs"));
        assert!(build_script.contains("Compress-Archive"));
        assert!(build_script.contains("rc-status"));
        assert!(build_script.contains("README-FIRST.txt"));
        assert!(build_script.contains("TuffCseWinFsSetup.exe"));

        for text in [&readme, &manifest, &readme_first, &build_script, &wxs] {
            assert_not_contains(text, "pnputil.exe");
            assert_not_contains(text, "signtool sign");
            assert_not_contains(text, "Start-Service");
            assert_not_contains(text, "New-Service");
            assert_not_contains(text, "sc.exe create");
        }
    }

    #[test]
    fn windows_installer_workflow_generates_artifact_and_keeps_ubuntu_ci_separate() {
        let root = repo_root();
        let workflow = read(root.join(".github/workflows/windows-installer-artifact.yml"));
        let ci = read(root.join(".github/workflows/ci.yml"));

        assert!(workflow.contains("windows-latest"));
        assert!(workflow.contains("cargo build --release --bins"));
        assert!(workflow.contains("cargo run --bin tuff-cse-winfsctl -- rc-status"));
        assert!(workflow.contains(".\\installer\\windows\\build-installer.ps1"));
        assert!(workflow.contains("actions/upload-artifact@v4"));
        assert!(ci.contains("windows-latest"));
        assert!(ci.contains("cargo run --bin TuffCseWinFsSetup -- install"));
        assert!(ci.contains("cargo run --bin TuffCseWinFsSetup -- verify"));

        assert_not_contains(&workflow, "pnputil");
        assert_not_contains(&workflow, "signtool");
        assert_not_contains(&workflow, "Start-Service");
        assert_not_contains(&workflow, "New-Service");
    }
}
