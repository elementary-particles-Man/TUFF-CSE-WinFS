use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tuff_cse_winfs::{driver_control, driver_state, install, uninstall, verify};

#[derive(Parser)]
#[command(name = "TuffCseWinFsSetup")]
#[command(about = "TUFF-CSE-WinFS v1 Dedicated Installer", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Install TUFF-CSE-WinFS v1
    Install {
        /// Path to the installation policy JSON
        #[arg(short, long)]
        policy: PathBuf,

        /// Path to the driver package
        #[arg(short, long)]
        driver_package: Option<PathBuf>,

        /// Perform a dry-run without making changes
        #[arg(long, conflicts_with = "live_driver_install")]
        dry_run: bool,

        /// Explicitly execute pnputil.exe to install a distribution-candidate driver package
        #[arg(long, requires = "driver_package")]
        live_driver_install: bool,
    },
    /// Verify the installation status
    Verify {
        /// Path to the installation policy JSON (optional)
        #[arg(short, long)]
        policy: Option<PathBuf>,

        /// Explicitly query read-only Windows SCM driver status
        #[arg(long)]
        live_driver_status: bool,
    },
    /// Start the installed TUFF-CSE-WinFS service
    Start {
        /// Explicitly execute StartServiceW for the fixed driver service
        #[arg(long)]
        live_driver_start: bool,
    },
    /// Uninstall TUFF-CSE-WinFS v1
    Uninstall {
        /// Force uninstallation even if unsafe
        #[arg(short, long)]
        force: bool,

        /// Path to the driver package
        #[arg(short, long)]
        driver_package: Option<PathBuf>,

        /// Explicitly execute DiUninstallDriverW for a distribution-candidate driver package
        #[arg(long, requires = "driver_package")]
        live_driver_uninstall: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Install {
            policy,
            driver_package,
            dry_run,
            live_driver_install,
        } => {
            let options = install::InstallOptions {
                dry_run,
                live_driver_install,
            };
            if let Err(e) = install::run_install_with_options(policy, driver_package, options) {
                eprintln!("Installation failed: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Verify {
            policy,
            live_driver_status,
        } => {
            let options = verify::VerifyOptions { live_driver_status };
            if let Err(e) = verify::run_verify_with_options(policy, options) {
                eprintln!("Verification failed: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Start { live_driver_start } => {
            if !live_driver_start {
                println!(
                    "Driver start remains disabled. Service: {}. Use --live-driver-start explicitly on Windows.",
                    driver_state::DRIVER_SERVICE_NAME
                );
                return;
            }

            let report = driver_state::collect_driver_state_verification_report();
            println!("Driver Service: {}", driver_state::DRIVER_SERVICE_NAME);
            println!(
                "Pre-start Runtime State: {:?}",
                report.observed_runtime_state
            );
            let result = driver_control::start_driver_live_from_report(&report);
            println!("Driver Start Result: {:?}", result);
            if let driver_control::DriverStartResult::Error {
                windows_error_code, ..
            } = &result
            {
                println!("Windows Error Code: {}", windows_error_code);
            }
            if matches!(
                result,
                driver_control::DriverStartResult::Running
                    | driver_control::DriverStartResult::StartPending
                    | driver_control::DriverStartResult::AlreadyRunning
                    | driver_control::DriverStartResult::AlreadyStarting
            ) {
                return;
            }
            eprintln!("Driver start failed: {:?}", result);
            std::process::exit(1);
        }
        Commands::Uninstall {
            force,
            driver_package,
            live_driver_uninstall,
        } => {
            let options = uninstall::UninstallOptions {
                live_driver_uninstall,
            };
            if let Err(e) = uninstall::run_uninstall_with_options(force, driver_package, options) {
                eprintln!("Uninstallation failed: {}", e);
                std::process::exit(1);
            }
        }
    }
}
