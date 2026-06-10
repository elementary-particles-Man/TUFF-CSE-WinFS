use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tuff_cse_winfs::{install, uninstall, verify};

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

        /// Path to the driver package (optional in P0)
        #[arg(short, long)]
        driver_package: Option<PathBuf>,

        /// Perform a dry-run without making changes
        #[arg(long)]
        dry_run: bool,
    },
    /// Verify the installation status
    Verify {
        /// Path to the installation policy JSON (optional)
        #[arg(short, long)]
        policy: Option<PathBuf>,
    },
    /// Uninstall TUFF-CSE-WinFS v1
    Uninstall {
        /// Force uninstallation even if unsafe
        #[arg(short, long)]
        force: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Install {
            policy,
            driver_package,
            dry_run,
        } => {
            if let Err(e) = install::run_install(policy, driver_package, dry_run) {
                eprintln!("Installation failed: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Verify { policy } => {
            if let Err(e) = verify::run_verify(policy) {
                eprintln!("Verification failed: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Uninstall { force } => {
            if let Err(e) = uninstall::run_uninstall(force) {
                eprintln!("Uninstallation failed: {}", e);
                std::process::exit(1);
            }
        }
    }
}
