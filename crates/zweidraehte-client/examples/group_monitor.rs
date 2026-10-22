//! Example: subscribe to group telegrams and print them.
//!
//! Usage:
//!     cargo run -p zweidraehte-client --features cli --example group_monitor -- \
//!         --server 192.168.1.100:3671
//!     cargo run -p zweidraehte-client --features cli --example group_monitor -- --usb
//!
//! With an ETS keyring export, secured group addresses are decrypted
//! (and plaintext on them is dropped as a downgrade attempt); such
//! telegrams print with a `secure` tag:
//!
//!     cargo run -p zweidraehte-client --features cli --example group_monitor -- \
//!         --server 192.168.1.100:3671 \
//!         --keyring project.knxkeys --keyring-password secret

mod common;

use clap::Parser;
use common::TargetArgs;
use zweidraehte_client::security::Keyring;
use zweidraehte_client::{GroupService, KnxBus, SecurityStore};

/// Monitor group telegrams on the bus.
#[derive(Parser)]
struct Args {
    #[command(flatten)]
    target: TargetArgs,

    /// ETS keyring export (.knxkeys) with the group keys
    #[arg(long, requires = "keyring_password")]
    keyring: Option<String>,

    /// Password the keyring was exported with
    #[arg(long, requires = "keyring")]
    keyring_password: Option<String>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args = Args::parse();

    let mut security = SecurityStore::new();
    if let Some((path, password)) = args.keyring.as_deref().zip(args.keyring_password.as_deref()) {
        let keyring = Keyring::load(path, password)?;
        security.import_keyring(&keyring)?;
        println!("Keyring '{}' loaded.", keyring.project);
    }

    let bus = KnxBus::builder().with_security(security).connect(&args.target.to_target()).await?;
    println!("Connected as {}. Monitoring group traffic (Ctrl-C to stop).", bus.assigned_address());

    let mut events = bus.group_events();
    loop {
        tokio::select! {
            event = events.recv() => {
                match event {
                    Ok(telegram) => {
                        let service = match telegram.service {
                            GroupService::Read => "Read    ",
                            GroupService::Write => "Write   ",
                            GroupService::Response => "Response",
                        };
                        let tag = if telegram.secured { " secure" } else { "" };
                        let data =
                            telegram.data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                        println!("{} → {}  {}{} [{}]", telegram.source, telegram.group, service, tag, data);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        eprintln!("(lagged, {} telegrams dropped)", n);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }

    bus.disconnect().await?;
    Ok(())
}
