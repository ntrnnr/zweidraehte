//! Example: subscribe to group telegrams and print them.
//!
//! Usage:
//!     cargo run -p zweidraehte-client --example group_monitor -- \
//!         --server 192.168.1.100:3671
//!     cargo run -p zweidraehte-client --example group_monitor -- --usb

mod common;

use clap::Parser;
use common::TargetArgs;
use zweidraehte_client::GroupService;

/// Monitor group telegrams on the bus.
#[derive(Parser)]
struct Args {
    #[command(flatten)]
    target: TargetArgs,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args = Args::parse();
    let bus = args.target.to_target().connect().await?;
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
                        let data =
                            telegram.data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                        println!("{} → {}  {} [{}]", telegram.source, telegram.group, service, data);
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
