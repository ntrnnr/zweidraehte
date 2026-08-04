//! Example: subscribe to group telegrams and print them.
//!
//! Usage:
//!     cargo run -p zweidraehte-client --example group_monitor -- \
//!         --server 192.168.1.100:3671
//!     cargo run -p zweidraehte-client --example group_monitor -- --usb

mod common;

use common::BusTarget;
use zweidraehte_client::GroupService;

fn parse_target(args: &[String]) -> Result<BusTarget, String> {
    let mut target = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--server" | "-s" => {
                i += 1;
                let addr = args.get(i).ok_or("--server requires a value")?;
                target = Some(BusTarget::Ip(addr.parse().map_err(|e| format!("{e}"))?));
            }
            "--usb" => target = Some(common::parse_usb_arg(args, &mut i)?),
            other => return Err(format!("unknown argument: {}", other)),
        }
        i += 1;
    }
    target.ok_or_else(|| format!("usage: group_monitor --server <ip:port> | --usb [vid:pid]\n{}", common::TARGET_USAGE))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    let target = parse_target(&args)?;

    let bus = target.connect().await?;
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
