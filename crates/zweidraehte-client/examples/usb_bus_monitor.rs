//! Capture raw TP1 telegrams and link-layer acknowledgements through KNX USB.
//!
//! Run alongside an independent KNX/IP tunnel, then correlate this output
//! with sender diagnostics. The USB interface is restored to DLL mode on exit.
//! A monitor can affect which bus participant sends ACKs. On the tested ABB
//! interface, active monitoring changed ACKs seen by an unrelated sender.

use std::time::{Duration, Instant};

use clap::Parser;
use zweidraehte_client::{KnxConnector, UsbConnector, UsbSelector};

#[derive(Parser)]
#[command(about = "Capture raw KNX USB bus-monitor frames and ACK/NACK/BUSY")]
struct Args {
    /// Exit after this many seconds; otherwise stop with Ctrl-C.
    #[arg(long)]
    seconds: Option<u64>,
}

fn describe_busmon(cemi: &[u8]) -> String {
    if cemi.first() != Some(&0x2b) || cemi.len() < 2 {
        return format!("other cEMI {cemi:02x?}");
    }

    let raw_start = 2 + usize::from(cemi[1]);
    if raw_start > cemi.len() {
        return format!("malformed L_Busmon.ind {cemi:02x?}");
    }

    let raw = &cemi[raw_start..];
    let status = cemi[2..raw_start].windows(3).find(|item| item[0] == 0x03 && item[1] == 1).map(|item| item[2]);
    let status_text = status.map_or(String::new(), |value| format!(" status={value:02x}"));

    // A TP1 acknowledge is a single raw octet. Keep the full raw bytes in
    // the output because some interfaces may report proprietary encodings.
    let kind = match raw {
        [0xcc] => "ACK",
        [0x0c] => "NACK",
        [0xc0] => "BUSY",
        [_] => "one-byte frame",
        _ => "telegram",
    };

    format!("{kind}{status_text} raw={raw:02x?}")
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mut usb = UsbConnector::connect_bus_monitor(&UsbSelector::AutoDiscover).await?;
    let started = Instant::now();

    println!("USB bus monitor active; Ctrl-C stops capture and restores data-link mode");
    println!("Monitor mode can change bus ACK behavior; compare with a capture made without it");

    let capture = async {
        loop {
            let cemi = usb.recv_cemi().await?;
            println!("{:>12.6}s {}", started.elapsed().as_secs_f64(), describe_busmon(&cemi));
        }
        #[allow(unreachable_code)]
        Ok::<(), zweidraehte_client::BusError>(())
    };

    let capture_result = match args.seconds {
        Some(seconds) => tokio::select! {
            result = capture => result,
            _ = tokio::time::sleep(Duration::from_secs(seconds)) => Ok(()),
            _ = tokio::signal::ctrl_c() => Ok(()),
        },
        None => tokio::select! {
            result = capture => result,
            _ = tokio::signal::ctrl_c() => Ok(()),
        },
    };

    let close_result = usb.close().await;
    capture_result?;
    close_result?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::describe_busmon;

    #[test]
    fn classifies_ack_after_additional_info() {
        assert_eq!(describe_busmon(&[0x2b, 3, 0x03, 1, 0x00, 0xcc]), "ACK status=00 raw=[cc]");
    }

    #[test]
    fn rejects_short_additional_info() {
        assert!(describe_busmon(&[0x2b, 7, 0x03]).starts_with("malformed"));
    }
}
