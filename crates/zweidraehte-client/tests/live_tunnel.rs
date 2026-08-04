//! Live integration tests against a real KNX/IP interface.
//!
//! These need hardware, so they are gated on environment variables and
//! silently skip otherwise (so `cargo test` stays hermetic):
//!
//! ```bash
//! # Tunnel connection, group traffic, NM scan:
//! KNX_TUNNEL_ADDR=192.168.1.10:3671 cargo test -p zweidraehte-client --test live_tunnel
//!
//! # Additionally exercise device management against one device:
//! KNX_TUNNEL_ADDR=192.168.1.10:3671 KNX_TARGET_IA=1.1.42 cargo test -p zweidraehte-client --test live_tunnel
//! ```
//!
//! The device-management test reads properties and the device descriptor
//! only — nothing is written, so it is safe against a commissioned
//! installation.
//!
//! TODO: replace the hardware dependency for the tunnel-level tests with a
//! loopback fixture running the device stack with the knxip tunneling
//! feature set (see CLIENT.md roadmap).

use std::net::SocketAddrV4;
use std::time::Duration;

use zweidraehte_client::{IndividualAddress, KnxBus};

/// PID_SERIAL_NUMBER on the Device Object.
const PID_SERIAL_NUMBER: u16 = 11;

fn tunnel_addr() -> Option<SocketAddrV4> {
    let addr = std::env::var("KNX_TUNNEL_ADDR").ok()?;
    Some(addr.parse().expect("KNX_TUNNEL_ADDR is host:port"))
}

fn target_ia() -> Option<IndividualAddress> {
    let addr = std::env::var("KNX_TARGET_IA").ok()?;
    let parts: Vec<u8> = addr.split('.').map(|p| p.parse().expect("KNX_TARGET_IA is a.l.d")).collect();
    let [area, line, device] = parts[..] else {
        panic!("KNX_TARGET_IA is a.l.d");
    };
    Some(IndividualAddress::new(area, line, device))
}

#[tokio::test]
async fn tunnel_connect_disconnect() {
    let Some(addr) = tunnel_addr() else {
        eprintln!("skipped: KNX_TUNNEL_ADDR not set");
        return;
    };

    let bus = KnxBus::connect_ip(addr).await.expect("tunnel connects");
    assert_ne!(bus.assigned_address(), IndividualAddress::new(0, 0, 0));
    assert!(bus.max_apdu() >= 15, "tunnel max APDU below the TP1 minimum");
    bus.disconnect().await.expect("tunnel disconnects");
}

#[tokio::test]
async fn programming_mode_scan_completes() {
    let Some(addr) = tunnel_addr() else {
        eprintln!("skipped: KNX_TUNNEL_ADDR not set");
        return;
    };

    let bus = KnxBus::connect_ip(addr).await.expect("tunnel connects");
    // Usually no device is in programming mode; the point is that the
    // scan window elapses cleanly and returns (not what it finds).
    let found =
        bus.network_management().read_individual_addresses(Duration::from_secs(2)).await.expect("scan completes");
    eprintln!("devices in programming mode: {:?}", found);
    bus.disconnect().await.expect("tunnel disconnects");
}

#[tokio::test]
async fn device_management_reads() {
    let Some(addr) = tunnel_addr() else {
        eprintln!("skipped: KNX_TUNNEL_ADDR not set");
        return;
    };
    let Some(target) = target_ia() else {
        eprintln!("skipped: KNX_TARGET_IA not set");
        return;
    };

    let bus = KnxBus::connect_ip(addr).await.expect("tunnel connects");

    // Connectionless first: the device descriptor identifies the mask.
    let descriptor = bus.network_management().device_descriptor_read(target, 0).await.expect("descriptor read (RCl)");
    assert_eq!(descriptor.len(), 2, "descriptor type 0 is the 2-byte mask version");
    eprintln!("device {} mask: {:02X}{:02X}", target, descriptor[0], descriptor[1]);

    // Connected (RCo): serial number property + clean close.
    let mut device = bus.connect_device(target).await.expect("T_Connect");
    let serial = device.property_read(0, PID_SERIAL_NUMBER, 1, 1).await.expect("serial number read");
    assert_eq!(serial.len(), 6, "KNX serial numbers are 6 bytes");
    eprintln!("device {} serial: {:02X?}", target, serial);
    device.close().await.expect("T_Disconnect");

    bus.disconnect().await.expect("tunnel disconnects");
}
