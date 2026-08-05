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

use zweidraehte_client::{IndividualAddress, KnxBus, SecurityEntry, SecurityStore};

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

fn env_hex<const N: usize>(var: &str) -> Option<[u8; N]> {
    let s = std::env::var(var).ok()?;
    assert_eq!(s.len(), N * 2, "{var} must be {} hex chars", N * 2);
    let mut out = [0u8; N];
    for (i, chunk) in out.iter_mut().enumerate() {
        *chunk = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap_or_else(|_| panic!("{var} is not hex"));
    }
    Some(out)
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

/// Data Secure management against a secured device. Additionally needs:
///
/// ```bash
/// KNX_TOOL_KEY=<32 hex>       # or KNX_FDSK=<32 hex> for a factory-fresh device
/// KNX_DEVICE_SERIAL=<12 hex>  # the device's KNX serial number
/// ```
///
/// Read-only: sync handshake, serial-number property, device descriptor.
#[tokio::test]
async fn secure_connect_and_read() {
    let Some(addr) = tunnel_addr() else {
        eprintln!("skipped: KNX_TUNNEL_ADDR not set");
        return;
    };
    let Some(target) = target_ia() else {
        eprintln!("skipped: KNX_TARGET_IA not set");
        return;
    };
    let tool_key = env_hex::<16>("KNX_TOOL_KEY");
    let fdsk = env_hex::<16>("KNX_FDSK");
    if tool_key.is_none() && fdsk.is_none() {
        eprintln!("skipped: neither KNX_TOOL_KEY nor KNX_FDSK set");
        return;
    }
    let Some(serial) = env_hex::<6>("KNX_DEVICE_SERIAL") else {
        eprintln!("skipped: KNX_DEVICE_SERIAL not set");
        return;
    };

    let mut security = SecurityStore::new();
    security.set_device_security(target, SecurityEntry {
        mode: zweidraehte_client::DeviceSecurityMode::Secure,
        tool_key,
        fdsk,
        serial: Some(serial),
    });
    let bus = KnxBus::connect_ip_with_security(addr, security).await.expect("tunnel connects");

    let mut device = bus.connect_device(target).await.expect("secure T_Connect incl. S-A_Sync");
    let read_serial = device.property_read(0, PID_SERIAL_NUMBER, 1, 1).await.expect("wrapped serial read");
    assert_eq!(read_serial, serial, "device serial matches KNX_DEVICE_SERIAL");
    let descriptor = device.device_descriptor_read(0).await.expect("wrapped descriptor read");
    eprintln!("secure device {} mask: {:02X?}", target, descriptor);
    device.close().await.expect("T_Disconnect");

    bus.disconnect().await.expect("tunnel disconnects");
}
