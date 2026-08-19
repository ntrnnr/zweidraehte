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

use zweidraehte_client::download::MaskDb;
use zweidraehte_client::security::Keyring;
use zweidraehte_client::{GroupAddress, GroupValueEncoding, IndividualAddress, KnxBus, SecurityEntry, SecurityStore};

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

fn keyring_security() -> Option<SecurityStore> {
    let path = std::env::var("KNX_KEYRING").ok()?;
    let password = std::env::var("KNX_KEYRING_PASSWORD").ok()?;
    let keyring = Keyring::load(&path, &password).expect("keyring loads");
    let mut security = SecurityStore::new();
    security.import_keyring(&keyring);
    Some(security)
}

fn group_ga(var: &str) -> Option<GroupAddress> {
    let s = std::env::var(var).ok()?;
    let parts: Vec<u16> = s.split('/').map(|p| p.parse().expect("GA is main/mid/sub")).collect();
    let [main, mid, sub] = parts[..] else {
        panic!("{var} is main/mid/sub");
    };
    Some(GroupAddress::from_three_level(main as u8, mid as u8, sub as u8))
}

/// Receive-only: listen on a secured group address and expect at least
/// one authenticated telegram. Additionally needs:
///
/// ```bash
/// KNX_KEYRING=<path to .knxkeys>  KNX_KEYRING_PASSWORD=<pw>
/// KNX_GROUP_GA=2/0/3              # a GA with secure traffic on it
/// ```
#[tokio::test]
async fn secure_group_monitor() {
    let Some(addr) = tunnel_addr() else {
        eprintln!("skipped: KNX_TUNNEL_ADDR not set");
        return;
    };
    let Some(security) = keyring_security() else {
        eprintln!("skipped: KNX_KEYRING / KNX_KEYRING_PASSWORD not set");
        return;
    };
    let Some(ga) = group_ga("KNX_GROUP_GA") else {
        eprintln!("skipped: KNX_GROUP_GA not set");
        return;
    };

    let bus = KnxBus::connect_ip_with_security(addr, security).await.expect("tunnel connects");
    let mut events = bus.group_events();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let telegram = tokio::time::timeout_at(deadline, events.recv())
            .await
            .expect("a secured telegram arrives on KNX_GROUP_GA within 15 s")
            .expect("broadcast channel open");
        eprintln!(
            "{} -> {} [{}{:?}] {:02X?}",
            telegram.source,
            telegram.group,
            if telegram.secured { "secure " } else { "" },
            telegram.service,
            telegram.data
        );
        if telegram.group == ga && telegram.secured {
            break;
        }
    }

    bus.disconnect().await.expect("tunnel disconnects");
}

/// Sends ONE secured group write. Only runs with an explicit target so
/// nobody flips a light by accident. Additionally needs:
///
/// ```bash
/// KNX_KEYRING=... KNX_KEYRING_PASSWORD=...
/// KNX_GROUP_WRITE_GA=2/0/3
/// KNX_GROUP_WRITE_VALUE=1         # single 6-bit value, short encoding
/// ```
#[tokio::test]
async fn secure_group_write_live() {
    let Some(addr) = tunnel_addr() else {
        eprintln!("skipped: KNX_TUNNEL_ADDR not set");
        return;
    };
    let Some(security) = keyring_security() else {
        eprintln!("skipped: KNX_KEYRING / KNX_KEYRING_PASSWORD not set");
        return;
    };
    let Some(ga) = group_ga("KNX_GROUP_WRITE_GA") else {
        eprintln!("skipped: KNX_GROUP_WRITE_GA not set");
        return;
    };
    let Some(value) = std::env::var("KNX_GROUP_WRITE_VALUE").ok().map(|v| v.parse::<u8>().expect("0..=63")) else {
        eprintln!("skipped: KNX_GROUP_WRITE_VALUE not set");
        return;
    };

    let bus = KnxBus::connect_ip_with_security(addr, security).await.expect("tunnel connects");
    bus.group_write(ga, &[value], GroupValueEncoding::Short)
        .await
        .expect("secured group write accepted by the interface");
    bus.disconnect().await.expect("tunnel disconnects");
}

// ============================================================================
// Configuration download
// ============================================================================

/// Reads back a live System 7 device's load states and table blobs
/// through the download engine's resource map — the read-only half of
/// the configuration path, safe against a commissioned installation.
///
/// ```bash
/// KNX_TUNNEL_ADDR=... KNX_TARGET_IA=1.1.42 cargo test -p zweidraehte-client --test live_tunnel
/// ```
#[tokio::test]
async fn system7_load_states_readable() {
    let Some(addr) = tunnel_addr() else {
        eprintln!("skipped: KNX_TUNNEL_ADDR not set");
        return;
    };
    let Some(target) = target_ia() else {
        eprintln!("skipped: KNX_TARGET_IA not set");
        return;
    };

    // Mask facts come from the master data, as they do everywhere
    // else — no hardcoded address table to fall back on.
    let Ok(masks) = MaskDb::resolve() else {
        eprintln!("skipped: no knx_master.xml (set KNX_MASTER_DATA or enable master-data-download)");
        return;
    };
    let resources = masks
        .mask(zweidraehte_client::MaskVersion::System7Tp1)
        .and_then(|m| m.memory_resources())
        .expect("MV-0705 is memory-mapped in the master data");

    let bus = KnxBus::connect_ip(addr).await.expect("tunnel connects");
    let mut device = bus.connect_device(target).await.expect("device connection opens");

    let descriptor = device.device_descriptor_read(0).await.expect("device descriptor read");
    assert_eq!(descriptor.len(), 2, "descriptor type 0 is two octets");
    if descriptor != [0x07, 0x05] {
        eprintln!("skipped: {target} is mask {descriptor:02X?}, not System 7 (0705)");
        device.close().await.expect("connection closes");
        bus.disconnect().await.expect("tunnel disconnects");
        return;
    }

    // The four load-state bytes at B6EAh (ADT, AST, APP, PEI) — a
    // commissioned device answers Loaded (01) on the first three.
    let states = device.memory_read(resources.load_status_addr, 4).await.expect("load states read");
    eprintln!("load states ADT/AST/APP/PEI: {states:02X?}");
    assert_eq!(states.len(), 4);

    // The RT8 table head: IA-inclusive length, then the IA —
    // which must be the address we are talking to.
    let adt_head = device.memory_read(resources.address_table_addr, 3).await.expect("address table read");
    eprintln!("address table: length {}, IA {:02X?}", adt_head[0], &adt_head[1..3]);
    assert_eq!(&adt_head[1..3], target.as_bytes(), "the address table holds the device's own IA");

    device.close().await.expect("connection closes");
    bus.disconnect().await.expect("tunnel disconnects");
}
