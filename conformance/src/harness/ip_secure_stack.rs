//! KNX IP Secure DUT stack definition.
//!
//! Unlike the TP1 conformance DUTs, this device talks over **real
//! loopback sockets** — the runner drives it as a KNXnet/IP secure
//! client over TCP instead of injecting TP1 bytes through the IPC link
//! layer. The DUT is therefore a standalone process with no SHM/IPC
//! channel: the test harness spawns it, connects to its TCP control
//! endpoint, and kills it for state isolation between tests.
//!
//! Device shape: a pure KNX IP Secure tunnelling interface (no group
//! objects, no application parameters), the spec's canonical secure
//! unicast server. Key material is fixed to the 03/08/09 Appendix A
//! values so the runner-side crypto can be cross-checked against the
//! published vectors:
//!
//! - Device Authentication Code = `CCM key for password "trustme"`
//!   (Appendix A.2.2), provisioned via the FDSK seed.
//! - User 1 (management) password hash = hash of `"secret"`
//!   (Appendix A.3.1), written into the default config.
//! - Tunnelling and Device Management families ship secured
//!   (security version 1) so plain-frame rejection is testable without
//!   a property-write bootstrap.

use const_default::ConstDefault;
use core::net::{Ipv4Addr, SocketAddrV4};
use serde::{Deserialize, Serialize};

use zweidraehte_device::bcus::system_b::{
    IpSecureInterfaceExtensionFor, IpSecureResources, SystemBDeviceState, SystemBStackDefinition,
};
use zweidraehte_device::ets::{DeviceDescriptor, MaskVersion};
use zweidraehte_device::layers::linklayers::knxip::{
    KnxNetIpBuilder, KnxNetIpDefinition, features::KnxIpSecureDeviceTcp,
};
use zweidraehte_device::layers::transport::TlStyle;
use zweidraehte_device::objects::comm::{
    ComObjectBusHook, ComObjectIndex, ComObjectInfo, ComObjectInfoMut, ComObjects,
};
use zweidraehte_device::prelude::IpPlatform;
use zweidraehte_device::storage::HasDeviceConfig;
use zweidraehte_platform::{IpConfig, LinuxIpTransport, NetworkConfig};

use super::secure_stack::GetrandomRng;

// ============================================================================
// Fixed key material (03/08/09 Appendix A)
// ============================================================================

/// Device Authentication Code — derived from the password `"trustme"`
/// (Appendix A.2.2). Provisioned as the FDSK so the factory-default
/// DAC-seeding path is exercised.
pub const DUT_DEVICE_AUTH_CODE: [u8; 16] =
    [0xe1, 0x58, 0xe4, 0x01, 0x20, 0x47, 0xbd, 0x6c, 0xc4, 0x1a, 0xaf, 0xbc, 0x5c, 0x04, 0xc1, 0xfc];

/// Management user (ID 1) password hash — derived from `"secret"`
/// (Appendix A.3.1).
pub const DUT_USER1_PASSWORD_HASH: [u8; 16] =
    [0x03, 0xfc, 0xed, 0xb6, 0x66, 0x60, 0x25, 0x1e, 0xc8, 0x1a, 0x1a, 0x71, 0x69, 0x01, 0x69, 0x6a];

/// Serial number of the IP Secure DUT.
pub const IP_SECURE_SERIAL_NUMBER: [u8; 6] = [0x00, 0xFA, 0x12, 0x34, 0x56, 0x78];

/// Secure Backbone Key for secure-routing tests — the 03/08/09
/// Appendix A.5/A.6 key `00 01 … 0f`.
pub const DUT_BACKBONE_KEY: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

/// Environment variable carrying the DUT's KNXnet/IP port (the harness
/// picks a free port per spawn; default 3671 for manual runs).
pub const PORT_ENV: &str = "KNX_IPS_PORT";

/// Environment variable carrying the routing multicast group. The
/// harness derives a per-spawn group in 239.250.0.0/16 from the control
/// port so concurrent runs never share a group; default 224.0.23.12.
pub const MCAST_ENV: &str = "KNX_IPS_MCAST";

/// Environment variable enabling secure routing in the DUT config
/// (`1` = secured Routing family + provisioned [`DUT_BACKBONE_KEY`]).
pub const SECURE_ROUTING_ENV: &str = "KNX_IPS_SECURE_ROUTING";

/// Tunnelling slot count = secure session pool size.
pub const TUNNEL_SLOTS: usize = 2;
/// Password hash slots (user IDs 1..=2).
pub const MAX_PW: usize = 2;
/// Tunnelling-users table capacity.
pub const MAX_TU: usize = 4;

// ============================================================================
// Device identity
// ============================================================================

pub const DEVICE_DESCRIPTOR: DeviceDescriptor = DeviceDescriptor {
    mask_version: MaskVersion::SystemBTp1,
    manufacturer_id: 0x00FA,
    hardware_type: [0x00, 0x00, 0x00, 0x00, 0x00, 0x11],
    application_id: 0x1001,
    application_version: 0x01,
    // 1 device IA + tunnelling slots.
    max_address_table_entries: 1 + TUNNEL_SLOTS as u16,
    max_association_table_entries: 1,
    max_com_objects: 0,
    pei_type: 0,
};

// ============================================================================
// Empty parameters / communication objects (pure tunnelling bridge)
// ============================================================================

#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, zerocopy::KnownLayout, zerocopy::Immutable, zerocopy::IntoBytes,
)]
#[repr(C)]
pub struct IpSecureDutParams {
    // Intentionally empty — the DUT has no application parameters.
    _private: (),
}

impl ConstDefault for IpSecureDutParams {
    const DEFAULT: Self = Self { _private: () };
}

#[derive(Debug, Clone, Copy)]
pub enum NoComObjectIndex {}

impl ComObjectIndex for NoComObjectIndex {
    fn from_index(_idx: u16) -> Option<Self> {
        None
    }
    fn index(&self) -> u16 {
        match *self {}
    }
}

/// Empty communication objects — the DUT only serves secure tunnelling.
pub struct IpSecureDutComObjects;

impl ComObjects for IpSecureDutComObjects {
    type Index = NoComObjectIndex;

    fn new() -> Self {
        Self
    }
    fn info(&self, _idx: u16) -> Option<ComObjectInfo<'_>> {
        None
    }
    fn info_mut(&mut self, _idx: u16) -> Option<ComObjectInfoMut<'_>> {
        None
    }
}

impl ComObjectBusHook for IpSecureDutComObjects {}

// ============================================================================
// Loopback platform
// ============================================================================

/// Fixed loopback [`IpPlatform`] — the DUT binds 127.0.0.1 only.
#[derive(Debug, Clone, Default)]
pub struct LoopbackIpPlatform;

impl IpPlatform for LoopbackIpPlatform {
    fn current_ip_address(&self) -> Ipv4Addr {
        Ipv4Addr::LOCALHOST
    }
    fn current_subnet_mask(&self) -> Ipv4Addr {
        Ipv4Addr::new(255, 0, 0, 0)
    }
    fn current_default_gateway(&self) -> Ipv4Addr {
        Ipv4Addr::UNSPECIFIED
    }
    fn mac_address(&self) -> [u8; 6] {
        [0x02, 0x00, 0x00, 0xFA, 0x12, 0x34]
    }
    fn current_ip_assignment_method(&self) -> u8 {
        0x01 // manual
    }
    fn ip_capabilities(&self) -> u8 {
        0x01
    }
}

impl NetworkConfig for LoopbackIpPlatform {
    type Error = core::convert::Infallible;

    fn apply_ip_config(&self, _config: &IpConfig) -> Result<(), Self::Error> {
        Ok(())
    }
}

// ============================================================================
// Stack definition
// ============================================================================

type Features = KnxIpSecureDeviceTcp<TUNNEL_SLOTS>;

pub type IpSecureDutExtension = IpSecureInterfaceExtensionFor<Features, MAX_PW, MAX_TU>;

pub type IpSecureDutState = SystemBDeviceState<
    { <IpSecureDutStack as SystemBStackDefinition>::ADT_SIZE },
    { <IpSecureDutStack as SystemBStackDefinition>::AST_SIZE },
    { <IpSecureDutStack as SystemBStackDefinition>::COT_SIZE },
    IpSecureDutStack,
    IpSecureDutExtension,
>;

pub type IpSecureDutDeviceConfig = <IpSecureDutState as HasDeviceConfig>::Config;

#[derive(Debug, Clone, Copy)]
pub struct IpSecureDutStack;

impl KnxNetIpDefinition for IpSecureDutStack {
    type Transport = LinuxIpTransport;
    type Features = Features;
    type Rng = GetrandomRng;
}

zweidraehte_device::system_b_standard_stack! {
    stack: IpSecureDutStack,
    device: &DEVICE_DESCRIPTOR,
    tl_style: TlStyle::Style3,
    params: IpSecureDutParams,
    com_objects: IpSecureDutComObjects,
    link_layer_builder: KnxNetIpBuilder<IpSecureDutStack>,
    platform: LoopbackIpPlatform,
    extension_state: IpSecureDutExtension,
    state: IpSecureDutState,
    al_extensions: (
        zweidraehte_device::layers::application::services::SystemBAlServices,
        zweidraehte_device::layers::application::services::PropertyExtValueService,
    ),
    layer_builder: zweidraehte_device::PlainIpDeviceBuilder,
    resources: IpSecureResources,
    extra {
        type Rng = GetrandomRng;
    },
}

// ============================================================================
// DUT construction helpers
// ============================================================================

/// The DUT's KNXnet/IP port: `$KNX_IPS_PORT` or 3671.
pub fn dut_port() -> u16 {
    std::env::var(PORT_ENV).ok().and_then(|p| p.parse().ok()).unwrap_or(3671)
}

/// The DUT's control endpoint on loopback.
pub fn dut_control_endpoint() -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::LOCALHOST, dut_port())
}

/// Factory-default device config with the test key material applied:
/// user 1's password set to `"secret"`, the tunnelling + device
/// management families secured, and two tunnelling addresses
/// provisioned so secure tunnel connects have an address to assign.
/// The DAC is left zero so the FDSK seeding path provisions
/// [`DUT_DEVICE_AUTH_CODE`].
pub fn default_dut_config() -> IpSecureDutDeviceConfig {
    use zweidraehte_device::bcus::system_b::DeviceConfig;
    use zweidraehte_proto::address::IndividualAddress;

    let mut config: IpSecureDutDeviceConfig = DeviceConfig::factory_default();
    config.individual_address = IndividualAddress::new(15, 15, 0);

    // extension_config = ((IpExtensionConfig, TunnellingExtensionConfig), IpSecureExtensionConfig)
    let ((_ip, tunnelling), secure) = &mut config.extension_config;

    // Two tunnelling addresses (15.15.1 / 15.15.2).
    let addrs = [IndividualAddress::new(15, 15, 1), IndividualAddress::new(15, 15, 2)];
    for (i, addr) in addrs.iter().enumerate().take(TUNNEL_SLOTS) {
        tunnelling.additional_individual_addresses[i] = addr.0;
    }
    tunnelling.additional_individual_addresses_len = TUNNEL_SLOTS.min(addrs.len()) as u8;

    let _ = secure.password_hashes.write_entries(0, &DUT_USER1_PASSWORD_HASH);
    secure.secured_tunnelling = 1;
    secure.secured_device_management = 1;
    config
}

/// Whether the spawning harness requested secure routing.
pub fn secure_routing_enabled() -> bool {
    std::env::var(SECURE_ROUTING_ENV).is_ok_and(|v| v == "1")
}

/// The routing multicast group for this DUT instance.
pub fn dut_multicast_group() -> Ipv4Addr {
    std::env::var(MCAST_ENV).ok().and_then(|v| v.parse().ok()).unwrap_or(zweidraehte_device::DEFAULT_MULTICAST_ADDR)
}

/// Secure the Routing family and provision the Appendix A backbone key
/// (secure-routing test mode), pointing `PID_ROUTING_MULTICAST_ADDRESS`
/// at the per-spawn test group.
pub fn apply_secure_routing_config(config: &mut IpSecureDutDeviceConfig, group: Ipv4Addr) {
    let ((ip, _tunnelling), secure) = &mut config.extension_config;
    ip.routing_multicast = group.octets();
    secure.secured_routing = 1;
    secure.backbone_key = DUT_BACKBONE_KEY;
}
