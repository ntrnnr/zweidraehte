//! Stack definition for the Linux-hosted light switch.
//!
//! Binds the transport-agnostic [`devices::light_switch`] definition to this
//! target's transport and platform: KNX/IP over the Linux socket stack, with
//! the read-only [`LinuxIpPlatform`] reporting the host's actual network
//! configuration (the OS owns networking, so `apply_ip_config` is a no-op).
//!
//! This is the host-target sibling of `firmware/rp2040/eth_light_switch`: the
//! same device definition, but a different feature set. The RP2040 target is
//! UDP-only (`KnxIpDeviceUdp`) because its embassy-net TCP is still a stub;
//! this host target runs `KnxIpDeviceTcp` (routing + remote config + TCP, no
//! tunnelling) over `LinuxIpTransport`, whose TCP listener/stream are a real
//! `std::net` implementation.

use devices::light_switch::{
    DEVICE_DESCRIPTOR_IP, LightSwitchParams, comm_objs::LightSwitchComObjects, full::easter_egg::EasterEggAugment,
};
use zweidraehte_device::bcus::system_b::Ip;
use zweidraehte_device::layers::linklayers::knxip::{KnxNetIpBuilder, KnxNetIpDefinition, features::KnxIpDeviceTcp};
use zweidraehte_device::prelude::*;
use zweidraehte_device::storage::ConfigStorage;
use zweidraehte_platform::{LinuxIpPlatform, LinuxIpTransport};

use support::storage::{FileIdentity, JsonStorage};

#[derive(Debug, Clone, Copy)]
pub struct LinuxEthLightSwitchDefinition;

pub type LinuxEthLightSwitch = Ip<LinuxEthLightSwitchDefinition>;

/// Unified state type derived by the standard KNX/IP preset.
pub type LightSwitchState = <LinuxEthLightSwitch as StackDefinition>::State;

/// On-stack config store: the JSON-file config backend wrapped in the
/// framework's [`ConfigStorage`] composite. Riding on the stack (rather than
/// living in `main`) lets this device use the shared `storage_task` for restart
/// handling and persistence, exactly like the embedded targets.
pub type LightSwitchStorage = ConfigStorage<JsonStorage<LightSwitchState, FileIdentity>>;

pub struct LinuxEthLightSwitchHooks;

impl DeviceHooks for LinuxEthLightSwitchHooks {
    type Augments<'a, D: StackDefinition> = EasterEggAugment;

    fn create_augments<'a, D: StackDefinition>(
        _state: &'a D::State,
        _platform: &'a D::Platform,
        _layer_ctx: &'a zweidraehte_device::context::layer::LayerContext<D>,
    ) -> Self::Augments<'a, D> {
        EasterEggAugment
    }
}

// IP-specific link-layer bill of materials. `KnxIpDeviceTcp` is a routing
// device with no tunnelling, so `TUNNEL_CAPACITY = 0`. Because TCP is enabled,
// the derived `MAX_TCP_STREAMS` / `MAX_TCP_CHANNELS` defaults are `1` — the one
// TCP connection every TCP-capable server must accept (03/08/02 Core §6.5),
// carrying the Device Management connection ETS opens over TCP. `MAX_UDP_SOCKETS`
// stays at the trait default of 2 (discovery + routing share one multicast
// socket; unicast control wants the second).
impl KnxNetIpDefinition for LinuxEthLightSwitchDefinition {
    type Transport = LinuxIpTransport;
    type Features = KnxIpDeviceTcp;
}

impl DeviceDefinition for LinuxEthLightSwitchDefinition {
    const DEVICE: &'static DeviceDescriptor = &DEVICE_DESCRIPTOR_IP;

    type Platform = LinuxIpPlatform;
    type Params = LightSwitchParams;
    type ComObjects = LightSwitchComObjects;
    type LinkLayer = KnxNetIpBuilder<LinuxEthLightSwitch>;
    // The JSON-file config store rides on the stack so the shared storage task
    // handles restart and persistence exactly like the embedded targets.
    type Storage = &'static LightSwitchStorage;
    type Hooks = LinuxEthLightSwitchHooks;
}
