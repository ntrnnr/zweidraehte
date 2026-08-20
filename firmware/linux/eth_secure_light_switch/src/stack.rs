//! Stack definition for the Linux-hosted **KNX IP Secure + Data Secure**
//! light switch.
//!
//! Secure sibling of [`super`](crate)'s plain
//! [`LinuxEthLightSwitch`](super::super) — the host-target twin of
//! `firmware/rp2040/eth_secure_light_switch`. Same device definition
//! ([`devices::light_switch`]) and read-only [`LinuxIpPlatform`], but the stack
//! adds two independent security mechanisms:
//!
//! - **KNX IP Secure (secure multicast routing)** — the KNXnet/IP backbone is
//!   secured with `SecureGroupSync` + `SecureWrapper` once ETS provisions a
//!   backbone key and enables the secured Routing family. Until then the device
//!   routes plain. The feature set is routing-only secure
//!   ([`KnxIpSecureRoutingTcp`]) — no tunnelling, but TCP is present because
//!   every KNX IP Secure profile must announce Core v2 (03/08/09 §2.5.1.1 +
//!   03/08/02 Core §9.2).
//! - **KNX Data Secure** — group telegrams are encrypted end-to-end via the
//!   Secure Application Layer, independent of the IP medium. Driven by
//!   [`SecureIpDeviceBuilder`].
//!
//! These are orthogonal: ETS can enable either, both, or neither. The
//! plain-routing / plain-APDU factory default behaves like the insecure Linux
//! target.

use devices::light_switch::{
    DEVICE_DESCRIPTOR_IP_SECURE, LightSwitchParams, comm_objs::LightSwitchComObjects,
    full::easter_egg::EasterEggAugment,
};
use zweidraehte_device::bcus::system_b::*;
use zweidraehte_device::layers::linklayers::knxip::{
    KnxNetIpBuilder, KnxNetIpDefinition, features::KnxIpSecureRoutingTcp,
};
use zweidraehte_device::prelude::*;
use zweidraehte_platform::{LinuxIpPlatform, LinuxIpTransport};

use support::storage::{FileSecureIdentity, JsonStorage, LinuxSiatStore};
use support::util::GetrandomRng;
use zweidraehte_device::storage::{SecureStorage, StaticIdentity};

// ============================================================================
// Capacity knobs
// ============================================================================

/// Feature set: the `KnxIpSecureRoutingTcp` preset — KNX/IP routing + remote
/// config + **IP Secure** + TCP, without tunnelling. TCP is mandatory for a
/// secure device (Core v2, 03/08/09 §2.5.1.1 + 03/08/02 §9.2), so the preset
/// parameter sizes a real secure-session pool: one session, matching the one
/// TCP stream `MAX_TCP_STREAMS` defaults to for a tunnel-less device.
type SecureRoutingTcp = KnxIpSecureRoutingTcp<1>;

#[derive(Clone, Copy)]
pub struct LinuxEthSecureLightSwitchDefinition;

/// Standard combined KNX/IP Secure and Data Secure stack. Its defaults match
/// this routing-only device: no P2P key table, one password, no tunnel users.
pub type LinuxEthSecureLightSwitch = SecureIp<LinuxEthSecureLightSwitchDefinition>;

/// Nominal state spelling for the state-parameterized JSON config store.
pub type LightSwitchSecureState = SecureIpInterfaceStateFor<LinuxEthSecureLightSwitch, SecureRoutingTcp, 0, 1, 0>;

/// On-stack persistent storage: the JSON-file config backend plus the
/// file-backed sequence/SIAT store, in the framework's [`SecureStorage`]
/// composite. It supplies `HasSeqStore` (how the secure layers reach the SIAT)
/// *and* `HasConfigStore` + `StorageHooks`, so the shared `storage_task` drives
/// config persistence and restart handling here as on the embedded targets.
pub type LightSwitchSecureStorage = SecureStorage<JsonStorage<LightSwitchSecureState, StaticIdentity>, LinuxSiatStore>;

// ============================================================================
// Standard stack inputs
// ============================================================================

pub struct LinuxEthSecureLightSwitchHooks;

impl DeviceHooks for LinuxEthSecureLightSwitchHooks {
    type Augments<'a, D: StackDefinition> = EasterEggAugment;

    fn create_augments<'a, D: StackDefinition>(
        _state: &'a D::State,
        _platform: &'a D::Platform,
        _layer_ctx: &'a zweidraehte_device::context::layer::LayerContext<D>,
    ) -> Self::Augments<'a, D> {
        EasterEggAugment
    }
}

// IP-specific link-layer bill of materials. Routing-only device on UDP + TCP
// (TCP is mandatory for a secure profile — see the feature-set alias above).
// `type Rng` is required by `SecureIpDeviceBuilder` (`NoRng` is rejected) and
// feeds the Secure Application Layer's `S-A_Sync` challenges plus IP Secure
// session nonces.
impl KnxNetIpDefinition for LinuxEthSecureLightSwitchDefinition {
    type Transport = LinuxIpTransport;
    type Features = SecureRoutingTcp;
    type Rng = GetrandomRng;
}

impl DeviceDefinition for LinuxEthSecureLightSwitchDefinition {
    const DEVICE: &'static DeviceDescriptor = &DEVICE_DESCRIPTOR_IP_SECURE;

    type Rng = GetrandomRng;
    type Platform = LinuxIpPlatform;
    type Params = LightSwitchParams;
    type ComObjects = LightSwitchComObjects;
    type LinkLayer = KnxNetIpBuilder<LinuxEthSecureLightSwitch>;
    // File-backed secure identity: serial number + FDSK, provisioned on first
    // run so the key is not baked into the binary.
    type Identity = FileSecureIdentity;
    type Storage = &'static LightSwitchSecureStorage;
    type Hooks = LinuxEthSecureLightSwitchHooks;
}
