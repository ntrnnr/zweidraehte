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
    DEVICE_DESCRIPTOR_IP_SECURE, LightSwitchParams, comm_objs::LightSwitchComObjects, easter_egg::EasterEggAugment,
};
use zweidraehte_device::bcus::system_b::*;
use zweidraehte_device::layers::linklayers::knxip::{
    KnxNetIpBuilder, KnxNetIpDefinition, features::KnxIpSecureRoutingTcp,
};
use zweidraehte_device::layers::transport::TlStyle;
use zweidraehte_device::prelude::*;
use zweidraehte_device::storage::SeqStorageFor;
use zweidraehte_platform::{LinuxIpPlatform, LinuxIpTransport};

use support::storage::{FileSecureIdentity, JsonStorage, LinuxSiatStore};
use support::util::GetrandomRng;
use zweidraehte_device::storage::{SecureStorage, StaticIdentity};

// ============================================================================
// Capacity knobs
// ============================================================================

/// P2P key table capacity. Group-only device with no secure P2P traffic, so
/// zero — matches the RP2040 secure light switch (`P2P_SIZE = 0`).
const P2P_SIZE: usize = 0;

/// IP Secure password-hash table capacity. One slot for the management user,
/// which backs the DAC / `SESSION_RESPONSE` path.
const MAX_PW: usize = 1;

/// IP Secure tunnelling-user table capacity. Zero — this device does no secure
/// tunnelling (routing-only secure; tunnelling is optional for a KNX IP end
/// device per 03/08/09 §2.5.1.1).
const MAX_TU: usize = 0;

/// Feature set: the `KnxIpSecureRoutingTcp` preset — KNX/IP routing + remote
/// config + **IP Secure** + TCP, without tunnelling. TCP is mandatory for a
/// secure device (Core v2, 03/08/09 §2.5.1.1 + 03/08/02 §9.2), so the preset
/// parameter sizes a real secure-session pool: one session, matching the one
/// TCP stream `MAX_TCP_STREAMS` defaults to for a tunnel-less device.
type SecureRoutingTcp = KnxIpSecureRoutingTcp<1>;

/// Device state: System B tables + the Data-Secure wrapper around the IP
/// **Secure** interface extension (PIDs 91–97), realised through the
/// `SecureIpInterfaceStateFor` alias.
pub type LightSwitchSecureState =
    SecureIpInterfaceStateFor<LinuxEthSecureLightSwitch, SecureRoutingTcp, P2P_SIZE, MAX_PW, MAX_TU>;

/// On-stack persistent storage: the JSON-file config backend plus the
/// file-backed sequence/SIAT store, in the framework's [`SecureStorage`]
/// composite. It supplies `HasSeqStore` (how the secure layers reach the SIAT)
/// *and* `HasConfigStore` + `StorageHooks`, so the shared `storage_task` drives
/// config persistence and restart handling here as on the embedded targets.
pub type LightSwitchSecureStorage = SecureStorage<JsonStorage<LightSwitchSecureState, StaticIdentity>, LinuxSiatStore>;

// ============================================================================
// StackDefinition
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub struct LinuxEthSecureLightSwitch;

/// Security augment type alias — produced by the secure extension for
/// `LinuxEthSecureLightSwitch`. It carries the Security IO (IOT 0x11) plus the
/// IP medium + IP Secure objects. The `SEQ` slot is the stack's own sequence
/// store, projected via `SeqStorageFor`.
type SecAugment<'a> = SecureAugmentBundle<
    'a,
    <IpSecureInterfaceExtensionFor<SecureRoutingTcp, MAX_PW, MAX_TU> as Extension<LinuxIpPlatform>>::Augment<
        'a,
        LinuxEthSecureLightSwitch,
    >,
    SeqStorageFor<LinuxEthSecureLightSwitch>,
    { <LinuxEthSecureLightSwitch as SystemBStackDefinition>::ADT_ENTRIES },
    P2P_SIZE,
    { <LinuxEthSecureLightSwitch as SystemBStackDefinition>::COT_ENTRIES },
>;

/// Augment chain: KNX Data Secure augment (Security IO 0x11) + the IP medium /
/// IP Secure augment, plus the Easter Egg demo augment. The secure augment
/// bundles the IP augment internally (the secure extension wraps the IP Secure
/// interface extension), so there is no separate `ip:` field as on the insecure
/// target.
#[derive(zweidraehte_device::service::ServiceRegistry)]
pub struct LightSwitchSecureAugments<'a> {
    #[service(augment)]
    sec: SecAugment<'a>,
    #[service(augment)]
    easter: EasterEggAugment,
}

// IP-specific link-layer bill of materials. Routing-only device on UDP + TCP
// (TCP is mandatory for a secure profile — see the feature-set alias above).
// `type Rng` is required by `SecureIpDeviceBuilder` (`NoRng` is rejected) and
// feeds the Secure Application Layer's `S-A_Sync` challenges plus IP Secure
// session nonces.
impl KnxNetIpDefinition for LinuxEthSecureLightSwitch {
    type Transport = LinuxIpTransport;
    type Features = SecureRoutingTcp;
    type Rng = GetrandomRng;
}

zweidraehte_device::system_b_standard_stack! {
    stack: LinuxEthSecureLightSwitch,
    device: &DEVICE_DESCRIPTOR_IP_SECURE,
    tl_style: TlStyle::Style3,
    params: LightSwitchParams,
    com_objects: LightSwitchComObjects,
    link_layer_builder: KnxNetIpBuilder<LinuxEthSecureLightSwitch>,
    platform: LinuxIpPlatform,
    // Data Secure wrapper around the IP Secure interface extension. `GRP`/`GO`
    // are entry counts (one group key slot per address table entry, one flag
    // byte per communication object), matching `SecureIpInterfaceStateFor`'s
    // invariant.
    extension_state: SecureExtensionState<
        IpSecureInterfaceExtensionFor<SecureRoutingTcp, MAX_PW, MAX_TU>,
        { Self::ADT_ENTRIES },
        P2P_SIZE,
        { Self::COT_ENTRIES },
    >,
    state: LightSwitchSecureState,
    al_extensions: zweidraehte_device::layers::application::services::SystemBSecureAlServices,
    layer_builder: SecureIpDeviceBuilder,
    // The IP Secure FDSK seed is built in `main` and threaded through
    // `StateInit`. `SecureResources::inner` is the IP Secure extension's own
    // `IpSecureResources { fdsk }`.
    resources: SecureResources<IpSecureInterfaceExtensionFor<SecureRoutingTcp, MAX_PW, MAX_TU>>,
    augments: {
        bundle: LightSwitchSecureAugments,
        create: |state, platform, layer_ctx| LightSwitchSecureAugments {
            sec: state.extension_state().create_secure_augment(platform, layer_ctx),
            easter: EasterEggAugment,
        },
    },
    extra {
        // File-backed secure identity: serial number + FDSK, provisioned to
        // `secure_device_identity.json` on first run so the key is not baked
        // into the binary.
        type Identity = FileSecureIdentity;
        // OS CSPRNG (getrandom).
        type Rng = GetrandomRng;
        // Config blob + the file-backed sequence/SIAT store, wired onto the
        // LayerContext: the secure layers pull the SIAT store out through
        // `HasSeqStore`, and the storage task the config through
        // `HasConfigStore`.
        type Storage = &'static LightSwitchSecureStorage;
    },
}
