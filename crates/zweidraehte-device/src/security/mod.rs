//! Security extension: persistent state, augment, and composable wrappers.
//!
//! Adds the KNX Data Secure Security Interface Object (Object Type 0x11)
//! to a device. KNX Data Security is a *profile module* (06 Profiles
//! v02.02.01 §9.1 "Profile Module S-AL") composed onto a base profile
//! rather than a profile of its own, so nothing here names a BCU family:
//! the medium extension it wraps is a type parameter of
//! [`SecureExtensionState`], and the device state it attaches to reaches
//! it through `HasExtensionState`. Each family contributes only its own
//! aliases, re-exported from its `bcus::*` root: which medium extension
//! each secure state wraps, and how the security table capacities fall
//! out of that family's table sizes.
//!
//! # Architecture
//!
//! Non-secure devices are unaffected. Security is opt-in:
//!
//! ```text
//! SecureExtensionState<Tp1ExtensionState, 64, 8, 32>
//!   ├── inner: Tp1ExtensionState           (medium-specific state)
//!   └── security: SecurityState<64, 8, 32> (security tables + mode)
//!
//! Extension::create_augment() produces:
//!   SecureAugmentBundle {
//!       inner:    Inner::Augment<'a, D>,    (e.g. &Tp1ExtensionState)
//!       security: SecurityAugment<'a, …>,
//!   }
//! ```
//!
//! `SecureAugmentBundle` is a `#[derive(ServiceRegistry)]` struct, so
//! it implements [`Augment<D>`](crate::service::Augment)
//! directly via the macro-emitted forwarding chain. Devices that don't
//! compose any extra augments can spell `type Augments<'a> = <Self::ES
//! as Extension<Self::Platform>>::Augment<'a, Self>` and let the runner
//! call `state.extension_state().create_augment::<Self>(platform)`.
//!
//! # Const Generics
//!
//! - `GRP`: Max Group Key Table entries (typically matches association table size)
//! - `P2P`: Max P2P Key Table entries (zero for group-only secure devices)
//! - `GO`: Max GO security flag entries (typically matches communication object count)
//!
//! The Security Individual Address Table is **not** a const generic on the
//! secure extension. Its capacity is the `N` of the
//! [`SiatStore`](crate::storage::views::SiatStore) chosen for the `SEQ` type parameter
//! — the SIAT is the sequence store (one LastValidSeqNr slot per non-tool secure
//! sender IA, 03/03/07 §5.3), not a separate table.

mod augment;

pub use augment::SecurityAugment;
// Array-property read/write helpers shared with the IP Secure augment
// (PIDs 93/97 use the same SecurityTable count semantics). That augment
// lives under `bcus::system_b::extensions::ip`, so the visibility is
// crate-wide rather than scoped to one module subtree.
#[cfg(feature = "ip-secure")]
pub(crate) use augment::{read_table_with_count_probe, write_security_table};
use zweidraehte_proto::messages::knx::RequiredSecurity;

use serde::{Deserialize, Serialize};

use crate::HasSecurityMode;
use crate::StackDefinition;
use crate::extension::{Extension, ExtensionConfig, ExtensionState};
use crate::objects::comm::HasGoSecurityView;
use crate::objects::interface::{HasDomainAddress, HasMaxRetryCount, HasRfDomainAddress, HasRfRetransmitter};
use crate::objects::tables::LoadState;
use crate::restart::EraseCode;
use crate::state::{HasSecurityState, SecurityFailureEntry, SecurityFailureType};
use crate::storage::SequenceNumberStorage;
use crate::storage::views::SiatAccess;

// ============================================================================
// Shared Data Secure core
// ============================================================================
//
// The tables, the persisted configuration, the runtime state and the failures
// log are `zweidraehte_proto::security`: KNX Data Security is a profile module
// composed onto a base profile, so none of it is System B's, System 7's, or
// even this crate's. What stays here is the part that *is* device-stack
// vocabulary — how the security state participates in this crate's extension
// persistence model, and how it answers the capability traits the object
// dispatch layer bounds on.
//
// Re-exported rather than merely imported so the established
// `bcus::system_b::…` / `crate::security::…` paths keep resolving.

pub use zweidraehte_proto::security::{SecurityConfig, SecurityFailuresLog, SecurityState, SecurityTable};

impl<const GRP: usize, const P2P: usize, const GO: usize> ExtensionConfig for SecurityConfig<GRP, P2P, GO> {}

impl<const GRP: usize, const P2P: usize, const GO: usize> HasSecurityMode for SecurityState<GRP, P2P, GO> {
    fn security_mode_enabled(&self) -> bool {
        SecurityState::security_mode_enabled(self)
    }

    fn log_access_denied(&self, source_addr: u16) {
        self.failures_log().borrow_mut().log_failure(SecurityFailureType::AccessError, source_addr, &[]);
    }

    fn has_group_key(&self, tsap: u16) -> bool {
        self.group_key_for_index(tsap).is_some()
    }
}

// ============================================================================
// Composed Extension — wraps a medium extension with security
// ============================================================================

/// Composed extension state that wraps a medium extension (TP1 or IP)
/// with Data Secure support.
///
/// The inner extension handles medium-specific state (e.g., TP1 retry
/// count, IP configuration). The security state handles the Security
/// Interface Object. Both are persisted independently.
///
/// # Non-Secure Devices
///
/// Devices that don't need Data Secure simply use the inner extension
/// directly (e.g., `Tp1ExtensionState`). This wrapper is only used
/// when security is desired.
pub struct SecureExtensionState<Inner: ExtensionState, const GRP: usize, const P2P: usize, const GO: usize> {
    /// The medium-specific extension state.
    pub inner: Inner,
    /// The security extension state.
    pub security: SecurityState<GRP, P2P, GO>,
    /// Factory Default Setup Key.
    ///
    /// This is the extension's runtime copy of the FDSK. It is consumed
    /// from [`SecureResources`] at construction and re-applied to the
    /// security store on every factory reset (03/05/01 §6.1.4) — that
    /// reseed happens in `on_erase`, which only sees `&self`, hence the
    /// copy. The factory source stays on the device identity
    /// ([`SecureDeviceIdentity::fdsk`](crate::storage::SecureDeviceIdentity::fdsk)).
    fdsk: [u8; 16],
}

// The secure wrapper is transparent to the medium-specific accessor traits: it
// forwards each to the inner extension so the device state's own forwarding
// impls stay satisfied whether or not a device is wrapped in Data
// Secure. `HasMaxRetryCount` (TP1), `HasDomainAddress` (the generic Domain
// Address used by `A_DomainAddressSerialNumber`), `HasRfDomainAddress` (RF
// Medium Object PID 56, required by the KNX-RF link layer's context trait), and
// `HasRfRetransmitter` (RF Medium Object PID 57 / Device Object PID 74, required
// by the `RetransmitEnabled` link layer) are all pure delegations.
// `forward_to_field!` generates the delegation to `self.inner`; the wrapper
// takes no persistence side-effect here (the device state above is what
// marks dirty). The six-parameter
// generic header — `Inner: ExtensionState + <bound>` plus `SEQ` and the
// four table-size consts — is the same for every forwarded trait; only the
// `<bound>` and the method set vary. There is no `mark_dirty` on a secure
// wrapper, so no `mark_dirty` suffix.
forward_to_field! {
    impl<[
        Inner: ExtensionState + HasMaxRetryCount,
        const GRP: usize, const P2P: usize, const GO: usize,
    ]> HasMaxRetryCount for SecureExtensionState<Inner, GRP, P2P, GO> {
        get fn max_retry_count(&self) -> u8;
        set fn set_max_retry_count(&self, value: u8);
    } => self.inner
}

forward_to_field! {
    impl<[
        Inner: ExtensionState + HasDomainAddress,
        const GRP: usize, const P2P: usize, const GO: usize,
    ]> HasDomainAddress for SecureExtensionState<Inner, GRP, P2P, GO> {
        const DOMAIN_ADDRESS_LENGTH: usize = Inner::DOMAIN_ADDRESS_LENGTH;
        out fn domain_address(&self, buf: &mut [u8]);
        set fn set_domain_address(&self, addr: &[u8]);
    } => self.inner
}

forward_to_field! {
    impl<[
        Inner: ExtensionState + HasRfDomainAddress,
        const GRP: usize, const P2P: usize, const GO: usize,
    ]> HasRfDomainAddress for SecureExtensionState<Inner, GRP, P2P, GO> {
        get fn rf_domain_address(&self) -> [u8; 6];
        set fn set_rf_domain_address(&self, addr: &[u8; 6]);
    } => self.inner
}

forward_to_field! {
    impl<[
        Inner: ExtensionState + HasRfRetransmitter,
        const GRP: usize, const P2P: usize, const GO: usize,
    ]> HasRfRetransmitter for SecureExtensionState<Inner, GRP, P2P, GO> {
        get fn rf_retransmit_enabled(&self) -> bool;
        set fn set_rf_retransmit_enabled(&self, value: bool);
        get fn rf_repeat_counter_limit(&self) -> u8;
        set fn set_rf_repeat_counter_limit(&self, value: u8);
    } => self.inner
}

// ----------------------------------------------------------------------------
// KNX/IP medium-accessor forwarding
// ----------------------------------------------------------------------------
//
// The four KNX/IP link-layer accessor traits (`HasIpExtensionState`,
// `HasRoutingMulticastRebind`, `HasAdditionalIas`, `HasIpSecureView`)
// follow the same conditional-forwarding shape as the medium accessors
// above (`HasDomainAddress` etc.): the impl applies only when `Inner`
// itself provides the trait, so wrapping a TP1/RF extension simply
// doesn't pick them up, while wrapping an IP (Secure) interface extension
// does. They are hand-written rather than `forward_to_field!`-generated
// because they return `&dyn` views / channel references and carry
// default-bodied methods the macro doesn't model.
//
// These let `SecureExtensionState<IpSecureInterfaceExtension<...>, ...>`
// (KNX Data Secure over KNX IP Secure, used by `SecureIpDeviceBuilder`)
// satisfy the IP link layer's `ES` bounds — the composition documented on
// `IpSecureInterfaceExtension`.

#[cfg(feature = "knxip")]
impl<Inner: ExtensionState + crate::ip::HasIpExtensionState, const GRP: usize, const P2P: usize, const GO: usize>
    crate::ip::HasIpExtensionState for SecureExtensionState<Inner, GRP, P2P, GO>
{
    fn ip_state(&self) -> &dyn crate::ip::IpStateView {
        self.inner.ip_state()
    }
}

// The macro names the implemented trait by bare ident, so import it here
// (under the same cfg gate as the impl).
#[cfg(feature = "knxip")]
use crate::ip::HasRoutingMulticastRebind;

#[cfg(feature = "knxip")]
forward_to_field! {
    impl<[
        Inner: ExtensionState + HasRoutingMulticastRebind,
        const GRP: usize, const P2P: usize, const GO: usize,
    ]> HasRoutingMulticastRebind for SecureExtensionState<Inner, GRP, P2P, GO> {
        ref fn routing_multicast_rebind_channel(&self)
            -> &embassy_sync::channel::Channel<embassy_sync::blocking_mutex::raw::NoopRawMutex, core::net::Ipv4Addr, 2>;
    } => self.inner
}

#[cfg(feature = "knxip")]
impl<Inner: ExtensionState + crate::ip::HasAdditionalIas, const GRP: usize, const P2P: usize, const GO: usize>
    crate::ip::HasAdditionalIas for SecureExtensionState<Inner, GRP, P2P, GO>
{
    fn write_additional_ias_into(&self, buf: &mut [zweidraehte_proto::address::IndividualAddress]) -> usize {
        self.inner.write_additional_ias_into(buf)
    }

    fn additional_ia_is_assigned(&self, addr: zweidraehte_proto::address::IndividualAddress) -> bool {
        self.inner.additional_ia_is_assigned(addr)
    }
}

#[cfg(feature = "knxip")]
impl<Inner: ExtensionState + crate::ip::HasIpSecureView, const GRP: usize, const P2P: usize, const GO: usize>
    crate::ip::HasIpSecureView for SecureExtensionState<Inner, GRP, P2P, GO>
{
    fn ip_secure_view(&self) -> Option<&dyn crate::ip::IpSecureStateView> {
        self.inner.ip_secure_view()
    }
}

impl<Inner: ExtensionState, const GRP: usize, const P2P: usize, const GO: usize> HasSecurityState
    for SecureExtensionState<Inner, GRP, P2P, GO>
{
    fn security_load_state(&self) -> LoadState {
        self.security.load_state()
    }

    fn tool_key(&self) -> [u8; 16] {
        self.security.tool_key()
    }

    fn group_key_for_index(&self, ga_index: u16) -> Option<[u8; 16]> {
        self.security.group_key_for_index(ga_index)
    }

    fn go_security_flags_for(&self, go_index: u16) -> Option<u8> {
        self.security.go_security_flags_for(go_index)
    }

    fn p2p_key_for_index(&self, ia_index: u16) -> Option<([u8; 16], u16)> {
        self.security.p2p_key_for_index(ia_index)
    }

    fn log_security_failure(&self, failure_type: SecurityFailureType, source_addr: u16, frame_fragment: &[u8]) {
        self.security.failures_log().borrow_mut().log_failure(failure_type, source_addr, frame_fragment);
        let prev = self.security.security_report();
        self.security.set_security_report(prev | 0x01);
    }

    fn security_report(&self) -> u8 {
        self.security.security_report()
    }

    fn security_report_enabled(&self) -> bool {
        self.security.security_report_enabled()
    }

    fn failure_counters(&self) -> [u8; 8] {
        self.security.failures_log().borrow().counters_as_bytes()
    }

    fn failure_entry(&self, index: u8) -> Option<SecurityFailureEntry> {
        self.security.failures_log().borrow().get_by_index(index).copied()
    }

    fn clear_failure_log(&self) {
        self.security.failures_log().borrow_mut().clear();
    }
}

// ============================================================================
// HasGoSecurityView — secure transmit-side policy
// ============================================================================
//
// Supplies the per-destination required security level that the plain
// Application Layer stamps on outbound buffers via
// `MessageBuilder::with_required_security`. The S-AL reads the stamp at
// outbox drain to apply the §5.5.3.x decision tree.
//
// This is the transmit-side counterpart of the receive-side check
// already implemented in [`SecureApplicationLayer::check_go_security_flags`].
// Both sides consult `PID_GO_SECURITY_FLAGS` (0-based) for groups; both
// must agree on the bit-to-level mapping below.
impl<Inner: ExtensionState, const GRP: usize, const P2P: usize, const GO: usize> HasGoSecurityView
    for SecureExtensionState<Inner, GRP, P2P, GO>
{
    fn required_security_for_asap(&self, go_slot: u16) -> RequiredSecurity {
        // At this level the argument is already the 0-based GO-flags table
        // slot. Which wire ASAP that corresponds to depends on the hosting
        // family's numbering base (`StackDefinition::FIRST_ASAP` — 1 for
        // System B, 0 for System 7's group object table), and the extension state
        // does not know its family — so the device state's forwarding impl
        // performs the `asap - FIRST_ASAP` translation before this is
        // reached. Keying the table positionally matches how
        // `secure_stack_config!` lays the flags down (element n for the
        // group object in table slot n, 03/05/01 §6.3.15).
        let go_index = go_slot;

        // Absent entries → no security required for this GO. Spec §6.3.15
        // permits divergent flags across ASAPs sharing a GA — by indexing
        // off the originating ASAP we get the correct level for *this*
        // sending GO regardless of what ETS wrote for siblings.
        let Some(flag) = self.security.go_security_flags_for(go_index) else {
            return RequiredSecurity::Plain;
        };

        // Bits are: b0 = auth, b1 = conf (03/05/01 §6.3.15.3). The
        // (auth=0, conf=1) combination is reserved/undefined — degrade to
        // plaintext rather than silently mismatching the receiver, mirroring
        // how `check_go_security_flags` treats absent entries.
        match flag & 0b11 {
            0b00 => RequiredSecurity::Plain,
            0b01 => RequiredSecurity::Auth,
            0b11 => RequiredSecurity::AuthConf,
            _ => RequiredSecurity::Plain,
        }
    }

    // `required_security_for_p2p` is deliberately left at the trait default
    // (Plain). Per 03/03/07 §5.5.3.4 a peer with a P2P key entry is mandatory
    // Auth+Conf, but deciding that needs the peer's IA_Index, and the SIAT that
    // resolves it lives in the sequence-number store rather than in the
    // extension state. The one place that has both — the S-AL's
    // `encrypt_spontaneous` — already makes this decision from the same table
    // when it looks the key up, so nothing is lost by not answering it a
    // second time from here.

    fn required_security_for_broadcast(&self) -> RequiredSecurity {
        // Spontaneous broadcasts that the spec marks as Plain (notably the
        // `A_NetworkParameter_InfoReport` security report per §6.3.11.4)
        // call the spontaneous helper directly with `RequiredSecurity::Plain`.
        // Reactive broadcast responses (e.g. `IndividualAddressResponse`)
        // inherit their stamp from the indication via the call site
        // chaining `.with_required_security(ind.required_security())`.
        RequiredSecurity::Plain
    }

    fn required_security_for_tool_access(&self) -> RequiredSecurity {
        // Spontaneous tool-channel sends are Auth+Conf only when the device
        // has been commissioned (security mode set, tool key non-zero). In
        // factory state the tool channel is plain.
        if self.security.security_mode_enabled() { RequiredSecurity::AuthConf } else { RequiredSecurity::Plain }
    }
}

/// Persisted config for the composed extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "InnerConfig: Serialize", deserialize = "InnerConfig: serde::de::DeserializeOwned"))]
pub struct SecureExtensionConfig<InnerConfig: ExtensionConfig, const GRP: usize, const P2P: usize, const GO: usize> {
    /// Medium-specific persisted config.
    pub inner: InnerConfig,
    /// Security persisted config.
    pub security: SecurityConfig<GRP, P2P, GO>,
}

impl<InnerConfig: ExtensionConfig, const GRP: usize, const P2P: usize, const GO: usize>
    SecureExtensionConfig<InnerConfig, GRP, P2P, GO>
{
    /// Compose the medium and security snapshots without exposing either
    /// component's internal fields at the device-construction boundary.
    pub fn new(inner: InnerConfig, security: SecurityConfig<GRP, P2P, GO>) -> Self {
        Self { inner, security }
    }
}

impl<InnerConfig: ExtensionConfig, const GRP: usize, const P2P: usize, const GO: usize> Default
    for SecureExtensionConfig<InnerConfig, GRP, P2P, GO>
{
    fn default() -> Self {
        Self { inner: InnerConfig::default(), security: SecurityConfig::default() }
    }
}

impl<InnerConfig: ExtensionConfig, const GRP: usize, const P2P: usize, const GO: usize> ExtensionConfig
    for SecureExtensionConfig<InnerConfig, GRP, P2P, GO>
{
}

/// Non-serialisable construction inputs for [`SecureExtensionState`].
///
/// Bundles the sequence-number storage handle (typically a platform-
/// owned resource such as shared memory or a flash sector mapping) with
/// the Factory Default Setup Key that must be baked into the initial
/// tool key. Both are required at construction time; carrying them
/// through [`ExtensionState::Resources`] removes the need for any
/// post-construction setters.
///
/// `fdsk` is non-optional here: if you are building a
/// `SecureExtensionState`, you are building a Data Secure device, and
/// a Data Secure device has an FDSK. The type system enforces this via
/// the [`SecureDeviceIdentity`](crate::storage::SecureDeviceIdentity)
/// bound at the device-state construction site.
pub struct SecureResources<Inner: ExtensionState> {
    /// Inner extension's own resources (e.g. `()` for TP1).
    pub inner: Inner::Resources,
    /// Factory Default Setup Key. Becomes the initial tool key on a
    /// factory-fresh device and is re-applied by `factory_reset`.
    pub fdsk: [u8; 16],
}

impl<Inner: ExtensionState> SecureResources<Inner>
where
    Inner::Resources: Default,
{
    /// Build resources for a leaf secure device whose inner medium extension
    /// needs no resources of its own (`Inner::Resources` defaults — e.g. `()`
    /// for TP1/RF). Mirrors [`SystemBStateInit::new`](crate::bcus::system_b::SystemBStateInit::new)
    /// so the `inner: Default::default()` field never has to be spelled at the
    /// call site. Devices whose inner *does* carry resources (e.g. the IP Secure
    /// interface's `IpSecureResources`) construct the struct directly instead.
    pub fn simple(fdsk: [u8; 16]) -> Self {
        Self { inner: Default::default(), fdsk }
    }
}

impl<Inner: ExtensionState, const GRP: usize, const P2P: usize, const GO: usize> ExtensionState
    for SecureExtensionState<Inner, GRP, P2P, GO>
{
    type Config = SecureExtensionConfig<Inner::Config, GRP, P2P, GO>;
    type Resources = SecureResources<Inner>;

    fn from_config(config: Self::Config, resources: Self::Resources) -> Self {
        let security = SecurityState::from_config(config.security);
        // A factory-fresh device (or one that just came out of
        // `factory_reset`) carries a zero tool key in its config; seed
        // the FDSK here so the device starts life with FDSK as the
        // active tool key (spec 03/05/01 §6.1.4). If the persisted
        // config already holds a non-zero key, ETS has written one and
        // we keep it.
        if security.tool_key() == [0u8; 16] {
            security.reset_tool_key_to_fdsk(resources.fdsk);
        }

        Self { inner: Inner::from_config(config.inner, resources.inner), security, fdsk: resources.fdsk }
    }

    fn to_config(&self) -> Self::Config {
        SecureExtensionConfig::new(self.inner.to_config(), self.security.to_config())
    }

    fn on_erase(&self, code: EraseCode) {
        // Wrapper pass-through contract: the inner (medium) extension
        // sees *every* erase code, not just the factory resets — it
        // decides for itself which codes are relevant. The security
        // handling below is purely additive.
        self.inner.on_erase(code);

        match code {
            EraseCode::FactoryReset | EraseCode::FactoryResetKeepIA => {
                // 03/05/01's master-reset tables split the two factory
                // resets on exactly two resources. "Reset to default
                // state" (02h) makes the tool key inactive (§6.3.10 —
                // §6.1.4 then has the FDSK become the active key again)
                // and disables the Security Mode (§6.3.5.4); "Reset to
                // default without IA" (07h) leaves both "not influenced".
                // Everything else the reset touches — the P2P and group
                // key tables (§6.3.6/§6.3.7), the SIAT (§6.3.8), the GO
                // security flags, the failures log (§6.3.9), the report
                // and its control (§6.3.11/§6.3.12) — is cleared by both.
                //
                // TSS J 3.8.13.6 keeps writing under TK1 across a 07h and
                // only switches to the FDSK after the 02h; 3.8.8.7's
                // acceptance says the Security Mode "is unchanged … for
                // factory reset without IA".
                let keep = (code == EraseCode::FactoryResetKeepIA)
                    .then(|| (self.security.tool_key(), self.security.security_mode_enabled()));

                self.security.factory_reset();

                // The extension owns its own copy of the FDSK (moved in
                // via `SecureResources`), so it can self-reset without any
                // parameter plumbing from `SystemBDeviceState`.
                let (tool_key, security_mode) = keep.unwrap_or((self.fdsk, false));
                self.security.reset_tool_key_to_fdsk(tool_key);
                if security_mode {
                    self.security.set_security_mode_enabled(true);
                }

                // The sending-SeqNr near-exhaustion re-init (03/05/01 §6.1.4 +
                // AN194) is the storage layer's slice of this erase: the
                // stores struct's composed `StorageHooks::erase` handles it
                // when the storage task applies the code to the durable
                // regions.
            }
            EraseCode::ResetLinks => {
                // Report cleared, control untouched — the one erase code
                // where §6.3.11 and §6.3.12 diverge.
                self.security.clear_security_report_only();
            }
            _ => {}
        }
    }
}

impl<Inner: ExtensionState, const GRP: usize, const P2P: usize, const GO: usize> HasSecurityMode
    for SecureExtensionState<Inner, GRP, P2P, GO>
{
    fn security_mode_enabled(&self) -> bool {
        self.security.security_mode_enabled()
    }

    fn log_access_denied(&self, source_addr: u16) {
        self.security.log_access_denied(source_addr);
    }

    fn has_group_key(&self, tsap: u16) -> bool {
        self.security.has_group_key(tsap)
    }
}

// ============================================================================
// Augment bundle — composes the inner medium augment with `SecurityAugment`
// ============================================================================

/// The augment chain that a Data-Secure stack exposes: the inner
/// medium augment (TP1 retry-count borrow, IP Parameter Object, …)
/// plus the [`SecurityAugment`] driving Security IO 0x11.
///
/// The macro-derived [`Augment<D>`](crate::service::Augment)
/// impl walks the two fields in declaration order: the inner medium
/// augment first, then security. Devices use the chain transparently
/// — they don't need to construct this struct themselves; the
/// [`Extension::create_augment`] impl below builds it from a
/// `SecureExtensionState` instance.
#[derive(crate::service::ServiceRegistry)]
pub struct SecureAugmentBundle<
    'a,
    InnerAugment,
    SEQ: SequenceNumberStorage + SiatAccess,
    const GRP: usize,
    const P2P: usize,
    const GO: usize,
> {
    #[service(augment)]
    pub inner: InnerAugment,
    #[service(augment)]
    pub security: SecurityAugment<'a, SEQ, GRP, P2P, GO>,
}

// ============================================================================
// Augment construction — pulls the SIAT store from the layer context
// ============================================================================

impl<Inner: ExtensionState, const GRP: usize, const P2P: usize, const GO: usize>
    SecureExtensionState<Inner, GRP, P2P, GO>
{
    /// Build the secure augment bundle: the inner medium augment plus the
    /// [`SecurityAugment`] driving Security IO 0x11.
    ///
    /// An inherent method (not `Extension::create_augment`) because the
    /// Security IO's SIAT/SeqNr PIDs need the storage-layer-owned sequence
    /// store, pulled from the layer context's storage handle — a bound
    /// (`D::Storage: HasSeqStore`) the `Extension` trait's method signature
    /// cannot carry. Device `augments:` closures call this with the
    /// `layer_ctx` they already receive.
    pub fn create_secure_augment<'a, D, Platform>(
        &'a self,
        platform: &'a Platform,
        layer_ctx: &'a crate::context::layer::LayerContext<D>,
    ) -> SecureAugmentBundle<'a, Inner::Augment<'a, D>, crate::storage::SeqStorageFor<D>, GRP, P2P, GO>
    where
        D: StackDefinition,
        D::Storage: crate::storage::HasSeqStore,
        Inner: Extension<Platform>,
    {
        use crate::storage::HasSeqStore as _;
        SecureAugmentBundle {
            inner: self.inner.create_augment::<D>(platform),
            security: SecurityAugment::new(&self.security, layer_ctx.storage.seq_store()),
        }
    }
}

/// Expansion of the `security:` block of
/// [`knx_stack_config!`](crate::knx_stack_config) — the Data Secure
/// constants and the `create_security_config()` constructor.
///
/// Lives next to [`SecurityConfig`] / [`SecurityTable`] so the
/// generic config macro does not name Data Secure types; it only
/// delegates here. Invoked by `knx_stack_config!`, not by device code.
#[macro_export]
macro_rules! secure_stack_config {
    (
        name: $name:ident,
        first_asap: $first_asap:expr,
        p2p_key_capacity: $p2p_cap:expr,
        siat_capacity: $siat_cap:expr,
        tool_key: $tool_key_hex:expr,

        group_keys: {
            $($gk_tsap:expr => $gk_hex:expr),* $(,)?
        },

        go_flags: {
            $($gf_co:expr => $gf_val:expr),* $(,)?
        } $(,)?
    ) => {
        impl $name {
            /// Max P2P Key Table entries.
            ///
            /// Independent of `SIAT_CAPACITY`: the P2P Key Table only
            /// carries entries for partners with whom the device has a
            /// secure P2P link (03/05/01 §6.3.6 NOTE 98). A group-only
            /// secure device therefore has `P2P_CAPACITY = 0`.
            pub const P2P_CAPACITY: usize = $p2p_cap;

            /// Max SIAT entries.
            ///
            /// Per 03/03/07 §5.3 the Security Individual Address Table
            /// stores LastValidSeqNr for every non-tool secure sender —
            /// including senders that only write to group addresses —
            /// so this sizes the union of P2P and group-secure senders,
            /// not just P2P.
            pub const SIAT_CAPACITY: usize = $siat_cap;

            /// Number of pre-configured group key entries.
            pub const NUM_GROUP_KEYS: usize = $crate::knx_stack_config!(@count $($gk_tsap)*);

            /// Number of pre-configured GO security flag entries.
            pub const NUM_GO_FLAGS: usize = $crate::knx_stack_config!(@count $($gf_co)*);

            /// Create a pre-populated security extension config.
            ///
            /// Group keys and GO flags are built at compile time from the
            /// `security` block in `knx_stack_config!`.
            ///
            /// Capacities are entry counts: the group key table holds at
            /// most one key per group address (`NUM_GROUP_ADDRS`), the GO
            /// flags table one byte per communication object
            /// (`NUM_COMM_OBJECTS`).
            pub fn create_security_config() -> $crate::security::SecurityConfig<
                { Self::NUM_GROUP_ADDRS },
                { Self::P2P_CAPACITY },
                { Self::NUM_COMM_OBJECTS },
            > {
                use $crate::security::{SecurityConfig, SecurityTable};

                let tool_key = $crate::config::parse_hex_key::<16>($tool_key_hex);

                // Build group key table: each entry is 18 bytes (2-byte TSAP + 16-byte key).
                let mut grp_data = [[0u8; 18]; Self::NUM_GROUP_ADDRS];
                let mut _gk_idx = 0usize;
                $(
                    {
                        let tsap_bytes = ($gk_tsap as u16).to_be_bytes();
                        let key = $crate::config::parse_hex_key::<16>($gk_hex);
                        grp_data[_gk_idx][0] = tsap_bytes[0];
                        grp_data[_gk_idx][1] = tsap_bytes[1];
                        let mut ki = 0;
                        while ki < 16 {
                            grp_data[_gk_idx][2 + ki] = key[ki];
                            ki += 1;
                        }
                        _gk_idx += 1;
                    }
                )*
                let grp_keys = SecurityTable::from_entries(grp_data, _gk_idx as u16);

                // Build GO security flags table: each entry is 1 byte,
                // positional — element n carries the flags of the group
                // object at table slot n (03/05/01 §6.3.15).
                let mut go_data = [[0u8; 1]; Self::NUM_COMM_OBJECTS];
                $(
                    // The `go_flags` keys are written in the family's own
                    // ASAP numbering, which starts at `FIRST_ASAP` — 1 for
                    // System B, 0 for System 7's group object table. Subtracting it
                    // lands each flag on its own object's slot; getting the
                    // base wrong secures every object as its neighbour.
                    go_data[$gf_co - $first_asap] = [$gf_val];
                )*
                // Count of populated entries = max CO index used.
                // The GO flags table count should equal the number of comm objects
                // so that all GOs have an entry (defaulting to 0x00 = plain).
                let go_flags = SecurityTable::from_entries(go_data, Self::NUM_COMM_OBJECTS as u16);

                SecurityConfig {
                    security_mode_enabled: false,
                    tool_key,
                    load_state: $crate::objects::tables::LoadState::Unloaded,
                    failures_log: Default::default(),
                    grp_keys,
                    p2p_keys: SecurityTable::new(),
                    go_flags,
                    // A boot image reports no security failures and does
                    // not report spontaneously; both are the KNX defaults
                    // (03/05/01 §6.3.11.3, §6.3.12.3).
                    security_report: 0,
                    security_report_enabled: false,
                }
            }
        }
    };
}
