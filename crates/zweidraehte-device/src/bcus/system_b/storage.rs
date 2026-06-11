//! Persistence infrastructure and extension composition for System B devices.
//!
//! This module provides System B-specific persistence types
//! ([`DeviceConfig`], [`IpExtensionConfig`], [`ExtensionConfig`],
//! [`ExtensionState`]) and the [`Extension`] trait that unifies persistence
//! with interface object augmentation.
//!
//! # `Config` / `State` / `Resources` vocabulary
//!
//! The three suffixes carry stable meaning across the stack:
//!
//! - `*Config` — serialisable persisted form. Round-trips through `serde`.
//!   Examples: [`DeviceConfig`] (the whole-device config), [`IpExtensionConfig`],
//!   and every `*ExtensionConfig`.
//! - `*State` — runtime in-memory form with interior mutability
//!   (`Cell`/`RefCell`). Converts to/from `Config` via
//!   [`ExtensionState::from_config`] / [`ExtensionState::to_config`] at the
//!   extension level, and via [`HasDeviceConfig::to_config`] plus
//!   `SystemBDeviceState::from_config` at the device level.
//! - `*Resources` — non-persistent construction-time inputs (pre-allocated
//!   channels, `MaybeUninit` buffers, factory-programmed keys such as
//!   FDSK, platform handles). Never serialised. Fed into
//!   [`ExtensionState::from_config`] as the second argument.
//! - `*StateInit` (on [`StackDefinition::StateInit`]) — constructor-args
//!   envelope passed to [`StackDefinition::create_state`]. May carry an
//!   optional persisted snapshot from storage plus identity data (serial
//!   number, FDSK) that is not itself persisted. The `Init` suffix
//!   distinguishes it from a serialisable `*Config`.
//!
//! The generic storage traits ([`DeviceStorage`](crate::storage::DeviceStorage),
//! [`NoStorage`](crate::storage::NoStorage)) live in [`crate::storage`].
//!
//! # Two Composition Paths
//!
//! ## Persisted extensions (`Extension<Platform>`)
//!
//! For state that must survive power cycles and also contributes interface
//! object properties. Implement [`ExtensionState`] for persistence and
//! [`Extension`] for augmentation. The augment is built by
//! [`StackDefinition::create_augments`](crate::StackDefinition::create_augments)
//! via `state.extension_state().create_augment::<Self>(platform)`,
//! and passed into the IO container by the runner.
//!
//! Examples: TP1 retry count, KNX/IP config, Security Interface Object.
//!
//! ## Runtime-only augments
//!
//! For state that does NOT survive power cycles and therefore does not
//! need [`ExtensionConfig`] / [`ExtensionState`] plumbing. Store the
//! state as a field on your state type (either a custom wrapper or
//! `SystemBDeviceState`) and add the augment as a `#[service(augment)]`
//! field on the device's [`#[derive(ServiceRegistry)]`](crate::service::ServiceRegistry)
//! augment-bundle struct. Access the state from layers via a `Has*`
//! context trait.
//!
//! Examples: `OperationModeState` (diagnostic mode), `CertificationObjectAugment`.

use const_default::ConstDefault;
use serde::{Deserialize, Serialize};

/// `#[derive(ExtensionState)]` — generates the `*Config` mirror and the
/// `ExtensionState` impl from a runtime `*State` struct. Shares the trait's
/// name so a single `use` brings both into scope.
pub use zweidraehte_device_macros::ExtensionState;

use crate::{
    StackDefinition,
    objects::comm::HasGoSecurityView,
    objects::tables::{
        Table,
        addr7::AddrTab7Impl,
        app::{Application, PeiApplication},
        asso6::AssoTab6Impl,
        co7::CoTab7Impl,
    },
    restart::EraseCode,
    service::Augment,
};
use zerocopy::{Immutable, IntoBytes, KnownLayout};
use zweidraehte_proto::address::IndividualAddress;

// ============================================================================
// SystemBStateInit — boilerplate-free `StateInit` envelope for System B
// ============================================================================

/// Standard `StateInit` shape for [`SystemBDeviceState`](super::SystemBDeviceState)-based devices.
///
/// Bundles the three things every System B device's `create_state` needs:
///
/// - `identity` — factory-programmed identity, threaded into the state.
/// - `loaded_config` — `Some(snapshot)` from a previous boot, or `None` for
///   factory-fresh.
/// - `resources` — non-serialisable construction inputs for the extension
///   state. `()` for non-secure stacks; for KNX Data Secure stacks, a
///   [`SecureResources`](super::SecureResources) carrying the FDSK and a
///   sequence-number storage handle.
///
/// Pair with [`SystemBDeviceState::from_init`](super::SystemBDeviceState::from_init)
/// to collapse the boilerplate `match init.loaded_config { Some => from_config, None => new }`
/// every device used to write by hand:
///
/// ```rust,ignore
/// type StateInit = SystemBStateInit<MyIdentity, <Self::State as HasDeviceConfig>::Config>;
///
/// fn create_state(init: Self::StateInit) -> Self::State {
///     <Self::State>::from_init(init)
/// }
/// ```
///
/// Devices with a non-`()` resource type (secure stacks) use the third type
/// parameter:
///
/// ```rust,ignore
/// type StateInit = SystemBStateInit<
///     FlashSecureIdentityData,
///     <Self::State as HasDeviceConfig>::Config,
///     SecureResources<(), MySeqStorage>,
/// >;
/// ```
pub struct SystemBStateInit<I, C, R = ()> {
    /// Factory-programmed device identity.
    pub identity: I,
    /// `Some(snapshot)` from a previous boot, or `None` for factory-fresh.
    pub loaded_config: Option<C>,
    /// Non-serialisable construction inputs for the extension state.
    pub resources: R,
}

impl<I, C> SystemBStateInit<I, C, ()> {
    /// Build an init envelope for a non-secure stack (resources defaulted to `()`).
    pub fn new(identity: I, loaded_config: Option<C>) -> Self {
        Self { identity, loaded_config, resources: () }
    }
}

// ============================================================================
// HasDeviceConfig — bridge between runtime state and its serializable config
// ============================================================================

/// Trait for converting between runtime state and its serializable config.
///
/// Implemented by [`SystemBDeviceState`](super::SystemBDeviceState) to
/// enable [`DeviceStorage`](crate::storage::DeviceStorage) backends to
/// work with the runtime state type directly, internalizing the
/// conversion to/from [`DeviceConfig`].
///
/// # Contract
///
/// - [`to_config`](Self::to_config) must capture all state that survives
///   a power cycle.
/// - `from_config` (inherent, on `SystemBDeviceState`) must restore
///   state such that the device behaves identically to before the power
///   cycle (modulo volatile state like programming mode and run state).
pub trait HasDeviceConfig: Sized {
    /// The serializable config type (device-level persisted form).
    type Config: Serialize + for<'de> Deserialize<'de>;

    /// Export current runtime state to a serializable config.
    fn to_config(&self) -> Self::Config;
}

// ============================================================================
// Extension config abstraction
// ============================================================================

/// Trait for extension-specific persistent configuration.
///
/// Each extension state type has a corresponding config type that
/// implements this trait. The config is what gets serialized to storage.
/// Implementations must be serializable and provide factory defaults.
pub trait ExtensionConfig: Default + Serialize + for<'de> Deserialize<'de> {}

impl ExtensionConfig for () {}

// Tuple combinator. Aggregating extension types like
// `IpInterfaceExtension` (IP + tunnelling) carry a tuple of inner
// configs as their `ExtensionState::Config`; this blanket impl lets
// the tuple round-trip through storage without a wrapping newtype.
// `serde` already derives `Serialize` / `Deserialize` for tuples
// whose elements satisfy them, and `Default` for the unit value
// `(A::default(), B::default())` is automatic.
impl<A: ExtensionConfig, B: ExtensionConfig> ExtensionConfig for (A, B) {}

/// Runtime state for extension-specific persistent configuration.
///
/// This trait bridges the serializable config ([`ExtensionConfig`]) and
/// the runtime representation with interior mutability (`Cell`/`RefCell`
/// fields). The runtime form allows `&self` mutation through accessor
/// traits (e.g., `IpStateView`, `HasMaxRetryCount`), while the config
/// form is what gets serialized.
///
/// Devices that need multiple extension concerns (e.g., IP config +
/// custom augment state) should define a single struct that combines
/// them and implements this trait directly.
///
/// For the common leaf-extension case — where the persisted config is
/// the runtime state with `Cell`/`RefCell` unwrapped — derive this trait
/// (and its `*Config` mirror) with `#[derive(ExtensionState)]` instead of
/// hand-writing `from_config`/`to_config`/`on_erase`. The derive shares
/// this trait's name; `use crate::bcus::system_b::ExtensionState` brings
/// both the trait and the derive into scope.
pub trait ExtensionState: Sized {
    /// The serializable config type for this extension state.
    type Config: ExtensionConfig;

    /// Non-serialisable construction inputs.
    ///
    /// Bundles platform-owned handles (sequence-number storage), keys
    /// that must be baked into the extension at construction time (the
    /// FDSK for secure extensions), and similar resources that cannot
    /// live in [`Self::Config`] because they do not round-trip through
    /// serde. Extensions without such resources use `()`.
    type Resources;

    /// Create runtime state from a persisted config and construction-time
    /// resources.
    ///
    /// Callers construct `Resources` once and hand ownership over; the
    /// extension is fully valid the moment this call returns — no
    /// post-construction setters.
    fn from_config(config: Self::Config, resources: Self::Resources) -> Self;

    /// Export current runtime state to serializable config.
    fn to_config(&self) -> Self::Config;

    /// Handle an erase code from a master reset.
    ///
    /// Extensions decide per-code what to clear. Called from
    /// `SystemBDeviceState` during `factory_reset()` and `execute_reset()`.
    /// Secure extensions fold the FDSK tool-key re-seed into the
    /// `FactoryReset` arm so the caller does not need to know about it
    /// (03/05/01 §6.1.4).
    fn on_erase(&self, code: EraseCode);
}

// The empty extension state has no security policy — every send is plain.
impl HasGoSecurityView for () {}

impl ExtensionState for () {
    type Config = ();
    type Resources = ();

    fn from_config(_config: (), _resources: ()) -> Self {}

    fn to_config(&self) {}

    fn on_erase(&self, _code: EraseCode) {
        // No extension state to reset.
    }
}

// ============================================================================
// Extension — unified persistence + augmentation
// ============================================================================

/// A medium extension that contributes persistent state AND interface
/// object augmentation to the device stack.
///
/// Unifies [`ExtensionState`] (persistence) with
/// [`Augment<D>`](crate::service::Augment) (property
/// handling) into a single concept. Each extension knows how to create
/// its own augment given a reference to the platform.
///
/// # Type Parameter
///
/// `Platform` flows from [`StackDefinition::Platform`](crate::StackDefinition::Platform).
/// Extensions that need no external context (e.g., TP1) use `Platform = ()`.
/// Extensions that need platform state (e.g., IP) are generic over
/// `P: IpPlatform`.
///
/// # Implementations
///
/// - [`()`] — no extension, no augment
/// - [`Tp1ExtensionState`](super::extensions::tp1::Tp1ExtensionState) — creates a
///   [`Tp1Augment`](super::extensions::tp1::Tp1Augment) borrowing self
/// - [`IpExtensionState`](super::extensions::ip::IpExtensionState) — creates an
///   [`IpAugment`](super::extensions::ip::IpAugment) from self + platform
pub trait Extension<Platform = ()>: ExtensionState {
    /// The augment type this extension creates.
    ///
    /// Bound is [`Augment<D>`](crate::service::Augment)
    /// — the trait surface the IO container dispatches through.
    /// Leaf augments satisfy it via `#[interface_object_augment]`
    /// codegen; composed bundles satisfy it via
    /// [`#[derive(ServiceRegistry)]`](crate::service::ServiceRegistry);
    /// the `()` impl covers the no-augment case.
    ///
    /// For TP1: `Tp1Augment<'a>` (borrows the extension state).
    /// For IP: `IpAugment<'a, P, CAPS>` (wraps extension + platform).
    /// For `Secure(Inner)`: `SecureAugmentBundle<'a, Inner::Augment, …>`
    ///   (a `#[derive(ServiceRegistry)]` struct holding the inner
    ///   augment plus `SecurityAugment`).
    /// For `()`: `()` (no augmentation).
    type Augment<'a, D: StackDefinition>: Augment<D>
    where
        Self: 'a,
        Platform: 'a;

    /// Create the augment from this extension state and the platform.
    fn create_augment<'a, D: StackDefinition>(&'a self, platform: &'a Platform) -> Self::Augment<'a, D>
    where
        Platform: 'a;
}

impl Extension<()> for () {
    type Augment<'a, D: StackDefinition>
        = ()
    where
        Self: 'a;

    fn create_augment<'a, D: StackDefinition>(&'a self, _platform: &'a ()) -> Self::Augment<'a, D>
    where
        (): 'a,
    {
    }
}

// ============================================================================
// DeviceConfig (device-level serialisable form)
// ============================================================================

/// All state that must survive power cycles — the device-level persisted
/// configuration.
///
/// This struct contains everything that ETS can configure and the device
/// must remember. It's serialized to storage when changes occur.
///
/// Plays the same role at the device level that `*ExtensionConfig` plays
/// at the extension level (see the [vocabulary block](self) at the top
/// of this module).
///
/// # Generic Parameters
///
/// The const generics are the actual byte sizes of each table:
/// - `ADT_SIZE`: Address table size (typically 2 + MAX_ADDR * 2)
/// - `AST_SIZE`: Association table size (typically 2 + MAX_ASSO * 4)
/// - `COT_SIZE`: Group object table size (typically 2 + MAX_CO * 2)
/// - `P`: Application parameters type
/// - `E`: Extension-specific persistent config (e.g., [`IpExtensionConfig`]
///   for KNX/IP devices, `()` for plain TP1 devices)
///
/// Use [`table_sizes`] to calculate the const generics from max entry counts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "P: Serialize", deserialize = "P: Deserialize<'de>",))]
pub struct DeviceConfig<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    P: ConstDefault + IntoBytes + KnownLayout + Immutable = (),
    E: ExtensionConfig = (),
> {
    /// Version of the device config format.
    ///
    /// Increment this when making breaking changes to allow migration.
    pub version: u8,

    /// Device individual address.
    pub individual_address: IndividualAddress,

    /// Authorization keys for levels 0-2.
    ///
    /// Level 3 has no key (it's the fallback when no key matches).
    /// Key value `[0xFF, 0xFF, 0xFF, 0xFF]` is the "default key".
    pub auth_keys: [[u8; 4]; 3],

    /// Routing count (hop count) for outgoing messages.
    pub routing_count: u8,

    /// Address table (TSAP → Group Address mapping).
    pub address_table: Table<AddrTab7Impl<ADT_SIZE>>,

    /// Association table (TSAP → ASAP mapping).
    pub association_table: Table<AssoTab6Impl<AST_SIZE>>,

    /// Group object table (CO type + flags).
    pub group_object_table: Table<CoTab7Impl<COT_SIZE>>,

    /// Application program data.
    pub application: Application<P>,

    /// PEI (Platform Extension Interface) program.
    pub pei_program: PeiApplication,

    /// Application program version (set by ETS during programming).
    pub program_version: [u8; 5],

    /// PEI program version (set by ETS during programming).
    pub pei_program_version: [u8; 5],

    /// Extension-specific persistent configuration.
    ///
    /// The type depends on the device's extension state (`E` parameter).
    /// Examples: [`IpExtensionConfig`] for KNX/IP, [`Tp1ExtensionConfig`]
    /// for TP1 with retry count, `()` for no extensions, or a tuple of
    /// configs for composed extension states.
    pub extension_config: E,
}

impl<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    P: ConstDefault + IntoBytes + KnownLayout + Immutable,
    E: ExtensionConfig,
> DeviceConfig<ADT_SIZE, AST_SIZE, COT_SIZE, P, E>
{
    /// Current version of the device config format.
    pub const VERSION: u8 = 1;

    /// Create a new device config with factory defaults.
    pub fn factory_default() -> Self {
        Self {
            version: Self::VERSION,
            individual_address: IndividualAddress::new(15, 15, 255),
            auth_keys: [[0xFF; 4]; 3], // All keys = default key
            routing_count: 6,          // Default per KNX spec
            address_table: Table::new(),
            association_table: Table::new(),
            group_object_table: Table::new(),
            application: Application::new(),
            pei_program: PeiApplication::new(),
            program_version: [0; 5],
            pei_program_version: [0; 5],
            extension_config: E::default(),
        }
    }
}

/// Calculate table sizes from max entry counts.
///
/// Returns `(adt_size, ast_size, cot_size)` for use as const generics.
///
/// # Example
///
/// ```rust,ignore
/// const SIZES: (usize, usize, usize) = table_sizes(64, 64, 32);
/// type MyDeviceConfig = DeviceConfig<{ SIZES.0 }, { SIZES.1 }, { SIZES.2 }, ()>;
/// ```
pub const fn table_sizes(max_addr: usize, max_asso: usize, max_co: usize) -> (usize, usize, usize) {
    (
        2 + max_addr * 2, // ADT: 2-byte count + 2 bytes per entry
        2 + max_asso * 4, // AST: 2-byte count + 4 bytes per entry
        2 + max_co * 2,   // COT: 2-byte count + 2 bytes per entry
    )
}
