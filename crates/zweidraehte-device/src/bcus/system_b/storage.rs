//! Persistence infrastructure for System B devices.
//!
//! This module provides System B-specific persistence types
//! ([`PersistedState`], [`PersistedIpConfig`], [`ExtensionConfig`],
//! [`ExtensionState`]).
//!
//! The generic storage traits ([`DeviceStorage`](crate::storage::DeviceStorage),
//! [`NoStorage`](crate::storage::NoStorage)) live in [`crate::storage`].

use const_default::ConstDefault;
use serde::{Deserialize, Serialize};

use crate::{
    address::IndividualAddress,
    objects::tables::{
        Table,
        addr7::AddrTab7Impl,
        app::{Application, PeiApplication},
        asso6::AssoTab6Impl,
        co7::CoTab7Impl,
    },
};

use crate::storage::DeviceIdentity;

// ============================================================================
// HasPersistedState — bridge between runtime and serializable state
// ============================================================================

/// Trait for converting between runtime state and its serializable form.
///
/// Implemented by [`SystemBDeviceState`](super::SystemBDeviceState) to
/// enable [`DeviceStorage`](crate::storage::DeviceStorage) backends to
/// work with the runtime state type directly, internalizing the
/// conversion to/from [`PersistedState`].
///
/// # Contract
///
/// - [`to_persisted`](Self::to_persisted) must capture all state that
///   survives a power cycle.
/// - [`from_persisted`](Self::from_persisted) must restore state such
///   that the device behaves identically to before the power cycle
///   (modulo volatile state like programming mode and run state).
pub trait HasPersistedState: Sized {
    /// The serializable snapshot type.
    type Persisted: Serialize + for<'de> Deserialize<'de>;

    /// Export current runtime state to a serializable snapshot.
    fn to_persisted(&self) -> Self::Persisted;

    /// Restore runtime state from a persisted snapshot and device identity.
    fn from_persisted(identity: &impl DeviceIdentity, persisted: Self::Persisted) -> Self;
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

/// Runtime state for extension-specific persistent configuration.
///
/// This trait bridges the serializable config ([`ExtensionConfig`]) and
/// the runtime representation with interior mutability (`Cell`/`RefCell`
/// fields). The runtime form allows `&self` mutation through accessor
/// traits (e.g., `IpStackState`, `HasMaxRetryCount`), while the config
/// form is what gets serialized.
///
/// Devices that need multiple extension concerns (e.g., IP config +
/// custom augment state) should define a single struct that combines
/// them and implements this trait directly.
pub trait ExtensionState: Sized {
    /// The serializable config type for this extension state.
    type Config: ExtensionConfig;

    /// Create runtime state from a persisted config.
    fn from_config(config: Self::Config) -> Self;

    /// Export current runtime state to serializable config.
    fn to_config(&self) -> Self::Config;

    /// Reset to factory defaults.
    fn factory_reset(&self);
}

/// Whether the device's Security Mode is currently enabled.
///
/// Extension state types that include security (e.g.,
/// [`SecureExtensionState`]) implement this to delegate to the Security
/// Interface Object's flag. Non-secure extensions use the default
/// (`false`).
///
/// Separated from [`ExtensionState`] because security mode is not a
/// persistence concern — TP1 and IP extensions should not need to know
/// about it.
pub trait HasSecurityMode {
    fn security_mode_enabled(&self) -> bool {
        false
    }
}

impl HasSecurityMode for () {}

impl ExtensionState for () {
    type Config = ();

    fn from_config(_config: ()) -> Self {}

    fn to_config(&self) {}

    fn factory_reset(&self) {
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
/// [`InterfaceObjectAugment`](crate::objects::interface::InterfaceObjectAugment)
/// (property handling) into a single concept. Each extension knows how
/// to create its own augment given a reference to the platform.
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
/// - [`Tp1ExtensionState`](super::extensions::tp1::Tp1ExtensionState) — self-contained, IS its own augment
/// - [`IpExtensionState<N>`](super::extensions::ip::IpExtensionState) — creates an
///   [`IpAugment`](super::extensions::ip::IpAugment) from self + platform
pub trait Extension<Platform = ()>: ExtensionState {
    /// The augment type this extension creates.
    ///
    /// For TP1: `&'a Tp1ExtensionState` (the extension IS the augment).
    /// For IP: `IpAugment<'a, P, N>` (wraps extension + platform).
    /// For `()`: `()` (no augmentation).
    type Augment<'a, S: crate::StackState>: crate::objects::interface::InterfaceObjectAugment<S>
    where
        Self: 'a,
        Platform: 'a;

    /// Create the augment from this extension state and the platform.
    fn create_augment<'a, S: crate::StackState>(&'a self, platform: &'a Platform) -> Self::Augment<'a, S>
    where
        Platform: 'a;
}

impl Extension<()> for () {
    type Augment<'a, S: crate::StackState>
        = ()
    where
        Self: 'a;

    fn create_augment<'a, S: crate::StackState>(&'a self, _platform: &'a ()) -> Self::Augment<'a, S>
    where
        (): 'a,
    {
    }
}

// ============================================================================
// Persisted state
// ============================================================================

/// All state that must survive power cycles.
///
/// This struct contains everything that ETS can configure and the device
/// must remember. It's serialized to storage when changes occur.
///
/// # Generic Parameters
///
/// The const generics are the actual byte sizes of each table:
/// - `ADT_SIZE`: Address table size (typically 2 + MAX_ADDR * 2)
/// - `AST_SIZE`: Association table size (typically 2 + MAX_ASSO * 4)
/// - `COT_SIZE`: Group object table size (typically 2 + MAX_CO * 2)
/// - `P`: Application parameters type
/// - `E`: Extension-specific persistent config (e.g., [`PersistedIpConfig`]
///   for KNX/IP devices, `()` for plain TP1 devices)
///
/// Use [`table_sizes`] to calculate the const generics from max entry counts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "P: Serialize", deserialize = "P: Deserialize<'de>",))]
pub struct PersistedState<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    P: ConstDefault = (),
    E: ExtensionConfig = (),
> {
    /// Version of the persisted state format.
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
    /// Examples: [`PersistedIpConfig`] for KNX/IP, [`Tp1ExtensionConfig`]
    /// for TP1 with retry count, `()` for no extensions, or a tuple of
    /// configs for composed extension states.
    pub extension_config: E,
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, E: ExtensionConfig>
    PersistedState<ADT_SIZE, AST_SIZE, COT_SIZE, P, E>
{
    /// Current version of the persisted state format.
    pub const VERSION: u8 = 1;

    /// Create a new persisted state with factory defaults.
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
/// type MyPersistedState = PersistedState<{ SIZES.0 }, { SIZES.1 }, { SIZES.2 }, ()>;
/// ```
pub const fn table_sizes(max_addr: usize, max_asso: usize, max_co: usize) -> (usize, usize, usize) {
    (
        2 + max_addr * 2, // ADT: 2-byte count + 2 bytes per entry
        2 + max_asso * 4, // AST: 2-byte count + 4 bytes per entry
        2 + max_co * 2,   // COT: 2-byte count + 2 bytes per entry
    )
}
