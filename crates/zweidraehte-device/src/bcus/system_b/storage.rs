//! Persistence infrastructure for System B devices.
//!
//! This module provides the System B device-level persistence types:
//! [`DeviceConfig`] (the whole-device serialisable form) and
//! [`SystemBStateInit`] (the constructor-args envelope). The BCU-agnostic
//! extension vocabulary — [`ExtensionConfig`], [`ExtensionState`], and the
//! [`Extension`] trait unifying persistence with interface object
//! augmentation — lives in [`crate::extension`] and is re-exported here.
//!
//! # `Config` / `State` / `Resources` vocabulary
//!
//! See [`crate::extension`] for the shared suffix vocabulary. System B adds:
//!
//! - [`DeviceConfig`] — the device-level `*Config`: everything ETS can
//!   configure and the device must remember. Converts to/from the runtime
//!   `SystemBDeviceState` via [`HasDeviceConfig::to_config`] plus
//!   `SystemBDeviceState::from_config`.
//! - `*StateInit` (on [`StackDefinition::StateInit`]) — constructor-args
//!   envelope passed to [`StackDefinition::create_state`]. May carry an
//!   optional persisted snapshot from storage plus identity data (serial
//!   number, FDSK) that is not itself persisted. The `Init` suffix
//!   distinguishes it from a serialisable `*Config`.
//!
//! The storage framework (the stores structs and the capability traits they
//! implement) lives in [`crate::storage`].
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

pub use crate::extension::{Extension, ExtensionConfig, ExtensionState};

use crate::objects::tables::{
    Table,
    addr7::AddrTab7Impl,
    app::{Application, PeiApplication},
    asso6::AssoTab6Impl,
    co7::CoTab7Impl,
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
// DeviceConfig (device-level serialisable form)
// ============================================================================

/// All state that must survive power cycles — the device-level persisted
/// configuration.
///
/// This struct contains everything that ETS can configure and the device
/// must remember. It's serialized to storage when changes occur.
///
/// Plays the same role at the device level that `*ExtensionConfig` plays
/// at the extension level (see the vocabulary block at the top
/// of this module).
///
/// # Generic Parameters
///
/// The const generics are the actual byte sizes of each table:
/// - `ADT_SIZE`: Address table size (typically 2 + MAX_ADDR * 2)
/// - `AST_SIZE`: Association table size (typically 2 + MAX_ASSO * 4)
/// - `COT_SIZE`: Group object table size (typically 2 + MAX_CO * 2)
/// - `P`: Application parameters type
/// - `E`: Extension-specific persistent config (e.g., [`IpExtensionConfig`](crate::bcus::system_b::IpExtensionConfig)
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
    /// Examples: [`IpExtensionConfig`](crate::bcus::system_b::IpExtensionConfig) for KNX/IP,
    /// [`Tp1ExtensionConfig`](crate::bcus::system_b::Tp1ExtensionConfig)
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
