//! Persistence infrastructure for System B devices.
//!
//! This module provides traits and types for persisting device state
//! across power cycles. All ETS-configurable values must be persisted.

use core::net::Ipv4Addr;

use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::{address::IndividualAddress, objects::tables::LoadState};

/// Trait for persisting device state to storage.
///
/// Implementations can target various storage backends:
/// - Flash memory (embedded)
/// - EEPROM
/// - Filesystem (std)
/// - In-memory (testing)
///
/// # Persistence Strategy
///
/// The device calls [`mark_dirty`](Self::mark_dirty) whenever persistent
/// state changes. Implementations can choose to:
///
/// 1. **Immediate write**: Save on every change (simple but high wear)
/// 2. **Deferred write**: Batch changes and write periodically
/// 3. **Shutdown write**: Only save on graceful shutdown
///
/// Call [`flush`](Self::flush) to force pending writes to storage.
pub trait DeviceStorage: Sized {
    /// Error type for storage operations.
    type Error;

    /// Load persistent state from storage.
    ///
    /// Returns:
    /// - `Ok(Some(state))` - Successfully loaded state
    /// - `Ok(None)` - No saved state exists (factory reset / first boot)
    /// - `Err(e)` - Storage error
    ///
    /// On first boot or after factory reset, this should return `Ok(None)`.
    /// The device will then use factory defaults.
    ///
    /// # Type Parameters
    ///
    /// - `ADT_SIZE`: Address table size in bytes (2 + MAX_ADDR * 2)
    /// - `AST_SIZE`: Association table size in bytes (2 + MAX_ASSO * 4)
    /// - `COT_SIZE`: Group object table size in bytes (2 + MAX_CO * 2)
    /// - `APP_SIZE`: Application data size in bytes
    fn load<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, const APP_SIZE: usize>(
        &mut self,
    ) -> Result<Option<PersistedState<ADT_SIZE, AST_SIZE, COT_SIZE, APP_SIZE>>, Self::Error>;

    /// Save persistent state to storage.
    ///
    /// This should atomically replace the previous state to prevent
    /// corruption on power loss during write.
    fn save<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, const APP_SIZE: usize>(
        &mut self,
        state: &PersistedState<ADT_SIZE, AST_SIZE, COT_SIZE, APP_SIZE>,
    ) -> Result<(), Self::Error>;

    /// Mark state as dirty (needs save).
    ///
    /// Called whenever persistent state changes. Implementations can
    /// use this to track that a save is needed without immediately
    /// writing to storage.
    fn mark_dirty(&mut self);

    /// Flush any pending writes to storage.
    ///
    /// Called to ensure all changes are persisted. Should be called:
    /// - On graceful shutdown
    /// - Periodically (for wear leveling)
    /// - After critical configuration changes
    fn flush(&mut self) -> Result<(), Self::Error>;

    /// Check if there are unsaved changes.
    fn is_dirty(&self) -> bool {
        false // Default: not tracked
    }
}

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
/// - `APP_SIZE`: Application data size
///
/// Use [`table_sizes`] to calculate these from the max entry counts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedState<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    const APP_SIZE: usize,
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

    /// Address table (TSAP → Group Address mapping).
    pub address_table: PersistedTable<ADT_SIZE>,

    /// Association table (TSAP → ASAP mapping).
    pub association_table: PersistedTable<AST_SIZE>,

    /// Group object table (CO type + flags).
    pub group_object_table: PersistedTable<COT_SIZE>,

    /// Application program data.
    pub application: PersistedApplication<APP_SIZE>,

    /// IP-specific configuration (only for 57B0 devices).
    ///
    /// Set to `None` for non-IP devices (07B0).
    pub ip_config: Option<PersistedIpConfig>,
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, const APP_SIZE: usize>
    PersistedState<ADT_SIZE, AST_SIZE, COT_SIZE, APP_SIZE>
{
    /// Current version of the persisted state format.
    pub const VERSION: u8 = 1;

    /// Create a new persisted state with factory defaults.
    pub fn factory_default() -> Self {
        Self {
            version: Self::VERSION,
            individual_address: IndividualAddress::new(15, 15, 255),
            auth_keys: [[0xFF; 4]; 3], // All keys = default key
            address_table: PersistedTable::default(),
            association_table: PersistedTable::default(),
            group_object_table: PersistedTable::default(),
            application: PersistedApplication::default(),
            ip_config: None,
        }
    }

    /// Create a new persisted state with factory defaults and IP config.
    pub fn factory_default_ip() -> Self {
        Self {
            ip_config: Some(PersistedIpConfig::default()),
            ..Self::factory_default()
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
/// type MyPersistedState = PersistedState<{ SIZES.0 }, { SIZES.1 }, { SIZES.2 }, 256>;
/// ```
pub const fn table_sizes(max_addr: usize, max_asso: usize, max_co: usize) -> (usize, usize, usize) {
    (
        2 + max_addr * 2, // ADT: 2-byte count + 2 bytes per entry
        2 + max_asso * 4, // AST: 2-byte count + 4 bytes per entry
        2 + max_co * 2,   // COT: 2-byte count + 2 bytes per entry
    )
}

/// Persisted table data.
///
/// Contains the table's load state, raw data, and MCB (Memory Control Block).
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedTable<const SIZE: usize> {
    /// Current load state of the table.
    pub load_state: LoadState,

    /// Raw table data.
    #[serde_as(as = "[_; SIZE]")]
    pub data: [u8; SIZE],

    /// Memory Control Block (8 bytes).
    ///
    /// Contains allocated size, mode, fill value, and CRC.
    pub mcb: [u8; 8],
}

impl<const SIZE: usize> Default for PersistedTable<SIZE> {
    fn default() -> Self {
        Self {
            load_state: LoadState::Unloaded,
            data: [0; SIZE],
            mcb: [0; 8],
        }
    }
}

/// Persisted application program data.
///
/// Similar to [`PersistedTable`] but does NOT include run state.
/// The run state is volatile - the application always starts in
/// `Halted` state and must be explicitly restarted after boot.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedApplication<const SIZE: usize> {
    /// Current load state of the application.
    pub load_state: LoadState,

    /// Raw application data.
    #[serde_as(as = "[_; SIZE]")]
    pub data: [u8; SIZE],

    /// Memory Control Block (8 bytes).
    pub mcb: [u8; 8],
}

impl<const SIZE: usize> Default for PersistedApplication<SIZE> {
    fn default() -> Self {
        Self {
            load_state: LoadState::Unloaded,
            data: [0; SIZE],
            mcb: [0; 8],
        }
    }
}

/// Persisted IP configuration (for 57B0 devices).
///
/// All IP-specific settings that can be configured via ETS or
/// the IP Parameter Object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedIpConfig {
    /// Friendly name for discovery (up to 30 bytes).
    pub friendly_name: [u8; 30],

    /// Length of the friendly name.
    pub friendly_name_len: u8,

    /// Configured (static) IP address.
    pub configured_ip: [u8; 4],

    /// Configured subnet mask.
    pub configured_subnet: [u8; 4],

    /// Configured default gateway.
    pub configured_gateway: [u8; 4],

    /// IP assignment method (bitfield: Manual=1, BootP=2, DHCP=4, AutoIP=8).
    pub ip_assignment_method: u8,

    /// Routing multicast address.
    pub routing_multicast: [u8; 4],

    /// Multicast TTL value.
    pub ttl: u8,

    /// Project installation ID.
    pub project_installation_id: u16,
}

impl Default for PersistedIpConfig {
    fn default() -> Self {
        Self {
            friendly_name: [0; 30],
            friendly_name_len: 0,
            configured_ip: [0, 0, 0, 0],
            configured_subnet: [255, 255, 255, 0],
            configured_gateway: [0, 0, 0, 0],
            ip_assignment_method: 0x04, // DHCP
            routing_multicast: [224, 0, 23, 12],
            ttl: 16,
            project_installation_id: 0,
        }
    }
}

impl PersistedIpConfig {
    /// Get the configured IP address as an Ipv4Addr.
    pub fn configured_ip_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.configured_ip)
    }

    /// Get the routing multicast address as an Ipv4Addr.
    pub fn routing_multicast_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.routing_multicast)
    }
}

// ============================================================================
// NoStorage - Null implementation for testing
// ============================================================================

/// Storage implementation that doesn't persist anything.
///
/// Useful for:
/// - Testing
/// - Devices without persistent storage
/// - Devices with fixed configuration
///
/// All state will be lost on power cycle.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoStorage;

impl DeviceStorage for NoStorage {
    type Error = core::convert::Infallible;

    fn load<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, const APP_SIZE: usize>(
        &mut self,
    ) -> Result<Option<PersistedState<ADT_SIZE, AST_SIZE, COT_SIZE, APP_SIZE>>, Self::Error> {
        Ok(None) // No saved state
    }

    fn save<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, const APP_SIZE: usize>(
        &mut self,
        _state: &PersistedState<ADT_SIZE, AST_SIZE, COT_SIZE, APP_SIZE>,
    ) -> Result<(), Self::Error> {
        Ok(()) // Silently discard
    }

    fn mark_dirty(&mut self) {
        // Nothing to mark
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}
