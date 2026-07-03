//! Flash-based persistent storage and device identity for RP2040/RP2350.
//!
//! # Flash Layout
//!
//! The provisioning sector lives at the very top of flash; config
//! storage occupies the sectors immediately below it. With the default
//! 4 KiB `STORAGE_SIZE` the layout for a 2 MB chip is:
//!
//! ```text
//! 0x1FE000 .. 0x1FF000  — Config storage (KNXS)            [grows backward]
//! 0x1FF000 .. 0x200000  — Provisioning sector (KNXP)       [last sector, fixed]
//! ```
//!
//! Putting provisioning last and config below it means bumping
//! `STORAGE_SIZE` to fit a larger config grows the region toward lower
//! addresses without ever touching the (write-once) provisioning data.
//!
//! The provisioning sector is written once on the production line by
//! the host-side `knx-provision` tool over SWD. Format and codec live
//! in [`zweidraehte_device::provisioning`]; the read/write helpers and
//! struct conversions live in [`crate::prov_storage`]. The config
//! sector stores ETS-programmed device state via a
//! [`ConfigStore`](zweidraehte_device::storage::ConfigStore) placed on the
//! [`RpFlash`] chip.
//!
//! # Config Sector Format
//!
//! ```text
//! [magic: 4B "KNXS"][len: 2B little-endian][postcard payload][...]
//! ```
//!
//! The magic bytes guard against reading uninitialized flash (all 0xFF).
//! The magic + length + postcard codec is shared with the STM32 target and
//! lives once in [`zweidraehte_device::storage::ConfigStore`]; a device builds
//! that store over [`RpFlashIo`] at its auto-derived offset on the [`RpFlash`]
//! chip. RP2040 flash writes
//! are byte-granular, so the config store uses `WRITE_ALIGN = 1` (no padding).
//!
//! # Wear Leveling
//!
//! Not implemented — KNX configuration writes are rare (only during ETS
//! programming), so the ~100K erase cycle limit is not a concern in
//! practice.
//!
//! # Flash Stall Warning
//!
//! `blocking_erase` and `blocking_write` disable XIP and interrupts on
//! RP2040, stalling all tasks for the duration. This is acceptable for
//! rare config saves but would disrupt real-time KNX communication if
//! done frequently.

use zweidraehte_device::storage::region::Chip;
use zweidraehte_device::storage::{DeviceIdentity, SecureDeviceIdentity};

use crate::flash_seq::RpFlashIo;
use crate::prov_storage::PROVISIONING_SECTOR_OFFSET;

// ================================================================================
// Constants
// ================================================================================

pub const FLASH_SIZE: usize = 2 * 1024 * 1024; // 2MB
pub const SECTOR_SIZE: usize = 4096;

/// Emit the shared flash handle every RP device builds identically: the
/// blocking `embassy_rp` flash driver behind a `&'static RefCell`, so the
/// config store and any other flash consumer (sequence store, mc_timer store)
/// can alias the single `FLASH` peripheral. Expands to an expression yielding
/// the `&'static RefCell<Flash<…>>`; the [`FLASH_SIZE`] const generic —
/// otherwise repeated four times per device in the handle's type — is pinned
/// here once.
///
/// ```ignore
/// let flash = rp_common::rp_flash_cell!(p.FLASH);
/// let identity_data = load_identity(&mut flash.borrow_mut());
/// let storage = Storage::open_at(RpFlashIo::new(flash), identity_data.clone(), CONFIG);
/// ```
#[macro_export]
macro_rules! rp_flash_cell {
    ($flash_peri:expr) => {{
        static __FLASH_CELL: ::static_cell::StaticCell<
            ::core::cell::RefCell<
                ::embassy_rp::flash::Flash<
                    'static,
                    ::embassy_rp::peripherals::FLASH,
                    ::embassy_rp::flash::Blocking,
                    { $crate::storage::FLASH_SIZE },
                >,
            >,
        > = ::static_cell::StaticCell::new();
        &*__FLASH_CELL.init(::core::cell::RefCell::new(::embassy_rp::flash::Flash::<
            _,
            ::embassy_rp::flash::Blocking,
            { $crate::storage::FLASH_SIZE },
        >::new_blocking($flash_peri)))
    }};
}

/// Emit the `load_identity` function every RP device otherwise copy-pastes:
/// read the flash unique ID, parse the `KNXP` provisioning record, and — under
/// the `provision-on-boot` feature — synthesize dev defaults from the caller's
/// `dev_provisioning` module when the record is missing.
///
/// The first token picks the identity flavour (`plain` →
/// [`FlashIdentityData`](crate::FlashIdentityData), `secure` →
/// [`FlashSecureIdentityData`](crate::FlashSecureIdentityData) with a mandatory
/// FDSK); `fdsk`/`mac` are the dev-default tags passed to
/// [`synthesize_and_write`](crate::synthesize_and_write) (only evaluated under
/// `provision-on-boot`, so referencing `dev_provisioning::…` is fine).
///
/// ```ignore
/// rp_common::rp_identity_loader!(plain, fdsk: None, mac: Some(dev_provisioning::DEV_MAC));
/// ```
#[macro_export]
macro_rules! rp_identity_loader {
    (@fn $ret:ty, $convert:expr, $fdsk:expr, $mac:expr) => {
        fn load_identity(
            flash: &mut ::embassy_rp::flash::Flash<
                'static,
                ::embassy_rp::peripherals::FLASH,
                ::embassy_rp::flash::Blocking,
                { $crate::storage::FLASH_SIZE },
            >,
        ) -> $ret {
            let mut unique_id = [0u8; 8];
            flash.blocking_unique_id(&mut unique_id).expect("flash unique ID");

            #[allow(clippy::redundant_closure_call)]
            match $crate::read_provisioning(flash) {
                Ok(rec) => ($convert)(&rec, unique_id),

                #[cfg(feature = "provision-on-boot")]
                Err(e) => {
                    ::defmt::warn!("no KNXP record ({:?}); writing dev defaults from build.rs", e);
                    $crate::synthesize_and_write(flash, dev_provisioning::DEV_SERIAL, $fdsk, $mac)
                        .expect("write dev KNXP");
                    let rec = $crate::read_provisioning(flash).expect("re-read freshly written KNXP");
                    ($convert)(&rec, unique_id)
                }

                #[cfg(not(feature = "provision-on-boot"))]
                Err(e) => ::defmt::panic!("no valid KNXP record: {:?}", e),
            }
        }
    };
    (plain, fdsk: $fdsk:expr, mac: $mac:expr) => {
        $crate::rp_identity_loader!(@fn $crate::FlashIdentityData, $crate::identity_from_record, $fdsk, $mac);
    };
    (secure, fdsk: $fdsk:expr, mac: $mac:expr) => {
        $crate::rp_identity_loader!(
            @fn $crate::FlashSecureIdentityData,
            |rec, uid| $crate::secure_identity_from_record(rec, uid).expect("KNXP record missing FDSK"),
            $fdsk,
            $mac
        );
    };
}

/// Bytes the config blob occupies — one 4 KiB sector. A compile-time const
/// because it sizes the `[u8; REGION_SIZE]` buffer inside
/// [`ConfigStore`](zweidraehte_device::storage::ConfigStore); the region's
/// *offset* is auto-derived by the storage layer from the placement list.
pub const RP_STORAGE_SIZE: usize = SECTOR_SIZE;

/// The config region every RP device places — one flash sector, carrying
/// the device's runtime state type `S` as its payload:
///
/// ```ignore
/// type Cfg = Placed<RpConfigRegion<MyDeviceState>, RpFlash, StorageMap>;
/// ```
///
/// The store type and its `open` derive from the region (`StoreOf<Cfg>` /
/// `Cfg::open(RpFlashIo::new(flash))`).
pub type RpConfigRegion<S> = zweidraehte_device::storage::region::ConfigRegion<RP_STORAGE_SIZE, S>;

// ================================================================================
// RpFlash — the storage layer's view of the RP2040 internal flash chip
// ================================================================================

/// The RP2040/RP2350 internal flash, as a [`Chip`] the storage layer packs
/// regions onto.
///
/// `BASE` is where the packed region span starts — pinned at `0x1F6000` so a
/// secure device's three regions (SIAT log, mc_timer log, config blob) fit
/// below the write-once provisioning sector, and a config-only device's single
/// region lands at the same base. `CAPACITY` stops at
/// [`PROVISIONING_SECTOR_OFFSET`] (the last sector, owned by
/// [`crate::prov_storage`]) so the per-chip capacity guard protects it.
///
/// One shared chip serves every RP device: the config-only ones pack one
/// region, the secure one packs three — the auto-packing derives each offset
/// from the declared region sizes, so no device states an address.
#[derive(Clone, Copy)]
pub struct RpFlash;

impl Chip for RpFlash {
    const TAG: u32 = 0;
    const BASE: u32 = 0x1F6000;
    const CAPACITY: u32 = PROVISIONING_SECTOR_OFFSET;
    const SECTOR_SIZE: u32 = SECTOR_SIZE as u32;
    type Io = RpFlashIo;
}

/// This crate's flash error type — the shared config-store error.
pub use zweidraehte_device::storage::ConfigStoreError as FlashError;

// ================================================================================
// Device identity (sourced from the KNXP provisioning sector)
// ================================================================================

/// Identity record built from a parsed `KNXP` provisioning record.
///
/// Carries the KNX serial, an optional MAC address (populated for IP
/// devices), and the SPI flash chip's unique ID. The unique ID is read
/// from hardware at boot (not stored in `KNXP`) so that
/// [`derive_seed`](FlashIdentityData::derive_seed) keeps working without
/// pulling extra fields into the provisioning record.
#[derive(Debug, Clone, defmt::Format)]
pub struct FlashIdentityData {
    /// KNX serial number: 2 bytes manufacturer ID (big-endian) + 4 bytes
    /// device-specific (assigned at provisioning time).
    pub serial_number: [u8; 6],

    /// Ethernet MAC address from the `KNXP` record. `None` on devices
    /// that don't need one (TP1-only).
    pub mac: Option<[u8; 6]>,

    /// Raw 8-byte SPI flash unique ID. Read from hardware at boot for
    /// per-device entropy seeds.
    pub unique_id: [u8; 8],
}

impl DeviceIdentity for FlashIdentityData {
    fn serial_number(&self) -> &[u8; 6] {
        &self.serial_number
    }
}

impl FlashIdentityData {
    /// Return the MAC address sourced from the `KNXP` record.
    ///
    /// # Panics
    /// Panics if the record had no MAC tag — wiring an Ethernet device
    /// with a missing MAC is a configuration error the firmware cannot
    /// recover from at boot.
    pub fn mac_address(&self) -> [u8; 6] {
        self.mac.expect("KNXP record missing MAC tag — re-provision this device")
    }

    /// Derive a deterministic `u64` seed from the unique ID.
    ///
    /// Suitable for embassy-net's IGMP random delay and similar uses
    /// where a per-device seed is needed.
    pub fn derive_seed(&self) -> u64 {
        u64::from_le_bytes(self.unique_id)
    }
}

/// Device identity for an RP2040 KNX **Data Secure** device.
///
/// The secure counterpart of [`FlashIdentityData`]: it carries the same
/// serial / MAC / unique-ID triple **plus** the 16-byte Factory Default
/// Setup Key (FDSK) that seeds the device's tool key and (for IP Secure)
/// the Device Authentication Code. The FDSK lives in the `KNXP`
/// provisioning record (the `FDSK` tag); see
/// [`secure_identity_from_record`](crate::secure_identity_from_record).
///
/// This is the RP2040 analogue of `stm32-common`'s `FlashSecureIdentityData`;
/// the difference is the extra `mac` / `unique_id` fields (IP devices need
/// a MAC, and the seed comes from the SPI-flash unique ID rather than an
/// on-chip UID register).
#[derive(Debug, Clone, defmt::Format)]
pub struct FlashSecureIdentityData {
    /// KNX serial number: 2 bytes manufacturer ID (big-endian) + 4 bytes
    /// device-specific.
    pub serial_number: [u8; 6],

    /// Ethernet MAC address from the `KNXP` record. `None` on devices
    /// that don't need one — but IP Secure devices always do.
    pub mac: Option<[u8; 6]>,

    /// Raw 8-byte SPI flash unique ID. Read from hardware at boot for
    /// per-device entropy seeds.
    pub unique_id: [u8; 8],

    /// Factory Default Setup Key (FDSK). Seeds the Data Secure tool key
    /// and the IP Secure Device Authentication Code on first
    /// commissioning.
    pub fdsk: [u8; 16],
}

impl DeviceIdentity for FlashSecureIdentityData {
    fn serial_number(&self) -> &[u8; 6] {
        &self.serial_number
    }
}

impl SecureDeviceIdentity for FlashSecureIdentityData {
    fn fdsk(&self) -> &[u8; 16] {
        &self.fdsk
    }
}

impl FlashSecureIdentityData {
    /// Return the MAC address sourced from the `KNXP` record.
    ///
    /// # Panics
    /// Panics if the record had no MAC tag — wiring an Ethernet device
    /// with a missing MAC is a configuration error the firmware cannot
    /// recover from at boot.
    pub fn mac_address(&self) -> [u8; 6] {
        self.mac.expect("KNXP record missing MAC tag — re-provision this device")
    }

    /// Derive a deterministic `u64` seed from the unique ID. Same as
    /// [`FlashIdentityData::derive_seed`].
    pub fn derive_seed(&self) -> u64 {
        u64::from_le_bytes(self.unique_id)
    }
}
