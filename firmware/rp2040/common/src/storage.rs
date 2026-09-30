//! Flash-based persistent storage and device identity for RP2040/RP2350.
//!
//! # Flash Layout
//!
//! The provisioning sector lives at the very top of flash; the storage
//! regions sit below it, packed upward from [`RpFlash::BASE`] in the order a
//! device lists them. For a 2 MB chip:
//!
//! ```text
//! 0x1F2000 .. 0x1F6000  — Config log (two 8 KiB banks)            [every device]
//! 0x1F6000 .. 0x1FC000  — SIAT / sequence log                     [secure only]
//! 0x1FC000 .. 0x1FE000  — mc_timer log                            [IP Secure only]
//! 0x1FE000 .. 0x1FF000  — unused (held the config blob before the log)
//! 0x1FF000 .. 0x200000  — Provisioning sector (KNXP)              [last sector, fixed]
//! ```
//!
//! A secure device lists the config log *first*, so its SIAT and mc_timer
//! logs keep the offsets they had when the config was a one-sector blob
//! after them, and a firmware update keeps the device's sequence counters.
//!
//! The provisioning sector is written once on the production line by
//! the host-side `knx-provision` tool over SWD. Format and codec live
//! in [`zweidraehte_device::provisioning`]; the read/write helpers and
//! struct conversions live in [`crate::prov_storage`].
//!
//! # Config storage
//!
//! The ETS-programmed configuration is the device state's persistent
//! sections, written through: the router appends every change to a
//! [`FlashLog`](zweidraehte_device::storage::region::ConfigLogRegion) before
//! the response to it leaves the device, and boot replays the log
//! ([`restore_config`]). RP2040 flash writes are byte-granular
//! (`WRITE_ALIGN = 1`).
//!
//! # Flash stalls
//!
//! `blocking_erase` and `blocking_write` disable XIP and interrupts on the
//! RP2040, stalling everything for their duration. An append programs one
//! or two 256-byte pages (roughly 0.4–1.5 ms); the TPUART driver has one
//! byte of receive buffering (573 µs at 19200 8E1), so a frame arriving
//! during an append can overrun it. Appends follow a dispatch, when the bus
//! is usually quiet, and the driver counts overruns; the hardware
//! validation of `plans/CONFIG_STORAGE_PLAN.md` measures whether a PIO
//! receiver with a deeper FIFO is needed. Compaction, the long erase, runs
//! from the storage task under the TPUART busy guard.

use zweidraehte_device::HasPersistence;
use zweidraehte_device::sections::PersistentSections;
use zweidraehte_device::storage::region::{Chip, ConfigLogRegion};
use zweidraehte_device::storage::{DeviceIdentity, Loaded, NvConfig, NvStore, SecureDeviceIdentity};

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

/// Config log size: four sectors, two banks of 8 KiB. Each bank must hold a
/// full snapshot of the device's sections plus room for the appends between
/// compactions; a download takes well under one bank.
pub const RP_CONFIG_SIZE: usize = 4 * SECTOR_SIZE;

/// The config region every RP device places, carrying the device's runtime
/// state type `S`:
///
/// ```ignore
/// type Cfg = Placed<RpConfigRegion<MyDeviceState>, RpFlash, StorageMap>;
/// ```
///
/// The store type and its `open` derive from the region (`StoreOf<Cfg>` /
/// `Cfg::open(RpFlashIo::new(flash))`); the store is an [`NvConfig`] the
/// router flushes, restored at boot by [`restore_config`].
pub type RpConfigRegion<S> = ConfigLogRegion<RP_CONFIG_SIZE, S>;

// ================================================================================
// RpFlash — the storage layer's view of the RP2040 internal flash chip
// ================================================================================

/// The RP2040/RP2350 internal flash, as a [`Chip`] the storage layer packs
/// regions onto.
///
/// `BASE` is where the packed region span starts, chosen so a secure
/// device's regions (config log, SIAT log, mc_timer log) fit below the
/// write-once provisioning sector, with the SIAT log at `0x1F6000` (see the
/// module docs). `CAPACITY` stops at [`PROVISIONING_SECTOR_OFFSET`] (the last
/// sector, owned by [`crate::prov_storage`]) so the per-chip capacity guard
/// protects it.
///
/// One shared chip serves every RP device: the config-only ones pack one
/// region, the secure ones two or three — the auto-packing derives each
/// offset from the declared region sizes, so no device states an address.
#[derive(Clone, Copy)]
pub struct RpFlash;

impl Chip for RpFlash {
    const TAG: u32 = 0;
    const BASE: u32 = 0x1F2000;
    const CAPACITY: u32 = PROVISIONING_SECTOR_OFFSET;
    const SECTOR_SIZE: u32 = SECTOR_SIZE as u32;
    type Io = RpFlashIo;
}

/// Boot: apply the config log to the freshly created stack's `state`, or
/// format the log with the factory state, and clear the dirty flag so the
/// router does not flush what was just loaded.
///
/// Call it after `zweidraehte_device::new` and before the runner task runs,
/// with the stores struct's `config` field.
///
/// # Panics
///
/// If the log cannot be used. `LayoutTooLarge` is a sizing mistake of the
/// firmware, found on its first boot; a flash error at boot is a hardware
/// fault. Running on would lose every change the device makes.
pub fn restore_config<N, S, St>(config: &NvConfig<N, S>, state: &St)
where
    N: NvStore,
    N::Error: core::fmt::Debug,
    St: PersistentSections + HasPersistence,
{
    match config.load(state) {
        Ok(Loaded::Restored) => defmt::info!("config restored from flash"),
        Ok(Loaded::Fresh) => defmt::info!("no stored config for this layout, starting fresh"),
        Err(error) => defmt::panic!("config log unusable: {}", defmt::Debug2Format(&error)),
    }
    state.clear_dirty();
}

/// Read part of the stored configuration before the stack exists.
///
/// Some boot decisions come before `zweidraehte_device::new`: an Ethernet
/// device needs its stored IP settings to configure the network stack whose
/// address the KNX/IP link layer is built with. This loads the log into a
/// throwaway factory-fresh state from `fresh` and returns what `read` takes
/// from it, told whether the log held a configuration
/// ([`Loaded::Restored`]) or the state still holds factory defaults.
///
/// `store` must be a second store opened over the same region
/// (`Cfg::open(..)` again): each log is loaded once. A blank or foreign log
/// is formatted with the factory state here, which the stack's own
/// [`restore_config`] then restores unchanged.
///
/// Not inlined, so the temporary state lives on the call stack for the
/// duration of the call, not in the caller's (static) `main` future.
///
/// # Panics
///
/// As [`restore_config`].
#[inline(never)]
pub fn peek_config<N, S, St, R>(
    store: NvConfig<N, S>,
    fresh: impl FnOnce() -> St,
    read: impl FnOnce(&St, Loaded) -> R,
) -> R
where
    N: NvStore,
    N::Error: core::fmt::Debug,
    St: PersistentSections,
{
    let state = fresh();
    match store.load(&state) {
        Ok(loaded) => read(&state, loaded),
        Err(error) => defmt::panic!("config log unusable: {}", defmt::Debug2Format(&error)),
    }
}

// The packed span must end below the provisioning sector with room for the
// largest layout: config log + SIAT log (6 sectors) + mc_timer log (2).
const _: () = core::assert!(
    RpFlash::BASE as usize + RP_CONFIG_SIZE + 8 * SECTOR_SIZE <= PROVISIONING_SECTOR_OFFSET as usize,
    "the RP storage regions overlap the provisioning sector"
);

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
