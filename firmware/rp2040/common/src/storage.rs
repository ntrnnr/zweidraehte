//! Flash-based persistent storage and device identity for RP2040/RP2350.
//!
//! # Flash Layout
//!
//! Where the stores go is the device's decision: it places each one on a
//! [`Medium`] ([`QspiFlash`], or another medium of its board) as a constant
//! [`Placement`](zweidraehte_device::storage::Placement). The board's flash
//! size comes from this crate's `flash-*` feature. The shipped boards pack
//! their stores upward from [`STORAGE_BASE`]; on 2 MiB flash:
//!
//! ```text
//! 0x1F2000 .. 0x1F6000  — Config log (two 8 KiB banks)            [every device]
//! 0x1F6000 .. 0x1FC000  — SIAT / sequence log                     [secure only]
//! 0x1FC000 .. 0x1FE000  — mc_timer log                             [IP Secure routing]
//! 0x1FE000 .. 0x1FF000  — unused
//! 0x1FF000 .. 0x200000  — Provisioning sector (KNXP)              [last sector]
//! ```
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
//! [`FlashLog`](zweidraehte_device::storage::FlashLog) before
//! the response to it leaves the device, and `zweidraehte_device::new`
//! replays the log at boot. RP2040 flash writes are byte-granular
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

use zweidraehte_device::sections::PersistentSections;
use zweidraehte_device::storage::{
    Area, DeviceIdentity, LayoutEntry, Loaded, Medium, Region, SecureDeviceIdentity, SiatStore, WearLeveledKv,
};

use crate::flash_seq::RpFlashIo;
use crate::prov_storage::PROVISIONING_SECTOR_OFFSET;

// ================================================================================
// Constants
// ================================================================================

/// The board's flash size, named by its `flash-*` feature of this crate.
#[cfg(feature = "flash-2mb")]
pub const FLASH_SIZE: usize = 2 * 1024 * 1024;
#[cfg(feature = "flash-4mb")]
pub const FLASH_SIZE: usize = 4 * 1024 * 1024;
#[cfg(feature = "flash-8mb")]
pub const FLASH_SIZE: usize = 8 * 1024 * 1024;
#[cfg(feature = "flash-16mb")]
pub const FLASH_SIZE: usize = 16 * 1024 * 1024;
#[cfg(not(any(feature = "flash-2mb", feature = "flash-4mb", feature = "flash-8mb", feature = "flash-16mb")))]
compile_error!("rp-common needs the board's flash size: enable exactly one `flash-*` feature");

/// The flash erase sector: 4 KiB on every QSPI part the RP boots from.
pub const SECTOR_SIZE: usize = 4096;

/// Emit the shared flash handle every RP device builds identically: the
/// blocking `embassy_rp` flash driver behind a `&'static RefCell`, so the
/// config store and any other flash consumer (the sequence store)
/// can alias the single `FLASH` peripheral. Expands to an expression yielding
/// the `&'static RefCell<Flash<…>>`; the [`FLASH_SIZE`] const generic —
/// otherwise repeated four times per device in the handle's type — is pinned
/// here once.
///
/// ```ignore
/// let flash = rp_common::rp_flash_cell!(p.FLASH);
/// let identity_data = load_identity(&mut flash.borrow_mut());
/// let storage = ConfigStorage::new(open_config_log::<ConfigArea>(RpFlashIo::new(flash)));
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

// ================================================================================
// The medium a device places its stores on
// ================================================================================

/// The provisioning sector: the last sector of the board's flash, written
/// once by `knx-provision` and owned by [`crate::prov_storage`].
pub const PROVISIONING_SECTOR: Area = Area::new(PROVISIONING_SECTOR_OFFSET, SECTOR_SIZE as u32);

/// Where the shipped boards' stores start: thirteen sectors below the
/// provisioning sector (`0x1F2000` on 2 MiB flash). They pack upward from
/// here, config log first, so a config-only device and an IP Secure device
/// keep their config log at the same address, and the SIAT log keeps the
/// offset it had when the config was a one-sector blob after it.
pub const STORAGE_BASE: u32 = PROVISIONING_SECTOR.offset - 13 * SECTOR_SIZE as u32;

/// The board's QSPI flash, as a [`Medium`] a device places stores on. Its
/// size comes from the board's `flash-*` feature of this crate; the
/// provisioning sector is reserved.
pub struct QspiFlash;

impl Medium for QspiFlash {
    const ID: u32 = 1;
    type Io = RpFlashIo;
    const CAPACITY: u32 = FLASH_SIZE as u32;
    const ERASE_SIZE: u32 = SECTOR_SIZE as u32;
    const RESERVED: &'static [Area] = &[PROVISIONING_SECTOR];
}

// ================================================================================
// Keeping the firmware image out of the storage
// ================================================================================

/// Where the flash appears in the address space (execute-in-place).
const XIP_BASE: u32 = 0x1000_0000;

/// The absolute address where the storage on the flash begins: the lowest
/// area of `layout` on [`QspiFlash`], or the provisioning sector when that is
/// lower. The layout itself is checked for overlaps where the device
/// declares it.
#[doc(hidden)]
pub const fn storage_start(layout: &[LayoutEntry]) -> u32 {
    let mut start = PROVISIONING_SECTOR.offset;
    let mut i = 0;
    while i < layout.len() {
        if layout[i].medium == QspiFlash::ID && layout[i].area.offset < start {
            start = layout[i].area.offset;
        }
        i += 1;
    }
    XIP_BASE + start
}

/// Declare to the linker the stores a device placed on the flash, from the
/// `STORAGE_LAYOUT` that
/// [`storage_layout!`](zweidraehte_device::storage_layout) declared, so a
/// firmware image that grows into them fails to link instead of overwriting
/// them when it is flashed. The provisioning sector is always included. The
/// device's `build.rs` links the check with `-Tstorage.x`.
///
/// ```ignore
/// zweidraehte_device::storage_layout! {
///     ConfigArea: QspiFlash = Area::new(rp_common::STORAGE_BASE, 16 * 1024);
/// }
/// rp_common::storage_platform!(STORAGE_LAYOUT);
/// ```
#[macro_export]
macro_rules! storage_platform {
    ($layout:path) => {
        ::core::arch::global_asm!(
            ".globl __zw_storage_start",
            ".set __zw_storage_start, {start}",
            start = const $crate::storage::storage_start($layout),
        );
    };
}

// ================================================================================
// The store types on the flash
// ================================================================================

/// The write-through config log on the flash
/// ([`open_config_log`](zweidraehte_device::storage::open_config_log)).
pub type ConfigLog = zweidraehte_device::storage::ConfigLog<Region<RpFlashIo>>;

/// The SIAT and sequence counters on the flash: the wear-levelled log under
/// a RAM mirror ([`open_seq_log`](zweidraehte_device::storage::open_seq_log)).
/// `ENTRIES` sizes the log's record mirror, `CACHE` the SIAT cache, and
/// `BATCH` how many sends the hot sending counter stays off flash.
pub type SiatLog<const ENTRIES: usize, const CACHE: usize, const BATCH: u64> =
    SiatStore<WearLeveledKv<Region<RpFlashIo>, ENTRIES>, CACHE, BATCH>;

/// The IP Secure multicast-timer watermark as a one-key log on the flash
/// ([`open_mc_timer_log`](zweidraehte_device::storage::open_mc_timer_log)).
pub type McTimerLog = WearLeveledKv<Region<RpFlashIo>, 1>;

/// Read part of the stored configuration before the stack exists.
///
/// Some boot decisions come before `zweidraehte_device::new`: an Ethernet
/// device needs its stored IP settings to configure the network stack whose
/// address the KNX/IP link layer is built with. This replays the log into a
/// throwaway factory-fresh state from `fresh` and returns what `read` takes
/// from it, told whether the log held a configuration
/// ([`Loaded::Restored`]) or the state still holds factory defaults.
///
/// `store` must be a second store opened at the same placement
/// (`open_config_log::<ConfigArea>` again). The peek only reads
/// ([`FlashLog::peek`](zweidraehte_device::storage::FlashLog::peek)): a
/// blank or foreign log is formatted, and a long one compacted, by the load
/// in `zweidraehte_device::new`.
///
/// Not inlined, so the temporary state lives on the call stack for the
/// duration of the call, not in the caller's (static) `main` future.
///
/// # Panics
///
/// If the log cannot be used: a layout too large for the area (a sizing
/// mistake of the firmware) or a flash error at boot (a hardware fault).
#[inline(never)]
pub fn peek_config<St, R>(store: ConfigLog, fresh: impl FnOnce() -> St, read: impl FnOnce(&St, Loaded) -> R) -> R
where
    St: PersistentSections,
{
    let state = fresh();
    match store.into_store().peek(&state) {
        Ok(loaded) => read(&state, loaded),
        Err(error) => defmt::panic!("config log unusable: {}", defmt::Debug2Format(&error)),
    }
}

/// Why writing the provisioning record failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum FlashError {
    /// Erasing the provisioning page failed.
    EraseFailed,
    /// Encoding or programming the record failed.
    WriteFailed,
}

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
