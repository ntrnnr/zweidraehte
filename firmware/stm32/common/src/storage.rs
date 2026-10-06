//! Flash-based persistent device-config storage and device identity for STM32
//! targets.
//!
//! # Flash Layout
//!
//! The provisioning page lives at the very top of flash. Where the stores go
//! is the device's decision: it places each one on a [`Medium`]
//! ([`InternalFlash`], [`Fram`]) as a constant
//! [`Placement`](zweidraehte_device::storage::Placement). The shipped boards
//! keep the config log directly below the provisioning page
//! ([`InternalFlash::below_provisioning`]), in flash bank 2 of the 512 KiB
//! STM32G0B0:
//!
//! ```text
//! FLASH_END - PAGE - CONFIG .. FLASH_END - PAGE  — Config log (two 8 KiB banks)
//! FLASH_END - PAGE          .. FLASH_END         — Provisioning page (KNXP) [last page, fixed]
//! ```
//!
//! Pinning provisioning at the very last page and putting the config below
//! it means config-region growth extends toward lower addresses without
//! ever touching the (write-once) provisioning data.
//!
//! The provisioning page is written once on the production line by the
//! host-side `knx-provision` tool over SWD. Format and codec live in
//! [`zweidraehte_device::provisioning`]; the read/write helpers and
//! struct conversions live in [`crate::prov_storage`].
//!
//! # Config storage
//!
//! The ETS-programmed configuration is the device state's persistent
//! sections, written through: the router appends every change to a
//! [`FlashLog`](zweidraehte_device::storage::FlashLog) before
//! the response to it leaves the device, and `zweidraehte_device::new`
//! replays the log at boot. The chip's write granularity (an 8-byte doubleword
//! on the STM32G0) is a fact of the
//! [`StmFlashIo`](crate::flash_io::StmFlashIo) adapter (`SectorIo::WRITE_ALIGN`,
//! from embassy-stm32's `WRITE_SIZE`).
//!
//! # Flash stalls
//!
//! The log lives in bank 2 and the firmware executes from bank 1. Dual-bank
//! flash reads one bank while it programs or erases the other (RM0454
//! §3.3.9): an append does not stall the CPU, and the TPUART keeps being
//! served. The G0B0 runs dual-bank only with the DUAL_BANK option bit set
//! (RM0454 §3.7.8, bit 21); single-bank, every flash operation stalls
//! instruction fetches, so [`log_config_flash_diagnostics`] warns when the
//! bit is clear.
//! The one long operation, compaction (erasing and rewriting a bank), runs
//! from the storage task under the TP1 busy guard either way.
//!
//! # Power loss
//!
//! A doubleword whose programming a power cut interrupted can read back
//! with a double ECC error, which raises an NMI. Replaying a log reads such
//! a torn tail by design, so every firmware installs the handler with
//! [`storage_platform!`](crate::storage_platform), which survives ECC errors
//! inside the device's flash stores (see [`crate::ecc`]).

use fm25l16b::CAPACITY as FRAM_CAPACITY;
use zweidraehte_device::storage::{
    Area, DeviceIdentity, LayoutEntry, Medium, PackedSeqStore, Region, SecureDeviceIdentity,
};

use crate::flash_io::StmFlashIo;
use crate::fram_seq::{FramChip, StmFramCs, StmFramSpi};

// ================================================================================
// The chip's flash geometry, from the chip the build targets
// ================================================================================
//
// embassy-stm32 generates these from the chip feature the device selects
// (`stm32g0b0re` on the shipped boards), so another chip brings its own
// geometry and the layout below follows it.

/// The chip's internal flash size.
pub const FLASH_SIZE: u32 = embassy_stm32::flash::FLASH_SIZE as u32;

/// The flash erase page.
pub const PAGE_SIZE: u32 = embassy_stm32::flash::MAX_ERASE_SIZE as u32;

/// The provisioning page: the last page of flash, written once by
/// `knx-provision` and owned by [`crate::prov_storage`].
pub const PROVISIONING_PAGE: Area = Area::new(FLASH_SIZE - PAGE_SIZE, PAGE_SIZE);

/// Where flash bank 2 starts, relative to the flash base, on a dual-bank
/// chip; `None` on a single-bank one.
pub const BANK2_OFFSET: Option<u32> = {
    let regions = embassy_stm32::flash::FLASH_REGIONS;
    let mut bank2 = None;
    let mut i = 0;
    while i < regions.len() {
        if bank2.is_none() && matches!(regions[i].bank, embassy_stm32::flash::FlashBank::Bank2) {
            bank2 = Some(regions[i].base - embassy_stm32::flash::FLASH_BASE as u32);
        }
        i += 1;
    }
    bank2
};

// ================================================================================
// The media a device places its stores on
// ================================================================================

/// The chip's internal flash, as a [`Medium`] a device places stores on.
/// Its geometry comes from the chip the build targets; the provisioning page
/// is reserved.
///
/// A config log here benefits from flash bank 2 on a dual-bank chip
/// ([`InternalFlash::in_bank2`]).
pub struct InternalFlash;

impl Medium for InternalFlash {
    const ID: u32 = 1;
    type Io = StmFlashIo;
    const CAPACITY: u32 = FLASH_SIZE;
    const ERASE_SIZE: u32 = PAGE_SIZE;
    const RESERVED: &'static [Area] = &[PROVISIONING_PAGE];
}

impl InternalFlash {
    /// The `len` bytes directly below the provisioning page: where the
    /// shipped boards keep their config log (`0x7B800` on the 512 KiB
    /// STM32G0B0).
    pub const fn below_provisioning(len: u32) -> Area {
        assert!(len <= PROVISIONING_PAGE.offset, "the area fits below the provisioning page");
        Area::new(PROVISIONING_PAGE.offset - len, len)
    }

    /// `area`, checked to lie in flash bank 2 on a dual-bank chip, away from
    /// the code in bank 1: read-while-write only lets an append run without
    /// stalling the CPU if the log is in the bank the code is not in. On a
    /// single-bank chip every area passes.
    ///
    /// # Panics
    ///
    /// If the area starts in bank 1; in a `const` that is a compile error.
    pub const fn in_bank2(area: Area) -> Area {
        if let Some(bank2) = BANK2_OFFSET {
            assert!(area.offset >= bank2, "the area lies in flash bank 2, away from the code in bank 1");
        }
        area
    }
}

/// The FM25L16B SPI FRAM some STM32 boards carry, as a byte-writable
/// [`Medium`]. Whether a board has one, and which stores live on it, is the
/// device's decision.
pub struct Fram;

impl Medium for Fram {
    const ID: u32 = 2;
    type Io = FramChip<StmFramSpi, StmFramCs>;
    const CAPACITY: u32 = FRAM_CAPACITY as u32;
    const ERASE_SIZE: u32 = 1;
}

// ================================================================================
// Keeping the firmware image out of the storage
// ================================================================================

/// The absolute address where the storage on the internal flash begins: the
/// lowest area of `layout` on [`InternalFlash`], or the provisioning page
/// when that is lower. The layout itself is checked for overlaps where the
/// device declares it.
#[doc(hidden)]
pub const fn storage_start(layout: &[LayoutEntry]) -> u32 {
    let mut start = PROVISIONING_PAGE.offset;
    let mut i = 0;
    while i < layout.len() {
        if layout[i].medium == InternalFlash::ID && layout[i].area.offset < start {
            start = layout[i].area.offset;
        }
        i += 1;
    }
    FLASH_BASE + start
}

/// The absolute address the firmware image must end below: the start of the
/// storage, or, on a dual-bank chip whose storage lies in bank 2, the start
/// of bank 2, unless `shared_bank` accepts code in the stores' bank.
#[doc(hidden)]
pub const fn code_limit(layout: &[LayoutEntry], shared_bank: bool) -> u32 {
    let start = storage_start(layout);
    match BANK2_OFFSET {
        Some(bank2) if !shared_bank && start >= FLASH_BASE + bank2 => FLASH_BASE + bank2,
        _ => start,
    }
}

/// The absolute flash base, from the chip the build targets.
const FLASH_BASE: u32 = embassy_stm32::flash::FLASH_BASE as u32;

/// Install what the platform needs to know about a device's stores, from the
/// `STORAGE_LAYOUT` that
/// [`storage_layout!`](zweidraehte_device::storage_layout) declared. Invoke
/// it once, at the top level of the firmware's `main.rs`: a handler defined
/// in this library would not reliably be linked.
///
/// - **Linker reservation.** The stores on [`InternalFlash`] and the
///   provisioning page are declared to the linker, so a firmware image that
///   grows into them fails to link instead of overwriting them when it is
///   flashed. The device's `build.rs` links the check with `-Tstorage.x`.
///   On a dual-bank chip whose stores lie in bank 2, the image must also stay
///   in bank 1: appending to a log in the bank the code runs from stalls the
///   code, which is what the bank split avoids (RM0454 §3.3.9). A device that
///   accepts the stalls in exchange for more code space declares
///   `storage_platform!(shared_bank: STORAGE_LAYOUT)`.
/// - **Flash ECC recovery.** The NMI handler acknowledges double ECC errors
///   inside the stores on [`InternalFlash`], which their log replay reads
///   past by design, and keeps every other NMI fatal (see [`crate::ecc`]).
///
/// ```ignore
/// zweidraehte_device::storage_layout! {
///     ConfigArea: InternalFlash = InternalFlash::in_bank2(InternalFlash::below_provisioning(16 * 1024));
/// }
/// stm32_common::storage_platform!(STORAGE_LAYOUT);
/// ```
#[macro_export]
macro_rules! storage_platform {
    (shared_bank: $layout:path) => {
        $crate::storage_platform!(@emit true; $layout);
    };
    (@emit $shared_bank:literal; $layout:path) => {
        ::core::arch::global_asm!(
            ".globl __zw_storage_start",
            ".set __zw_storage_start, {start}",
            ".globl __zw_code_limit",
            ".set __zw_code_limit, {limit}",
            start = const $crate::storage::storage_start($layout),
            limit = const $crate::storage::code_limit($layout, $shared_bank),
        );

        #[::cortex_m_rt::exception]
        unsafe fn NonMaskableInt() {
            // SAFETY: this is the NMI handler.
            if !unsafe { $crate::ecc::recover_flash_ecc_error($layout) } {
                ::defmt::panic!("NMI: not a flash ECC error inside a flash store");
            }
        }
    };
    ($layout:path) => {
        $crate::storage_platform!(@emit false; $layout);
    };
}

// ================================================================================
// The store types on these media
// ================================================================================

/// The write-through config log on the internal flash
/// ([`open_config_log`](zweidraehte_device::storage::open_config_log)).
pub type ConfigLog = zweidraehte_device::storage::ConfigLog<Region<StmFlashIo>>;

/// The SIAT and sequence counters in the packed layout on the FRAM, for
/// `SLOTS` SIAT elements
/// ([`open_packed_seq`](zweidraehte_device::storage::open_packed_seq)).
pub type FramSeqStore<const SLOTS: usize> = PackedSeqStore<Region<FramChip<StmFramSpi, StmFramCs>>, SLOTS>;

/// Log what boot learned about the config flash: a warning when the flash
/// runs single-bank, and the torn doublewords the log replay passed.
///
/// `zweidraehte_device::new` replays the log; call this after it, so the
/// ECC count covers that replay.
pub fn log_config_flash_diagnostics() {
    // RM0454 §3.7.8: DUAL_BANK clear runs the 512 KiB flash single-bank.
    if !embassy_stm32::pac::FLASH.optr().read().dual_bank() {
        defmt::warn!("flash runs single-bank (DUAL_BANK option clear): config appends stall the CPU and the TPUART");
    }

    let ecc_errors = crate::ecc::recovered_ecc_errors();
    if ecc_errors > 0 {
        defmt::warn!("config log replay passed {} torn doublewords (flash ECC)", ecc_errors);
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
// Device identity (sourced from the KNXP provisioning page)
// ================================================================================

/// Identity record for a plain (non-secure) device.
///
/// Built from the parsed `KNXP` record by
/// [`crate::prov_storage::identity_from_record`]. Holds just the KNX
/// serial — no FDSK, no MAC.
#[derive(Debug, Clone, defmt::Format)]
pub struct FlashIdentityData {
    /// KNX serial number: 2 bytes manufacturer ID (big-endian) followed by
    /// 4 bytes assigned at provisioning time.
    pub serial_number: [u8; 6],
}

impl DeviceIdentity for FlashIdentityData {
    fn serial_number(&self) -> &[u8; 6] {
        &self.serial_number
    }
}

/// Derive a deterministic `u64` seed from the live STM32 factory UID.
///
/// Used for embassy-net's IGMP delay and other per-device entropy needs
/// that don't require crypto-strength randomness. The UID is not stored in
/// the provisioning record; the peripheral is read at call time.
fn derive_seed_from_uid() -> u64 {
    let uid = embassy_stm32::uid::uid();
    let mut buf = [0u8; 8];
    for (i, b) in buf.iter_mut().enumerate() {
        *b = uid[i] ^ uid[(i + 4) % 12];
    }
    u64::from_le_bytes(buf)
}

impl FlashIdentityData {
    /// Deterministic per-device seed — see [`derive_seed_from_uid`].
    pub fn derive_seed(&self) -> u64 {
        derive_seed_from_uid()
    }
}

/// Identity record for a KNX Data Secure device.
///
/// Mirrors [`FlashIdentityData`] and adds the 16-byte FDSK from the
/// provisioning record. Built by
/// [`crate::prov_storage::secure_identity_from_record`].
#[derive(Debug, Clone, defmt::Format)]
pub struct FlashSecureIdentityData {
    pub serial_number: [u8; 6],
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
    /// Deterministic per-device seed — see [`derive_seed_from_uid`].
    pub fn derive_seed(&self) -> u64 {
        derive_seed_from_uid()
    }

    /// Hyphenated Base32 ETS label code. Thin shim over
    /// [`fdsk_label::fdsk_string`]; kept on the type for ergonomic
    /// `identity_data.fdsk_string()` calls in firmware.
    pub fn fdsk_string(&self) -> [u8; 41] {
        fdsk_label::fdsk_string(&self.serial_number, &self.fdsk)
    }
}
