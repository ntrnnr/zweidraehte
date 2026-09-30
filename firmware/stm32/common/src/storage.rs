//! Flash-based persistent device-config storage and device identity for STM32
//! targets.
//!
//! # Flash Layout
//!
//! The provisioning page lives at the very top of flash; the config log
//! sits immediately below it, in flash bank 2 of the 512 KiB STM32G0B0:
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
//! [`FlashLog`](zweidraehte_device::storage::region::ConfigLogRegion) before
//! the response to it leaves the device, and boot replays the log
//! ([`restore_config`]). The family's 8-byte doubleword write granularity is
//! a fact of the [`StmFlashIo`](crate::flash_io::StmFlashIo) adapter
//! (`SectorIo::WRITE_ALIGN = 8`).
//!
//! # Flash stalls
//!
//! The log lives in bank 2 and the firmware executes from bank 1. Dual-bank
//! flash reads one bank while it programs or erases the other (RM0454
//! §3.3.9): an append does not stall the CPU, and the TPUART keeps being
//! served. The G0B0 runs dual-bank only with the DUAL_BANK option bit set
//! (RM0454 §3.7.8, bit 21); single-bank, every flash operation stalls
//! instruction fetches, so [`restore_config`] warns when the bit is clear.
//! The one long operation, compaction (erasing and rewriting a bank), runs
//! from the storage task under the TP1 busy guard either way.
//!
//! # Power loss
//!
//! A doubleword whose programming a power cut interrupted can read back
//! with a double ECC error, which raises an NMI. Replaying the log reads
//! such a torn tail by design, so every firmware installs
//! [`stm32_flash_ecc_nmi!`](crate::stm32_flash_ecc_nmi), which survives
//! ECC errors inside the config log (see [`crate::ecc`]).

use zweidraehte_device::HasPersistence;
use zweidraehte_device::sections::PersistentSections;
use zweidraehte_device::storage::region::{Chip, ConfigLogRegion};
use zweidraehte_device::storage::{DeviceIdentity, Loaded, NvConfig, NvStore, SecureDeviceIdentity};

use crate::flash_io::StmFlashIo;

// ================================================================================
// STM32G0 config-region layout
// ================================================================================

/// Total internal flash on the STM32G0B0RE.
pub const STM32G0_FLASH_SIZE: u32 = 512 * 1024;
/// STM32G0 flash erase-page size.
pub const STM32G0_PAGE_SIZE: u32 = 2 * 1024;
/// Where flash bank 2 starts, relative to the flash base.
pub const STM32G0_BANK2_OFFSET: u32 = STM32G0_FLASH_SIZE / 2;
/// Config log size: 8 pages, two banks of 8 KiB. Each bank must hold a full
/// snapshot of the device's sections plus room for the appends between
/// compactions; a download takes well under one bank.
pub const STM32G0_CONFIG_SIZE: usize = 16 * 1024;

/// The config region every STM32G0 device places, carrying the device's
/// runtime state type `S`:
///
/// ```ignore
/// type Cfg = Placed<StmConfigRegion<MyDeviceState>, StmFlash, StorageMap>;
/// ```
///
/// The store type and its `open` derive from the region (`StoreOf<Cfg>` /
/// `Cfg::open(StmFlashIo::new(flash))`); the store is an
/// [`NvConfig`] the router flushes, restored at boot by [`restore_config`].
pub type StmConfigRegion<S> = ConfigLogRegion<STM32G0_CONFIG_SIZE, S>;

// ================================================================================
// StmFlash — the storage layer's view of the STM32G0 internal flash chip
// ================================================================================

/// The STM32G0 internal flash, as a [`Chip`] the storage layer packs regions
/// onto.
///
/// `BASE` is the start of the config log, directly below the write-once
/// provisioning page owned by [`crate::prov_storage`]. Every STM32G0 device
/// has exactly one flash region (the config log); the FRAM-secure variants
/// keep their SIAT on the separate [`Fram`](crate::fram_seq::Fram) chip, so
/// a single-region pack lands the config at `BASE`. `CAPACITY` stops one page
/// below the top so the per-chip guard protects the provisioning page.
///
/// A new STM32 family with a different page/flash size adds a sibling `Chip`
/// impl with its own `BASE`/`CAPACITY`.
#[derive(Clone, Copy)]
pub struct StmFlash;

impl Chip for StmFlash {
    const TAG: u32 = 0;
    const BASE: u32 = STM32G0_FLASH_SIZE - STM32G0_PAGE_SIZE - STM32G0_CONFIG_SIZE as u32;
    const CAPACITY: u32 = STM32G0_FLASH_SIZE - STM32G0_PAGE_SIZE;
    const SECTOR_SIZE: u32 = STM32G0_PAGE_SIZE;
    type Io = StmFlashIo;
}

// Read-while-write only helps if the log is in the bank the code is not in.
const _: () = core::assert!(
    StmFlash::BASE >= STM32G0_BANK2_OFFSET,
    "the config log must lie in flash bank 2, away from the code in bank 1"
);

/// Boot: apply the config log to the freshly created stack's `state`, or
/// format the log with the factory state, and clear the dirty flag so the
/// router does not flush what was just loaded. Logs the outcome and any
/// torn doublewords the replay passed, and warns when the flash runs
/// single-bank.
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
    // RM0454 §3.7.8: DUAL_BANK clear runs the 512 KiB flash single-bank.
    if !embassy_stm32::pac::FLASH.optr().read().dual_bank() {
        defmt::warn!("flash runs single-bank (DUAL_BANK option clear): config appends stall the CPU and the TPUART");
    }

    match config.load(state) {
        Ok(Loaded::Restored) => defmt::info!("config restored from flash"),
        Ok(Loaded::Fresh) => defmt::info!("no stored config for this layout, starting fresh"),
        Err(error) => defmt::panic!("config log unusable: {}", defmt::Debug2Format(&error)),
    }
    let ecc_errors = crate::ecc::recovered_ecc_errors();
    if ecc_errors > 0 {
        defmt::warn!("config log replay passed {} torn doublewords (flash ECC)", ecc_errors);
    }
    state.clear_dirty();
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
