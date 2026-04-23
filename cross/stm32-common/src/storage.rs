//! Flash-based persistent storage and device identity for STM32 targets.
//!
//! # Flash Layout
//!
//! The last two flash pages are reserved for KNX persistence. Page size is
//! generic across supported STM32 families but the defaults assume the
//! STM32G0 family's 2 KB page:
//!
//! ```text
//! FLASH_END - 2*PAGE_SIZE .. FLASH_END - PAGE_SIZE   — Identity page
//! FLASH_END -   PAGE_SIZE .. FLASH_END                — Config page
//! ```
//!
//! The identity page is written once on first boot and survives firmware
//! updates and factory resets. The config page stores ETS-programmed
//! device state via [`StmFlashStorage`].
//!
//! # Identity Page Format
//!
//! ```text
//! [magic: 4B "KNXI"][serial_number: 6B][uid: 12B][padding to doubleword]
//! ```
//!
//! The STM32's 96-bit factory UID (from `embassy_stm32::uid::uid()`) is
//! XOR-folded into 4 device-specific bytes to produce the lower half of
//! the 6-byte KNX serial number; the manufacturer ID forms the upper 2.
//!
//! # Config Page Format
//!
//! ```text
//! [magic: 4B "KNXS"][len: 2B little-endian][postcard payload]
//! ```
//!
//! The magic bytes guard against reading uninitialized flash (all `0xFF`).
//!
//! # Write Granularity
//!
//! STM32 flash on the G0 family writes 8 bytes (one doubleword) at a
//! time. All writes are padded up to a multiple of 8 bytes with `0xFF`,
//! which is the erased value and therefore a valid post-erase content.
//!
//! # Flash Stall Warning
//!
//! `blocking_erase` and `blocking_write` suspend CPU execution for several
//! milliseconds per page. Following the same policy as `pico_tp1`, we
//! save only in the restart handler — never periodically — so a stall
//! cannot corrupt the TPUART UART timing.

use embassy_stm32::flash::{Blocking, Flash};
use serde::{Deserialize, Serialize};

use zweidraehte_device::bcus::system_b::HasDeviceConfig;
use zweidraehte_device::storage::DeviceIdentity;

// ================================================================================
// Constants
// ================================================================================

/// Doubleword alignment required by STM32 flash writes.
const WRITE_ALIGN: usize = 8;

// -- Config page constants ----------------------------------------------------

const CONFIG_MAGIC: [u8; 4] = *b"KNXS";
/// 4 bytes magic + 2 bytes payload length.
const CONFIG_HEADER_SIZE: usize = 6;

// -- Identity page constants --------------------------------------------------

const IDENTITY_MAGIC: [u8; 4] = *b"KNXI";
/// 4B magic + 6B serial + 12B factory UID.
const IDENTITY_RECORD_SIZE: usize = 4 + 6 + 12;

// ================================================================================
// StmFlashStorage
// ================================================================================

/// Persistent storage backed by STM32 internal flash.
///
/// Type parameters:
/// - `S` — runtime state type (e.g. `Stm32G0Tp1State`). Converted to/from
///   its serializable `S::Config` via [`HasDeviceConfig`].
/// - `I` — device identity (typically [`FlashIdentityData`]).
/// - `FLASH_SIZE` — total flash in bytes. For STM32G0B0RE this is
///   `512 * 1024`.
/// - `PAGE_SIZE` — flash erase-page size in bytes. STM32G0 = 2048, STM32G4
///   = 2048 or 4096, STM32F4 = variable. Check the datasheet.
///
/// The two last pages of flash are used; nothing overlapping those
/// regions can be written by firmware (reserve them in `memory.x` if the
/// linker would otherwise place code there — embassy-stm32's
/// `"memory-x"` feature leaves the whole flash available).
pub struct StmFlashStorage<S, I, const FLASH_SIZE: u32, const PAGE_SIZE: u32> {
    flash: Flash<'static, Blocking>,
    identity: I,
    dirty: bool,
    _phantom: core::marker::PhantomData<S>,
}

impl<S, I, const FLASH_SIZE: u32, const PAGE_SIZE: u32> StmFlashStorage<S, I, FLASH_SIZE, PAGE_SIZE> {
    // Offset (not absolute address) of the config page. embassy-stm32's
    // `Flash::blocking_*` API takes offsets from the flash base
    // (0x0800_0000 on STM32G0). The identity-page offset lives in
    // `read_or_provision_identity` so identity provisioning does not
    // have to fabricate a `StmFlashStorage` just to compute it.
    const CONFIG_OFFSET: u32 = FLASH_SIZE - PAGE_SIZE;

    const _VALIDATE: () = {
        assert!(PAGE_SIZE > 0, "PAGE_SIZE must be non-zero");
        assert!(FLASH_SIZE >= 2 * PAGE_SIZE, "FLASH_SIZE must hold two reserved pages");
        assert!(FLASH_SIZE % PAGE_SIZE == 0, "FLASH_SIZE must be a multiple of PAGE_SIZE");
    };

    pub fn new(flash: Flash<'static, Blocking>, identity: I) -> Self {
        let _ = Self::_VALIDATE;
        Self { flash, identity, dirty: false, _phantom: core::marker::PhantomData }
    }

    pub fn identity(&self) -> &I {
        &self.identity
    }
}

impl<S, I, const FLASH_SIZE: u32, const PAGE_SIZE: u32> StmFlashStorage<S, I, FLASH_SIZE, PAGE_SIZE>
where
    S: HasDeviceConfig,
    S::Config: Serialize + for<'de> Deserialize<'de>,
{
    /// Read and deserialize the persisted config from flash.
    ///
    /// `None` means either the config page is erased (first boot) or its
    /// magic bytes do not match. Postcard deserialization failures are
    /// treated the same as a missing config — the device starts fresh.
    pub fn load_config(&mut self) -> Result<Option<S::Config>, FlashError> {
        // We only need the header plus the payload length worth of
        // bytes, but reading the full page is simpler and costs nothing.
        // Allocate at most PAGE_SIZE on the stack. PAGE_SIZE is 2 KiB on
        // G0 — comfortably fits even on the smallest M0+ stack.
        assert!(PAGE_SIZE <= 4096, "PAGE_SIZE too large for stack buffer");
        let mut region = [0u8; 4096];
        let region = &mut region[..PAGE_SIZE as usize];

        self.flash.blocking_read(Self::CONFIG_OFFSET, region).map_err(|_| FlashError::ReadFailed)?;

        if region[0..4] != CONFIG_MAGIC {
            return Ok(None);
        }
        let len = u16::from_le_bytes([region[4], region[5]]) as usize;
        if len == 0 || CONFIG_HEADER_SIZE + len > region.len() {
            return Ok(None);
        }

        let payload = &region[CONFIG_HEADER_SIZE..CONFIG_HEADER_SIZE + len];
        match postcard::from_bytes::<S::Config>(payload) {
            Ok(persisted) => Ok(Some(persisted)),
            Err(_) => {
                defmt::warn!("Flash storage: postcard deserialization failed, returning None");
                Ok(None)
            }
        }
    }
}

impl<S, I, const FLASH_SIZE: u32, const PAGE_SIZE: u32> StmFlashStorage<S, I, FLASH_SIZE, PAGE_SIZE>
where
    S: HasDeviceConfig,
    S::Config: Serialize + for<'de> Deserialize<'de>,
    I: DeviceIdentity,
{
    /// Serialize `state` and persist it to the config page.
    ///
    /// Erases the page and writes header + postcard payload, padded up to
    /// a doubleword boundary with `0xFF`. Clears the dirty flag on success.
    pub fn save(&mut self, state: &S) -> Result<(), FlashError> {
        let persisted = state.to_config();

        // One page worth of stack buffer — same bound as `load_config`.
        assert!(PAGE_SIZE <= 4096, "PAGE_SIZE too large for stack buffer");
        let mut buf = [0xFFu8; 4096];
        let buf = &mut buf[..PAGE_SIZE as usize];

        buf[0..4].copy_from_slice(&CONFIG_MAGIC);

        let payload = postcard::to_slice(&persisted, &mut buf[CONFIG_HEADER_SIZE..])
            .expect("serialized state exceeds flash page size");
        let len = payload.len();
        buf[4..6].copy_from_slice(&(len as u16).to_le_bytes());

        // Pad up to a doubleword so the STM32 flash write accepts it.
        let used = CONFIG_HEADER_SIZE + len;
        let padded = (used + WRITE_ALIGN - 1) & !(WRITE_ALIGN - 1);

        self.flash
            .blocking_erase(Self::CONFIG_OFFSET, Self::CONFIG_OFFSET + PAGE_SIZE)
            .map_err(|_| FlashError::EraseFailed)?;
        self.flash.blocking_write(Self::CONFIG_OFFSET, &buf[..padded]).map_err(|_| FlashError::WriteFailed)?;

        self.dirty = false;
        Ok(())
    }

    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }
}

// ================================================================================
// Error type
// ================================================================================

#[derive(Debug, defmt::Format)]
pub enum FlashError {
    ReadFailed,
    EraseFailed,
    WriteFailed,
}

// ================================================================================
// Flash Identity Provisioning
// ================================================================================

/// Identity record read from (or provisioned into) the flash identity page.
///
/// Stores the 6-byte KNX serial number plus the raw 96-bit factory UID
/// so downstream code can derive MAC addresses or RNG seeds without
/// re-reading the UID peripheral.
#[derive(Debug, Clone, defmt::Format)]
pub struct FlashIdentityData {
    /// KNX serial number: 2 bytes manufacturer ID (big-endian) followed by
    /// 4 bytes XOR-folded from the factory UID.
    pub serial_number: [u8; 6],
    /// Raw factory UID (96-bit). Useful for deriving MAC addresses and
    /// entropy seeds beyond the KNX serial number.
    pub uid: [u8; 12],
}

impl DeviceIdentity for FlashIdentityData {
    fn serial_number(&self) -> &[u8; 6] {
        &self.serial_number
    }
}

impl FlashIdentityData {
    /// Derive a locally-administered unicast MAC address.
    ///
    /// `oui` provides the 3-byte vendor prefix; bit 1 of the first byte
    /// (locally administered) is forced set, bit 0 (multicast) forced
    /// clear. The remaining 3 bytes come from the UID.
    pub fn derive_mac_address(&self, oui: [u8; 3]) -> [u8; 6] {
        [(oui[0] | 0x02) & 0xFE, oui[1], oui[2], self.uid[0], self.uid[1], self.uid[2]]
    }

    /// Derive a deterministic `u64` seed from the UID.
    pub fn derive_seed(&self) -> u64 {
        let mut buf = [0u8; 8];
        // Fold the 12-byte UID into 8 bytes.
        for (i, b) in buf.iter_mut().enumerate() {
            *b = self.uid[i] ^ self.uid[(i + 4) % 12];
        }
        u64::from_le_bytes(buf)
    }
}

/// Read the device identity from flash, or provision it on first boot.
///
/// On first boot (identity page erased, `0xFF`):
/// 1. Reads the STM32's 96-bit factory UID via
///    `embassy_stm32::uid::uid()`.
/// 2. XOR-folds it into 4 device-specific bytes.
/// 3. Prepends the `manufacturer_id` to form the 6-byte KNX serial
///    number.
/// 4. Writes the identity page to flash (one-time, brief CPU stall).
///
/// On subsequent boots, reads and returns the stored identity.
///
/// # Panics
/// Panics if flash I/O fails. Identity provisioning is critical for KNX
/// operation — there is no meaningful fallback at boot time.
pub fn read_or_provision_identity<const FLASH_SIZE: u32, const PAGE_SIZE: u32>(
    flash: &mut Flash<'static, Blocking>,
    manufacturer_id: [u8; 2],
) -> FlashIdentityData {
    let identity_offset = FLASH_SIZE - 2 * PAGE_SIZE;

    let mut buf = [0u8; IDENTITY_RECORD_SIZE];
    flash.blocking_read(identity_offset, &mut buf).expect("identity page read");

    if buf[0..4] == IDENTITY_MAGIC {
        let mut serial_number = [0u8; 6];
        serial_number.copy_from_slice(&buf[4..10]);
        let mut uid = [0u8; 12];
        uid.copy_from_slice(&buf[10..22]);
        defmt::info!("Identity loaded: serial={=[u8]:02x}", serial_number);
        return FlashIdentityData { serial_number, uid };
    }

    // First boot — derive from the factory UID.
    defmt::info!("Identity page empty, provisioning from STM32 factory UID...");
    let uid = embassy_stm32::uid::uid();

    // XOR-fold the 96-bit UID into 4 device-specific bytes. Any consistent
    // fold works; we use three 4-byte chunks XORed together so every bit
    // of the UID contributes to the serial.
    let device_bytes =
        [uid[0] ^ uid[4] ^ uid[8], uid[1] ^ uid[5] ^ uid[9], uid[2] ^ uid[6] ^ uid[10], uid[3] ^ uid[7] ^ uid[11]];

    let serial_number =
        [manufacturer_id[0], manufacturer_id[1], device_bytes[0], device_bytes[1], device_bytes[2], device_bytes[3]];

    // Pad IDENTITY_RECORD_SIZE (22) up to a doubleword (24) for the
    // STM32 flash write unit.
    let padded = (IDENTITY_RECORD_SIZE + WRITE_ALIGN - 1) & !(WRITE_ALIGN - 1);
    let mut write_buf = [0xFFu8; 32];
    let write_buf = &mut write_buf[..padded];
    write_buf[0..4].copy_from_slice(&IDENTITY_MAGIC);
    write_buf[4..10].copy_from_slice(&serial_number);
    write_buf[10..22].copy_from_slice(&uid);

    flash.blocking_erase(identity_offset, identity_offset + PAGE_SIZE).expect("identity page erase");
    flash.blocking_write(identity_offset, write_buf).expect("identity page write");

    defmt::info!("Identity provisioned: serial={=[u8]:02x}, uid={=[u8]:02x}", serial_number, uid,);

    FlashIdentityData { serial_number, uid }
}
