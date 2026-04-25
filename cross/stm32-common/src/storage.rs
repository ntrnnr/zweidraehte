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
//! Plain (non-secure):
//! ```text
//! [magic: 4B "KNXI"][serial_number: 6B][padding to doubleword]
//! ```
//!
//! Data Secure:
//! ```text
//! [magic: 4B "KNX2"][serial_number: 6B][fdsk: 16B][padding to doubleword]
//! ```
//!
//! The STM32's 96-bit factory UID (from `embassy_stm32::uid::uid()`) is
//! XOR-folded into 4 device-specific bytes to produce the lower half of
//! the 6-byte KNX serial number; the manufacturer ID forms the upper 2.
//! The UID itself is *not* persisted — downstream helpers that need it
//! read the peripheral at call time.
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
use zweidraehte_device::storage::{DeviceIdentity, SecureDeviceIdentity};

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

/// Magic for the plain (non-secure) identity record.
const IDENTITY_MAGIC: [u8; 4] = *b"KNXI";
/// 4B magic + 6B serial.
const IDENTITY_RECORD_SIZE: usize = 4 + 6;

/// Magic for the Data Secure identity record. Different from the plain
/// magic so a chip first programmed with the insecure firmware and then
/// re-flashed to the secure one triggers a fresh provisioning pass
/// (rather than reading back a zero FDSK).
///
/// Bumped from `"KNXS"` to `"KNX2"` when the stored UID was removed
/// from the record — old-format devices re-provision automatically on
/// next boot after a firmware update (requires `ZZ_FDSK_HEX` set at
/// build time, same as a fresh provisioning).
const SECURE_IDENTITY_MAGIC: [u8; 4] = *b"KNX2";
/// 4B magic + 6B serial + 16B FDSK.
const SECURE_IDENTITY_RECORD_SIZE: usize = 4 + 6 + 16;

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
/// Holds just the 6-byte KNX serial number. The serial is XOR-folded
/// from the factory UID at provisioning time; helpers that need raw
/// UID bytes (`derive_mac_address`, `derive_seed`) read the peripheral
/// via `embassy_stm32::uid::uid()` directly.
#[derive(Debug, Clone, defmt::Format)]
pub struct FlashIdentityData {
    /// KNX serial number: 2 bytes manufacturer ID (big-endian) followed by
    /// 4 bytes XOR-folded from the factory UID.
    pub serial_number: [u8; 6],
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
    /// clear. The remaining 3 bytes come from the live STM32 factory UID.
    pub fn derive_mac_address(&self, oui: [u8; 3]) -> [u8; 6] {
        let uid = embassy_stm32::uid::uid();
        [(oui[0] | 0x02) & 0xFE, oui[1], oui[2], uid[0], uid[1], uid[2]]
    }

    /// Derive a deterministic `u64` seed from the live factory UID.
    pub fn derive_seed(&self) -> u64 {
        let uid = embassy_stm32::uid::uid();
        let mut buf = [0u8; 8];
        // Fold the 12-byte UID into 8 bytes.
        for (i, b) in buf.iter_mut().enumerate() {
            *b = uid[i] ^ uid[(i + 4) % 12];
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
        defmt::info!("Identity loaded: serial={=[u8]:02x}", serial_number);
        return FlashIdentityData { serial_number };
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

    // Pad IDENTITY_RECORD_SIZE (10) up to a doubleword (16) for the
    // STM32 flash write unit.
    let padded = (IDENTITY_RECORD_SIZE + WRITE_ALIGN - 1) & !(WRITE_ALIGN - 1);
    let mut write_buf = [0xFFu8; 16];
    let write_buf = &mut write_buf[..padded];
    write_buf[0..4].copy_from_slice(&IDENTITY_MAGIC);
    write_buf[4..10].copy_from_slice(&serial_number);

    flash.blocking_erase(identity_offset, identity_offset + PAGE_SIZE).expect("identity page erase");
    flash.blocking_write(identity_offset, write_buf).expect("identity page write");

    defmt::info!("Identity provisioned: serial={=[u8]:02x}", serial_number);

    FlashIdentityData { serial_number }
}

// ================================================================================
// Secure Flash Identity Provisioning (KNX Data Secure)
// ================================================================================

/// Identity record for a KNX Data Secure device.
///
/// Mirrors [`FlashIdentityData`] and adds a 16-byte FDSK (Factory
/// Default Setup Key). The FDSK is baked in at provisioning time — on
/// first boot the firmware supplies it (normally via a build-time env
/// var) and it is written into the identity page alongside the serial,
/// never to change again.
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
    /// Same derivations as [`FlashIdentityData::derive_mac_address`] —
    /// reads the live STM32 factory UID from the peripheral.
    pub fn derive_mac_address(&self, oui: [u8; 3]) -> [u8; 6] {
        let uid = embassy_stm32::uid::uid();
        [(oui[0] | 0x02) & 0xFE, oui[1], oui[2], uid[0], uid[1], uid[2]]
    }

    pub fn derive_seed(&self) -> u64 {
        let uid = embassy_stm32::uid::uid();
        let mut buf = [0u8; 8];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = uid[i] ^ uid[(i + 4) % 12];
        }
        u64::from_le_bytes(buf)
    }

    /// Format the serial + FDSK as the dashed Base32 string that ETS
    /// expects on the printed device label.
    ///
    /// Output: 36 RFC 4648 Base32 characters (A–Z, 2–7) broken into
    /// six dash-separated groups of six — `XXXXXX-XXXXXX-…-XXXXXX`.
    /// Total 41 bytes, no terminator.
    ///
    /// Construction:
    ///
    /// 1. Concatenate `[serial(6) || fdsk(16) || 0x00]` → 23 bytes.
    /// 2. Compute CRC-4 (x⁴+x+1, nibble-wise high-then-low) over the
    ///    first 22 bytes (the serial and FDSK, **not** the trailing
    ///    placeholder), place it in the high nibble of the last byte.
    /// 3. Base32-encode the first 180 bits (= first 36 symbols; the
    ///    trailing 37th symbol encoding the four zero pad bits is
    ///    discarded).
    /// 4. Insert `-` after every 6 output chars.
    ///
    /// The KNX spec (03/05/01 §6.1.3) leaves the label format
    /// unspecified — "function of the Security Algorithm". This
    /// hyphenated-Base32 encoding is what ETS accepts in practice.
    ///
    /// Example: `serial=00FA.DEAD.BEEF`, `fdsk=00..0F` →
    /// `AD5K3V-4XPIAA-QEBAGB-AGEAYD-AOBQHA-YDAMBA`.
    pub fn fdsk_string(&self) -> [u8; 41] {
        fdsk_string(&self.serial_number, &self.fdsk)
    }
}

/// CRC-4 table (generator polynomial x⁴+x+1), nibble-wise.
const FDSK_CRC4_TAB: [u8; 16] = [0x0, 0x3, 0x6, 0x5, 0xc, 0xf, 0xa, 0x9, 0xb, 0x8, 0xd, 0xe, 0x7, 0x4, 0x1, 0x2];

fn fdsk_crc4(bytes: &[u8]) -> u8 {
    let mut c: u8 = 0;
    for &b in bytes {
        // High nibble first, then low nibble — exactly the reference's
        // order. Swapping these produces a different (wrong) CRC.
        c = FDSK_CRC4_TAB[(c ^ (b >> 4)) as usize];
        c = FDSK_CRC4_TAB[(c ^ (b & 0x0F)) as usize];
    }
    c
}

/// Build the 41-byte `XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX` string.
///
/// Pulled out as a free function (not a method on `FlashSecureIdentityData`)
/// so it can be unit-tested against hardcoded serial/FDSK pairs and
/// reused by firmware that doesn't route through the flash identity
/// struct (e.g. a provisioning tool).
fn fdsk_string(serial: &[u8; 6], fdsk: &[u8; 16]) -> [u8; 41] {
    // Build the 23-byte buffer: 6 serial + 16 fdsk + 1 CRC-placeholder.
    let mut buf = [0u8; 23];
    buf[0..6].copy_from_slice(serial);
    buf[6..22].copy_from_slice(fdsk);
    // CRC-4 is computed over the serial+FDSK (22 bytes), **not
    // including** the trailing placeholder byte.
    let crc = fdsk_crc4(&buf[..22]);
    // CRC goes in the high nibble of the last byte; the low nibble
    // stays zero and is discarded by the 36-char truncation below.
    buf[22] = (crc << 4) & 0xF0;

    // Base32-encode the first 180 bits (36 symbols). The 37th symbol
    // — from the low nibble of buf[22] plus one implicit zero pad bit
    // — is discarded.
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut encoded = [0u8; 36];
    // Stream 5 bits at a time out of the 23-byte buffer.
    // bit_pos = number of bits consumed so far.
    for (i, out) in encoded.iter_mut().enumerate() {
        let bit_pos = i * 5;
        let byte = bit_pos / 8;
        let shift = bit_pos & 7;
        // Pull the next 5 bits, straddling a byte boundary if needed.
        let first = (buf[byte] as u16) << 8;
        let second = if byte + 1 < buf.len() { buf[byte + 1] as u16 } else { 0 };
        let combined = first | second;
        let idx = ((combined >> (11 - shift)) & 0x1F) as usize;
        *out = ALPHABET[idx];
    }

    // Insert `-` every 6 chars: 6+1+6+1+6+1+6+1+6+1+6 = 41.
    let mut out = [0u8; 41];
    let mut dst = 0;
    for (i, &c) in encoded.iter().enumerate() {
        if i != 0 && i % 6 == 0 {
            out[dst] = b'-';
            dst += 1;
        }
        out[dst] = c;
        dst += 1;
    }
    debug_assert!(dst == 41);
    out
}

#[cfg(test)]
mod fdsk_tests {
    use super::*;

    /// Regression vectors for the FDSK label encoding. Cross-verified
    /// against a reference C implementation; if these ever diverge from
    /// what ETS accepts, re-check the CRC input range and the 36-char
    /// truncation in `fdsk_string`.
    #[test]
    fn known_vectors() {
        let cases = [
            (
                [0x00, 0xFA, 0xDE, 0xAD, 0xBE, 0xEF],
                [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F],
                b"AD5N5L-N654AA-CAQDAQ-CQMBYI-BEFAWD-ANBYHX",
            ),
            (
                [0x00, 0xFA, 0x01, 0x02, 0x03, 0x04],
                [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F],
                b"AD5ACA-QDAQAA-CAQDAQ-CQMBYI-BEFAWD-ANBYHV",
            ),
        ];
        for (serial, fdsk, expected) in cases {
            let got = fdsk_string(&serial, &fdsk);
            assert_eq!(
                &got,
                expected,
                "fdsk_string({serial:02x?}, {fdsk:02x?}) = {} want {}",
                core::str::from_utf8(&got).unwrap(),
                core::str::from_utf8(expected).unwrap()
            );
        }
    }
}

/// Read the secure identity from flash, or provision it on first boot.
///
/// On first boot (identity page does not carry the [`SECURE_IDENTITY_MAGIC`]),
/// derives the serial from the UID exactly like
/// [`read_or_provision_identity`], pairs it with the caller-supplied
/// `fdsk`, and writes the whole record. Subsequent boots re-read the
/// stored record unchanged — the FDSK argument is ignored once the
/// record exists.
///
/// The FDSK **must** survive firmware updates (it is printed on the
/// device label and paired with ETS), so the record lives in a
/// reserved flash page that normal config saves never touch. Re-
/// flashing the firmware with a different FDSK in the env var will be
/// silently ignored unless the identity page is also erased.
///
/// # Panics
/// Panics on flash I/O failure — identity provisioning is critical; no
/// meaningful boot-time fallback exists.
pub fn read_or_provision_secure_identity<const FLASH_SIZE: u32, const PAGE_SIZE: u32>(
    flash: &mut Flash<'static, Blocking>,
    manufacturer_id: [u8; 2],
    fdsk: [u8; 16],
) -> FlashSecureIdentityData {
    let identity_offset = FLASH_SIZE - 2 * PAGE_SIZE;

    let mut buf = [0u8; SECURE_IDENTITY_RECORD_SIZE];
    flash.blocking_read(identity_offset, &mut buf).expect("identity page read");

    if buf[0..4] == SECURE_IDENTITY_MAGIC {
        let mut serial_number = [0u8; 6];
        serial_number.copy_from_slice(&buf[4..10]);
        let mut fdsk = [0u8; 16];
        fdsk.copy_from_slice(&buf[10..26]);
        defmt::info!("Secure identity loaded: serial={=[u8]:02x}", serial_number);
        return FlashSecureIdentityData { serial_number, fdsk };
    }

    defmt::info!("Secure identity page empty, provisioning from STM32 factory UID + build-time FDSK...");
    let uid = embassy_stm32::uid::uid();

    let device_bytes =
        [uid[0] ^ uid[4] ^ uid[8], uid[1] ^ uid[5] ^ uid[9], uid[2] ^ uid[6] ^ uid[10], uid[3] ^ uid[7] ^ uid[11]];

    let serial_number =
        [manufacturer_id[0], manufacturer_id[1], device_bytes[0], device_bytes[1], device_bytes[2], device_bytes[3]];

    // 26 bytes → padded up to 32 (doubleword).
    let padded = (SECURE_IDENTITY_RECORD_SIZE + WRITE_ALIGN - 1) & !(WRITE_ALIGN - 1);
    let mut write_buf = [0xFFu8; 32];
    let write_buf = &mut write_buf[..padded];
    write_buf[0..4].copy_from_slice(&SECURE_IDENTITY_MAGIC);
    write_buf[4..10].copy_from_slice(&serial_number);
    write_buf[10..26].copy_from_slice(&fdsk);

    flash.blocking_erase(identity_offset, identity_offset + PAGE_SIZE).expect("identity page erase");
    flash.blocking_write(identity_offset, write_buf).expect("identity page write");

    defmt::info!("Secure identity provisioned: serial={=[u8]:02x}, fdsk={=[u8]:02x}", serial_number, fdsk,);

    FlashSecureIdentityData { serial_number, fdsk }
}
