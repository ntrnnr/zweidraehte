//! Versioned factory-provisioning record (`KNXP`).
//!
//! A KNX device's serial number, FDSK, and MAC address are written
//! exactly once on the production line and read at every boot. This
//! module defines the on-flash layout and a `no_std`, alloc-free codec
//! shared by the device firmware and the host-side provisioning tool.
//!
//! # Layout
//!
//! ```text
//! offset  len  field
//! ------  ---  -----
//! 0       4    magic         = b"KNXP"
//! 4       1    version       = 0x01
//! 5       2    payload_len   u16 LE — byte count of TLV region
//! 7       N    tlv[]
//! 7+N     4    crc32         IEEE 802.3 over bytes [0 .. 7+N)
//! ```
//!
//! Each TLV element is `tag: u8 | len: u16 LE | value: [u8; len]`.
//! Unknown tags are skipped on parse, which lets older firmware
//! tolerate records written by newer host tools without bumping
//! `version`. `version` is reserved for structural / semantic breaks.
//!
//! # Threat model
//!
//! The CRC-32 detects flash corruption and erased pages. It does not
//! defeat an attacker with flash readout — the FDSK is in cleartext.
//! Readout-protection is a separate production step (STM32 RDP option
//! bytes); see `SESSION.md`.

use zweidraehte_proto::util::crc::{crc32, fdsk_crc4};

// ================================================================================
// Constants
// ================================================================================

/// Magic bytes that mark a `KNXP` provisioning record.
pub const PROV_MAGIC: [u8; 4] = *b"KNXP";

/// Current record format version. Bumped only for structural breaks —
/// new TLV tags are added without a version bump.
pub const PROV_VERSION: u8 = 0x01;

/// Header: 4B magic + 1B version + 2B payload_len = 7B.
pub const PROV_HEADER_LEN: usize = 7;

/// CRC-32 trailer width.
pub const PROV_CRC_LEN: usize = 4;

/// Worst-case fully-populated record size used to bound stack buffers.
/// 7 header + 11 SERIAL + 19 FDSK + 9 MAC + 4 CRC = 50; round up.
pub const PROV_BUF_LEN: usize = 64;

/// TLV tag constants. New tags can be appended without bumping `PROV_VERSION`
/// — older firmware skips them via the unknown-tag path in [`parse`].
pub mod tag {
    /// 6-byte KNX serial number `[manuf_id:2][device_id:4]` (big-endian).
    pub const SERIAL: u8 = 0x01;
    /// 16-byte Factory Default Setup Key. Data Secure devices only.
    pub const FDSK: u8 = 0x02;
    /// 6-byte Ethernet MAC address. IP devices only.
    pub const MAC: u8 = 0x03;
}

// ================================================================================
// Decoded record + error type
// ================================================================================

/// Provisioning record after parse.
///
/// Only the fields the firmware actually consumes today are surfaced
/// here. Unknown TLV tags encountered during [`parse`] are silently
/// skipped, not stored — when a new tag becomes consumable, add a
/// field here and a write/read path in this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisioningRecord {
    pub serial: [u8; 6],
    pub fdsk: Option<[u8; 16]>,
    pub mac: Option<[u8; 6]>,
}

impl ProvisioningRecord {
    /// Build a record carrying only a serial number — typical of plain
    /// (non-secure) TP1 devices.
    pub fn from_serial(serial: [u8; 6]) -> Self {
        Self { serial, fdsk: None, mac: None }
    }
}

/// Parse / encoding errors. `defmt::Format` is implemented behind the
/// `defmt` feature so embedded callers can `defmt::panic!("{:?}", e)`
/// directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisioningError {
    MagicMismatch,
    VersionUnsupported(u8),
    TruncatedHeader,
    TruncatedTlv,
    CrcMismatch {
        expected: u32,
        got: u32,
    },
    MissingRequiredTag(u8),
    /// `write` failed because the destination buffer is smaller than
    /// the encoded record.
    BufferTooSmall,
    /// A TLV value had an unexpected length (e.g. a SERIAL tag whose
    /// value is not 6 bytes). Corrupted record.
    TlvLength {
        tag: u8,
        expected: u16,
        got: u16,
    },
}

#[cfg(feature = "defmt")]
impl defmt::Format for ProvisioningError {
    fn format(&self, f: defmt::Formatter) {
        match self {
            Self::MagicMismatch => defmt::write!(f, "MagicMismatch"),
            Self::VersionUnsupported(v) => defmt::write!(f, "VersionUnsupported({=u8})", *v),
            Self::TruncatedHeader => defmt::write!(f, "TruncatedHeader"),
            Self::TruncatedTlv => defmt::write!(f, "TruncatedTlv"),
            Self::CrcMismatch { expected, got } => {
                defmt::write!(f, "CrcMismatch(expected={=u32:08x}, got={=u32:08x})", *expected, *got)
            }
            Self::MissingRequiredTag(t) => defmt::write!(f, "MissingRequiredTag({=u8})", *t),
            Self::BufferTooSmall => defmt::write!(f, "BufferTooSmall"),
            Self::TlvLength { tag, expected, got } => {
                defmt::write!(f, "TlvLength(tag={=u8}, expected={=u16}, got={=u16})", *tag, *expected, *got)
            }
        }
    }
}

// ================================================================================
// Parse
// ================================================================================

/// Decode a `KNXP` record from a byte slice.
///
/// `buf` may include trailing garbage (e.g. an entire flash page read
/// in one shot, padded with `0xFF`); the parser stops at the CRC
/// trailer derived from `payload_len`.
///
/// Returns the first hard error encountered. Unknown TLV tags are not
/// errors — they are skipped so a record written by a newer host tool
/// remains parseable.
pub fn parse(buf: &[u8]) -> Result<ProvisioningRecord, ProvisioningError> {
    // Header.
    if buf.len() < PROV_HEADER_LEN {
        return Err(ProvisioningError::TruncatedHeader);
    }

    if buf[0..4] != PROV_MAGIC {
        return Err(ProvisioningError::MagicMismatch);
    }

    let version = buf[4];
    if version != PROV_VERSION {
        return Err(ProvisioningError::VersionUnsupported(version));
    }

    let payload_len = u16::from_le_bytes([buf[5], buf[6]]) as usize;

    // Bounds check the full record (header + payload + CRC).
    let record_end = PROV_HEADER_LEN + payload_len;
    if buf.len() < record_end + PROV_CRC_LEN {
        return Err(ProvisioningError::TruncatedTlv);
    }

    // CRC over [0 .. record_end). Verify before trusting the payload.
    let expected = u32::from_le_bytes([buf[record_end], buf[record_end + 1], buf[record_end + 2], buf[record_end + 3]]);
    let got = crc32(&buf[..record_end]);
    if expected != got {
        return Err(ProvisioningError::CrcMismatch { expected, got });
    }

    // Walk the TLV stream.
    let mut serial: Option<[u8; 6]> = None;
    let mut fdsk: Option<[u8; 16]> = None;
    let mut mac: Option<[u8; 6]> = None;
    let mut i = PROV_HEADER_LEN;

    while i < record_end {
        // Each element header is 3 bytes: tag + len(u16 LE).
        if record_end - i < 3 {
            return Err(ProvisioningError::TruncatedTlv);
        }

        let t = buf[i];
        let len = u16::from_le_bytes([buf[i + 1], buf[i + 2]]) as usize;
        let value_start = i + 3;
        let value_end = value_start + len;

        if value_end > record_end {
            return Err(ProvisioningError::TruncatedTlv);
        }

        let value = &buf[value_start..value_end];

        match t {
            tag::SERIAL => {
                if value.len() != 6 {
                    return Err(ProvisioningError::TlvLength { tag: t, expected: 6, got: len as u16 });
                }

                let mut s = [0u8; 6];
                s.copy_from_slice(value);
                serial = Some(s);
            }

            tag::FDSK => {
                if value.len() != 16 {
                    return Err(ProvisioningError::TlvLength { tag: t, expected: 16, got: len as u16 });
                }

                let mut k = [0u8; 16];
                k.copy_from_slice(value);
                fdsk = Some(k);
            }

            tag::MAC => {
                if value.len() != 6 {
                    return Err(ProvisioningError::TlvLength { tag: t, expected: 6, got: len as u16 });
                }

                let mut m = [0u8; 6];
                m.copy_from_slice(value);
                mac = Some(m);
            }

            // Unknown tag — forward compatibility: skip and keep walking.
            _ => {}
        }

        i = value_end;
    }

    let serial = serial.ok_or(ProvisioningError::MissingRequiredTag(tag::SERIAL))?;
    Ok(ProvisioningRecord { serial, fdsk, mac })
}

// ================================================================================
// Write
// ================================================================================

/// Encode `record` into `buf`. Returns the number of bytes written.
///
/// The encoder emits TLVs in tag order (SERIAL, FDSK, MAC) so the
/// output is byte-for-byte deterministic — useful for golden-file tests
/// and for the host tool's read-back-and-compare verification step.
pub fn write(record: &ProvisioningRecord, buf: &mut [u8]) -> Result<usize, ProvisioningError> {
    // Header.
    if buf.len() < PROV_HEADER_LEN {
        return Err(ProvisioningError::BufferTooSmall);
    }

    buf[0..4].copy_from_slice(&PROV_MAGIC);
    buf[4] = PROV_VERSION;
    // payload_len patched in once we know it.

    // TLV region.
    let mut i = PROV_HEADER_LEN;
    write_tlv(buf, &mut i, tag::SERIAL, &record.serial)?;

    if let Some(fdsk) = record.fdsk.as_ref() {
        write_tlv(buf, &mut i, tag::FDSK, fdsk)?;
    }

    if let Some(mac) = record.mac.as_ref() {
        write_tlv(buf, &mut i, tag::MAC, mac)?;
    }

    let payload_len = i - PROV_HEADER_LEN;

    if payload_len > u16::MAX as usize {
        return Err(ProvisioningError::BufferTooSmall);
    }

    buf[5..7].copy_from_slice(&(payload_len as u16).to_le_bytes());

    // CRC over [0 .. i) (header through final TLV byte).
    if buf.len() < i + PROV_CRC_LEN {
        return Err(ProvisioningError::BufferTooSmall);
    }

    let crc = crc32(&buf[..i]);
    buf[i..i + PROV_CRC_LEN].copy_from_slice(&crc.to_le_bytes());

    Ok(i + PROV_CRC_LEN)
}

fn write_tlv(buf: &mut [u8], i: &mut usize, t: u8, value: &[u8]) -> Result<(), ProvisioningError> {
    let need = 3 + value.len();
    if *i + need > buf.len() {
        return Err(ProvisioningError::BufferTooSmall);
    }

    buf[*i] = t;
    buf[*i + 1..*i + 3].copy_from_slice(&(value.len() as u16).to_le_bytes());
    buf[*i + 3..*i + 3 + value.len()].copy_from_slice(value);
    *i += need;

    Ok(())
}

// ================================================================================
// FDSK label string
// ================================================================================
//
// Hyphenated Base32 encoding of the (serial || fdsk || crc4) tuple,
// the de-facto label format ETS prompts for. Pulled into this module
// (instead of `cross/stm32-common/src/storage.rs`) so the host
// provisioning tool can produce label strings without a transitive
// dependency on the embedded HAL.

/// Build the 41-byte `XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX` ETS
/// label code from a 6-byte serial and a 16-byte FDSK.
///
/// Construction (matches what ETS accepts; the spec leaves the label
/// format unspecified):
///
/// 1. Concatenate `[serial(6) || fdsk(16) || 0x00]` → 23 bytes.
/// 2. CRC-4 over the first 22 bytes; high nibble of byte 22.
/// 3. Base32-encode the first 180 bits (36 symbols).
/// 4. Insert `-` after every 6 chars.
pub fn fdsk_string(serial: &[u8; 6], fdsk: &[u8; 16]) -> [u8; 41] {
    let mut buf = [0u8; 23];
    buf[0..6].copy_from_slice(serial);
    buf[6..22].copy_from_slice(fdsk);
    let crc = fdsk_crc4(&buf[..22]);
    buf[22] = (crc << 4) & 0xF0;

    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    let mut encoded = [0u8; 36];
    for (i, out) in encoded.iter_mut().enumerate() {
        let bit_pos = i * 5;
        let byte = bit_pos / 8;
        let shift = bit_pos & 7;
        let first = (buf[byte] as u16) << 8;
        let second = if byte + 1 < buf.len() { buf[byte + 1] as u16 } else { 0 };
        let combined = first | second;
        let idx = ((combined >> (11 - shift)) & 0x1F) as usize;
        *out = ALPHABET[idx];
    }

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

// ================================================================================
// Tests
// ================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ProvisioningRecord {
        ProvisioningRecord {
            serial: [0x00, 0xFA, 0xDE, 0xAD, 0xBE, 0xEF],
            fdsk: Some([
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            ]),
            mac: Some([0x02, 0x00, 0x12, 0x34, 0x56, 0x78]),
        }
    }

    #[test]
    fn roundtrip_serial_only() {
        let rec = ProvisioningRecord::from_serial([1, 2, 3, 4, 5, 6]);
        let mut buf = [0u8; PROV_BUF_LEN];
        let n = write(&rec, &mut buf).unwrap();
        let parsed = parse(&buf[..n]).unwrap();
        assert_eq!(parsed, rec);
    }

    #[test]
    fn roundtrip_serial_and_fdsk() {
        let mut rec = sample();
        rec.mac = None;
        let mut buf = [0u8; PROV_BUF_LEN];
        let n = write(&rec, &mut buf).unwrap();
        let parsed = parse(&buf[..n]).unwrap();
        assert_eq!(parsed, rec);
    }

    #[test]
    fn roundtrip_full() {
        let rec = sample();
        let mut buf = [0u8; PROV_BUF_LEN];
        let n = write(&rec, &mut buf).unwrap();
        let parsed = parse(&buf[..n]).unwrap();
        assert_eq!(parsed, rec);
    }

    #[test]
    fn crc_mismatch_detected() {
        let rec = sample();
        let mut buf = [0u8; PROV_BUF_LEN];
        let n = write(&rec, &mut buf).unwrap();
        // Flip a single bit in the SERIAL value (offset 7+3 = 10).
        buf[10] ^= 0x01;
        match parse(&buf[..n]) {
            Err(ProvisioningError::CrcMismatch { .. }) => {}
            other => panic!("expected CrcMismatch, got {other:?}"),
        }
    }

    #[test]
    fn unknown_tag_skipped() {
        // Build a record with a SERIAL tag plus a synthetic 0xFF tag in
        // the middle, then fix up payload_len + CRC manually. Older
        // firmware should parse the SERIAL successfully and ignore the
        // unknown tag.
        let mut buf = [0u8; PROV_BUF_LEN];
        buf[0..4].copy_from_slice(&PROV_MAGIC);
        buf[4] = PROV_VERSION;

        // SERIAL tag.
        let mut i = PROV_HEADER_LEN;
        buf[i] = tag::SERIAL;
        buf[i + 1..i + 3].copy_from_slice(&6u16.to_le_bytes());
        buf[i + 3..i + 9].copy_from_slice(&[0x00, 0xFA, 0x11, 0x22, 0x33, 0x44]);
        i += 9;

        // Synthetic unknown tag with arbitrary 4-byte payload.
        buf[i] = 0xFF;
        buf[i + 1..i + 3].copy_from_slice(&4u16.to_le_bytes());
        buf[i + 3..i + 7].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        i += 7;

        let payload_len = i - PROV_HEADER_LEN;
        buf[5..7].copy_from_slice(&(payload_len as u16).to_le_bytes());
        let crc = crc32(&buf[..i]);
        buf[i..i + 4].copy_from_slice(&crc.to_le_bytes());

        let parsed = parse(&buf[..i + 4]).unwrap();
        assert_eq!(parsed.serial, [0x00, 0xFA, 0x11, 0x22, 0x33, 0x44]);
        assert!(parsed.fdsk.is_none());
        assert!(parsed.mac.is_none());
    }

    #[test]
    fn version_unsupported() {
        let rec = ProvisioningRecord::from_serial([1, 2, 3, 4, 5, 6]);
        let mut buf = [0u8; PROV_BUF_LEN];
        let n = write(&rec, &mut buf).unwrap();
        // Bump version, recompute CRC so we don't fail on CrcMismatch first.
        buf[4] = 0x02;
        let payload_end = PROV_HEADER_LEN + u16::from_le_bytes([buf[5], buf[6]]) as usize;
        let crc = crc32(&buf[..payload_end]);
        buf[payload_end..payload_end + 4].copy_from_slice(&crc.to_le_bytes());

        match parse(&buf[..n]) {
            Err(ProvisioningError::VersionUnsupported(0x02)) => {}
            other => panic!("expected VersionUnsupported(2), got {other:?}"),
        }
    }

    #[test]
    fn truncated_header() {
        assert_eq!(parse(b"KNX"), Err(ProvisioningError::TruncatedHeader));
    }

    #[test]
    fn truncated_tlv() {
        // Valid header claiming 100 bytes of payload but no payload follows.
        let mut buf = [0u8; PROV_HEADER_LEN];
        buf[0..4].copy_from_slice(&PROV_MAGIC);
        buf[4] = PROV_VERSION;
        buf[5..7].copy_from_slice(&100u16.to_le_bytes());
        assert_eq!(parse(&buf), Err(ProvisioningError::TruncatedTlv));
    }

    #[test]
    fn missing_serial_rejected() {
        // Hand-build a record whose only TLV is an unknown tag — no
        // SERIAL — and verify the parser surfaces MissingRequiredTag.
        let mut buf = [0u8; PROV_BUF_LEN];
        buf[0..4].copy_from_slice(&PROV_MAGIC);
        buf[4] = PROV_VERSION;
        let mut i = PROV_HEADER_LEN;
        buf[i] = 0xFF;
        buf[i + 1..i + 3].copy_from_slice(&0u16.to_le_bytes());
        i += 3;
        let payload_len = i - PROV_HEADER_LEN;
        buf[5..7].copy_from_slice(&(payload_len as u16).to_le_bytes());
        let crc = crc32(&buf[..i]);
        buf[i..i + 4].copy_from_slice(&crc.to_le_bytes());

        assert_eq!(parse(&buf[..i + 4]), Err(ProvisioningError::MissingRequiredTag(tag::SERIAL)));
    }

    #[test]
    fn fdsk_string_known_vectors() {
        let cases: [([u8; 6], [u8; 16], &[u8; 41]); 2] = [
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
            assert_eq!(&fdsk_string(&serial, &fdsk), expected);
        }
    }
}
