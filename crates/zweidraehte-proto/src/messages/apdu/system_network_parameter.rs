//! `A_SystemNetworkParameter_Read` / `Response` APDU layout.
//!
//! Wire format (spec 03/05/02 §2.20 Figures 5–8, 03/03/07 §3.3.8 Fig 33):
//!
//! ```text
//!   offset   field               layout
//!   ------   -----               ------
//!   +0..+1   APCI                10-bit APCI (0x01C8 read / 0x01C9 response)
//!   +2..+3   object_type         16-bit big-endian
//!   +4       PID[11:4]           high 8 bits of 12-bit PID
//!   +5[7:4]  PID[3:0]            low 4 bits of PID
//!   +5[3:0]  reserved = 0        low nibble of octet 11
//!   +6       operand             first test_info byte (full octet)
//!   +7..+N   test_info tail /    subsequent test_info octets (e.g.
//!            test_result         random_wait_time) followed by test_result
//! ```
//!
//! Offsets are relative to [`offsets::MSG_APCI`].

use crate::messages::knx::offsets;
use crate::util::crc::crc16_ccitt;

// ============================================================================
// NM_Read_SerialNumber_By_ProgrammingMode
// ============================================================================

/// Operand of `NM_Read_SerialNumber_By_ProgrammingMode` (03/05/02 §2.20.1.4):
/// the whole `test_info` of that request, which "shall consist of a single
/// octet operand 01h".
pub const OPERAND_SERIAL_NUMBER_BY_PROGRAMMING_MODE: u8 = 0x01;

/// Upper bound (exclusive) of the random wait before a device answers
/// `NM_Read_SerialNumber_By_ProgrammingMode`: "between 0 s and 1 s"
/// (03/05/02 §2.20.1.4).
pub const PROGRAMMING_MODE_SCAN_WAIT_MS: u32 = 1_000;

/// The random wait, in milliseconds below [`PROGRAMMING_MODE_SCAN_WAIT_MS`],
/// before this device answers a programming-mode serial-number scan.
///
/// The wait exists so that several devices in programming mode do not answer
/// at once. TP1's bitwise arbitration survives that, RF and a burst on KNX/IP
/// multicast do not. What matters is that the waits differ between devices,
/// not that they are unpredictable, so no random number generator is needed
/// (plain devices have none): the KNX serial number is unique per device and
/// separates devices that powered up together, and `clock` — any free-running
/// local time at receipt — varies it between repeated scans.
pub fn programming_mode_scan_wait_ms(serial_number: &[u8; 6], clock: u32) -> u32 {
    let mut seed = [0u8; 10];
    seed[..6].copy_from_slice(serial_number);
    seed[6..].copy_from_slice(&clock.to_le_bytes());

    u32::from(crc16_ccitt(&seed)) % PROGRAMMING_MODE_SCAN_WAIT_MS
}

// ============================================================================
// SystemNetworkParameter Read
// ============================================================================

/// Parsed header from `A_SystemNetworkParameter_Read`.
#[derive(Debug, Clone, Copy)]
pub struct SystemNetworkParameterRead {
    pub object_type: u16,
    /// 12-bit Property Identifier.
    pub pid: u16,
    /// First `test_info` octet — the procedure operand
    /// (01h / 02h / 03h / FEh per spec §2.20.1.3).
    pub operand: u8,
}

impl SystemNetworkParameterRead {
    /// Minimum wire size: APCI(2) + object_type(2) + PID+reserved(2) + operand(1) = 7.
    pub const MIN_MSG_LEN: usize = offsets::MSG_APCI + 7;

    /// Parse the fixed header from a full message buffer.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::MIN_MSG_LEN {
            return None;
        }
        let object_type = u16::from_be_bytes([buf[offsets::MSG_APCI + 2], buf[offsets::MSG_APCI + 3]]);
        let pid_hi = buf[offsets::MSG_APCI + 4] as u16;
        let pid_lo = (buf[offsets::MSG_APCI + 5] >> 4) as u16;
        let pid = (pid_hi << 4) | pid_lo;
        let operand = buf[offsets::MSG_APCI + 6];
        Some(Self { object_type, pid, operand })
    }

    /// Borrow any `test_info` octets that follow the `operand` byte
    /// (e.g. `random_wait_time` for the ExFactoryState / PowerReset
    /// variants, or a 2-byte manufacturer code for operand `FEh`).
    pub fn test_info_tail<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        let start = offsets::MSG_APCI + 7;
        if buf.len() > start { &buf[start..] } else { &[] }
    }

    /// Write the request. `operand` is the first test_info byte;
    /// `test_info_tail` is any additional test_info octets.
    pub fn write(buf: &mut [u8], object_type: u16, pid: u16, operand: u8, test_info_tail: &[u8]) {
        let base = offsets::MSG_APCI;
        buf[base + 2..base + 4].copy_from_slice(&object_type.to_be_bytes());
        buf[base + 4] = (pid >> 4) as u8;
        buf[base + 5] = ((pid & 0x0F) as u8) << 4; // reserved low nibble = 0
        buf[base + 6] = operand;
        if !test_info_tail.is_empty() {
            let start = base + 7;
            buf[start..start + test_info_tail.len()].copy_from_slice(test_info_tail);
        }
    }

    /// Total message length for a given `test_info_tail` size.
    pub const fn msg_len(test_info_tail_len: usize) -> usize {
        offsets::MSG_APCI + 7 + test_info_tail_len
    }
}

// ============================================================================
// SystemNetworkParameter Response
// ============================================================================

/// Parsed header from `A_SystemNetworkParameter_Response`.
#[derive(Debug, Clone, Copy)]
pub struct SystemNetworkParameterResponse {
    pub object_type: u16,
    pub pid: u16,
    /// Echoed procedure operand.
    pub operand: u8,
}

impl SystemNetworkParameterResponse {
    /// Minimum wire size matches the request.
    pub const MIN_MSG_LEN: usize = offsets::MSG_APCI + 7;

    /// Parse the fixed header from a full message buffer.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        SystemNetworkParameterRead::parse(buf).map(|r| Self {
            object_type: r.object_type,
            pid: r.pid,
            operand: r.operand,
        })
    }

    /// Borrow the `test_info tail || test_result` octets that follow
    /// the `operand` byte. For `NM_Read_SerialNumber_By_ProgrammingMode`
    /// the entire tail is `test_result` (6-byte KNX Serial Number).
    pub fn tail<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        let start = offsets::MSG_APCI + 7;
        if buf.len() > start { &buf[start..] } else { &[] }
    }

    /// Write a response. `tail` carries any remaining test_info octets
    /// followed by the test_result.
    pub fn write(buf: &mut [u8], object_type: u16, pid: u16, operand: u8, tail: &[u8]) {
        SystemNetworkParameterRead::write(buf, object_type, pid, operand, tail);
    }

    /// Total message length for a given tail size.
    pub const fn msg_len(tail_len: usize) -> usize {
        offsets::MSG_APCI + 7 + tail_len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_read_serial_by_prog_mode() {
        // NM_Read_SerialNumber_By_ProgrammingMode: object_type = Device,
        // PID = 11, operand = 0x01, no test_info tail.
        let mut buf = [0u8; SystemNetworkParameterRead::msg_len(0)];
        SystemNetworkParameterRead::write(&mut buf, 0x0000, 11, 0x01, &[]);

        let parsed = SystemNetworkParameterRead::parse(&buf).unwrap();
        assert_eq!(parsed.object_type, 0x0000);
        assert_eq!(parsed.pid, 11);
        assert_eq!(parsed.operand, 0x01);
        assert!(parsed.test_info_tail(&buf).is_empty());
    }

    #[test]
    fn round_trip_read_by_power_reset_with_wait_time() {
        // NM_Read_SerialNumber_By_PowerReset: operand = 0x03 + 1-octet
        // random_wait_time.
        let mut buf = [0u8; SystemNetworkParameterRead::msg_len(1)];
        SystemNetworkParameterRead::write(&mut buf, 0x0000, 11, 0x03, &[0x1E]);

        let parsed = SystemNetworkParameterRead::parse(&buf).unwrap();
        assert_eq!(parsed.operand, 0x03);
        assert_eq!(parsed.test_info_tail(&buf), &[0x1E]);
    }

    #[test]
    fn round_trip_response_with_serial() {
        let serial = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let mut buf = [0u8; SystemNetworkParameterResponse::msg_len(6)];
        SystemNetworkParameterResponse::write(&mut buf, 0x0000, 11, 0x01, &serial);

        let parsed = SystemNetworkParameterResponse::parse(&buf).unwrap();
        assert_eq!(parsed.object_type, 0x0000);
        assert_eq!(parsed.pid, 11);
        assert_eq!(parsed.operand, 0x01);
        assert_eq!(parsed.tail(&buf), &serial);
    }

    #[test]
    fn parse_rejects_short_buffer() {
        let buf = [0u8; SystemNetworkParameterRead::MIN_MSG_LEN - 1];
        assert!(SystemNetworkParameterRead::parse(&buf).is_none());
        assert!(SystemNetworkParameterResponse::parse(&buf).is_none());
    }

    #[test]
    fn write_zeros_reserved_nibble() {
        let mut buf = [0xFFu8; SystemNetworkParameterRead::msg_len(0)];
        SystemNetworkParameterRead::write(&mut buf, 0x0000, 0xFFF, 0x01, &[]);
        // PID low nibble occupies high nibble of octet +5; reserved low
        // nibble must be zero.
        assert_eq!(buf[offsets::MSG_APCI + 5] & 0x0F, 0);
    }

    #[test]
    fn nonzero_object_type_and_pid_round_trip() {
        let mut buf = [0u8; SystemNetworkParameterRead::msg_len(0)];
        SystemNetworkParameterRead::write(&mut buf, 0xABCD, 0x5D3, 0xFE, &[]);

        let parsed = SystemNetworkParameterRead::parse(&buf).unwrap();
        assert_eq!(parsed.object_type, 0xABCD);
        assert_eq!(parsed.pid, 0x5D3);
        assert_eq!(parsed.operand, 0xFE);
    }

    #[test]
    fn scan_wait_stays_within_the_window_and_differs_between_devices() {
        let first = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x01];
        let second = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x02];

        for clock in [0, 1, 999, 0x1234_5678, u32::MAX] {
            assert!(programming_mode_scan_wait_ms(&first, clock) < PROGRAMMING_MODE_SCAN_WAIT_MS);
        }
        // Two devices that powered up together see the same clock.
        assert_ne!(programming_mode_scan_wait_ms(&first, 0), programming_mode_scan_wait_ms(&second, 0));
        // One device scanned twice sees a different clock.
        assert_ne!(programming_mode_scan_wait_ms(&first, 0), programming_mode_scan_wait_ms(&first, 1));
    }

    #[test]
    fn wire_layout_matches_spec_figure_7() {
        // Figure 7: object_type = Device (0x0000), PID = 11 (0x00B),
        // reserved = 0, operand = 0x01 at octet 12.
        let mut buf = [0u8; SystemNetworkParameterRead::msg_len(0)];
        SystemNetworkParameterRead::write(&mut buf, 0x0000, 11, 0x01, &[]);

        assert_eq!(buf[offsets::MSG_APCI + 2], 0x00, "object_type high");
        assert_eq!(buf[offsets::MSG_APCI + 3], 0x00, "object_type low");
        assert_eq!(buf[offsets::MSG_APCI + 4], 0x00, "PID high 8 bits");
        assert_eq!(buf[offsets::MSG_APCI + 5], 0xB0, "PID low 4 bits in high nibble, reserved=0");
        assert_eq!(buf[offsets::MSG_APCI + 6], 0x01, "operand");
    }
}
