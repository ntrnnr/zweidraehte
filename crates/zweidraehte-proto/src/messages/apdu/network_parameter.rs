//! `A_NetworkParameter_InfoReport` APDU layout.
//!
//! Wire format (spec 03/03/07 §3.2.8, Figure 18):
//!
//! ```text
//!   offset   field               layout
//!   ------   -----               ------
//!   +0..+1   APCI                10-bit APCI 0x3DB (shared with
//!                                `A_NetworkParameter_Response`)
//!   +2..+3   object_type         16-bit big-endian
//!   +4       property_id         8-bit PID
//!   +5..+N   test_info           variable, parameter-type dependent
//!   +N+1..+M test_result         variable, parameter-type dependent
//! ```
//!
//! Offsets are relative to [`offsets::MSG_APCI`].
//!
//! Unlike `A_SystemNetworkParameter_*` (which packs a 12-bit PID into
//! 1.5 octets with a reserved low nibble), `A_NetworkParameter_*` uses
//! a single-octet 8-bit PID with no reserved bits.
//!
//! The only caller in this crate today is the Security Interface Object's
//! spontaneous security-report emission per 03/05/01 §6.3.11.4
//! (`DMP_InterfaceObjectInfoReport_RCl`): `object_type = 0x0011`,
//! `property_id = 57` (PID_SECURITY_REPORT), `test_info = 0x00`,
//! `test_result = SecurityReport` (1 byte of DPT_Security_Report).

use crate::messages::knx::offsets;

// ============================================================================
// NetworkParameter InfoReport
// ============================================================================

/// Parsed header from `A_NetworkParameter_InfoReport`.
#[derive(Debug, Clone, Copy)]
pub struct NetworkParameterInfoReport {
    pub object_type: u16,
    pub property_id: u8,
}

impl NetworkParameterInfoReport {
    /// Minimum wire size: APCI(2) + object_type(2) + PID(1) = 5.
    /// `test_info` and `test_result` are parameter-type dependent and
    /// may be zero-length for some reports; the runtime body of a
    /// Security Report adds `test_info(1) + test_result(1) = 2` more
    /// octets, for a total of 7.
    pub const MIN_MSG_LEN: usize = offsets::MSG_APCI + 5;

    /// Parse the fixed header from a full message buffer.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::MIN_MSG_LEN {
            return None;
        }
        let object_type = u16::from_be_bytes([buf[offsets::MSG_APCI + 2], buf[offsets::MSG_APCI + 3]]);
        let property_id = buf[offsets::MSG_APCI + 4];
        Some(Self { object_type, property_id })
    }

    /// Borrow the `test_info || test_result` octets that follow the PID.
    pub fn payload<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        let start = offsets::MSG_APCI + 5;
        if buf.len() > start { &buf[start..] } else { &[] }
    }

    /// Write the report. `payload` carries the concatenated
    /// `test_info || test_result` octets.
    pub fn write(buf: &mut [u8], object_type: u16, property_id: u8, payload: &[u8]) {
        let base = offsets::MSG_APCI;
        buf[base + 2..base + 4].copy_from_slice(&object_type.to_be_bytes());
        buf[base + 4] = property_id;
        if !payload.is_empty() {
            let start = base + 5;
            buf[start..start + payload.len()].copy_from_slice(payload);
        }
    }

    /// Total message length for a given payload size.
    pub const fn msg_len(payload_len: usize) -> usize {
        offsets::MSG_APCI + 5 + payload_len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Security Report per 03/05/01 §6.3.11.4:
    /// object_type = 0x0011 (Security IO), PID = 57, test_info = 0x00,
    /// test_result = 0x01 (Security Failure bit set).
    #[test]
    fn round_trip_security_report() {
        let mut buf = [0u8; NetworkParameterInfoReport::msg_len(2)];
        let payload = [0x00u8, 0x01u8];
        NetworkParameterInfoReport::write(&mut buf, 0x0011, 57, &payload);

        let parsed = NetworkParameterInfoReport::parse(&buf).expect("parse must succeed for well-formed report");
        assert_eq!(parsed.object_type, 0x0011);
        assert_eq!(parsed.property_id, 57);
        assert_eq!(parsed.payload(&buf), &payload);
    }

    #[test]
    fn parse_rejects_short_buffer() {
        let short = [0u8; NetworkParameterInfoReport::MIN_MSG_LEN - 1];
        assert!(NetworkParameterInfoReport::parse(&short).is_none());
    }

    #[test]
    fn empty_payload_ok() {
        let mut buf = [0u8; NetworkParameterInfoReport::msg_len(0)];
        NetworkParameterInfoReport::write(&mut buf, 0xABCD, 0x42, &[]);

        let parsed = NetworkParameterInfoReport::parse(&buf).expect("empty-payload parse");
        assert_eq!(parsed.object_type, 0xABCD);
        assert_eq!(parsed.property_id, 0x42);
        assert!(parsed.payload(&buf).is_empty());
    }
}
