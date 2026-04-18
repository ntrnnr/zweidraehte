//! `A_SystemNetworkParameter_Read` / `Response` APDU layout.
//!
//! Wire format (spec 03/05/02 §2.20 Figure 5):
//!
//! ```text
//!   offset   field              layout
//!   ------   -----              ------
//!   +0..+1   APCI               10-bit APCI (0x01C8 read / 0x01C9 response)
//!   +2       object_type hi     full high byte of 12-bit object_type
//!   +3       object_type lo +   high nibble = object_type low 4 bits,
//!            PID hi             low nibble  = PID high 4 bits
//!   +4       PID lo +           high nibble = PID low 4 bits,
//!            reserved           low nibble  = reserved (0)
//!   +5       operand            single-byte test_info operand
//!   +6..+N   test_result        response only
//! ```
//!
//! Offsets are relative to [`offsets::MSG_APCI`].

use crate::messages::knx::offsets;

/// Parser for incoming `A_SystemNetworkParameter_Read` PDUs.
pub struct SystemNetworkParameterRead;

impl SystemNetworkParameterRead {
    /// Minimum wire size: APCI(2) + parameter_type(2) + reserved/operand(2) = 6.
    pub const MIN_MSG_LEN: usize = offsets::MSG_APCI + 6;

    /// Parse `object_type` (12 bits).
    pub fn object_type(buf: &[u8]) -> Option<u16> {
        if buf.len() < Self::MIN_MSG_LEN {
            return None;
        }
        let hi = buf[offsets::MSG_APCI + 2] as u16;
        let lo_hi = (buf[offsets::MSG_APCI + 3] >> 4) as u16;
        Some((hi << 4) | lo_hi)
    }

    /// Parse `PID` (8 bits straddling octets +3 and +4).
    pub fn pid(buf: &[u8]) -> Option<u8> {
        if buf.len() < Self::MIN_MSG_LEN {
            return None;
        }
        let hi = (buf[offsets::MSG_APCI + 3] & 0x0F) << 4;
        let lo = buf[offsets::MSG_APCI + 4] >> 4;
        Some(hi | lo)
    }

    /// Parse the single-byte `operand` (first byte of `test_info`).
    pub fn operand(buf: &[u8]) -> Option<u8> {
        if buf.len() < Self::MIN_MSG_LEN {
            return None;
        }
        Some(buf[offsets::MSG_APCI + 5])
    }
}

/// Writer for `A_SystemNetworkParameter_Response` PDUs.
///
/// Response layout mirrors the request up through `operand`, then appends
/// `test_result`. For `NM_Read_SerialNumber_By_ProgrammingMode`:
/// `test_result` = 6-byte KNX Serial Number.
pub struct SystemNetworkParameterResponse;

impl SystemNetworkParameterResponse {
    /// Total `msg_len` for a response with `test_result_len` bytes of result.
    /// Header: APCI(2) + parameter_type(2) + reserved/operand(2).
    pub const fn msg_len(test_result_len: usize) -> usize {
        offsets::MSG_APCI + 6 + test_result_len
    }

    /// Write the response header echoing `object_type`, `pid`, `operand` from
    /// the request, then copy `test_result`.
    pub fn write(buf: &mut [u8], object_type: u16, pid: u8, operand: u8, test_result: &[u8]) {
        let base = offsets::MSG_APCI;
        buf[base + 2] = (object_type >> 4) as u8;
        buf[base + 3] = (((object_type & 0x0F) as u8) << 4) | (pid >> 4);
        buf[base + 4] = (pid & 0x0F) << 4; // reserved = 0
        buf[base + 5] = operand;
        buf[base + 6..base + 6 + test_result.len()].copy_from_slice(test_result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_device_object_pid_serial_number_operand_01() {
        let mut buf = [0u8; SystemNetworkParameterRead::MIN_MSG_LEN];
        // APCI 0x01C8
        buf[offsets::MSG_APCI] = 0x01;
        buf[offsets::MSG_APCI + 1] = 0xC8;
        // object_type = 0x000, PID = 11 (0x0B)
        // octet+2 = object_type hi = 0x00
        // octet+3 = (object_type lo << 4) | (PID hi nibble) = (0 << 4) | 0 = 0x00
        // octet+4 = (PID lo nibble << 4) | reserved = (0xB << 4) | 0 = 0xB0
        // octet+5 = operand = 0x01
        buf[offsets::MSG_APCI + 4] = 0xB0;
        buf[offsets::MSG_APCI + 5] = 0x01;
        assert_eq!(SystemNetworkParameterRead::object_type(&buf), Some(0x000));
        assert_eq!(SystemNetworkParameterRead::pid(&buf), Some(11));
        assert_eq!(SystemNetworkParameterRead::operand(&buf), Some(0x01));
    }

    #[test]
    fn write_response_round_trips_fields() {
        let mut buf = [0u8; SystemNetworkParameterResponse::msg_len(6)];
        buf[offsets::MSG_APCI] = 0x01;
        buf[offsets::MSG_APCI + 1] = 0xC9;
        let serial = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        SystemNetworkParameterResponse::write(&mut buf, 0x000, 11, 0x01, &serial);
        assert_eq!(SystemNetworkParameterRead::object_type(&buf), Some(0x000));
        assert_eq!(SystemNetworkParameterRead::pid(&buf), Some(11));
        assert_eq!(SystemNetworkParameterRead::operand(&buf), Some(0x01));
        assert_eq!(&buf[offsets::MSG_APCI + 6..offsets::MSG_APCI + 12], &serial);
    }

    #[test]
    fn write_parses_nonzero_object_type_and_pid() {
        let mut buf = [0u8; SystemNetworkParameterResponse::msg_len(0)];
        SystemNetworkParameterResponse::write(&mut buf, 0xABC, 0x5D, 0xFE, &[]);
        assert_eq!(SystemNetworkParameterRead::object_type(&buf), Some(0xABC));
        assert_eq!(SystemNetworkParameterRead::pid(&buf), Some(0x5D));
        assert_eq!(SystemNetworkParameterRead::operand(&buf), Some(0xFE));
    }
}
