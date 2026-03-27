//! Device management APDUs (`A_DeviceDescriptor_*`, `A_IndividualAddress*`,
//! `A_ADC_*`).
//!
//! Most of these use "short" APCIs where the low 6 bits of APCI byte 1 carry
//! data (descriptor type, channel number, etc.). The write functions preserve
//! the high APCI bits while setting the data bits.

use crate::messages::knx::offsets;

// ============================================================================
// DeviceDescriptor (Read / Response)
// ============================================================================

/// Parsed fields from `A_DeviceDescriptor_Read`.
///
/// The descriptor type occupies the low 6 bits of APCI byte 1.
#[derive(Debug, Clone, Copy)]
pub struct DeviceDescriptorRead {
    pub descriptor_type: u8,
}

impl DeviceDescriptorRead {
    pub const MIN_MSG_LEN: usize = offsets::MSG_APCI + 2;

    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::MIN_MSG_LEN {
            return None;
        }
        Some(Self { descriptor_type: buf[offsets::MSG_APCI + 1] & 0x3F })
    }

    /// Write a `DeviceDescriptorRead` request into a message buffer.
    ///
    /// Sets the descriptor type in the low 6 bits of APCI byte 1, preserving
    /// the high bits already set by `set_apci_code`.
    pub fn write(buf: &mut [u8], descriptor_type: u8) {
        buf[offsets::MSG_APCI + 1] = (buf[offsets::MSG_APCI + 1] & 0xC0) | (descriptor_type & 0x3F);
    }
}

/// Writer for `A_DeviceDescriptor_Response`.
pub struct DeviceDescriptorResponse;

impl DeviceDescriptorResponse {
    /// Message length for a type-0 response (APCI + 2-byte mask version).
    pub const TYPE0_MSG_LEN: usize = offsets::MSG_APCI + 4;
    /// Message length for a type-2 response (APCI + 14-byte DD2).
    pub const TYPE2_MSG_LEN: usize = offsets::MSG_APCI + 16;
    /// Message length for an error response (APCI only).
    pub const ERROR_MSG_LEN: usize = offsets::MSG_APCI + 2;

    /// Write a type-0 response (mask version).
    pub fn write_type0(buf: &mut [u8], mask_version: &[u8; 2]) {
        // Clear descriptor type bits (low 6 of APCI byte 1)
        buf[offsets::MSG_APCI + 1] &= 0xC0;
        buf[offsets::MSG_APCI + 2..offsets::MSG_APCI + 4].copy_from_slice(mask_version);
    }

    /// Write a type-2 response (DD2 extended device info).
    pub fn write_type2(buf: &mut [u8], dd2: &[u8; 14]) {
        buf[offsets::MSG_APCI + 1] = (buf[offsets::MSG_APCI + 1] & 0xC0) | 0x02;
        buf[offsets::MSG_APCI + 2..offsets::MSG_APCI + 16].copy_from_slice(dd2);
    }

    /// Write an error response (descriptor_type = 0x3F, no data).
    pub fn write_error(buf: &mut [u8]) {
        buf[offsets::MSG_APCI + 1] = (buf[offsets::MSG_APCI + 1] & 0xC0) | 0x3F;
    }
}

// ============================================================================
// IndividualAddress (Read / Write / SerialNumber variants)
// ============================================================================

/// Parsed fields from `A_IndividualAddress_Write`.
///
/// The new address is at APDU[2-3].
pub struct IndividualAddressWrite;

impl IndividualAddressWrite {
    pub const MIN_MSG_LEN: usize = offsets::MSG_APCI + 4;

    /// Extract the new individual address bytes from the buffer.
    pub fn address_bytes(buf: &[u8]) -> Option<&[u8]> {
        if buf.len() < Self::MIN_MSG_LEN {
            return None;
        }
        Some(&buf[offsets::MSG_APCI + 2..offsets::MSG_APCI + 4])
    }
}

/// Parsed fields from `A_IndividualAddressSerialNumber_Read`.
pub struct IndividualAddressSerialNumberRead;

impl IndividualAddressSerialNumberRead {
    pub const MIN_MSG_LEN: usize = offsets::MSG_APCI + 8;

    /// Extract the serial number (6 bytes) from the buffer.
    pub fn serial_number(buf: &[u8]) -> Option<&[u8]> {
        if buf.len() < Self::MIN_MSG_LEN {
            return None;
        }
        Some(&buf[offsets::MSG_APCI + 2..offsets::MSG_APCI + 8])
    }
}

/// Writer for `A_IndividualAddressSerialNumber_Response`.
pub struct IndividualAddressSerialNumberResponse;

impl IndividualAddressSerialNumberResponse {
    /// Response: APCI(2) + serial(6) + domain/reserved(4) = 12 bytes APDU.
    pub const MSG_LEN: usize = offsets::MSG_APCI + 12;

    /// Write serial number into the response buffer.
    /// Domain address / reserved (4 bytes at APDU[8-11]) should be zeroed
    /// (already zero from alloc).
    pub fn write_serial(buf: &mut [u8], serial: &[u8; 6]) {
        buf[offsets::MSG_APCI + 2..offsets::MSG_APCI + 8].copy_from_slice(serial);
    }
}

/// Parsed fields from `A_IndividualAddressSerialNumber_Write`.
pub struct IndividualAddressSerialNumberWrite;

impl IndividualAddressSerialNumberWrite {
    pub const MIN_MSG_LEN: usize = offsets::MSG_APCI + 14;

    /// Extract the serial number (6 bytes) from the buffer.
    pub fn serial_number(buf: &[u8]) -> Option<&[u8]> {
        if buf.len() < Self::MIN_MSG_LEN {
            return None;
        }
        Some(&buf[offsets::MSG_APCI + 2..offsets::MSG_APCI + 8])
    }

    /// Extract the new individual address bytes (2 bytes at APDU[8-9]).
    pub fn address_bytes(buf: &[u8]) -> Option<&[u8]> {
        if buf.len() < Self::MIN_MSG_LEN {
            return None;
        }
        Some(&buf[offsets::MSG_APCI + 8..offsets::MSG_APCI + 10])
    }
}

// ============================================================================
// DomainAddressSerialNumber (Read / Response / Write)
// ============================================================================

/// Parser for `A_DomainAddressSerialNumber_Read`.
///
/// Wire format: APCI(2) + serial(6).
pub struct DomainAddressSerialNumberRead;

impl DomainAddressSerialNumberRead {
    pub const MIN_MSG_LEN: usize = offsets::MSG_APCI + 8;

    /// Extract the serial number (6 bytes) from the buffer.
    pub fn serial_number(buf: &[u8]) -> Option<&[u8]> {
        if buf.len() < Self::MIN_MSG_LEN {
            return None;
        }
        Some(&buf[offsets::MSG_APCI + 2..offsets::MSG_APCI + 8])
    }
}

/// Writer for `A_DomainAddressSerialNumber_Response`.
///
/// Wire format: APCI(2) + serial(6) + domain_address(N).
/// N depends on the medium: 0 for TP1, 4 for IP (multicast address), 6 for RF.
pub struct DomainAddressSerialNumberResponse;

impl DomainAddressSerialNumberResponse {
    /// Response length with no domain address (TP1 / minimal).
    pub const MSG_LEN_NO_DOA: usize = offsets::MSG_APCI + 8;
    /// Response length with 4-byte domain address (IP multicast).
    pub const MSG_LEN_IP: usize = offsets::MSG_APCI + 12;

    /// Write serial number into the response buffer.
    pub fn write_serial(buf: &mut [u8], serial: &[u8; 6]) {
        buf[offsets::MSG_APCI + 2..offsets::MSG_APCI + 8].copy_from_slice(serial);
    }

    /// Write domain address into the response buffer (after the serial number).
    pub fn write_domain_address(buf: &mut [u8], doa: &[u8]) {
        let start = offsets::MSG_APCI + 8;
        buf[start..start + doa.len()].copy_from_slice(doa);
    }
}

/// Parser for `A_DomainAddressSerialNumber_Write`.
///
/// Wire format: APCI(2) + serial(6) + domain_address(N).
///
/// The domain address length depends on the medium:
/// - 2 octets: PL110
/// - 4 octets: KNX/IP (routing multicast address)
/// - 6 octets: RF
/// - 21 octets: KNX/IP Secure (multicast + security version + backbone key)
///
/// Note: this service does NOT carry a new individual address. Address
/// assignment uses `A_IndividualAddressSerialNumber_Write` instead.
pub struct DomainAddressSerialNumberWrite;

impl DomainAddressSerialNumberWrite {
    /// Minimum length: APCI(2) + serial(6) = 8 bytes past MSG_APCI.
    pub const MIN_MSG_LEN: usize = offsets::MSG_APCI + 8;

    /// Extract the serial number (6 bytes) from the buffer.
    pub fn serial_number(buf: &[u8]) -> Option<&[u8]> {
        if buf.len() < Self::MIN_MSG_LEN {
            return None;
        }
        Some(&buf[offsets::MSG_APCI + 2..offsets::MSG_APCI + 8])
    }

    /// Extract the domain address (variable length, starting after serial).
    /// Returns an empty slice if no domain address is present.
    pub fn domain_address(buf: &[u8]) -> &[u8] {
        let start = offsets::MSG_APCI + 8;
        if buf.len() <= start {
            &[]
        } else {
            &buf[start..buf.len()]
        }
    }
}

// ============================================================================
// ADC (Read / Response)
// ============================================================================

/// Parsed fields from `A_ADC_Read`.
///
/// Channel is in the low 6 bits of APCI byte 1; read count follows in byte 2.
#[derive(Debug, Clone, Copy)]
pub struct AdcRead {
    pub channel: u8,
    pub count: u8,
}

impl AdcRead {
    pub const MIN_MSG_LEN: usize = offsets::MSG_APCI + 3;

    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::MIN_MSG_LEN {
            return None;
        }
        Some(Self { channel: buf[offsets::MSG_APCI + 1] & 0x3F, count: buf[offsets::MSG_APCI + 2] })
    }
}

/// Writer for `A_ADC_Response`.
pub struct AdcResponse;

impl AdcResponse {
    /// Response: APCI(2) + count(1) + sum(2) = 5 bytes APDU.
    pub const MSG_LEN: usize = offsets::MSG_APCI + 5;

    /// Write an ADC response: channel in APCI low bits, count, and sum value.
    pub fn write(buf: &mut [u8], channel: u8, count: u8, sum: u16) {
        buf[offsets::MSG_APCI + 1] = (buf[offsets::MSG_APCI + 1] & 0xC0) | (channel & 0x3F);
        buf[offsets::MSG_APCI + 2] = count;
        buf[offsets::MSG_APCI + 3] = (sum >> 8) as u8;
        buf[offsets::MSG_APCI + 4] = sum as u8;
    }
}

// ============================================================================
// IndividualAddressRead / Response (APCI-only, no payload)
// ============================================================================

// IndividualAddressRead and IndividualAddressResponse have no payload beyond
// the APCI code. The individual address is conveyed in the source address
// field of the L_Data frame. No parse/write types are needed.

/// Message length constants for APCI-only services.
pub const APCI_ONLY_MSG_LEN: usize = offsets::MSG_APCI + 2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_descriptor_read_parse() {
        let mut buf = [0u8; 8];
        buf[offsets::MSG_APCI + 1] = 0xC0 | 2; // type 2
        let req = DeviceDescriptorRead::parse(&buf).unwrap();
        assert_eq!(req.descriptor_type, 2);
    }

    #[test]
    fn device_descriptor_response_type0() {
        let mut buf = [0u8; 12];
        buf[offsets::MSG_APCI + 1] = 0xFF; // All bits set
        DeviceDescriptorResponse::write_type0(&mut buf, &[0x07, 0x01]);
        // Low 6 bits should be cleared (type 0)
        assert_eq!(buf[offsets::MSG_APCI + 1] & 0x3F, 0);
        assert_eq!(buf[offsets::MSG_APCI + 2], 0x07);
        assert_eq!(buf[offsets::MSG_APCI + 3], 0x01);
    }

    #[test]
    fn device_descriptor_response_error() {
        let mut buf = [0u8; 8];
        buf[offsets::MSG_APCI + 1] = 0xC0;
        DeviceDescriptorResponse::write_error(&mut buf);
        assert_eq!(buf[offsets::MSG_APCI + 1] & 0x3F, 0x3F);
    }

    #[test]
    fn adc_read_parse() {
        let mut buf = [0u8; 9];
        buf[offsets::MSG_APCI + 1] = 0x80 | 3; // channel 3
        buf[offsets::MSG_APCI + 2] = 5; // count
        let req = AdcRead::parse(&buf).unwrap();
        assert_eq!(req.channel, 3);
        assert_eq!(req.count, 5);
    }

    #[test]
    fn adc_response_write() {
        let mut buf = [0u8; 12];
        buf[offsets::MSG_APCI + 1] = 0xC0; // APCI high bits
        AdcResponse::write(&mut buf, 4, 8, 0x1234);
        assert_eq!(buf[offsets::MSG_APCI + 1] & 0x3F, 4);
        assert_eq!(buf[offsets::MSG_APCI + 2], 8);
        assert_eq!(buf[offsets::MSG_APCI + 3], 0x12);
        assert_eq!(buf[offsets::MSG_APCI + 4], 0x34);
    }

    #[test]
    fn individual_address_write_parse() {
        let mut buf = [0u8; 10];
        buf[offsets::MSG_APCI + 2] = 0x11;
        buf[offsets::MSG_APCI + 3] = 0x05;
        let addr = IndividualAddressWrite::address_bytes(&buf).unwrap();
        assert_eq!(addr, &[0x11, 0x05]);
    }

    #[test]
    fn serial_number_read_parse() {
        let mut buf = [0u8; 14];
        buf[offsets::MSG_APCI + 2..offsets::MSG_APCI + 8].copy_from_slice(&[0x00, 0x83, 0x01, 0x02, 0x03, 0x04]);
        let sn = IndividualAddressSerialNumberRead::serial_number(&buf).unwrap();
        assert_eq!(sn, &[0x00, 0x83, 0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn serial_number_write_parse() {
        let mut buf = [0u8; 20];
        buf[offsets::MSG_APCI + 2..offsets::MSG_APCI + 8].copy_from_slice(&[0x00, 0x83, 0x01, 0x02, 0x03, 0x04]);
        buf[offsets::MSG_APCI + 8] = 0x11;
        buf[offsets::MSG_APCI + 9] = 0x05;
        let sn = IndividualAddressSerialNumberWrite::serial_number(&buf).unwrap();
        assert_eq!(sn, &[0x00, 0x83, 0x01, 0x02, 0x03, 0x04]);
        let addr = IndividualAddressSerialNumberWrite::address_bytes(&buf).unwrap();
        assert_eq!(addr, &[0x11, 0x05]);
    }
}
