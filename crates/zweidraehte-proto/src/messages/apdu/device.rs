//! Device management APDUs (`A_DeviceDescriptor_*`, `A_IndividualAddress*`,
//! `A_ADC_*`).
//!
//! Most of these use "short" APCIs where the low 6 bits of APCI byte 1 carry
//! data (descriptor type, channel number, etc.). The write functions preserve
//! the high APCI bits while setting the data bits.

use crate::address::IndividualAddress;
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

/// Writer/parser for `A_DeviceDescriptor_Response`.
pub struct DeviceDescriptorResponse;

impl DeviceDescriptorResponse {
    /// Message length for a type-0 response (APCI + 2-byte mask version).
    pub const TYPE0_MSG_LEN: usize = offsets::MSG_APCI + 4;
    /// Message length for a type-2 response (APCI + 14-byte DD2).
    pub const TYPE2_MSG_LEN: usize = offsets::MSG_APCI + 16;
    /// Message length for an error response (APCI only).
    pub const ERROR_MSG_LEN: usize = offsets::MSG_APCI + 2;

    /// Descriptor type marking an unsupported descriptor request (error).
    pub const ERROR_DESCRIPTOR_TYPE: u8 = 0x3F;

    /// Extract the descriptor type (low 6 bits of APCI byte 1).
    ///
    /// [`ERROR_DESCRIPTOR_TYPE`](Self::ERROR_DESCRIPTOR_TYPE) means the
    /// device rejected the requested type.
    pub fn descriptor_type(buf: &[u8]) -> Option<u8> {
        if buf.len() < Self::ERROR_MSG_LEN {
            return None;
        }
        Some(buf[offsets::MSG_APCI + 1] & 0x3F)
    }

    /// Parse a type-0 response into its mask version.
    ///
    /// Returns `None` if the response carries a different descriptor type or
    /// is too short.
    pub fn parse_type0(buf: &[u8]) -> Option<[u8; 2]> {
        if Self::descriptor_type(buf)? != 0 || buf.len() < Self::TYPE0_MSG_LEN {
            return None;
        }
        let mut mask = [0u8; 2];
        mask.copy_from_slice(&buf[offsets::MSG_APCI + 2..offsets::MSG_APCI + 4]);
        Some(mask)
    }

    /// Parse a type-2 response into the 14-byte DD2 block.
    ///
    /// Returns `None` if the response carries a different descriptor type or
    /// is too short.
    pub fn parse_type2(buf: &[u8]) -> Option<[u8; 14]> {
        if Self::descriptor_type(buf)? != 2 || buf.len() < Self::TYPE2_MSG_LEN {
            return None;
        }
        let mut dd2 = [0u8; 14];
        dd2.copy_from_slice(&buf[offsets::MSG_APCI + 2..offsets::MSG_APCI + 16]);
        Some(dd2)
    }

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

/// Parser/writer for `A_IndividualAddress_Write`.
///
/// The new address is at APDU[2-3].
pub struct IndividualAddressWrite;

impl IndividualAddressWrite {
    pub const MIN_MSG_LEN: usize = offsets::MSG_APCI + 4;
    pub const MSG_LEN: usize = Self::MIN_MSG_LEN;

    /// Extract the new individual address bytes from the buffer.
    pub fn address_bytes(buf: &[u8]) -> Option<&[u8]> {
        if buf.len() < Self::MIN_MSG_LEN {
            return None;
        }
        Some(&buf[offsets::MSG_APCI + 2..offsets::MSG_APCI + 4])
    }

    /// Write the new individual address into a request buffer (client side,
    /// NM_IndividualAddress_Write — the device is selected by programming
    /// mode, so the address is the only payload).
    pub fn write(buf: &mut [u8], addr: IndividualAddress) {
        buf[offsets::MSG_APCI + 2..offsets::MSG_APCI + 4].copy_from_slice(addr.as_bytes());
    }
}

/// Parser/writer for `A_IndividualAddressSerialNumber_Read`.
pub struct IndividualAddressSerialNumberRead;

impl IndividualAddressSerialNumberRead {
    pub const MIN_MSG_LEN: usize = offsets::MSG_APCI + 8;
    pub const MSG_LEN: usize = Self::MIN_MSG_LEN;

    /// Extract the serial number (6 bytes) from the buffer.
    pub fn serial_number(buf: &[u8]) -> Option<&[u8]> {
        if buf.len() < Self::MIN_MSG_LEN {
            return None;
        }
        Some(&buf[offsets::MSG_APCI + 2..offsets::MSG_APCI + 8])
    }

    /// Write the serial number into a request buffer (client side,
    /// NM_IndividualAddress_SerialNumber_Read).
    pub fn write(buf: &mut [u8], serial: &[u8; 6]) {
        buf[offsets::MSG_APCI + 2..offsets::MSG_APCI + 8].copy_from_slice(serial);
    }
}

/// Writer/parser for `A_IndividualAddressSerialNumber_Response`.
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

    /// Extract the serial number (6 bytes) from a received response (client
    /// side). The responding device's individual address is the frame's
    /// source address, not part of this payload.
    pub fn serial_number(buf: &[u8]) -> Option<&[u8]> {
        if buf.len() < Self::MSG_LEN {
            return None;
        }
        Some(&buf[offsets::MSG_APCI + 2..offsets::MSG_APCI + 8])
    }
}

/// Parser/writer for `A_IndividualAddressSerialNumber_Write`.
pub struct IndividualAddressSerialNumberWrite;

impl IndividualAddressSerialNumberWrite {
    pub const MIN_MSG_LEN: usize = offsets::MSG_APCI + 14;
    pub const MSG_LEN: usize = Self::MIN_MSG_LEN;

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

    /// Write serial number and new individual address into a request buffer
    /// (client side, NM_IndividualAddress_SerialNumber_Write). The trailing
    /// 4 reserved octets (APDU[10-13]) stay zero.
    pub fn write(buf: &mut [u8], serial: &[u8; 6], addr: IndividualAddress) {
        buf[offsets::MSG_APCI + 2..offsets::MSG_APCI + 8].copy_from_slice(serial);
        buf[offsets::MSG_APCI + 8..offsets::MSG_APCI + 10].copy_from_slice(addr.as_bytes());
    }
}

// ============================================================================
// DomainAddressSerialNumber (Read / Response / Write)
// ============================================================================

/// A domain address used by the KNX open media.
///
/// PL110 and RF deliberately remain distinct variants. They share the
/// `A_DomainAddress_*` APCIs, but their wire widths are part of the medium
/// profile and must never be inferred by truncating or padding a byte slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OpenMediumDomainAddress {
    /// The PL110 domain number. Its wire representation is `[0, number]`;
    /// 03/02/03 §4.2.2 deliberately implements the reduced 8-bit RT1 address
    /// space even though `A_DomainAddress_*` transports two octets.
    Pl(u8),
    Rf([u8; 6]),
}

impl OpenMediumDomainAddress {
    pub const PL_LENGTH: usize = 2;
    pub const RF_LENGTH: usize = 6;

    pub const fn encoded_len(self) -> usize {
        match self {
            Self::Pl(_) => Self::PL_LENGTH,
            Self::Rf(_) => Self::RF_LENGTH,
        }
    }

    /// Parse the exact medium-specific representation.
    ///
    /// Four- and 21-octet KNX/IP domain operands are intentionally rejected:
    /// they carry routing configuration with different security rules and are
    /// not interchangeable with an open-medium domain address.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        match bytes {
            [0, number] => Some(Self::Pl(*number)),
            bytes if bytes.len() == Self::RF_LENGTH => {
                let mut domain = [0; Self::RF_LENGTH];
                domain.copy_from_slice(bytes);

                Some(Self::Rf(domain))
            }
            _ => None,
        }
    }

    pub fn write(self, destination: &mut [u8]) {
        assert_eq!(destination.len(), self.encoded_len(), "domain-address buffer has the selected medium width");

        match self {
            Self::Pl(domain) => destination.copy_from_slice(&[0, domain]),
            Self::Rf(domain) => destination.copy_from_slice(&domain),
        }
    }
}

/// Parser for `A_DomainAddressSerialNumber_Read`.
///
/// Wire format: APCI(2) + serial(6).
pub struct DomainAddressSerialNumberRead;

impl DomainAddressSerialNumberRead {
    pub const MIN_MSG_LEN: usize = offsets::MSG_APCI + 8;
    pub const MSG_LEN: usize = Self::MIN_MSG_LEN;

    /// Extract the serial number (6 bytes) from the buffer.
    pub fn serial_number(buf: &[u8]) -> Option<&[u8]> {
        if buf.len() < Self::MIN_MSG_LEN {
            return None;
        }
        Some(&buf[offsets::MSG_APCI + 2..offsets::MSG_APCI + 8])
    }

    pub fn write(buf: &mut [u8], serial: &[u8; 6]) {
        buf[offsets::MSG_APCI + 2..offsets::MSG_APCI + 8].copy_from_slice(serial);
    }
}

/// Writer for `A_DomainAddressSerialNumber_Response`.
///
/// Wire format: APCI(2) + serial(6) + domain_address(N).
/// N depends on the medium: 2 for PL110, 4 for IP (multicast address), 6 for
/// RF. TP1 has no domain address and does not use this service.
pub struct DomainAddressSerialNumberResponse;

impl DomainAddressSerialNumberResponse {
    /// Response length with no domain address (TP1 / minimal).
    pub const MSG_LEN_NO_DOA: usize = offsets::MSG_APCI + 8;
    /// Response length with a 2-byte PL110 domain address.
    pub const MSG_LEN_PL: usize = Self::MSG_LEN_NO_DOA + OpenMediumDomainAddress::PL_LENGTH;
    /// Response length with 4-byte domain address (IP multicast).
    pub const MSG_LEN_IP: usize = offsets::MSG_APCI + 12;
    /// Response length with a 6-byte RF domain address.
    pub const MSG_LEN_RF: usize = Self::MSG_LEN_NO_DOA + OpenMediumDomainAddress::RF_LENGTH;

    /// Write serial number into the response buffer.
    pub fn write_serial(buf: &mut [u8], serial: &[u8; 6]) {
        buf[offsets::MSG_APCI + 2..offsets::MSG_APCI + 8].copy_from_slice(serial);
    }

    /// Write domain address into the response buffer (after the serial number).
    pub fn write_domain_address(buf: &mut [u8], doa: &[u8]) {
        let start = offsets::MSG_APCI + 8;
        buf[start..start + doa.len()].copy_from_slice(doa);
    }

    pub fn serial_number(buf: &[u8]) -> Option<&[u8]> {
        if buf.len() < Self::MSG_LEN_NO_DOA {
            return None;
        }

        Some(&buf[offsets::MSG_APCI + 2..offsets::MSG_APCI + 8])
    }

    pub fn domain_address(buf: &[u8]) -> Option<OpenMediumDomainAddress> {
        if buf.len() < Self::MSG_LEN_NO_DOA {
            return None;
        }

        OpenMediumDomainAddress::parse(&buf[offsets::MSG_APCI + 8..])
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

    pub const fn msg_len(domain_address: OpenMediumDomainAddress) -> usize {
        Self::MIN_MSG_LEN + domain_address.encoded_len()
    }

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
        if buf.len() <= start { &[] } else { &buf[start..buf.len()] }
    }

    pub fn write(buf: &mut [u8], serial: &[u8; 6], domain_address: OpenMediumDomainAddress) {
        buf[offsets::MSG_APCI + 2..offsets::MSG_APCI + 8].copy_from_slice(serial);

        let start = offsets::MSG_APCI + 8;
        domain_address.write(&mut buf[start..start + domain_address.encoded_len()]);
    }
}

// ============================================================================
// DomainAddress (plain, broadcast / programming-mode — A_DomainAddress_*)
// ============================================================================

/// Parser for `A_DomainAddress_Write` (KNX 03/03/07 §3.3.3).
///
/// Unlike the serial-number variant, the device is selected by being in
/// programming mode, so the PDU carries no serial number — just the new domain
/// address right after the APCI. Wire format: APCI(2) + domain_address(N), with
/// N = 2 (KNX-PL110) or 6 (KNX-RF).
pub struct DomainAddressWrite;

impl DomainAddressWrite {
    /// Minimum length: APCI(2), no domain address yet.
    pub const MIN_MSG_LEN: usize = offsets::MSG_APCI + 2;

    pub const fn msg_len(domain_address: OpenMediumDomainAddress) -> usize {
        Self::MIN_MSG_LEN + domain_address.encoded_len()
    }

    /// Extract the domain address (the bytes after the APCI). Empty if absent.
    pub fn domain_address(buf: &[u8]) -> &[u8] {
        let start = offsets::MSG_APCI + 2;
        if buf.len() <= start { &[] } else { &buf[start..buf.len()] }
    }

    pub fn write(buf: &mut [u8], domain_address: OpenMediumDomainAddress) {
        let start = offsets::MSG_APCI + 2;
        domain_address.write(&mut buf[start..start + domain_address.encoded_len()]);
    }
}

/// Writer for `A_DomainAddress_Response` (KNX 03/03/07 §3.3.4).
///
/// Wire format: APCI(2) + domain_address(N).
pub struct DomainAddressResponse;

impl DomainAddressResponse {
    /// APDU length with no domain address (APCI only).
    pub const MSG_LEN_NO_DOA: usize = offsets::MSG_APCI + 2;
    /// Response length with a 2-byte PL110 domain address.
    pub const MSG_LEN_PL: usize = Self::MSG_LEN_NO_DOA + OpenMediumDomainAddress::PL_LENGTH;
    /// Response length with a 6-byte RF domain address.
    pub const MSG_LEN_RF: usize = Self::MSG_LEN_NO_DOA + OpenMediumDomainAddress::RF_LENGTH;

    /// Write the domain address right after the APCI.
    pub fn write_domain_address(buf: &mut [u8], doa: &[u8]) {
        let start = offsets::MSG_APCI + 2;
        buf[start..start + doa.len()].copy_from_slice(doa);
    }

    pub fn domain_address(buf: &[u8]) -> Option<OpenMediumDomainAddress> {
        if buf.len() < Self::MSG_LEN_NO_DOA {
            return None;
        }

        OpenMediumDomainAddress::parse(&buf[offsets::MSG_APCI + 2..])
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

    /// Write a request with the channel in the short APCI's low six bits.
    pub fn write(buf: &mut [u8], channel: u8, count: u8) {
        buf[offsets::MSG_APCI + 1] = (buf[offsets::MSG_APCI + 1] & 0xC0) | (channel & 0x3F);
        buf[offsets::MSG_APCI + 2] = count;
    }
}

/// Parsed result of `A_ADC_Response`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdcResult {
    pub channel: u8,
    pub count: u8,
    pub sum: u16,
}

/// Parser and writer for `A_ADC_Response`.
pub struct AdcResponse;

impl AdcResponse {
    /// Response: APCI(2) + count(1) + sum(2) = 5 bytes APDU.
    pub const MSG_LEN: usize = offsets::MSG_APCI + 5;

    /// Parse the echoed channel/count and the big-endian converter sum.
    pub fn parse(buf: &[u8]) -> Option<AdcResult> {
        if buf.len() < Self::MSG_LEN {
            return None;
        }

        Some(AdcResult {
            channel: buf[offsets::MSG_APCI + 1] & 0x3F,
            count: buf[offsets::MSG_APCI + 2],
            sum: u16::from_be_bytes([buf[offsets::MSG_APCI + 3], buf[offsets::MSG_APCI + 4]]),
        })
    }

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
    fn adc_read_write_roundtrips() {
        let mut buf = [0u8; AdcRead::MIN_MSG_LEN];
        buf[offsets::MSG_APCI + 1] = 0xC0;
        AdcRead::write(&mut buf, 0x2A, 7);

        let request = AdcRead::parse(&buf).expect("complete ADC request");
        assert_eq!(request.channel, 0x2A);
        assert_eq!(request.count, 7);
        assert_eq!(buf[offsets::MSG_APCI + 1] & 0xC0, 0xC0);
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

        let response = AdcResponse::parse(&buf).expect("complete ADC response");
        assert_eq!(response, AdcResult { channel: 4, count: 8, sum: 0x1234 });
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

    #[test]
    fn device_descriptor_response_type0_roundtrip() {
        let mut buf = [0u8; DeviceDescriptorResponse::TYPE0_MSG_LEN];
        buf[offsets::MSG_APCI + 1] = 0xC0;
        DeviceDescriptorResponse::write_type0(&mut buf, &[0x07, 0xB0]);
        assert_eq!(DeviceDescriptorResponse::descriptor_type(&buf), Some(0));
        assert_eq!(DeviceDescriptorResponse::parse_type0(&buf), Some([0x07, 0xB0]));
        assert_eq!(DeviceDescriptorResponse::parse_type2(&buf), None);
    }

    #[test]
    fn device_descriptor_response_type2_roundtrip() {
        let mut buf = [0u8; DeviceDescriptorResponse::TYPE2_MSG_LEN];
        buf[offsets::MSG_APCI + 1] = 0xC0;
        let dd2: [u8; 14] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
        DeviceDescriptorResponse::write_type2(&mut buf, &dd2);
        assert_eq!(DeviceDescriptorResponse::parse_type2(&buf), Some(dd2));
        assert_eq!(DeviceDescriptorResponse::parse_type0(&buf), None);
    }

    #[test]
    fn device_descriptor_response_error_detected() {
        let mut buf = [0u8; DeviceDescriptorResponse::ERROR_MSG_LEN];
        buf[offsets::MSG_APCI + 1] = 0xC0;
        DeviceDescriptorResponse::write_error(&mut buf);
        assert_eq!(
            DeviceDescriptorResponse::descriptor_type(&buf),
            Some(DeviceDescriptorResponse::ERROR_DESCRIPTOR_TYPE)
        );
        assert_eq!(DeviceDescriptorResponse::parse_type0(&buf), None);
    }

    #[test]
    fn individual_address_write_roundtrip() {
        let mut buf = [0u8; IndividualAddressWrite::MSG_LEN];
        IndividualAddressWrite::write(&mut buf, IndividualAddress::new(1, 1, 42));
        let bytes = IndividualAddressWrite::address_bytes(&buf).unwrap();
        assert_eq!(IndividualAddress::from_bytes(bytes), IndividualAddress::new(1, 1, 42));
    }

    #[test]
    fn serial_number_read_write_roundtrip() {
        let serial = [0x00, 0x83, 0x01, 0x02, 0x03, 0x04];
        let mut buf = [0u8; IndividualAddressSerialNumberRead::MSG_LEN];
        IndividualAddressSerialNumberRead::write(&mut buf, &serial);
        assert_eq!(IndividualAddressSerialNumberRead::serial_number(&buf).unwrap(), &serial);
    }

    #[test]
    fn serial_number_response_parse() {
        let serial = [0x00, 0x83, 0x01, 0x02, 0x03, 0x04];
        let mut buf = [0u8; IndividualAddressSerialNumberResponse::MSG_LEN];
        IndividualAddressSerialNumberResponse::write_serial(&mut buf, &serial);
        assert_eq!(IndividualAddressSerialNumberResponse::serial_number(&buf).unwrap(), &serial);
    }

    #[test]
    fn serial_number_write_builder_roundtrip() {
        let serial = [0x00, 0x83, 0x01, 0x02, 0x03, 0x04];
        let mut buf = [0u8; IndividualAddressSerialNumberWrite::MSG_LEN];
        IndividualAddressSerialNumberWrite::write(&mut buf, &serial, IndividualAddress::new(2, 3, 4));
        assert_eq!(IndividualAddressSerialNumberWrite::serial_number(&buf).unwrap(), &serial);
        let addr = IndividualAddressSerialNumberWrite::address_bytes(&buf).unwrap();
        assert_eq!(IndividualAddress::from_bytes(addr), IndividualAddress::new(2, 3, 4));
    }

    #[test]
    fn programming_mode_domain_writes_preserve_the_medium_width() {
        let pl = OpenMediumDomainAddress::Pl(0xA5);
        let mut pl_buf = vec![0; DomainAddressWrite::msg_len(pl)];
        DomainAddressWrite::write(&mut pl_buf, pl);

        assert_eq!(DomainAddressWrite::domain_address(&pl_buf), [0x00, 0xA5]);
        assert_eq!(OpenMediumDomainAddress::parse(DomainAddressWrite::domain_address(&pl_buf)), Some(pl));

        let rf = OpenMediumDomainAddress::Rf([1, 2, 3, 4, 5, 6]);
        let mut rf_buf = vec![0; DomainAddressWrite::msg_len(rf)];
        DomainAddressWrite::write(&mut rf_buf, rf);

        assert_eq!(DomainAddressWrite::domain_address(&rf_buf), [1, 2, 3, 4, 5, 6]);
        assert_eq!(OpenMediumDomainAddress::parse(DomainAddressWrite::domain_address(&rf_buf)), Some(rf));
    }

    #[test]
    fn serial_domain_apdus_roundtrip_for_pl_and_rf() {
        let serial = [0x00, 0x83, 0x01, 0x02, 0x03, 0x04];

        let mut read = [0; DomainAddressSerialNumberRead::MSG_LEN];
        DomainAddressSerialNumberRead::write(&mut read, &serial);
        assert_eq!(DomainAddressSerialNumberRead::serial_number(&read), Some(serial.as_slice()));

        for domain in [OpenMediumDomainAddress::Pl(0x7F), OpenMediumDomainAddress::Rf([6, 5, 4, 3, 2, 1])] {
            let mut write = vec![0; DomainAddressSerialNumberWrite::msg_len(domain)];
            DomainAddressSerialNumberWrite::write(&mut write, &serial, domain);

            assert_eq!(DomainAddressSerialNumberWrite::serial_number(&write), Some(serial.as_slice()));
            assert_eq!(
                OpenMediumDomainAddress::parse(DomainAddressSerialNumberWrite::domain_address(&write)),
                Some(domain)
            );

            let mut response = vec![0; DomainAddressSerialNumberResponse::MSG_LEN_NO_DOA + domain.encoded_len()];
            DomainAddressSerialNumberResponse::write_serial(&mut response, &serial);
            let start = offsets::MSG_APCI + 8;
            domain.write(&mut response[start..]);

            assert_eq!(DomainAddressSerialNumberResponse::serial_number(&response), Some(serial.as_slice()));
            assert_eq!(DomainAddressSerialNumberResponse::domain_address(&response), Some(domain));
        }
    }

    #[test]
    fn open_medium_domain_parser_rejects_ip_widths() {
        assert_eq!(OpenMediumDomainAddress::parse(&[1, 0]), None);
        assert_eq!(OpenMediumDomainAddress::parse(&[224, 0, 23, 12]), None);
        assert_eq!(OpenMediumDomainAddress::parse(&[0; 21]), None);
    }
}
