//! TP1 standard-frame view and builder.
//!
//! A BCU2 speaks TP1 standard frames only: its 15-octet APDU ceiling
//! means an extended frame never carries anything it could say. That
//! lets this stack work directly on the wire layout (minus the
//! checksum octet, which the link driver owns):
//!
//! ```text
//! octet 0      control  (FT=1, repeat flag, priority)
//! octet 1..=2  source individual address
//! octet 3..=4  destination address
//! octet 5      [AT:1][hop count:3][APDU length:4]
//! octet 6      TPCI (+ APCI bits 9..8 for data PDUs)
//! octet 7      APCI bits 7..0 (present when length >= 1)
//! octet 8..    APDU payload
//! ```
//!
//! The length nibble counts the octets *after* octet 6, so a frame is
//! `7 + length` bytes. This is the same byte layout the rest of the
//! workspace calls the "internal format" for standard frames, which is
//! why the conformance harness's TP1-without-checksum injects can be
//! fed in verbatim.

use heapless::Vec;
use zweidraehte_proto::address::{GroupAddress, IndividualAddress};

/// Largest frame this stack emits or accepts: 7 header octets plus a
/// 15-octet APDU.
pub const MAX_FRAME: usize = 7 + 15;

/// One outbound frame.
pub type FrameBuf = Vec<u8, MAX_FRAME>;

// ============================================================================
// 10-bit APCI vocabulary
// ============================================================================

/// The 10-bit APCI values a BCU2 needs, spelled as full 10-bit numbers
/// (bits 9..6 select the short code; escaped services use 3Cxh with
/// the low octet carrying the sub-code).
pub mod apci {
    pub const GROUP_VALUE_READ: u16 = 0x000;
    pub const GROUP_VALUE_RESPONSE: u16 = 0x040;
    pub const GROUP_VALUE_WRITE: u16 = 0x080;
    pub const INDIVIDUAL_ADDRESS_WRITE: u16 = 0x0C0;
    pub const INDIVIDUAL_ADDRESS_READ: u16 = 0x100;
    pub const INDIVIDUAL_ADDRESS_RESPONSE: u16 = 0x140;
    pub const ADC_READ: u16 = 0x180;
    pub const ADC_RESPONSE: u16 = 0x1C0;
    pub const MEMORY_READ: u16 = 0x200;
    pub const MEMORY_RESPONSE: u16 = 0x240;
    pub const MEMORY_WRITE: u16 = 0x280;
    pub const DEVICE_DESCRIPTOR_READ: u16 = 0x300;
    pub const DEVICE_DESCRIPTOR_RESPONSE: u16 = 0x340;
    pub const RESTART: u16 = 0x380;
    pub const AUTHORIZE_REQUEST: u16 = 0x3D1;
    pub const AUTHORIZE_RESPONSE: u16 = 0x3D2;
    pub const PROPERTY_VALUE_READ: u16 = 0x3D5;
    pub const PROPERTY_VALUE_RESPONSE: u16 = 0x3D6;
    pub const PROPERTY_VALUE_WRITE: u16 = 0x3D7;
    pub const PROPERTY_DESCRIPTION_READ: u16 = 0x3D8;
    pub const PROPERTY_DESCRIPTION_RESPONSE: u16 = 0x3D9;
}

/// TPCI classification of octet 6 (top two bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tpci {
    /// Unnumbered data (T_Data_Group / T_Data_Broadcast /
    /// T_Data_Individual).
    Unnumbered,
    /// Numbered data on a transport connection, sequence 0..=15.
    Numbered { seq: u8 },
    /// T_Connect (0x80) or T_Disconnect (0x81).
    Control { disconnect: bool },
    /// T_ACK (0xC2) or T_NAK (0xC3) with sequence number.
    ControlAck { nak: bool, seq: u8 },
    /// A control PDU this stack does not know.
    Unknown,
}

/// A parsed view over one standard frame (without checksum).
#[derive(Debug, Clone, Copy)]
pub struct FrameView<'a> {
    pub control: u8,
    pub source: IndividualAddress,
    pub dest_raw: [u8; 2],
    pub is_group: bool,
    pub hop_count: u8,
    /// Octet 6 onward: TPCI octet plus `length` APDU octets.
    pub tpdu: &'a [u8],
}

impl<'a> FrameView<'a> {
    /// Parse a standard frame. Rejects extended frames (control bit 7
    /// clear) — a BCU2 does not understand them — and frames whose
    /// length nibble disagrees with the byte count.
    pub fn parse(frame: &'a [u8]) -> Option<Self> {
        if frame.len() < 7 {
            return None;
        }
        let control = frame[0];
        if control & 0x80 == 0 {
            return None;
        }
        let length = (frame[5] & 0x0F) as usize;
        if frame.len() != 7 + length {
            return None;
        }
        Some(Self {
            control,
            source: IndividualAddress::from_bytes(&frame[1..3]),
            dest_raw: [frame[3], frame[4]],
            is_group: frame[5] & 0x80 != 0,
            hop_count: (frame[5] >> 4) & 0x07,
            tpdu: &frame[6..],
        })
    }

    pub fn tpci(&self) -> Tpci {
        let octet = self.tpdu[0];
        match octet >> 6 {
            0b00 => Tpci::Unnumbered,
            0b01 => Tpci::Numbered { seq: (octet >> 2) & 0x0F },
            0b10 => match octet {
                0x80 => Tpci::Control { disconnect: false },
                0x81 => Tpci::Control { disconnect: true },
                _ => Tpci::Unknown,
            },
            _ => match octet & 0xC3 {
                0xC2 => Tpci::ControlAck { nak: false, seq: (octet >> 2) & 0x0F },
                0xC3 => Tpci::ControlAck { nak: true, seq: (octet >> 2) & 0x0F },
                _ => Tpci::Unknown,
            },
        }
    }

    /// The 10-bit APCI of a data PDU (needs at least one APDU octet).
    pub fn apci(&self) -> Option<u16> {
        if self.tpdu.len() < 2 {
            return None;
        }
        Some((((self.tpdu[0] & 0x03) as u16) << 8) | self.tpdu[1] as u16)
    }

    /// APDU payload after the two APCI octets.
    pub fn payload(&self) -> &'a [u8] {
        if self.tpdu.len() < 2 { &[] } else { &self.tpdu[2..] }
    }

    pub fn dest_group(&self) -> GroupAddress {
        GroupAddress(self.dest_raw)
    }

    pub fn dest_individual(&self) -> IndividualAddress {
        IndividualAddress(self.dest_raw)
    }

    /// Priority bits of the control octet (bits 3..2).
    pub fn priority_bits(&self) -> u8 {
        self.control & 0x0C
    }
}

// ============================================================================
// Building
// ============================================================================

/// Control octet for a fresh (not repeated) standard frame with the
/// given priority bits (already shifted to bits 3..2).
fn control_octet(priority_bits: u8) -> u8 {
    // FT=1 (standard), repeat flag 1 (= not repeated), the two
    // fixed-one bits of the TP1 control octet, priority as given.
    0xB0 | (priority_bits & 0x0C)
}

/// Build one standard frame. `tpci_octet` carries the TPCI bits; for a
/// data PDU the APCI's top two bits are OR-ed in here and `apci_low`
/// is octet 7. `payload` follows.
fn build(
    priority_bits: u8,
    source: IndividualAddress,
    dest: [u8; 2],
    is_group: bool,
    tpci_octet: u8,
    apdu: &[u8],
) -> FrameBuf {
    let mut frame = FrameBuf::new();
    let length = apdu.len();
    debug_assert!(length <= 15, "APDU exceeds the standard-frame length nibble");
    // The push cannot fail: 7 + length <= MAX_FRAME by the assert above.
    let _ = frame.push(control_octet(priority_bits));
    let _ = frame.extend_from_slice(source.as_bytes());
    let _ = frame.extend_from_slice(&dest);
    let at = if is_group { 0x80 } else { 0x00 };
    // Hop count 6 — the value every non-router device transmits with.
    let _ = frame.push(at | 0x60 | (length as u8));
    let _ = frame.push(tpci_octet);
    let _ = frame.extend_from_slice(apdu);
    frame
}

/// A data APDU: 10-bit APCI plus payload, with up to 6 bits of small
/// data folded into the APCI low octet.
// A frame is exactly these eight facts; a builder struct would spread
// one wire layout over two types.
#[allow(clippy::too_many_arguments)]
pub fn data_frame(
    priority_bits: u8,
    source: IndividualAddress,
    dest: [u8; 2],
    is_group: bool,
    tpci_bits: u8,
    apci10: u16,
    small_data: u8,
    payload: &[u8],
) -> FrameBuf {
    let tpci = tpci_bits | ((apci10 >> 8) as u8 & 0x03);
    let apci_low = (apci10 as u8) | (small_data & 0x3F);
    let mut apdu: Vec<u8, 15> = Vec::new();
    let _ = apdu.push(apci_low);
    let _ = apdu.extend_from_slice(payload);
    build(priority_bits, source, dest, is_group, tpci, &apdu)
}

/// TPCI bits for an unnumbered data PDU.
pub const TPCI_UNNUMBERED: u8 = 0x00;

/// TPCI bits for a numbered (connection-oriented) data PDU.
pub fn tpci_numbered(seq: u8) -> u8 {
    0x40 | ((seq & 0x0F) << 2)
}

/// A T_ACK / T_NAK control frame.
pub fn ack_frame(
    priority_bits: u8,
    source: IndividualAddress,
    dest: IndividualAddress,
    nak: bool,
    seq: u8,
) -> FrameBuf {
    let octet = if nak { 0xC3 } else { 0xC2 } | ((seq & 0x0F) << 2);
    build(priority_bits, source, dest.0, false, octet, &[])
}

/// A T_Disconnect control frame.
pub fn disconnect_frame(source: IndividualAddress, dest: IndividualAddress) -> FrameBuf {
    // Connection control PDUs travel at system priority.
    build(0x00, source, dest.0, false, 0x81, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_group_write() {
        // 1.1.1 -> 1/0/1, low priority, A_GroupValue_Write, value 1.
        let raw = [0xBC, 0x11, 0x01, 0x08, 0x01, 0xE1, 0x00, 0x81];
        let view = FrameView::parse(&raw).expect("valid standard frame");
        assert!(view.is_group);
        assert_eq!(view.tpci(), Tpci::Unnumbered);
        assert_eq!(view.apci(), Some(apci::GROUP_VALUE_WRITE | 0x01));
        assert_eq!(view.hop_count, 6);
        assert_eq!(view.payload(), &[]);
    }

    #[test]
    fn parses_connect_and_ack() {
        let connect = [0xB0, 0x00, 0x01, 0x11, 0x0A, 0x60, 0x80];
        let view = FrameView::parse(&connect).expect("valid control frame");
        assert!(!view.is_group);
        assert_eq!(view.tpci(), Tpci::Control { disconnect: false });

        let ack = [0xB0, 0x00, 0x01, 0x11, 0x0A, 0x60, 0xC6];
        let view = FrameView::parse(&ack).expect("valid ack frame");
        assert_eq!(view.tpci(), Tpci::ControlAck { nak: false, seq: 1 });
    }

    #[test]
    fn length_nibble_must_match() {
        // Length says 2 but only one APDU octet follows.
        let raw = [0xBC, 0x11, 0x01, 0x08, 0x01, 0xE2, 0x00, 0x81];
        assert!(FrameView::parse(&raw).is_none());
    }

    #[test]
    fn builds_a_numbered_memory_response() {
        // Device 1.1.10 answers a memory read: seq 2, 3 bytes @ 0116h.
        let frame = data_frame(
            0x00,
            IndividualAddress::new(1, 1, 10),
            IndividualAddress::new(0, 0, 1).0,
            false,
            tpci_numbered(2),
            apci::MEMORY_RESPONSE,
            3,
            &[0x01, 0x16, 0xAA, 0xBB, 0xCC],
        );
        assert_eq!(frame.as_slice(), &[0xB0, 0x11, 0x0A, 0x00, 0x01, 0x66, 0x4A, 0x43, 0x01, 0x16, 0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn escaped_apci_lands_in_both_octets() {
        // A_PropertyValue_Response (3D6h): octet 6 low bits 11, octet 7 D6h.
        let frame = data_frame(
            0x00,
            IndividualAddress::new(1, 1, 10),
            IndividualAddress::new(0, 0, 1).0,
            false,
            tpci_numbered(0),
            apci::PROPERTY_VALUE_RESPONSE,
            0,
            &[0x01, 0x05, 0x10, 0x01],
        );
        assert_eq!(frame[6], 0x43);
        assert_eq!(frame[7], 0xD6);
    }
}
