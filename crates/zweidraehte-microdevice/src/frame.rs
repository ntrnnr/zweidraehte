//! TP1 standard-frame view and builder.
//!
//! Every family supported by this stack speaks TP1 standard frames
//! only. Its fixed 15-octet APDU ceiling fits that format, so extended
//! frames are deliberately unsupported. That lets this stack work
//! directly on the wire layout (minus the checksum octet, which the
//! link driver owns):
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
//!
//! The protocol vocabulary — [`ApciCode`], [`Tpci`] and their wire
//! codings — is the proto crate's; this module only owns the frame
//! octet layout around them.

use heapless::Vec;
use zweidraehte_proto::address::{GroupAddress, IndividualAddress};
use zweidraehte_proto::config::MAX_APDU_LENGTH_TP1_STANDARD;
use zweidraehte_proto::encoding::tp1::{NPCI_HOP_COUNT_6, TP1_STD_CTRL_BASE};
use zweidraehte_proto::messages::knx::AddressType;

pub use zweidraehte_proto::messages::knx::{ApciCode, Tpci};

pub(crate) const MAX_APDU_LENGTH: usize = MAX_APDU_LENGTH_TP1_STANDARD as usize;
pub(crate) const MAX_APDU_PAYLOAD_LENGTH: usize = MAX_APDU_LENGTH - 1;

/// Largest frame this stack emits or accepts: seven header octets plus the
/// standard TP1 APDU limit.
pub const MAX_FRAME: usize = 7 + MAX_APDU_LENGTH;

/// One outbound frame.
pub type FrameBuf = Vec<u8, MAX_FRAME>;

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
    /// clear) — this stack does not understand them — and frames whose
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

    /// The destination's address type: the AT bit, with the zero group
    /// address distinguished as the broadcast.
    fn address_type(&self) -> AddressType {
        if !self.is_group {
            AddressType::Individual
        } else if self.dest_raw == [0, 0] {
            AddressType::Broadcast
        } else {
            AddressType::Group
        }
    }

    /// The frame's TPCI. `None` covers the codings 03/03/04 leaves
    /// reserved — among them unnumbered data with non-zero sequence
    /// bits, which the conformance suite expects dropped (transport
    /// layer 2.1).
    pub fn tpci(&self) -> Option<Tpci> {
        Tpci::from_octet(self.tpdu[0], self.address_type())
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
    debug_assert!(length <= MAX_APDU_LENGTH, "APDU exceeds the standard-frame length nibble");
    // The push cannot fail: 7 + length <= MAX_FRAME by the assert above.
    let _ = frame.push(TP1_STD_CTRL_BASE | (priority_bits & 0x0C));
    let _ = frame.extend_from_slice(source.as_bytes());
    let _ = frame.extend_from_slice(&dest);
    let at = if is_group { 0x80 } else { 0x00 };
    // Hop count 6 — the value every non-router device transmits with.
    let _ = frame.push(at | NPCI_HOP_COUNT_6 | (length as u8));
    let _ = frame.push(tpci_octet);
    let _ = frame.extend_from_slice(apdu);
    frame
}

/// A data APDU: the service's APCI plus payload, with up to 6 bits of
/// small data folded into the APCI low octet (short services only —
/// the other families spend those bits on the service code).
// A frame is exactly these eight facts; a builder struct would spread
// one wire layout over two types.
#[allow(clippy::too_many_arguments)]
pub fn data_frame(
    priority_bits: u8,
    source: IndividualAddress,
    dest: [u8; 2],
    is_group: bool,
    tpci: Tpci,
    apci: ApciCode,
    small_data: u8,
    payload: &[u8],
) -> FrameBuf {
    let apci10 = apci.wire10_base() | u16::from(small_data & 0x3F);
    let tpci_octet = tpci.octet() | ((apci10 >> 8) as u8 & 0x03);
    let mut apdu: Vec<u8, MAX_APDU_LENGTH> = Vec::new();
    let _ = apdu.push(apci10 as u8);
    let _ = apdu.extend_from_slice(payload);
    build(priority_bits, source, dest, is_group, tpci_octet, &apdu)
}

/// A T_ACK / T_NAK control frame.
pub fn ack_frame(
    priority_bits: u8,
    source: IndividualAddress,
    dest: IndividualAddress,
    nak: bool,
    seq: u8,
) -> FrameBuf {
    let tpci = if nak { Tpci::Nack(seq) } else { Tpci::Ack(seq) };
    build(priority_bits, source, dest.0, false, tpci.octet(), &[])
}

/// A T_Disconnect control frame.
pub fn disconnect_frame(source: IndividualAddress, dest: IndividualAddress) -> FrameBuf {
    // Connection control PDUs travel at system priority.
    build(0x00, source, dest.0, false, Tpci::Disconnect.octet(), &[])
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
        assert_eq!(view.tpci(), Some(Tpci::DataGroup));
        assert_eq!(view.apci(), Some(ApciCode::GroupValueWrite.wire10_base() | 0x01));
        assert_eq!(view.hop_count, 6);
        assert_eq!(view.payload(), &[]);
    }

    #[test]
    fn parses_connect_and_ack() {
        let connect = [0xB0, 0x00, 0x01, 0x11, 0x0A, 0x60, 0x80];
        let view = FrameView::parse(&connect).expect("valid control frame");
        assert!(!view.is_group);
        assert_eq!(view.tpci(), Some(Tpci::Connect));

        let ack = [0xB0, 0x00, 0x01, 0x11, 0x0A, 0x60, 0xC6];
        let view = FrameView::parse(&ack).expect("valid ack frame");
        assert_eq!(view.tpci(), Some(Tpci::Ack(1)));
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
            Tpci::DataConnected(2),
            ApciCode::MemoryReadResponse,
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
            Tpci::DataConnected(0),
            ApciCode::PropertyValueResponse,
            0,
            &[0x01, 0x05, 0x10, 0x01],
        );
        assert_eq!(frame[6], 0x43);
        assert_eq!(frame[7], 0xD6);
    }
}
