//! Canonical KNX frame view and builder, and the TP1 wire conversion
//! either side of it.
//!
//! The core works on the workspace's **canonical** frame layout — the
//! one `zweidraehte_proto::messages::knx` calls the internal format:
//!
//! ```text
//! octet 0      control  (FT, repeat flag, priority)
//! octet 1..=2  source individual address
//! octet 3..=4  destination address
//! octet 5      [AT:1][hop count:3][EFF:4]
//! octet 6      TPCI (+ APCI bits 9..8 for data PDUs)
//! octet 7      APCI bits 7..0 (present when an APDU follows)
//! octet 8..    APDU payload
//! ```
//!
//! On the TP1 wire a **standard** frame is the same layout with the APDU
//! length in the low nibble of octet 5, and an **extended** frame spends
//! an extra octet on the extended control field, pushing everything after
//! it right by one. The two therefore disagree about where the TPCI is,
//! which is why the boundary is explicit rather than implicit: the core
//! never sees wire bytes. [`normalize`] converts and validates on the way
//! in, [`to_wire`] converts on the way out, and the checksum stays the
//! byte-oriented link driver's business at the very edge.
//!
//! Working canonically is what lets this stack reuse the workspace's
//! frame and APDU codecs unchanged — including, once KNX Data Secure
//! lands here, `messages::apdu::secure`, whose offsets are canonical.
//!
//! The standard-frame conversion is spelled here because it is a copy and
//! a nibble mask, and because
//! `zweidraehte_proto::encoding::tp1`'s generic helpers carry the
//! extended-frame branch with them — around 550 bytes of flash in a
//! BCU1/BCU2 image that has just *refused* an extended frame. The
//! extended direction will call those helpers, in the profile that admits
//! one; there is no second extended-frame layout in this crate.
//!
//! The protocol vocabulary — [`ApciCode`], [`Tpci`] and their wire
//! codings — is the proto crate's; this module only owns the frame
//! octet layout around them.

use heapless::Vec;
use zweidraehte_proto::address::{GroupAddress, IndividualAddress};
pub use zweidraehte_proto::config::MAX_APDU_LENGTH_TP1_STANDARD;
use zweidraehte_proto::encoding::tp1::{NPCI_HOP_COUNT_6, TP1_STD_CTRL_BASE, tp1_to_knx_bytes_no_checksum};
use zweidraehte_proto::messages::knx::AddressType;

pub use zweidraehte_proto::messages::knx::{ApciCode, Tpci};

pub(crate) const MAX_APDU_LENGTH: usize = MAX_APDU_LENGTH_TP1_STANDARD as usize;

/// Largest frame this stack emits or accepts: seven header octets plus the
/// standard TP1 APDU limit.
///
/// This is the standard-frame profile's capacity; an extended-frame profile
/// uses [`EXTENDED_FRAME`], which adds the octet the wire form spends on the
/// extended control field.
pub const MAX_FRAME: usize = 7 + MAX_APDU_LENGTH;

/// The APDU ceiling a KNX Data Secure BCU2 advertises.
///
/// Not a round number by choice: it is what the bench MV-0021 device answers
/// for `PID_MAX_APDULENGTH` (`0028`), and what ETS then negotiates down to
/// ("DetermineMaxApduLengthToUse evaluates to 40 … restricted by
/// ByTargetDevice"). Sizing to the protocol-wide 254 instead would cost a
/// small MCU ten times the buffer for octets the peer will never send.
pub const EXTENDED_APDU: u16 = 40;

/// Frame capacity for a profile at [`EXTENDED_APDU`]: seven header octets,
/// the APDU, and one more for the extended control octet the wire form
/// carries. Canonical frames leave that last octet unused.
pub const EXTENDED_FRAME: usize = 7 + EXTENDED_APDU as usize + 1;

/// Frame capacity for the APDU-40 Data Secure profile: the advertised
/// plaintext capacity plus the S-A_Data envelope. Keeping this separate from
/// [`EXTENDED_APDU`] prevents PID 56 from accidentally advertising the outer
/// secure PDU size as application capacity.
pub const SECURE_EXTENDED_FRAME: usize = EXTENDED_FRAME + zweidraehte_proto::messages::apdu::secure::OVERHEAD;

/// Derive the APDU ceiling from the frame capacity.
///
/// One const generic instead of two: `FRAME_CAP` determines the APDU
/// ceiling, not the other way around. Standard profiles have
/// `cap = 7 + APDU`; extended ones add one for the wire's ECF octet.
pub const fn max_apdu(frame_cap: usize) -> u16 {
    if frame_cap > MAX_FRAME { (frame_cap - 8) as u16 } else { (frame_cap - 7) as u16 }
}

/// Whether a frame capacity admits extended frames.
pub const fn is_extended(frame_cap: usize) -> bool {
    max_apdu(frame_cap) > MAX_APDU_LENGTH_TP1_STANDARD
}

/// One frame in canonical layout, sized by the profile.
///
/// `N` is the profile's frame capacity: seven header octets plus its APDU
/// ceiling, and for an extended-frame profile one more octet so the same
/// width also holds the wire form. A plain BCU1/BCU2 build instantiates
/// this at [`MAX_FRAME`] and pays nothing for a bigger profile elsewhere in
/// the workspace.
pub type FrameBuf<const N: usize = MAX_FRAME> = Vec<u8, N>;

/// One frame in TP1 wire layout, without its checksum.
///
/// Deliberately the same width as [`FrameBuf`]. A standard frame is the
/// same length either way; an extended frame is one octet longer on the
/// wire, which its profile absorbs by sizing `N` for the wire form and
/// leaving the canonical buffer one octet of slack. One width means one
/// buffer type to thread through the stack.
pub type WireBuf<const N: usize = MAX_FRAME> = Vec<u8, N>;

/// A parsed view over one canonical frame.
#[derive(Debug, Clone, Copy)]
pub struct FrameView<'a> {
    /// The whole canonical frame. The extended property and
    /// function-property parsers in `zweidraehte_proto::messages::apdu`
    /// index from `offsets::MSG_APCI`, so they need the frame, not the
    /// payload slice.
    pub frame: &'a [u8],
    pub control: u8,
    pub source: IndividualAddress,
    pub dest_raw: [u8; 2],
    pub is_group: bool,
    pub hop_count: u8,
    /// Octet 6 onward: TPCI octet plus `length` APDU octets.
    pub tpdu: &'a [u8],
}

impl<'a> FrameView<'a> {
    /// Parse a canonical frame — the output of [`normalize`], never raw
    /// wire bytes.
    ///
    /// There is no length field to cross-check here: canonically the APDU
    /// length *is* the buffer length. The wire's length octet is validated
    /// against the byte count in [`normalize`], where it still exists.
    pub fn parse(frame: &'a [u8]) -> Option<Self> {
        if frame.len() < 7 {
            return None;
        }
        let control = frame[0];
        Some(Self {
            frame,
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
    /// bits — and TPDUs whose length cannot carry that service.
    ///
    /// Control TPDUs consist of exactly their one TPCI octet. Accepting
    /// trailing octets is not benign: a malformed T_ACK would otherwise
    /// advance the connection state machine. Data TPDUs need the following
    /// APCI octet, even when their application value fits in its low six
    /// bits.
    pub fn tpci(&self) -> Option<Tpci> {
        let tpci = Tpci::from_octet(self.tpdu[0], self.address_type())?;
        let valid_length = match tpci {
            Tpci::Connect | Tpci::Disconnect | Tpci::Ack(_) | Tpci::Nack(_) => self.tpdu.len() == 1,
            Tpci::DataBroadcast
            | Tpci::DataSystemBroadcast
            | Tpci::DataGroup
            | Tpci::DataIndividual
            | Tpci::DataConnected(_) => self.tpdu.len() >= 2,
        };
        valid_length.then_some(tpci)
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

/// Write the seven canonical header octets, up to and including the TPCI.
///
/// Canonically the header does not depend on the APDU — the length nibble
/// that used to make it do so belongs to the wire form now — so callers can
/// append their payload straight onto the returned buffer instead of
/// building it separately and copying it in.
fn header<const N: usize>(
    priority_bits: u8,
    source: IndividualAddress,
    dest: [u8; 2],
    is_group: bool,
    tpci_octet: u8,
) -> FrameBuf<N> {
    const { assert!(N >= 7, "a frame capacity must hold at least the header") };
    let mut frame = FrameBuf::new();
    // None of these can fail: the const assert above guarantees the room.
    let _ = frame.push(TP1_STD_CTRL_BASE | (priority_bits & 0x0C));
    let _ = frame.extend_from_slice(source.as_bytes());
    let _ = frame.extend_from_slice(&dest);
    let at = if is_group { 0x80 } else { 0x00 };
    // Hop count 6 — the value every non-router device transmits with. The
    // low nibble stays clear: canonically it is the EFF field, and the
    // length it carries on a standard wire frame is added by `to_wire`.
    let _ = frame.push(at | NPCI_HOP_COUNT_6);
    let _ = frame.push(tpci_octet);
    frame
}

/// A data APDU: the service's APCI plus payload, with up to 6 bits of
/// small data folded into the APCI low octet (short services only —
/// the other families spend those bits on the service code).
// A frame is exactly these eight facts; a builder struct would spread
// one wire layout over two types.
#[allow(clippy::too_many_arguments)]
pub fn data_frame<const N: usize>(
    priority_bits: u8,
    source: IndividualAddress,
    dest: [u8; 2],
    is_group: bool,
    tpci: Tpci,
    apci: ApciCode,
    small_data: u8,
    payload: &[u8],
) -> FrameBuf<N> {
    let apci10 = apci.wire10_base() | u16::from(small_data & 0x3F);
    let mut frame = header(priority_bits, source, dest, is_group, tpci.octet() | ((apci10 >> 8) as u8 & 0x03));
    debug_assert!(8 + payload.len() <= N, "APDU exceeds the profile's frame capacity");
    let _ = frame.push(apci10 as u8);
    let _ = frame.extend_from_slice(payload);
    frame
}

/// Require the extended TP1 wire form even when this canonical APDU would fit
/// in a standard frame.
///
/// Most short responses should remain standard. The management specification
/// has narrow exceptions, notably the count-zero `A_Memory_Response` for a
/// request above `PID_MAX_APDU_LENGTH`. Bit 7 of the canonical control octet
/// is otherwise rewritten at the wire boundary, so it doubles as a zero-cost
/// internal format hint and never changes the transmitted control field.
pub(crate) fn force_extended<const N: usize>(frame: &mut FrameBuf<N>) {
    if is_extended(N) {
        frame[0] &= !0x80;
    }
}

/// A T_ACK / T_NAK control frame.
pub fn ack_frame<const N: usize>(
    priority_bits: u8,
    source: IndividualAddress,
    dest: IndividualAddress,
    nak: bool,
    seq: u8,
) -> FrameBuf<N> {
    let tpci = if nak { Tpci::Nack(seq) } else { Tpci::Ack(seq) };
    header(priority_bits, source, dest.0, false, tpci.octet())
}

/// A T_Disconnect control frame.
pub fn disconnect_frame<const N: usize>(source: IndividualAddress, dest: IndividualAddress) -> FrameBuf<N> {
    // Connection control PDUs travel at system priority.
    header(0x00, source, dest.0, false, Tpci::Disconnect.octet())
}

// ============================================================================
// The TP1 wire boundary
// ============================================================================

/// Convert one received TP1 frame (without checksum) to canonical layout,
/// validating what only the wire form can express.
///
/// Returns `None` for a frame the core must not see:
///
/// - shorter than a frame can be;
/// - a **standard** frame whose length octet disagrees with the byte count.
///   That octet is the only redundancy TP1 gives us, and the conformance
///   suite leans on it (transport layer 2.1 and 2.5 both inject frames whose
///   declared length is a lie). Canonically it is gone, so it has to be
///   checked here.
///
/// An **extended** frame is accepted only by a profile whose frame capacity
/// needs one, and its length octet is validated the same way. A
/// standard-only profile refuses it rather than truncating into buffers
/// that were never sized for it.
pub fn normalize<const N: usize>(wire: &[u8]) -> Option<FrameBuf<N>> {
    if wire.len() < 7 {
        return None;
    }
    // Frame type lives in the control octet, bit 7: set for standard.
    if wire[0] & 0x80 == 0 {
        // Extended. The frame capacity determines whether extended frames are
        // accepted; a standard-only profile compiles this whole arm away rather
        // proto helper it calls.
        if !is_extended(N) {
            return None;
        }
        // Extended layout: ctrl | ext_ctrl | src(2) | dst(2) | len | TPDU.
        if wire.len() < 8 {
            return None;
        }
        let length = wire[6] as usize;
        if wire.len() != 8 + length || length > max_apdu(N) as usize {
            return None;
        }
        // One octet shorter canonically, so the wire form is the binding
        // capacity check.
        if wire.len() > N + 1 {
            return None;
        }
        return Some(tp1_to_knx_bytes_no_checksum::<N>(wire));
    }
    let length = (wire[5] & 0x0F) as usize;
    if wire.len() != 7 + length {
        return None;
    }
    if wire.len() > N {
        return None;
    }
    let mut out = FrameBuf::new();
    // Standard wire and canonical differ in exactly one nibble, so the
    // conversion is a copy and a mask. `tp1_to_knx_bytes_no_checksum` says
    // the same thing generically, but it also carries the extended-frame
    // branch, and pulling that into a profile that has no extended frames
    // costs a BCU1/BCU2 image real flash for code it can never reach.
    let _ = out.extend_from_slice(wire);
    out[5] &= 0xf0;
    Some(out)
}

/// Convert one canonical frame to TP1 wire layout, without its checksum.
///
/// The checksum stays with the byte-oriented link driver: it is the one
/// octet that depends on the whole frame having been assembled, and the
/// TPUART host protocol appends it as part of transmission.
#[inline(never)]
fn to_extended_wire<const N: usize>(frame: &[u8]) -> WireBuf<N> {
    let mut out = WireBuf::new();
    out.push((frame[0] & 0x0C) | 0x30).expect("extended control fits");
    out.push(frame[5]).expect("extended control field fits");
    out.extend_from_slice(&frame[1..5]).expect("extended address fields fit");
    out.push((frame.len() - 7) as u8).expect("extended length fits");
    out.extend_from_slice(&frame[6..]).expect("extended TPDU fits");
    out
}

pub fn to_wire<const N: usize>(frame: &[u8]) -> WireBuf<N> {
    debug_assert!(frame.len() >= 7, "to_wire: frame too short (len={})", frame.len());
    // Only a profile that admits extended frames can produce one. The
    // capacity half is compile-time known, so a standard-only profile drops
    // this branch and the separate encoder — including its bounds checks and
    // panic strings — at link time.
    if is_extended(N) && (frame.len() > MAX_FRAME || frame[0] & 0x80 == 0) {
        return to_extended_wire(frame);
    }
    let mut out = WireBuf::new();
    let _ = out.extend_from_slice(frame);
    // The length the wire carries is the APDU octet count — everything past
    // the seven header octets — and the control octet keeps only its
    // priority bits over the standard-frame base.
    out[5] = (out[5] & 0xf0) | ((frame.len() - 7) as u8);
    out[0] = (out[0] & 0x0c) | TP1_STD_CTRL_BASE;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire bytes of a group write: 1.1.1 -> 1/0/1, low priority,
    /// `A_GroupValue_Write` with value 1.
    const GROUP_WRITE_WIRE: &[u8] = &[0xBC, 0x11, 0x01, 0x08, 0x01, 0xE1, 0x00, 0x81];

    #[test]
    fn parses_a_group_write() {
        let canonical = normalize::<MAX_FRAME>(GROUP_WRITE_WIRE).expect("valid standard frame");
        let view = FrameView::parse(&canonical).expect("parsable");
        assert!(view.is_group);
        assert_eq!(view.tpci(), Some(Tpci::DataGroup));
        assert_eq!(view.apci(), Some(ApciCode::GroupValueWrite.wire10_base() | 0x01));
        assert_eq!(view.hop_count, 6);
        assert_eq!(view.payload(), &[]);
    }

    #[test]
    fn parses_connect_and_ack() {
        let connect = normalize::<MAX_FRAME>(&[0xB0, 0x00, 0x01, 0x11, 0x0A, 0x60, 0x80]).expect("valid control frame");
        let view = FrameView::parse(&connect).expect("parsable");
        assert!(!view.is_group);
        assert_eq!(view.tpci(), Some(Tpci::Connect));

        let ack = normalize::<MAX_FRAME>(&[0xB0, 0x00, 0x01, 0x11, 0x0A, 0x60, 0xC6]).expect("valid ack frame");
        let view = FrameView::parse(&ack).expect("parsable");
        assert_eq!(view.tpci(), Some(Tpci::Ack(1)));
    }

    #[test]
    fn rejects_wrong_transport_pdu_lengths() {
        let malformed_ack =
            normalize::<MAX_FRAME>(&[0xB0, 0x00, 0x01, 0x11, 0x0A, 0x61, 0xC6, 0x11]).expect("wire length agrees");
        assert_eq!(FrameView::parse(&malformed_ack).expect("canonical frame").tpci(), None);

        let truncated_data =
            normalize::<MAX_FRAME>(&[0xB0, 0x00, 0x01, 0x11, 0x0A, 0x60, 0x40]).expect("wire length agrees");
        assert_eq!(FrameView::parse(&truncated_data).expect("canonical frame").tpci(), None);
    }

    #[test]
    fn normalize_rejects_a_lying_length_octet() {
        // Length says 2 but only one APDU octet follows. Canonically there is
        // no length field left to catch this, so `normalize` is the only place
        // it can be caught — transport layer 2.1 and 2.5 depend on it.
        assert!(normalize::<MAX_FRAME>(&[0xBC, 0x11, 0x01, 0x08, 0x01, 0xE2, 0x00, 0x81]).is_none());
        // And the other direction: more octets than declared.
        assert!(normalize::<MAX_FRAME>(&[0xBC, 0x11, 0x01, 0x08, 0x01, 0xE1, 0x00, 0x81, 0x99]).is_none());
    }

    #[test]
    fn normalize_rejects_runts_and_extended_frames() {
        assert!(normalize::<MAX_FRAME>(&[0xBC, 0x11, 0x01, 0x08]).is_none(), "shorter than a frame can be");
        // Control bit 7 clear marks an extended frame; no profile here is
        // sized for one yet, so it must be refused rather than truncated.
        assert!(normalize::<MAX_FRAME>(&[0x3C, 0xE0, 0x11, 0x01, 0x08, 0x01, 0x01, 0x00, 0x81]).is_none());
    }

    #[test]
    fn normalize_and_to_wire_are_inverse_for_standard_frames() {
        let canonical = normalize::<MAX_FRAME>(GROUP_WRITE_WIRE).expect("valid standard frame");
        // Canonically the length nibble is gone; the APDU length is the
        // buffer length instead.
        assert_eq!(canonical[5] & 0x0F, 0);
        assert_eq!(canonical.len(), GROUP_WRITE_WIRE.len());
        assert_eq!(&to_wire::<MAX_FRAME>(&canonical)[..], GROUP_WRITE_WIRE);
    }

    #[test]
    fn builds_a_numbered_memory_response() {
        // Device 1.1.10 answers a memory read: seq 2, 3 bytes @ 0116h.
        let frame = data_frame::<MAX_FRAME>(
            0x00,
            IndividualAddress::new(1, 1, 10),
            IndividualAddress::new(0, 0, 1).0,
            false,
            Tpci::DataConnected(2),
            ApciCode::MemoryReadResponse,
            3,
            &[0x01, 0x16, 0xAA, 0xBB, 0xCC],
        );
        // The builder produces the canonical layout — length nibble clear …
        assert_eq!(frame[5], 0x60);
        // … and the wire conversion is what puts the length back on.
        assert_eq!(to_wire::<MAX_FRAME>(&frame).as_slice(), &[
            0xB0, 0x11, 0x0A, 0x00, 0x01, 0x66, 0x4A, 0x43, 0x01, 0x16, 0xAA, 0xBB, 0xCC
        ]);
    }

    #[test]
    fn escaped_apci_lands_in_both_octets() {
        // A_PropertyValue_Response (3D6h): octet 6 low bits 11, octet 7 D6h.
        let frame = data_frame::<MAX_FRAME>(
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

    // ------------------------------------------------------------------
    // Extended frames — only a profile that advertises a large APDU
    // ------------------------------------------------------------------

    /// A canonical frame with a 20-octet APDU: too long for the standard
    /// length nibble, so the wire form must be extended.
    fn long_canonical() -> FrameBuf<EXTENDED_FRAME> {
        let mut f: FrameBuf<EXTENDED_FRAME> = FrameBuf::new();
        f.extend_from_slice(&[0xBC, 0x11, 0x01, 0x08, 0x01, 0x60, 0x43]).expect("header fits");
        for i in 0..20u8 {
            f.push(i).expect("payload fits");
        }
        f
    }

    #[test]
    fn a_long_apdu_goes_out_as_an_extended_frame() {
        let canonical = long_canonical();
        let wire = to_wire::<EXTENDED_FRAME>(&canonical);
        // Control bit 7 clear marks extended, and the frame grew by the
        // extended control octet.
        assert_eq!(wire[0] & 0x80, 0);
        assert_eq!(wire.len(), canonical.len() + 1);
        // Octet 6 carries the full length rather than a nibble.
        assert_eq!(wire[6] as usize, canonical.len() - 7);
    }

    #[test]
    fn extended_frames_round_trip_through_the_boundary() {
        let canonical = long_canonical();
        let wire = to_wire::<EXTENDED_FRAME>(&canonical);
        let back = normalize::<EXTENDED_FRAME>(&wire).expect("our own frame is well-formed");
        // Octet 0's frame-type bits are the encoder's business; everything
        // that carries meaning survives.
        assert_eq!(&back[1..], &canonical[1..]);
    }

    #[test]
    fn a_short_apdu_still_goes_out_standard_on_an_extended_profile() {
        // A device that *can* send extended frames still sends short ones
        // the ordinary way — anything else would be a wire regression for
        // every peer on the line.
        let canonical = normalize::<EXTENDED_FRAME>(GROUP_WRITE_WIRE).expect("valid");
        let wire = to_wire::<EXTENDED_FRAME>(&canonical);
        assert_eq!(&wire[..], GROUP_WRITE_WIRE);
    }

    #[test]
    fn a_short_apdu_can_explicitly_use_the_extended_wire_form() {
        let mut canonical = normalize::<EXTENDED_FRAME>(GROUP_WRITE_WIRE).expect("valid");
        force_extended(&mut canonical);
        let wire = to_wire::<EXTENDED_FRAME>(&canonical);
        assert_eq!(wire[0] & 0x80, 0);
        assert_eq!(wire[1], 0xE0, "the ordinary AT and hop-count field becomes the extended control");
        assert_eq!(wire.len(), canonical.len() + 1);
        assert_eq!(normalize::<EXTENDED_FRAME>(&wire).expect("forced frame round trips")[1..], canonical[1..]);
    }

    #[test]
    fn a_standard_only_profile_refuses_extended_frames() {
        let wide = to_wire::<EXTENDED_FRAME>(&long_canonical());
        assert!(normalize::<MAX_FRAME>(&wide).is_none());
    }

    #[test]
    fn normalize_rejects_a_lying_extended_length_octet() {
        let mut wire = to_wire::<EXTENDED_FRAME>(&long_canonical());
        wire[6] = wire[6].wrapping_add(1);
        assert!(normalize::<EXTENDED_FRAME>(&wire).is_none());
    }
}
