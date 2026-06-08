//! KNX-RF (Radio Frequency) data-link frame-field codec.
//!
//! This module converts between a **CRC-stripped KNX-RF telegram** (the on-air
//! byte stream after the physical layer has removed Manchester coding and the
//! per-block FT3 CRCs) and the stack's internal `KnxMessageBuffer` layout — the
//! same 6-byte-header format produced by [`super::tp1`] and consumed by the
//! network / transport / application layers.
//!
//! It deliberately does **not** touch Manchester coding, block CRCs, preamble,
//! or the SX1211 — those live in the `knxrf` physical-layer crate. The boundary
//! is the contiguous telegram whose first octet is the length field.
//!
//! Scope: **KNX RF Ready asynchronous Standard Telegrams** (KNX 03/02/05
//! §6.1.2.4–6.1.2.5). LTE-extended frames, RF Multi, and BiBat are out of scope.
//!
//! # Frame layout
//!
//! The two relevant blocks of an RF Standard Telegram (CRCs already stripped):
//!
//! ```text
//! Block 1 (first block, 10 octets):
//!   [0]  Length     total user octets from the C-field, excluding CRCs
//!   [1]  C = 0x44   IEC 870-5 SEND/NO-REPLY
//!   [2]  Esc = 0xFF fixed start delimiter
//!   [3]  RF-info    bit0 = Unidir, bit1 = Battery-OK, bits3:2 = RSSI, bit7 = RouteLast
//!   [4..10] SN/DoA  6-octet KNX Serial Number (AET=0) or RF Domain Address (AET=1)
//!
//! Block 2 (Standard Telegram, ≤16 octets):
//!   [10] KNX Ctrl   bits7:4 = frame-type (ffff), bits3:0 = EFF (0000 = standard)
//!   [11..13] SA     source Individual Address
//!   [13..15] DA     destination Group / Individual / broadcast address
//!   [15] LPCI-1     bit7 = AT, bits6:4 = RC, bits3:1 = LFN, bit0 = AET
//!   [16] LPCI-2     bits7:6 = TPCI, bits5:2 = Seq.number, bits1:0 = APCI(hi)
//!   [17] APCI       APCI(lo)
//!   [18..] data
//! ```
//!
//! # Internal layout
//!
//! ```text
//!   [0] CTRL  [1..3] SRC  [3..5] DST  [5] NPDU(AT/HC/EFF)  [6] TPCI  [7] APCI  [8..] data
//! ```
//!
//! The mapping is mechanical: SA/DA copy straight across; the on-air LPCI-1 is
//! split (AT → NPDU bit7, AET → routed to metadata/CTRL system-broadcast bit, RC
//! and LFN → metadata); TPCI/APCI/data copy from octet 16 onward unchanged. The
//! `KNX Ctrl` octet contributes only its EFF nibble to NPDU.

// ================================================================================
// Telegram field offsets and bit masks
// ================================================================================

/// Index of the IEC length octet (block 1, octet 1).
pub const LEN_IDX: usize = 0;
/// Index and required value of the C-field (block 1, octet 2).
pub const C_FIELD_IDX: usize = 1;
/// IEC 870-5 C-field used by KNX: SEND / NO REPLY.
pub const C_FIELD: u8 = 0x44;
/// Index and required value of the Esc / start-delimiter octet (block 1, octet 3).
pub const ESC_IDX: usize = 2;
/// Fixed start-delimiter value.
pub const ESC: u8 = 0xFF;
/// Index of the RF-info octet (block 1, octet 4).
pub const RF_INFO1_IDX: usize = 3;
/// Index of the 6-octet SN/DoA field (block 1, octets 5–10).
pub const SN_DOA_IDX: usize = 4;
/// Length of the SN/DoA field.
pub const SN_DOA_LEN: usize = 6;
/// Total length of the first block (length .. SN/DoA), before its CRC.
pub const BLOCK1_LEN: usize = 10;
/// Index of the KNX-Ctrl octet (block 2, octet 1).
pub const KNX_CTRL_IDX: usize = 10;
/// Index of the source address (block 2, octets 2–3).
pub const SA_IDX: usize = 11;
/// Index of the destination address (block 2, octets 4–5).
pub const DA_IDX: usize = 13;
/// Index of the first LPCI octet (block 2, octet 6).
pub const LPCI1_IDX: usize = 15;
/// Index of the block-2 payload (TPCI/APCI/data; block 2, octet 7 onward).
pub const BLOCK2_PAYLOAD_IDX: usize = 16;

/// Octets a CRC-stripped telegram carries on top of its APDU: the 16-octet RF
/// block-1 + block-2 link header up to and including LPCI-1
/// ([`BLOCK2_PAYLOAD_IDX`]) plus the TPCI octet (the APDU/NPDU length-field
/// value counts from *after* the TPCI). So `telegram_len = APDU + this`, and the
/// largest APDU a buffer of size `N` can frame is `N - this`.
pub const TELEGRAM_HEADER_OVERHEAD: usize = BLOCK2_PAYLOAD_IDX + 1;

/// Largest CRC-stripped telegram [`knx_message_to_rf`] produces for an internal
/// frame carrying an APDU of `max_apdu_length` octets (the NPDU length-field /
/// PID 56 `MAX_APDU_LENGTH` value, spec 03/05/01 §4.3.7). Size the RF link
/// layer's frame buffers to this so legal frames never hit
/// [`RfError::BufferTooSmall`].
///
/// This mirrors [`crate::config::max_outgoing_msg_len`]: the internal `msg_len`
/// for that APDU is `INT_PAYLOAD + 1 + apdu`; the telegram swaps the 6-octet
/// internal header (`INT_PAYLOAD`) for the 16-octet RF link header
/// ([`BLOCK2_PAYLOAD_IDX`]), which is exactly [`TELEGRAM_HEADER_OVERHEAD`] above
/// the APDU. (Cross-checked against the captured frame: `max_telegram_len(3)` ==
/// `CAPTURED.len()` == 20.)
pub const fn max_telegram_len(max_apdu_length: u16) -> usize {
    TELEGRAM_HEADER_OVERHEAD + max_apdu_length as usize
}

/// RF-info octet: frame sent by a unidirectional device.
pub const RF_INFO1_UNIDIR: u8 = 0x01;
/// RF-info octet: battery state OK (0 = weak).
pub const RF_INFO1_BATTERY_OK: u8 = 0x02;

/// LPCI-1: Address Type — 1 = Group, 0 = Individual (block-2 destination kind).
pub const LPCI1_AT: u8 = 0x80;
/// LPCI-1: Repetition counter field mask (bits 6:4).
pub const LPCI1_RC_MASK: u8 = 0x70;
/// LPCI-1: Repetition counter field shift.
pub const LPCI1_RC_SHIFT: u8 = 4;
/// LPCI-1: Link-layer Frame Number field mask (bits 3:1).
pub const LPCI1_LFN_MASK: u8 = 0x0E;
/// LPCI-1: Link-layer Frame Number field shift.
pub const LPCI1_LFN_SHIFT: u8 = 1;
/// LPCI-1: Address Extension Type — 1 = SN/DoA holds the RF Domain Address.
pub const LPCI1_AET: u8 = 0x01;

// Internal `KnxMessageBuffer` offsets (mirrors `messages::knx::offsets`, kept
// local so the codec reads top-to-bottom without cross-module hopping).
const INT_CTRL: usize = 0;
const INT_SRC: usize = 1;
const INT_DST: usize = 3;
const INT_NPDU: usize = 5;
const INT_PAYLOAD: usize = 6;
/// Minimum internal frame: the 6-octet header plus at least one block-2 payload
/// octet. Transport *control* frames (T_Connect / T_ACK / T_Disconnect) carry
/// only a TPCI octet and no APCI, so the minimum is 7 — not 8.
const INT_MIN_LEN: usize = INT_PAYLOAD + 1;

/// Standard internal control octet for a received L_Data frame (FT=std, low
/// priority, system-broadcast bit set → *not* a system broadcast by default).
/// Mirrors the value a TP1 standard frame carries internally (see [`super::tp1`]).
const INT_CTRL_STANDARD: u8 = 0xBC;
/// System-broadcast bit within the internal CTRL octet. Cleared marks a frame
/// as a *system* broadcast; set marks an installation broadcast / normal frame
/// (see `KnxMessageBuffer::get_address_type`).
const INT_CTRL_SB_BIT: u8 = 0x10;
/// Hop count written into the NPDU of received frames. RF carries no hop count;
/// the reference stack injects 6, which we mirror.
const RX_HOP_COUNT: u8 = 6;

// ================================================================================
// Errors and decoded metadata
// ================================================================================

/// Reasons a telegram could not be decoded into / encoded from the internal format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RfError {
    /// The telegram is shorter than its own length field claims, or too short
    /// to contain a full Standard-Telegram header.
    TooShort,
    /// The C-field was not `0x44`.
    BadCField,
    /// The Esc / start-delimiter octet was not `0xFF`.
    BadEsc,
    /// The destination buffer cannot hold the converted frame.
    BufferTooSmall,
}

/// Link-layer metadata extracted from a received RF telegram. The link layer
/// uses this for Domain-Address acceptance and LFN duplicate suppression; the
/// converted internal frame itself does not carry these fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RfRxMeta {
    /// Number of bytes written to the internal-format output buffer.
    pub internal_len: usize,
    /// The 6-octet SN/DoA field from block 1 (interpretation depends on `aet`).
    pub sn_or_doa: [u8; SN_DOA_LEN],
    /// Address Extension Type: `true` ⇒ `sn_or_doa` is the RF Domain Address,
    /// `false` ⇒ it is the sender's KNX Serial Number.
    pub aet: bool,
    /// Link-layer Frame Number (0–7), for duplicate suppression.
    pub lfn: u8,
    /// Repetition counter from the LPCI.
    pub rc: u8,
    /// Frame sent by a unidirectional device.
    pub unidir: bool,
    /// Battery state OK (`false` ⇒ weak).
    pub battery_ok: bool,
    /// Frame-type nibble (`ffff`) from the KNX-Ctrl octet — `0x0`, `0x8`, `0x9`
    /// for async Standard data; other values indicate non-RF-Ready frames.
    pub frame_type: u8,
}

// ================================================================================
// Reception: RF telegram → internal KNX message
// ================================================================================

/// Decode a CRC-stripped RF Standard Telegram into the internal `KnxMessageBuffer`
/// layout, writing the result into `out` and returning the extracted metadata.
///
/// Structural validation only (C-field, Esc, lengths); frame-type *acceptance*
/// (RF-Ready async vs. BiBat/RF-Multi) and Domain-Address filtering are policy
/// decisions left to the link layer, which reads them from the returned
/// [`RfRxMeta`].
pub fn rf_to_knx_message(telegram: &[u8], out: &mut [u8]) -> Result<RfRxMeta, RfError> {
    // The length octet counts everything from the C-field to the last data
    // octet (CRCs excluded), so the contiguous telegram spans `length + 1`
    // octets. Anything shorter than that — or shorter than a full header — is
    // malformed.
    if telegram.len() <= LEN_IDX {
        return Err(RfError::TooShort);
    }
    let useful_len = telegram[LEN_IDX] as usize + 1;
    // Need the full block-2 header (through LPCI-1) plus at least one payload
    // octet (the TPCI of a transport control frame).
    if telegram.len() < useful_len || useful_len <= BLOCK2_PAYLOAD_IDX {
        return Err(RfError::TooShort);
    }
    if telegram[C_FIELD_IDX] != C_FIELD {
        return Err(RfError::BadCField);
    }
    if telegram[ESC_IDX] != ESC {
        return Err(RfError::BadEsc);
    }

    // The block-2 payload (TPCI/APCI/data) starts right after LPCI-1 and runs to
    // the end of the useful telegram. The internal frame is that payload plus a
    // 6-octet header we synthesise from the addresses and the split LPCI.
    let payload = &telegram[BLOCK2_PAYLOAD_IDX..useful_len];
    let internal_len = INT_PAYLOAD + payload.len();
    if out.len() < internal_len {
        return Err(RfError::BufferTooSmall);
    }

    let rf_info1 = telegram[RF_INFO1_IDX];
    let lpci1 = telegram[LPCI1_IDX];
    let aet = (lpci1 & LPCI1_AET) != 0;

    // CTRL: start from the standard value, then encode the system-broadcast
    // distinction. Per spec an AET=0 frame to DA=0000h is a *system* broadcast
    // (cross-installation); the internal format marks that by *clearing* the SB
    // bit. AET=1 / non-broadcast frames keep the bit set.
    let dest_is_zero = telegram[DA_IDX] == 0 && telegram[DA_IDX + 1] == 0;
    let mut ctrl = INT_CTRL_STANDARD;
    if !aet && dest_is_zero {
        ctrl &= !INT_CTRL_SB_BIT;
    }
    out[INT_CTRL] = ctrl;

    // Source and destination copy straight across.
    out[INT_SRC] = telegram[SA_IDX];
    out[INT_SRC + 1] = telegram[SA_IDX + 1];
    out[INT_DST] = telegram[DA_IDX];
    out[INT_DST + 1] = telegram[DA_IDX + 1];

    // NPDU = Address Type (LPCI-1 bit7) | injected hop count | EFF (KNX-Ctrl low
    // nibble). RF carries no hop count, so we inject a fixed value.
    let at = lpci1 & LPCI1_AT;
    let eff = telegram[KNX_CTRL_IDX] & 0x0F;
    out[INT_NPDU] = at | (RX_HOP_COUNT << 4) | eff;

    // TPCI / APCI / data copy verbatim.
    out[INT_PAYLOAD..internal_len].copy_from_slice(payload);

    let mut sn_or_doa = [0u8; SN_DOA_LEN];
    sn_or_doa.copy_from_slice(&telegram[SN_DOA_IDX..SN_DOA_IDX + SN_DOA_LEN]);

    Ok(RfRxMeta {
        internal_len,
        sn_or_doa,
        aet,
        lfn: (lpci1 & LPCI1_LFN_MASK) >> LPCI1_LFN_SHIFT,
        rc: (lpci1 & LPCI1_RC_MASK) >> LPCI1_RC_SHIFT,
        unidir: (rf_info1 & RF_INFO1_UNIDIR) != 0,
        battery_ok: (rf_info1 & RF_INFO1_BATTERY_OK) != 0,
        frame_type: telegram[KNX_CTRL_IDX] >> 4,
    })
}

// ================================================================================
// Transmission: internal KNX message → RF telegram
// ================================================================================

/// Encode an internal KNX message into a CRC-stripped RF Standard Telegram,
/// writing the result into `out` and returning the number of octets written.
///
/// The caller supplies the link-layer fields the internal frame does not carry:
/// - `block1_addr`: the 6-octet SN/DoA to place in block 1 (the device's RF
///   Domain Address when `aet`, else its KNX Serial Number — chosen by the link
///   layer per KNX 03/02/05 §6.1.5.1).
/// - `aet`: Address Extension Type to advertise in the LPCI.
/// - `lfn`: Link-layer Frame Number (low 3 bits used).
/// - `rc`: Repetition counter (low 3 bits used; 6 for RF-Ready end devices).
/// - `unidir`: set if this device is unidirectional (clears the bidir flag).
pub fn knx_message_to_rf(
    msg: &[u8],
    block1_addr: &[u8; SN_DOA_LEN],
    aet: bool,
    lfn: u8,
    rc: u8,
    unidir: bool,
    out: &mut [u8],
) -> Result<usize, RfError> {
    if msg.len() < INT_MIN_LEN {
        return Err(RfError::TooShort);
    }

    // The block-2 payload (TPCI/APCI/data) is the internal frame minus its
    // 6-octet header. The telegram is that payload plus the 10-octet first block
    // and the 6-octet block-2 header (KNX-Ctrl, SA, DA, LPCI-1).
    let payload = &msg[INT_PAYLOAD..];
    let telegram_len = BLOCK2_PAYLOAD_IDX + payload.len();
    if out.len() < telegram_len {
        return Err(RfError::BufferTooSmall);
    }

    // Block 1.
    out[LEN_IDX] = (telegram_len - 1) as u8; // octets from the C-field, CRCs excluded
    out[C_FIELD_IDX] = C_FIELD;
    out[ESC_IDX] = ESC;
    out[RF_INFO1_IDX] = RF_INFO1_BATTERY_OK | if unidir { RF_INFO1_UNIDIR } else { 0 };
    out[SN_DOA_IDX..SN_DOA_IDX + SN_DOA_LEN].copy_from_slice(block1_addr);

    // Block 2 header. KNX-Ctrl carries only the EFF nibble for async Standard
    // frames (frame-type nibble = 0000).
    out[KNX_CTRL_IDX] = msg[INT_NPDU] & 0x0F;
    out[SA_IDX] = msg[INT_SRC];
    out[SA_IDX + 1] = msg[INT_SRC + 1];
    out[DA_IDX] = msg[INT_DST];
    out[DA_IDX + 1] = msg[INT_DST + 1];
    out[LPCI1_IDX] = (msg[INT_NPDU] & LPCI1_AT)
        | ((rc << LPCI1_RC_SHIFT) & LPCI1_RC_MASK)
        | ((lfn << LPCI1_LFN_SHIFT) & LPCI1_LFN_MASK)
        | if aet { LPCI1_AET } else { 0 };

    // TPCI / APCI / data copy verbatim.
    out[BLOCK2_PAYLOAD_IDX..telegram_len].copy_from_slice(payload);

    Ok(telegram_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck_macros::quickcheck;

    /// A real KNX-RF frame captured by the SX1211 playground: a GroupValueWrite
    /// of a DPT 9.001 temperature, domain-addressed (AET=1), LFN=1, RC=6.
    const CAPTURED: [u8; 20] = [
        0x13, 0x44, 0xff, 0x02, 0x00, 0xfa, 0xb6, 0xab, 0xb2, 0x86, 0x00, 0x12, 0x01, 0x01, 0x00, 0xe3, 0x00, 0x80,
        0x0c, 0xc4,
    ];

    #[test]
    fn decode_captured_frame() {
        let mut out = [0u8; 32];
        let meta = rf_to_knx_message(&CAPTURED, &mut out).expect("captured frame decodes");

        // Metadata extracted from block 1 + LPCI-1 (0xe3 = AT|RC6|LFN1|AET).
        assert_eq!(meta.sn_or_doa, [0x00, 0xfa, 0xb6, 0xab, 0xb2, 0x86]);
        assert!(meta.aet, "AET bit set ⇒ domain address");
        assert_eq!(meta.lfn, 1);
        assert_eq!(meta.rc, 6);
        assert!(!meta.unidir, "RF-info 0x02 ⇒ bidirectional");
        assert!(meta.battery_ok);
        assert_eq!(meta.frame_type, 0x0, "async Standard data frame");

        // Internal frame: CTRL, 1.2.1 → group 0x0100, GroupValueWrite, temp.
        let frame = &out[..meta.internal_len];
        assert_eq!(frame, &[0xBC, 0x12, 0x01, 0x01, 0x00, 0xe0, 0x00, 0x80, 0x0c, 0xc4]);
    }

    #[test]
    fn max_telegram_len_matches_captured_frame() {
        // The captured frame decodes to a 10-octet internal frame, i.e. an APDU
        // of 3 (internal_len = INT_PAYLOAD + 1 + apdu = 6 + 1 + 3). Its on-air
        // telegram is therefore the maximum for a 3-octet APDU.
        assert_eq!(max_telegram_len(3), CAPTURED.len());
        // The buffer-sizing identity the RF link layer relies on: the telegram
        // for a given APDU is the internal frame for that APDU with the 6-octet
        // header swapped for the 16-octet RF link header (a net +10 octets).
        assert_eq!(max_telegram_len(55), INT_PAYLOAD + 1 + 55 + (BLOCK2_PAYLOAD_IDX - INT_PAYLOAD));
    }

    #[test]
    fn encode_reproduces_captured_frame() {
        // Re-encode the internal frame the captured telegram decodes to, with the
        // same link-layer fields, and expect the original on-air bytes back.
        let internal = [0xBCu8, 0x12, 0x01, 0x01, 0x00, 0xe0, 0x00, 0x80, 0x0c, 0xc4];
        let doa = [0x00, 0xfa, 0xb6, 0xab, 0xb2, 0x86];
        let mut out = [0u8; 32];
        let n = knx_message_to_rf(&internal, &doa, true, 1, 6, false, &mut out).expect("internal frame encodes");
        assert_eq!(&out[..n], &CAPTURED);
    }

    #[test]
    fn system_broadcast_clears_sb_bit() {
        // AET=0 to DA=0000h is a system broadcast: the internal CTRL SB bit (0x10)
        // must be cleared so the stack classifies it as SystemBroadcast.
        let mut tel = CAPTURED;
        tel[LPCI1_IDX] &= !LPCI1_AET; // AET = 0
        tel[DA_IDX] = 0x00;
        tel[DA_IDX + 1] = 0x00;
        let mut out = [0u8; 32];
        let meta = rf_to_knx_message(&tel, &mut out).unwrap();
        assert!(!meta.aet);
        assert_eq!(out[INT_CTRL] & INT_CTRL_SB_BIT, 0, "SB bit cleared for system broadcast");

        // AET=1 to DA=0000h is an installation broadcast: SB bit stays set.
        let mut tel2 = CAPTURED;
        tel2[DA_IDX] = 0x00;
        tel2[DA_IDX + 1] = 0x00;
        let meta2 = rf_to_knx_message(&tel2, &mut out).unwrap();
        assert!(meta2.aet);
        assert_ne!(out[INT_CTRL] & INT_CTRL_SB_BIT, 0, "SB bit set for installation broadcast");
    }

    #[test]
    fn transport_control_frame_roundtrips() {
        // A 7-octet transport control frame (T_ACK to 1.0.3): 6-octet header +
        // a single TPCI octet, no APCI. Regression for "frame encode failed:
        // TooShort" when ETS opens a connection-oriented download.
        let internal = [0xB0u8, 0x12, 0x03, 0x10, 0x03, 0x60, 0xC2];
        let doa = [0x00, 0xfa, 0xb6, 0xab, 0xb2, 0x86];
        let mut wire = [0u8; 32];
        let n =
            knx_message_to_rf(&internal, &doa, true, 1, 6, false, &mut wire).expect("7-octet control frame encodes");

        let mut decoded = [0u8; 32];
        let meta = rf_to_knx_message(&wire[..n], &mut decoded).expect("control frame decodes");
        assert_eq!(meta.internal_len, internal.len(), "7-octet control frame preserved end to end");
        // CTRL is synthesised on RX (RF standard frames carry no priority field);
        // the addresses, NPDU and the lone TPCI octet round-trip intact.
        assert_eq!(&decoded[1..meta.internal_len], &internal[1..]);
    }

    #[test]
    fn rejects_bad_c_field_and_esc() {
        let mut out = [0u8; 32];
        let mut bad_c = CAPTURED;
        bad_c[C_FIELD_IDX] = 0x00;
        assert_eq!(rf_to_knx_message(&bad_c, &mut out), Err(RfError::BadCField));

        let mut bad_esc = CAPTURED;
        bad_esc[ESC_IDX] = 0x00;
        assert_eq!(rf_to_knx_message(&bad_esc, &mut out), Err(RfError::BadEsc));
    }

    #[test]
    fn rejects_truncated_and_too_short_buffers() {
        let mut out = [0u8; 32];
        // Length field claims more than the slice holds.
        assert_eq!(rf_to_knx_message(&CAPTURED[..10], &mut out), Err(RfError::TooShort));
        // Output buffer too small.
        let mut tiny = [0u8; 4];
        assert_eq!(rf_to_knx_message(&CAPTURED, &mut tiny), Err(RfError::BufferTooSmall));
    }

    /// Round-trip: any well-formed internal frame survives encode → decode with
    /// its addresses, payload, and the chosen link-layer fields intact.
    #[quickcheck]
    fn roundtrip_internal_frame(
        src: u16,
        dst: u16,
        flags: u8,
        payload: Vec<u8>,
        doa_seed: u64,
        lfn: u8,
        rc: u8,
    ) -> bool {
        // quickcheck caps function arity and lacks `Arbitrary` for `[u8; 6]`, so
        // pack the booleans into `flags` and derive the DoA from a seed.
        let group = flags & 0x01 != 0;
        let aet = flags & 0x02 != 0;
        let unidir = flags & 0x04 != 0;
        let s = doa_seed.to_le_bytes();
        let doa = [s[0], s[1], s[2], s[3], s[4], s[5]];
        // Build a plausible internal frame: at least TPCI+APCI, bounded payload.
        let mut tpci_apci_data = payload;
        tpci_apci_data.truncate(40);
        while tpci_apci_data.len() < 2 {
            tpci_apci_data.push(0);
        }
        let at = if group { 0x80 } else { 0x00 };
        // NPDU = AT | hop count | EFF; keep EFF=0 (standard) for the round trip.
        let npdu = at | (RX_HOP_COUNT << 4);
        // The CTRL system-broadcast bit is conveyed on the wire via AET (TX
        // ignores CTRL; RX reconstructs it). Pre-apply the same rule the decoder
        // uses so encode→decode is a true fixpoint.
        let mut ctrl = INT_CTRL_STANDARD;
        if !aet && dst == 0 {
            ctrl &= !INT_CTRL_SB_BIT;
        }
        let mut internal = vec![ctrl, (src >> 8) as u8, src as u8, (dst >> 8) as u8, dst as u8, npdu];
        internal.extend_from_slice(&tpci_apci_data);

        let mut wire = [0u8; 96];
        let n = match knx_message_to_rf(&internal, &doa, aet, lfn, rc, unidir, &mut wire) {
            Ok(n) => n,
            Err(_) => return true, // oversized payloads legitimately reject
        };

        let mut decoded = [0u8; 96];
        let meta = match rf_to_knx_message(&wire[..n], &mut decoded) {
            Ok(m) => m,
            Err(_) => return false,
        };

        meta.sn_or_doa == doa
            && meta.aet == aet
            && meta.lfn == (lfn & 0x07)
            && meta.rc == (rc & 0x07)
            && meta.unidir == unidir
            && decoded[..meta.internal_len] == internal[..]
    }
}
