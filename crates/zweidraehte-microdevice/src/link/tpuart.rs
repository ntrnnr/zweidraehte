//! Sync TPUART driver: bytes from the UART ISR ring in, whole TP1
//! frames (checksum-stripped) out, plus the byte stream to transmit.
//!
//! Speaks the TPUART-2/NCN51xx host protocol subset a BCU2-class
//! device needs:
//!
//! - reception of standard and profile-enabled extended L_Data frames
//!   with checksum verification and the immediate-acknowledge decision
//!   (`U_AckInformation`)
//! - transmission as `U_L_DataStart/Continue/End`-wrapped octet pairs,
//!   echo verification, and the `L_Data.confirm` byte
//! - `U_Reset.request` / `Reset.indication` bring-up
//!
//! Everything is polled: the caller feeds one byte at a time from its
//! ISR ring (plus a millisecond timestamp) and writes whatever
//! [`TpUart::pending_tx`] holds to the UART. No interrupts, no
//! executor, no `embassy_time` — timeouts are plain `u32` millisecond
//! arithmetic, following the pure-state-machine design of the async
//! stack's TPUART layer.

use heapless::Vec;
use zweidraehte_proto::encoding::tp1::calculate_tp1_checksum;
use zweidraehte_proto::messages::knx::{Ctrl1Field, Ctrl2Field, FrameType};

use crate::frame;

/// Standard frame plus checksum. This default keeps a plain profile's buffers
/// at the BCU-era limit; extended profiles opt into larger const parameters.
pub const STANDARD_WIRE_CAPACITY: usize = frame::MAX_FRAME + 1;

/// Two host-protocol octets are queued for each frame octet.
pub const STANDARD_TX_CAPACITY: usize = STANDARD_WIRE_CAPACITY * 2;

/// Host→TPUART service codes.
const U_RESET_REQUEST: u8 = 0x01;
const U_ACK_INFORMATION: u8 = 0x10;
const U_L_DATA_START: u8 = 0x80;
const U_L_DATA_END: u8 = 0x40;

/// `U_AckInformation` flags.
const ACK_ADDRESSED: u8 = 0x01;

// Receive-direction classifiers of the host protocol. The chip tags
// what it forwards by the byte's shape: L_Data control fields have bit
// 7 set / bit 6 clear / bits 4, 1..0 fixed, everything else is a
// service code.
/// Control-field pattern of a standard L_Data frame: `10x1 xx00`.
const LDATA_CLASSIFIER_MASK: u8 = 0xD3;
const LDATA_STANDARD_CLASSIFIER: u8 = 0x90;
/// Control-field pattern of an extended L_Data frame: `00x1 xx00`.
const LDATA_EXTENDED_CLASSIFIER: u8 = 0x10;
/// Reset.indication — the chip completed a reset and is ready.
const RESET_INDICATION: u8 = 0x03;
/// L_Data.confirm: `x000 1011`, bit 7 carries success.
const LDATA_CONFIRM_MASK: u8 = 0x7F;
const LDATA_CONFIRM_PATTERN: u8 = 0x0B;
const LDATA_CONFIRM_POSITIVE: u8 = 0x80;

/// Inter-byte gap after which a half-received frame is abandoned.
/// TP1's own gap limit is ~2.6 bit times; 5 ms is generous slack for
/// a polling loop without risking gluing two frames together.
const RX_GAP_MS: u32 = 5;

/// How long a transmission may wait for its echo + confirm before the
/// driver declares it failed (bus busy, collision storm).
const TX_TIMEOUT_MS: u32 = 100;

/// What one received byte produced.
pub enum TpUartEvent<const WIRE_CAP: usize = STANDARD_WIRE_CAPACITY> {
    None,
    /// The chip announced a reset (power-up or `U_Reset.request` done).
    ResetIndication,
    /// A complete, checksum-valid frame addressed to us or not — the
    /// caller's stack does its own address filtering anyway.
    Frame(Vec<u8, WIRE_CAP>),
    /// The pending transmission was confirmed by the chip.
    TxConfirmed {
        positive: bool,
    },
}

enum RxState<const WIRE_CAP: usize> {
    Idle,
    Receiving { buf: Vec<u8, WIRE_CAP>, expected: usize, last_byte_ms: u32, acked: bool },
}

enum TxState<const WIRE_CAP: usize> {
    Idle,
    /// Waiting for our own frame to echo back octet by octet, then the
    /// confirm byte.
    AwaitingEcho {
        frame: Vec<u8, WIRE_CAP>,
        echoed: usize,
        started_ms: u32,
    },
    AwaitingConfirm {
        started_ms: u32,
    },
}

/// The driver borrows its immediate-ACK policy on each byte via
/// [`Self::push_byte`]. The caller can consult live device state without the
/// driver retaining a borrow that would prevent the next stack poll.
///
/// `WIRE_CAP` includes the checksum. `TX_CAP` is normally twice that because
/// every transmitted octet is preceded by a TPUART selector. Both defaults
/// are exact standard-frame bounds, so extended-frame storage only exists in
/// a profile that asks for it.
pub struct TpUart<const WIRE_CAP: usize = STANDARD_WIRE_CAPACITY, const TX_CAP: usize = STANDARD_TX_CAPACITY> {
    rx: RxState<WIRE_CAP>,
    tx: TxState<WIRE_CAP>,
    /// Bytes the caller must write to the UART. Drained by
    /// [`Self::pending_tx`].
    tx_queue: Vec<u8, TX_CAP>,
}

impl TpUart {
    pub fn new() -> Self {
        Self::new_sized()
    }
}

impl<const WIRE_CAP: usize, const TX_CAP: usize> Default for TpUart<WIRE_CAP, TX_CAP> {
    fn default() -> Self {
        Self::new_sized()
    }
}

impl<const WIRE_CAP: usize, const TX_CAP: usize> TpUart<WIRE_CAP, TX_CAP> {
    /// Construct a driver with explicitly selected profile capacities.
    pub fn new_sized() -> Self {
        const { assert!(WIRE_CAP >= STANDARD_WIRE_CAPACITY, "wire buffer must hold a standard frame") };
        const { assert!(TX_CAP >= WIRE_CAP * 2, "TX buffer must hold selector/data pairs") };
        let mut this = Self { rx: RxState::Idle, tx: TxState::Idle, tx_queue: Vec::new() };
        let _ = this.tx_queue.push(U_RESET_REQUEST);
        this
    }

    /// Bytes waiting to go out on the UART. The caller transmits them
    /// (blocking or IRQ-driven) and then calls [`Self::clear_tx`].
    pub fn pending_tx(&self) -> &[u8] {
        &self.tx_queue
    }

    pub fn clear_tx(&mut self) {
        self.tx_queue.clear();
    }

    /// Whether a new frame transmission can be queued.
    pub fn ready_to_send(&self) -> bool {
        matches!(self.tx, TxState::Idle) && self.tx_queue.is_empty()
    }

    /// Queue one TP1 frame (without checksum) for transmission,
    /// wrapped in the `U_L_DataStart/Continue/End` octet pairs.
    pub fn send_frame(&mut self, frame: &[u8], now_ms: u32) -> bool {
        if !self.ready_to_send() || frame.len() + 1 > WIRE_CAP {
            return false;
        }
        let mut wire: Vec<u8, WIRE_CAP> = Vec::new();
        let _ = wire.extend_from_slice(frame);
        let _ = wire.push(calculate_tp1_checksum(frame));
        for (i, &byte) in wire.iter().enumerate() {
            let selector = if i + 1 == wire.len() {
                // The last octet rides with U_L_DataEnd carrying the
                // total length index.
                U_L_DATA_END | (i as u8 & 0x3F)
            } else {
                U_L_DATA_START | (i as u8 & 0x3F)
            };
            let _ = self.tx_queue.push(selector);
            let _ = self.tx_queue.push(byte);
        }
        self.tx = TxState::AwaitingEcho { frame: wire, echoed: 0, started_ms: now_ms };
        true
    }

    /// Call periodically with no byte: abandons stuck receptions and
    /// times out lost transmissions. Returns a synthetic negative
    /// confirm when a transmission died.
    pub fn poll_timer(&mut self, now_ms: u32) -> TpUartEvent<WIRE_CAP> {
        if let RxState::Receiving { last_byte_ms, .. } = &self.rx
            && now_ms.wrapping_sub(*last_byte_ms) > RX_GAP_MS
        {
            self.rx = RxState::Idle;
        }
        match &self.tx {
            TxState::AwaitingEcho { started_ms, .. } | TxState::AwaitingConfirm { started_ms }
                if now_ms.wrapping_sub(*started_ms) > TX_TIMEOUT_MS =>
            {
                self.tx = TxState::Idle;
                TpUartEvent::TxConfirmed { positive: false }
            }
            _ => TpUartEvent::None,
        }
    }

    /// Feed one byte received from the UART.
    ///
    /// The policy sees the first six raw header octets once the header is
    /// complete, after format/capacity checks and before the checksum arrives.
    /// It must read the current address/table state; it decides ACK only, not
    /// whether a complete frame is delivered. The closure is statically
    /// dispatched and its borrow ends before the caller handles the event.
    pub fn push_byte(
        &mut self,
        byte: u8,
        now_ms: u32,
        should_ack: impl FnOnce(&[u8; 6]) -> bool,
    ) -> TpUartEvent<WIRE_CAP> {
        // While a transmission is on the wire, the chip echoes our own
        // octets back; they must not be mistaken for a new reception.
        if let TxState::AwaitingEcho { frame, echoed, started_ms } = &mut self.tx
            && byte == frame[*echoed]
        {
            *echoed += 1;
            if *echoed == frame.len() {
                self.tx = TxState::AwaitingConfirm { started_ms: *started_ms };
            }
            return TpUartEvent::None;
        }
        // An echo mismatch (collision) falls through to reception: the
        // incoming byte belongs to the winning sender's frame, and the
        // confirm/timeout path reports our failure.

        match &mut self.rx {
            RxState::Idle => self.classify_first_byte(byte, now_ms),
            RxState::Receiving { buf, expected, last_byte_ms, acked } => {
                if now_ms.wrapping_sub(*last_byte_ms) > RX_GAP_MS {
                    // Stale reception — treat this byte as a fresh start.
                    self.rx = RxState::Idle;
                    return self.classify_first_byte(byte, now_ms);
                }
                *last_byte_ms = now_ms;
                let _ = buf.push(byte);

                // The standard header carries its length at octet 5; an
                // extended frame inserts its ECF at octet 1 and carries an
                // eight-bit length at octet 6.
                let extended = WIRE_CAP > STANDARD_WIRE_CAPACITY && Ctrl1Field::new(buf[0]).ft() == FrameType::Extended;
                let header_len = if extended { 7 } else { 6 };
                if buf.len() == header_len {
                    *expected = if extended { 8 + usize::from(buf[6]) + 1 } else { 7 + usize::from(buf[5] & 0x0F) + 1 };
                    if *expected > WIRE_CAP {
                        self.rx = RxState::Idle;
                        return TpUartEvent::None;
                    }
                    // The immediate-ack window: the decision is made on
                    // the header and told to the chip before the frame
                    // ends.
                    // Unknown EFF must receive no link ACK, even if the
                    // destination filter accepts it (03/03/02 §2.2.4).
                    if !*acked
                        && (!extended || Ctrl2Field::new(buf[1]).extended_frame_format() == 0)
                        && should_ack(buf[..6].try_into().expect("complete header"))
                    {
                        *acked = true;
                        let _ = self.tx_queue.push(U_ACK_INFORMATION | ACK_ADDRESSED);
                    }
                }

                if buf.len() >= 6 && buf.len() == *expected {
                    let mut complete = core::mem::replace(buf, Vec::new());
                    self.rx = RxState::Idle;
                    let wire_checksum = complete.pop().expect("complete frame has checksum");
                    if (!extended || Ctrl2Field::new(complete[1]).extended_frame_format() == 0)
                        && wire_checksum == calculate_tp1_checksum(&complete)
                    {
                        return TpUartEvent::Frame(complete);
                    }
                }
                TpUartEvent::None
            }
        }
    }

    fn classify_first_byte(&mut self, byte: u8, now_ms: u32) -> TpUartEvent<WIRE_CAP> {
        let classifier = byte & LDATA_CLASSIFIER_MASK;
        if classifier == LDATA_STANDARD_CLASSIFIER
            || (WIRE_CAP > STANDARD_WIRE_CAPACITY && classifier == LDATA_EXTENDED_CLASSIFIER)
        {
            let mut buf = Vec::new();
            let _ = buf.push(byte);
            self.rx = RxState::Receiving { buf, expected: usize::MAX, last_byte_ms: now_ms, acked: false };
            return TpUartEvent::None;
        }
        match byte {
            RESET_INDICATION => TpUartEvent::ResetIndication,
            b if b & LDATA_CONFIRM_MASK == LDATA_CONFIRM_PATTERN => {
                self.tx = TxState::Idle;
                TpUartEvent::TxConfirmed { positive: b & LDATA_CONFIRM_POSITIVE != 0 }
            }
            // TODO: BCU2 fast polling needs an NCN51xx-capable poll seam.
            // Poll-data indications currently fall through with other
            // unsupported TPUART services.
            // State.indication (xxxxx111) and everything else the
            // chip may volunteer: ignored.
            _ => TpUartEvent::None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zweidraehte_proto::encoding::tp1::extract_header_fields;

    fn addressed(header: &[u8; 6]) -> bool {
        let (hi, lo, group) = extract_header_fields(header);
        !group && [hi, lo] == [0x10, 0x01]
    }

    fn driver() -> TpUart {
        let mut d = TpUart::new();
        d.clear_tx(); // discard the boot U_Reset.request
        d
    }

    #[test]
    fn unknown_formats_are_neither_acknowledged_nor_delivered() {
        const WIRE_CAP: usize = frame::SECURE_EXTENDED_FRAME + 1;
        let mut driver: TpUart<WIRE_CAP, { WIRE_CAP * 2 }> = TpUart::new_sized();
        for eff in (1..16).chain(core::iter::once(0)) {
            driver.clear_tx();
            let wire = [0x3C, 0x60 | eff, 0xAF, 0xFE, 0x10, 0x01, 0x01, 0x03, 0x00];
            let mut delivered = false;
            for byte in wire.into_iter().chain(core::iter::once(calculate_tp1_checksum(&wire))) {
                delivered |= matches!(driver.push_byte(byte, 1, |_| true), TpUartEvent::Frame(_));
            }
            assert_eq!(delivered, eff == 0);
            assert_eq!(driver.pending_tx().is_empty(), eff != 0);
        }
    }

    #[test]
    fn receives_a_checksummed_frame_and_acks() {
        let mut d = driver();
        let frame = [0xBC, 0xAF, 0xFE, 0x10, 0x01, 0x61, 0x43, 0x00];
        let mut result = None;
        for (i, &b) in frame.iter().enumerate() {
            match d.push_byte(b, i as u32, addressed) {
                TpUartEvent::Frame(f) => result = Some(f),
                TpUartEvent::None => {}
                _ => panic!("unexpected event"),
            }
        }
        assert!(result.is_none(), "checksum still outstanding");
        // The ack decision fired on the header.
        assert_eq!(d.pending_tx(), &[U_ACK_INFORMATION | ACK_ADDRESSED]);
        let TpUartEvent::Frame(f) = d.push_byte(calculate_tp1_checksum(&frame), 8, addressed) else {
            panic!("frame must complete on its checksum octet");
        };
        assert_eq!(f.as_slice(), &frame);
    }

    #[test]
    fn bad_checksum_drops_the_frame() {
        let mut d = driver();
        let frame = [0xBC, 0xAF, 0xFE, 0x10, 0x01, 0x61, 0x43, 0x00];
        for (i, &b) in frame.iter().enumerate() {
            d.push_byte(b, i as u32, addressed);
        }
        assert!(matches!(d.push_byte(0x00, 8, addressed), TpUartEvent::None));
    }

    #[test]
    fn transmission_wraps_echoes_and_confirms() {
        let mut d = driver();
        let frame = [0xB0, 0x10, 0x01, 0xAF, 0xFE, 0x60, 0xC2];
        assert!(d.send_frame(&frame, 0));
        // Octet pairs: selector + data, ending with U_L_DataEnd.
        let tx = d.pending_tx().to_vec();
        assert_eq!(tx.len(), (frame.len() + 1) * 2);
        assert_eq!(tx[0], U_L_DATA_START);
        assert_eq!(tx[1], 0xB0);
        assert_eq!(tx[tx.len() - 2], U_L_DATA_END | 7);
        assert_eq!(tx[tx.len() - 1], calculate_tp1_checksum(&frame));
        d.clear_tx();
        assert!(!d.ready_to_send(), "busy until confirmed");

        // The chip echoes the frame, then confirms.
        for &b in frame.iter() {
            assert!(matches!(d.push_byte(b, 1, addressed), TpUartEvent::None));
        }
        assert!(matches!(d.push_byte(calculate_tp1_checksum(&frame), 1, addressed), TpUartEvent::None));
        let TpUartEvent::TxConfirmed { positive: true } = d.push_byte(0x8B, 2, addressed) else {
            panic!("positive confirm expected");
        };
        assert!(d.ready_to_send());
    }

    #[test]
    fn extended_frames_use_profile_sized_receive_and_transmit_buffers() {
        const WIRE_CAP: usize = frame::SECURE_EXTENDED_FRAME + 1;
        const TX_CAP: usize = WIRE_CAP * 2;

        let mut d: TpUart<WIRE_CAP, TX_CAP> = TpUart::new_sized();
        d.clear_tx();

        // Exercise the exact upper bound of the APDU-40 secure profile. PID 56
        // counts the S-A_Data envelope, so the whole extended frame occupies
        // 48 wire octets plus its checksum.
        let mut wire: Vec<u8, WIRE_CAP> = Vec::new();
        wire.extend_from_slice(&[0x3C, 0x60, 0xAF, 0xFE, 0x10, 0x01, 0x28, 0x00]).expect("header fits");
        wire.extend_from_slice(&[0xCC; 40]).expect("payload fits");
        assert_eq!(wire.len() + 1, WIRE_CAP, "frame plus checksum fills the profile buffer");
        let checksum = calculate_tp1_checksum(&wire);

        let mut received = None;
        for (i, byte) in wire.iter().copied().chain(core::iter::once(checksum)).enumerate() {
            match d.push_byte(byte, i as u32, addressed) {
                TpUartEvent::Frame(frame) => received = Some(frame),
                TpUartEvent::None => {}
                _ => panic!("unexpected event"),
            }
        }
        assert_eq!(received.expect("complete frame").as_slice(), wire.as_slice());
        assert_eq!(d.pending_tx(), &[U_ACK_INFORMATION | ACK_ADDRESSED]);

        d.clear_tx();
        assert!(d.send_frame(&wire, 100));
        assert_eq!(d.pending_tx().len(), (wire.len() + 1) * 2);
        assert_eq!(d.pending_tx()[d.pending_tx().len() - 2], U_L_DATA_END | wire.len() as u8);
    }
}
