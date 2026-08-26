//! Security sequence numbers: the 48-bit codec, the spec's fixed values, and
//! the two traits a stack implements to give the S-AL durable counters.
//!
//! Like [`ConnectionCore`](crate::transport::ConnectionCore) for the transport
//! state machine, the traits here are the seam rather than an implementation:
//! this module owns no storage and performs no I/O. Concrete stores — a
//! wear-levelled flash view, a FRAM region, a file, a shared-memory region for
//! a test harness — live in the crate that owns the medium.

use crate::messages::apdu::restart::EraseCode;

// ============================================================================
// The 6-octet wire codec
// ============================================================================

/// Decode a 6-octet big-endian sequence number to `u64`.
pub fn seq6_to_u64(seq: &[u8; 6]) -> u64 {
    u64::from_be_bytes([0, 0, seq[0], seq[1], seq[2], seq[3], seq[4], seq[5]])
}

/// Encode the low 48 bits of `val` as a 6-octet big-endian sequence number.
pub fn u64_to_seq6(val: u64) -> [u8; 6] {
    let b = val.to_be_bytes();
    [b[2], b[3], b[4], b[5], b[6], b[7]]
}

/// Largest value a 6-octet sequence number can carry (`2^48 - 1`).
pub const SEQ6_MAX: u64 = 0xFFFF_FFFF_FFFF;

/// Spec-default sending sequence number on a fresh device.
///
/// The secure AL treats `[0,0,0,0,0,1]` as "no history"; remotes reject seq 0,
/// and ETS reconciles via `S-A_Sync`.
pub const DEFAULT_SENDING: [u8; 6] = [0, 0, 0, 0, 0, 1];

/// Near-exhaustion threshold for the 6-byte (48-bit) sending SeqNr:
/// `FF 00 00 00 00 00`. A factory reset re-initialises the counter only at or
/// above this value (03/05/01 §6.1.4 + AN194) — below it the counter is
/// preserved, since receivers have already seen those values and would reject
/// a lower re-init as a replay.
pub const SEQ_EXHAUSTION_THRESHOLD: u64 = 0xFF00_0000_0000;

/// Re-init target after a near-exhaustion factory reset.
///
/// 03/03/07 §5.3.1 requires the re-initialised value to sit "at least 20
/// and at maximum FFFFh higher than the preceding initial value": ours is
/// [`DEFAULT_SENDING`]'s 1, so 21. A fixed target technically shortchanges
/// a *second* re-init in the same device life, but reaching one would mean
/// counting from 21 back up to the 2^48-order threshold — the spec's own
/// NOTE 33 blesses implementation-specific schemes, and storing a
/// re-init generation to add 20 each time buys nothing real.
pub const SEQ_REINIT_VALUE: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x15];

// ============================================================================
// Storage seams
// ============================================================================

/// Wear-resistant storage for security sequence numbers.
///
/// Sequence numbers increment on every outgoing secure message, so they
/// cannot live in regular flash/EEPROM without wear-leveling.
///
/// Implementations may use:
/// - FRAM (I2C/SPI) — unlimited write endurance, ideal
/// - Battery-backed SRAM
/// - A dedicated file (Linux userspace)
/// - RAM-only (accepting reset on power cycle)
///
/// # Sending sequence number
///
/// Per KNX 03/03/07 §5.x a device maintains **one single Sequence Number
/// Sending** for *all* its outgoing secure communication — group, broadcast,
/// P2P, and tool access alike — incremented on every secure frame it sends.
/// Receiving state is the separate, genuinely per-partner part: the SIAT (one
/// last-valid per sender IA) plus the tool-access receiving counter below.
pub trait SequenceNumberStorage {
    /// Error type for storage operations.
    type Error;

    /// Load the device's Sequence Number Sending (6 bytes big-endian).
    fn load_sending_seq(&self) -> Result<[u8; 6], Self::Error>;

    /// Save the device's Sequence Number Sending. Called after every outgoing
    /// secure message.
    fn save_sending_seq(&mut self, seq: &[u8; 6]) -> Result<(), Self::Error>;

    /// Load last-valid receiving sequence number for a peer, keyed by
    /// sender IA.
    ///
    /// Per 03/03/07 §5.3, this covers *every* non-tool secure sender —
    /// P2P partners and pure group-secure senders alike — not only
    /// P2P. "Peer" here means any remote IA from which this device has
    /// ever accepted a non-tool secure frame. Returns `None` if no
    /// sequence is stored for this peer.
    fn load_receiving_seq(&self, peer_ia: u16) -> Result<Option<[u8; 6]>, Self::Error>;

    /// Save last-valid receiving sequence number for a sender IA.
    /// Called after successful MAC verification of an incoming message.
    /// Same keying as [`load_receiving_seq`](Self::load_receiving_seq).
    fn save_receiving_seq(&mut self, peer_ia: u16, seq: &[u8; 6]) -> Result<(), Self::Error>;

    /// Load the last-valid receiving sequence number for tool access.
    ///
    /// Per spec §5.3.1 Note 27, the tool access receiving SeqNr is stored
    /// separately from the SIAT — there is no standardized resource for it.
    fn load_tool_receiving_seq(&self) -> Result<Option<[u8; 6]>, Self::Error>;

    /// Save the last-valid receiving sequence number for tool access.
    fn save_tool_receiving_seq(&mut self, seq: &[u8; 6]) -> Result<(), Self::Error>;
}

/// The SIAT operations that are *not* part of [`SequenceNumberStorage`]:
/// by-index array access (the PID 54 property service), the element count,
/// and membership/clear.
///
/// The Security Individual Address Table is not a separate table from the
/// receiving counters — a SIAT element *is* a sender IA plus its Last Valid
/// SeqNr (03/05/01 §6.3.8), which is why one store serves both traits and a
/// PID 54 read returns the live value.
pub trait SiatAccess {
    /// Error type for storage operations.
    type Error;

    /// Number of SIAT entries (PID 54 element-count read at index 0).
    fn siat_count(&self) -> u16;
    /// The 1-based `IA_Index` of `ia`, or `None` if it is not in the SIAT — the
    /// join key into the Point-to-point Key Table (03/05/01 §6.3.8.4).
    fn siat_index_of(&self, ia: u16) -> Option<u16>;
    /// Whether `ia` is in the SIAT.
    ///
    /// A non-tool S-A_Data sender absent from this table is discarded before
    /// further security processing without updating the Security Failures Log
    /// (03/03/07 §5.1.3.5, reception step 1).
    fn siat_contains(&self, ia: u16) -> bool {
        self.siat_index_of(ia).is_some()
    }
    /// Entry at 0-based `idx` in array order (PID 54 entry read).
    fn siat_read_entry(&self, idx: u16) -> Option<(u16, [u8; 6])>;
    /// Provision the element at 0-based `idx` (PID 54 entry write). Positional:
    /// the element the writer named is the one replaced, because its position
    /// is the `IA_Index` the P2P key table joins on. Writing at or beyond the
    /// current count extends the table through `idx`, filling any gap with
    /// zero entries; ETS clears the count before streaming replacement rows.
    fn siat_write_entry(&mut self, idx: u16, ia: u16, seq: [u8; 6]) -> Result<(), Self::Error>;
    /// Set the SIAT element count (PID 54 write at index 0; 0 clears).
    fn siat_set_count(&mut self, count: u16) -> Result<(), Self::Error>;
    /// Remove all entries (factory reset).
    fn siat_clear(&mut self) -> Result<(), Self::Error>;
}

// ============================================================================
// Restart semantics
// ============================================================================

/// The sending counter's slice of a restart erase.
///
/// The master-reset table in 03/03/07 §5.3.1 ("Sequence Number Sending
/// and Master Reset") gives the sending SeqNr exactly one way to move: a
/// "Reset to default state" (02h, and its no-bus local twin) while the
/// counter is at or above the 48-bit near-exhaustion threshold
/// re-initialises it; every other code — including "Reset to default
/// without IA" (07h), which the table lists as "not influenced" in *both*
/// columns — preserves it, as does 02h below the threshold. Receivers
/// have already seen the lower values and would reject a lower re-init
/// as a replay; TSS J 3.8.15.7 walks every code through both columns.
pub fn erase_seq_on_factory_reset<S: SequenceNumberStorage>(seq: &mut S, code: EraseCode) -> bool {
    if code != EraseCode::FactoryReset {
        return true;
    }
    let Ok(current) = seq.load_sending_seq() else {
        return false;
    };
    if seq6_to_u64(&current) >= SEQ_EXHAUSTION_THRESHOLD && seq.save_sending_seq(&SEQ_REINIT_VALUE).is_err() {
        warn!("sending-SeqNr exhaustion re-init failed");
        return false;
    }
    true
}

// ============================================================================
// Sending-sequence reservation
// ============================================================================

/// Reserve and persist the next sending sequence number.
///
/// Returns the *current* value of the device's single Sequence Number Sending
/// — the one to place in the frame about to go out — and persists the
/// incremented value before returning it. Persisting first is the point: a
/// frame must never leave the device carrying a sequence number the store has
/// not durably advanced past, or a power cut mid-send lets the next boot reuse
/// it.
///
/// There is one counter for all outgoing secure communication, tool access
/// included (03/03/07 §5.3), so this takes no per-partner argument.
///
/// Returns `None` when the 48-bit counter is exhausted or the store refuses
/// the write; both mean the caller must abort the transmission rather than
/// send an unnumbered or reused frame.
pub fn reserve_next_seq_nr<S: SequenceNumberStorage>(storage: &mut S) -> Option<[u8; 6]> {
    // The backend owns the representation of an uninitialised counter and
    // should return `DEFAULT_SENDING` for it. A read error is different: if
    // we guessed the default here, a transient storage failure could reuse a
    // sequence number that had already gone on the wire.
    let seq = storage.load_sending_seq().ok()?;
    let val = seq6_to_u64(&seq);

    // 48-bit overflow guard.
    if val >= SEQ6_MAX {
        return None;
    }

    // A save failure here is unexpected (storage corruption or a full flash
    // sector) — warn and abort the send rather than emitting a frame whose
    // sequence number has not been durably stored.
    if storage.save_sending_seq(&u64_to_seq6(val + 1)).is_err() {
        warn!("S-AL: failed to persist sending SeqNr; aborting secure frame");
        return None;
    }

    Some(seq)
}

// ============================================================================
// Receiving-sequence verdict (03/03/07 §5.3.1)
// ============================================================================

/// What an incoming secure frame's sequence number means, given the Last Valid
/// SeqNr stored for that sender.
///
/// The three-way split is the spec's, and the middle case is the one that is
/// easy to get wrong: an exactly-equal sequence number is a retransmission,
/// which is dropped *without* a failure-log entry, while a lower one is a
/// replay, which is dropped *with* one. Collapsing them into a single "not
/// greater" branch makes a device count ordinary bus retransmissions as
/// security failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeqVerdict {
    /// Fresh: accept the frame and store `received` as the new Last Valid.
    Accept,
    /// Equal to the stored value: a retransmission. Drop silently.
    Retransmission,
    /// Below the stored value: a replay. Drop and log a sequence failure.
    Replay,
    /// Sequence number zero, which the spec never assigns. Drop and log.
    Invalid,
}

/// Classify an incoming sequence number against the stored Last Valid SeqNr.
///
/// `stored` is `None` for a sender with no history, which compares as zero —
/// so any non-zero sequence number from a new sender is accepted.
pub fn check_receiving_seq(received: &[u8; 6], stored: Option<[u8; 6]>) -> SeqVerdict {
    if *received == [0u8; 6] {
        return SeqVerdict::Invalid;
    }
    let received = seq6_to_u64(received);
    let stored = stored.map(|s| seq6_to_u64(&s)).unwrap_or(0);
    match received.cmp(&stored) {
        core::cmp::Ordering::Greater => SeqVerdict::Accept,
        core::cmp::Ordering::Equal => SeqVerdict::Retransmission,
        core::cmp::Ordering::Less => SeqVerdict::Replay,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seq6_codec_round_trips() {
        for val in [0u64, 1, 0x15, 0x0012_3456_789A, SEQ6_MAX] {
            assert_eq!(seq6_to_u64(&u64_to_seq6(val)), val);
        }
    }

    #[test]
    fn u64_to_seq6_keeps_only_the_low_48_bits() {
        assert_eq!(u64_to_seq6(0xDEAD_FFFF_FFFF_FFFF), [0xFF; 6]);
    }

    #[test]
    fn a_new_sender_is_accepted_on_any_non_zero_sequence() {
        assert_eq!(check_receiving_seq(&[0, 0, 0, 0, 0, 1], None), SeqVerdict::Accept);
    }

    #[test]
    fn sequence_zero_is_never_valid() {
        assert_eq!(check_receiving_seq(&[0; 6], None), SeqVerdict::Invalid);
        assert_eq!(check_receiving_seq(&[0; 6], Some([0, 0, 0, 0, 0, 5])), SeqVerdict::Invalid);
    }

    #[test]
    fn equal_is_a_retransmission_and_lower_is_a_replay() {
        let stored = Some([0, 0, 0, 0, 0, 5]);
        assert_eq!(check_receiving_seq(&[0, 0, 0, 0, 0, 6], stored), SeqVerdict::Accept);
        assert_eq!(check_receiving_seq(&[0, 0, 0, 0, 0, 5], stored), SeqVerdict::Retransmission);
        assert_eq!(check_receiving_seq(&[0, 0, 0, 0, 0, 4], stored), SeqVerdict::Replay);
    }
}
