//! Security sequence-number storage: the wear-resistant seam and its
//! stores-struct projections.
//!
//! [`SequenceNumberStorage`] is what the secure layers require of a sequence
//! store; [`HasSeqStore`] is how they reach the device's concrete store on
//! the macro-emitted stores struct, carried as
//! [`StackDefinition::Storage`](crate::StackDefinition::Storage) on the
//! `LayerContext`.

use core::cell::RefCell;

use crate::restart::EraseCode;

use super::kv::{SEQ_EXHAUSTION_THRESHOLD, SEQ_REINIT_VALUE, seq6_to_u64};
use super::views::SiatAccess;

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

/// Typed access to the sequence/SIAT store on a device's stores struct.
/// Implemented by the seq-carrying stores structs
/// ([`SecureStorage`](super::SecureStorage), [`SecureIpStorage`](super::SecureIpStorage));
/// its absence is what gates the secure context/builders at compile time.
pub trait HasSeqStore {
    /// The concrete sequence store type.
    type Seq: SequenceNumberStorage + SiatAccess;
    /// The store's `RefCell`, borrowed per call by the secure layers.
    fn seq_store(&self) -> &RefCell<Self::Seq>;
}

// A device's `StackDefinition::Storage` is the *reference* to its stores
// struct (e.g. `&'static SecureStorage<…>`), so the capability forwards through the
// reference — bounds stay a single line (`D::Storage: HasSeqStore`).
impl<T: HasSeqStore> HasSeqStore for &T {
    type Seq = T::Seq;
    fn seq_store(&self) -> &RefCell<Self::Seq> {
        (*self).seq_store()
    }
}

/// The sequence-store type behind a device's
/// [`Storage`](crate::StackDefinition::Storage) handle — the secure builders'
/// `SEQ` parameter.
pub type SeqStorageFor<D> = <<D as crate::definition::StackDefinition>::Storage as HasSeqStore>::Seq;

/// The sequence store's slice of a restart erase.
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
///
/// Called from the seq-carrying stores structs' `StorageHooks` impls when the
/// stores block declares `seq:`.
pub fn erase_seq_on_factory_reset<S: SequenceNumberStorage>(seq: &mut S, code: EraseCode) {
    if code != EraseCode::FactoryReset {
        return;
    }
    let Ok(current) = seq.load_sending_seq() else {
        return;
    };
    if seq6_to_u64(&current) >= SEQ_EXHAUSTION_THRESHOLD && seq.save_sending_seq(&SEQ_REINIT_VALUE).is_err() {
        crate::logging::warn!("sending-SeqNr exhaustion re-init failed");
    }
}
