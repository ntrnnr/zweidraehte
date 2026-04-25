//! RAM-only KNX Data Secure sequence-number storage.
//!
//! Implements [`SequenceNumberStorage`] in a single struct held
//! entirely in RAM. Sequence numbers are **lost on power cycle**,
//! which breaks cross-reboot replay protection — ETS re-syncs via
//! `S-A_Sync` after each reset, but a MitM that recorded a ciphertext
//! before the reboot can replay it during the window before sync
//! completes.
//!
//! Suitable for lab bring-up of the Data Secure stack. Production
//! devices must back this with FRAM, battery-backed SRAM, or a
//! wear-levelled flash partition.
//!
//! The SIAT receive cache is sized `P2P` (default 8) via
//! [`heapless::FnvIndexMap`], matching the conformance DUT's default.

use core::convert::Infallible;

use heapless::index_map::FnvIndexMap;
use zweidraehte_device::storage::SequenceNumberStorage;

/// RAM-only sequence-number store. See module docs for caveats.
///
/// `P2P` is the SIAT receive-cache capacity — the number of distinct
/// peers whose last-valid receiving sequence number is remembered. Must
/// be a power of two (heapless `FnvIndexMap` requirement).
pub struct RamSeqStorage<const P2P: usize = 8> {
    regular_send: [u8; 6],
    tool_send: [u8; 6],
    tool_recv: Option<[u8; 6]>,
    peers: FnvIndexMap<u16, [u8; 6], P2P>,
}

impl<const P2P: usize> RamSeqStorage<P2P> {
    pub const fn new() -> Self {
        Self { regular_send: [0; 6], tool_send: [0; 6], tool_recv: None, peers: FnvIndexMap::new() }
    }
}

impl<const P2P: usize> Default for RamSeqStorage<P2P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const P2P: usize> SequenceNumberStorage for RamSeqStorage<P2P> {
    type Error = Infallible;

    fn load_sending_seqs(&self) -> Result<([u8; 6], [u8; 6]), Self::Error> {
        Ok((self.regular_send, self.tool_send))
    }

    fn save_sending_seqs(&mut self, regular: &[u8; 6], tool: &[u8; 6]) -> Result<(), Self::Error> {
        self.regular_send = *regular;
        self.tool_send = *tool;
        Ok(())
    }

    fn load_receiving_seq(&self, peer_ia: u16) -> Result<Option<[u8; 6]>, Self::Error> {
        Ok(self.peers.get(&peer_ia).copied())
    }

    fn save_receiving_seq(&mut self, peer_ia: u16, seq: &[u8; 6]) -> Result<(), Self::Error> {
        // Insert or update. On a full cache the oldest entry is not
        // evicted automatically — the insert fails silently. For
        // bring-up with ≤ P2P paired devices this is fine; if it ever
        // matters the caller can size P2P larger.
        let _ = self.peers.insert(peer_ia, *seq);
        Ok(())
    }

    fn load_tool_receiving_seq(&self) -> Result<Option<[u8; 6]>, Self::Error> {
        Ok(self.tool_recv)
    }

    fn save_tool_receiving_seq(&mut self, seq: &[u8; 6]) -> Result<(), Self::Error> {
        self.tool_recv = Some(*seq);
        Ok(())
    }
}
