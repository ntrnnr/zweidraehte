//! KNX-RF data-link frame geometry.
//!
//! A decoded KNX-RF frame is a length byte followed by the KNX-RF telegram,
//! split into CRC-protected blocks: the first block holds 10 bytes, every
//! following block 16 bytes, and each block is followed by a 2-byte CRC (see
//! [`crate::crc`]). The "on-air" buffer is the Manchester-decoded byte stream
//! *including* those interspersed CRC bytes; the "data"/stripped buffer is the
//! telegram with the CRC bytes removed.

use crate::sx1211::regs::{SYNC_WORD, TX_POSTAMBLE, TX_PREAMBLE_BYTE, TX_PREAMBLE_LEN};

/// Smallest legal value of the length field. The on-air length check
/// `(byte - 9) < 0x3F`, which rejects anything below 9.
pub const MIN_DATA_LEN: u8 = 9;

/// Largest legal value of the length field. `(byte - 9) < 0x3F` ⇒ `byte < 72`,
/// so the last accepted value is 71.
pub const MAX_DATA_LEN: u8 = 71;

/// Upper bound on a decoded (CRC-included) on-air frame, used to size fixed
/// buffers. `rx_onair_len(MAX_DATA_LEN)` plus a little slack.
pub const MAX_ONAIR_LEN: usize = 96;

/// Total number of Manchester-decoded bytes in a frame whose length field is
/// `len`, i.e. the telegram bytes plus the per-block CRC bytes.
///
/// Computed as `len + 2 * ((len + 6) >> 4) + 3`. The `+3` accounts for the length byte,
/// the first block's CRC, and rounding; `2 * ((len + 6) >> 4)` adds two CRC
/// bytes for each subsequent 16-byte block.
pub fn rx_onair_len(len: u8) -> usize {
    let len = len as usize;
    len + 2 * ((len + 6) >> 4) + 3
}

/// Returns `true` if `len` is an acceptable KNX-RF length field.
pub fn is_valid_len(len: u8) -> bool {
    (MIN_DATA_LEN..=MAX_DATA_LEN).contains(&len)
}

/// A decoded, CRC-verified KNX-RF frame: the telegram bytes (length byte
/// first, CRC bytes stripped) together with the link budget reported by the
/// transceiver for the reception.
#[derive(Clone)]
pub struct RfFrame {
    /// Telegram bytes, `data[0]` is the length field.
    pub data: [u8; MAX_ONAIR_LEN],
    /// Number of valid bytes in [`Self::data`].
    pub len: usize,
    /// Raw RSSI register value sampled at reception (see
    /// [`crate::sx1211::Sx1211::get_rssi`]).
    pub rssi: u8,
}

impl RfFrame {
    /// The valid telegram bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

/// Build the on-air byte stream for a telegram: insert per-block CRCs, then
/// Manchester-encode the result. `telegram[0]` is the length field. Returns
/// the number of on-air bytes written to `onair`.
///
/// This is the transmit-side counterpart of the receive decode path and is
/// fully exercised by the round-trip tests. The preamble and sync word are
/// *not* included here — they are the transceiver's responsibility (see the
/// TX notes on [`crate::sx1211`]).
///
/// # Panics
/// Panics if `onair` is smaller than `2 * crate::crc::insert_block_crcs(..)`;
/// size it to at least `2 * MAX_ONAIR_LEN`.
pub fn prepare_tx_buf(telegram: &[u8], onair: &mut [u8]) -> usize {
    let mut crc_buf = [0u8; MAX_ONAIR_LEN];
    let crc_len = crate::crc::insert_block_crcs(telegram, &mut crc_buf);
    crate::manchester::encode_buf(&crc_buf[..crc_len], onair);
    crc_len * 2
}

/// Upper bound on a fully-assembled on-air transmit buffer — preamble, sync
/// word, the Manchester-encoded telegram (with per-block CRCs), and postamble —
/// for the longest legal frame. Use it to size the buffer passed to
/// [`build_tx_buf`].
pub const TX_BUF_CAP: usize = TX_PREAMBLE_LEN + SYNC_WORD.len() + 2 * MAX_ONAIR_LEN + TX_POSTAMBLE.len();

/// Assemble the complete on-air byte sequence for `telegram` into `out` and
/// return its length: the `0x55` preamble, the sync word, the
/// Manchester-encoded telegram with interspersed block CRCs ([`prepare_tx_buf`]),
/// and the postamble end marker.
///
/// This is the full byte stream the transceiver feeds through its FIFO in
/// transmit mode; the preamble/sync/postamble that `prepare_tx_buf` deliberately
/// omits are added here. `telegram[0]` is the length field.
///
/// # Panics
/// Panics if `out` is shorter than the assembled frame; size it to
/// [`TX_BUF_CAP`].
pub fn build_tx_buf(telegram: &[u8], out: &mut [u8]) -> usize {
    let mut pos = 0;

    // Preamble: a run of the 0x55 chip pair for the bit synchroniser to lock on.
    out[pos..pos + TX_PREAMBLE_LEN].fill(TX_PREAMBLE_BYTE);
    pos += TX_PREAMBLE_LEN;

    // Sync word — the same bytes the receiver's sync detector is programmed with.
    out[pos..pos + SYNC_WORD.len()].copy_from_slice(&SYNC_WORD);
    pos += SYNC_WORD.len();

    // Telegram body: block CRCs inserted, then Manchester-encoded.
    pos += prepare_tx_buf(telegram, &mut out[pos..]);

    // Postamble end marker (not checked by receivers, mandatory on transmit).
    out[pos..pos + TX_POSTAMBLE.len()].copy_from_slice(&TX_POSTAMBLE);
    pos += TX_POSTAMBLE.len();

    pos
}
