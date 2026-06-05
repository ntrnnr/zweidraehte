//! KNX-RF data-link frame geometry.
//!
//! A decoded KNX-RF frame is a length byte followed by the KNX-RF telegram,
//! split into CRC-protected blocks: the first block holds 10 bytes, every
//! following block 16 bytes, and each block is followed by a 2-byte CRC (see
//! [`crate::crc`]). The "on-air" buffer is the Manchester-decoded byte stream
//! *including* those interspersed CRC bytes; the "data"/stripped buffer is the
//! telegram with the CRC bytes removed.

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
