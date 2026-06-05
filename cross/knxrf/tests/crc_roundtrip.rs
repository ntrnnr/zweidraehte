//! Host property tests for the block-CRC insert/verify pair and the full
//! transmit-side `prepare_tx_buf` → receive-side decode round-trip.

use knxrf::crc::{block_fcs, insert_block_crcs, verify_and_strip};
use knxrf::frame::{self, MAX_DATA_LEN, MAX_ONAIR_LEN, MIN_DATA_LEN};
use knxrf::manchester::decode_buf;
use quickcheck_macros::quickcheck;

/// KNX 03/02/05 §6.1.2.4, EXAMPLE 3: the sequence `01..08` has CRC `0xFCBC`
/// (FT3 of IEC 870-5-1, complemented, MSB first). This is the authoritative
/// known-answer check that our polynomial / init / complement are correct.
#[test]
fn knx_standard_crc_vector() {
    let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    assert_eq!(block_fcs(&data), 0xFCBC);
}

/// Build a telegram whose length field is `len`, filled with pseudo-random but
/// deterministic bytes derived from `seed`.
fn make_telegram(len: u8, seed: u8) -> Vec<u8> {
    let mut t = vec![0u8; len as usize + 1];
    t[0] = len;
    for (i, b) in t.iter_mut().enumerate().skip(1) {
        *b = seed.wrapping_add(i as u8).wrapping_mul(0x9D);
    }
    t
}

/// Map an arbitrary byte onto a valid KNX-RF length field.
fn valid_len(raw: u8) -> u8 {
    MIN_DATA_LEN + (raw % (MAX_DATA_LEN - MIN_DATA_LEN + 1))
}

/// insert → verify recovers the telegram, and the on-air length matches the
/// geometry formula.
#[quickcheck]
fn crc_roundtrips(len_raw: u8, seed: u8) -> bool {
    let telegram = make_telegram(valid_len(len_raw), seed);
    let mut onair = [0u8; MAX_ONAIR_LEN];
    let n = insert_block_crcs(&telegram, &mut onair);
    if n != frame::rx_onair_len(telegram[0]) {
        return false;
    }
    let mut out = [0u8; MAX_ONAIR_LEN];
    matches!(verify_and_strip(&onair[..n], &mut out), Ok(m) if m == telegram.len())
        && out[..telegram.len()] == telegram[..]
}

/// The whole transmit chain (`prepare_tx_buf`) followed by the receive chain
/// (Manchester decode + CRC verify) recovers the original telegram.
#[quickcheck]
fn tx_to_rx_roundtrips(len_raw: u8, seed: u8) -> bool {
    let telegram = make_telegram(valid_len(len_raw), seed);

    // Transmit side: block CRCs + Manchester encode.
    let mut onair = [0u8; MAX_ONAIR_LEN * 2];
    let onair_len = frame::prepare_tx_buf(&telegram, &mut onair);

    // Receive side: Manchester decode, then CRC verify + strip.
    let mut decoded = [0u8; MAX_ONAIR_LEN];
    let decoded_len = match decode_buf(&onair[..onair_len], &mut decoded) {
        Ok(n) => n,
        Err(_) => return false,
    };
    let mut out = [0u8; MAX_ONAIR_LEN];
    matches!(verify_and_strip(&decoded[..decoded_len], &mut out), Ok(m) if m == telegram.len())
        && out[..telegram.len()] == telegram[..]
}

#[test]
fn detects_payload_corruption() {
    let telegram = make_telegram(20, 0x33);
    let mut onair = [0u8; MAX_ONAIR_LEN];
    let n = insert_block_crcs(&telegram, &mut onair);
    onair[5] ^= 0xFF; // flip a payload bit in the first block
    let mut out = [0u8; MAX_ONAIR_LEN];
    assert!(verify_and_strip(&onair[..n], &mut out).is_err());
}

#[test]
fn detects_second_block_corruption() {
    // A 20-byte length field spans two blocks (10 + 11). Corrupt the second.
    let telegram = make_telegram(20, 0x9C);
    let mut onair = [0u8; MAX_ONAIR_LEN];
    let n = insert_block_crcs(&telegram, &mut onair);
    onair[15] ^= 0x01;
    let mut out = [0u8; MAX_ONAIR_LEN];
    assert!(verify_and_strip(&onair[..n], &mut out).is_err());
}
