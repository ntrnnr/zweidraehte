//! Host property tests for the Manchester codec.

use knxrf::manchester::{decode_buf, decode_pair, encode_buf, encode_byte};
use quickcheck_macros::quickcheck;

/// Every byte survives an encode → decode round-trip.
#[quickcheck]
fn byte_roundtrips(b: u8) -> bool {
    let (high, low) = encode_byte(b);
    decode_pair(high, low) == Ok(b)
}

/// Buffer encode → decode round-trips and preserves length.
#[quickcheck]
fn buf_roundtrips(data: Vec<u8>) -> bool {
    let mut enc = vec![0u8; data.len() * 2];
    encode_buf(&data, &mut enc);
    let mut dec = vec![0u8; data.len()];
    matches!(decode_buf(&enc, &mut dec), Ok(n) if n == data.len()) && dec == data
}

#[test]
fn known_vectors() {
    // Data 0 → on-air `10`; a zero byte is four `10` pairs = 0b1010_1010.
    assert_eq!(encode_byte(0x00), (0xAA, 0xAA));
    // Data 1 → on-air `01`; an all-ones byte is four `01` pairs = 0b0101_0101.
    assert_eq!(encode_byte(0xFF), (0x55, 0x55));
    assert_eq!(decode_pair(0xAA, 0xAA), Ok(0x00));
    assert_eq!(decode_pair(0x55, 0x55), Ok(0xFF));
}

#[test]
fn rejects_invalid_manchester() {
    // `00` and `11` bit-pairs are not valid Manchester symbols.
    assert!(decode_pair(0x00, 0x00).is_err());
    assert!(decode_pair(0xFF, 0xFF).is_err());
}
