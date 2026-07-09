//! Manchester coding for the KNX-RF modem stream.
//!
//! KNX-RF uses G.E. Thomas Manchester coding: a data bit `1` is sent as the
//! on-air chip sequence `01` (fLO→fHI transition), a data bit `0` as `10`
//! (fHI→fLO) — per KNX 03/02/05 §5.1.2.1, Table 4. Each data byte therefore
//! expands to two on-air bytes (8 data bits → 16 chips). The SX1211 is run in
//! buffered mode, so the FIFO carries these raw on-air bytes and we encode /
//! decode them here in software.
//!
//! The high nibble of a data byte maps to the first on-air byte, the low
//! nibble to the second, both MSB-first.

/// Returned when a received on-air bit-pair is neither `01` nor `10` — i.e.
/// the demodulated stream is not valid Manchester (noise, clock slip, or a
/// frame that ended mid-byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ManchesterError;

/// Encode one data byte into its two on-air bytes `(high_nibble, low_nibble)`.
pub fn encode_byte(data: u8) -> (u8, u8) {
    (encode_nibble(data >> 4), encode_nibble(data & 0x0F))
}

/// Encode the four low bits of `nibble` (MSB-first) into one on-air byte.
fn encode_nibble(nibble: u8) -> u8 {
    let mut out = 0u8;
    // Walk the four data bits from MSB to LSB, emitting `01` for a 1-bit and
    // `10` for a 0-bit, most-significant bit first.
    for i in (0..4).rev() {
        let bit = (nibble >> i) & 1;
        out <<= 1;
        if bit == 0 {
            out |= 1; // first sub-bit is high only for a data 0
        }
        out <<= 1;
        if bit == 1 {
            out |= 1; // second sub-bit is high only for a data 1
        }
    }
    out
}

/// Decode two on-air bytes back into one data byte, or fail if either byte is
/// not valid Manchester.
pub fn decode_pair(high: u8, low: u8) -> Result<u8, ManchesterError> {
    Ok((decode_nibble(high)? << 4) | decode_nibble(low)?)
}

/// Decode one on-air byte into the four data bits it carries.
fn decode_nibble(mut man: u8) -> Result<u8, ManchesterError> {
    let mut data = 0u8;
    for _ in 0..4 {
        data <<= 1;
        match man & 0xC0 {
            0x40 => data |= 1, // `01` → 1
            0x80 => {}         // `10` → 0
            _ => return Err(ManchesterError),
        }
        man <<= 2;
    }
    Ok(data)
}

/// Encode `src` into `dst`, writing `2 * src.len()` on-air bytes.
///
/// # Panics
/// Panics if `dst.len() < 2 * src.len()`.
pub fn encode_buf(src: &[u8], dst: &mut [u8]) {
    assert!(dst.len() >= src.len() * 2, "Manchester dst too small");
    for (i, &b) in src.iter().enumerate() {
        let (high, low) = encode_byte(b);
        dst[i * 2] = high;
        dst[i * 2 + 1] = low;
    }
}

/// Decode `src` (which must hold an even number of on-air bytes) into `dst`,
/// writing `src.len() / 2` data bytes. Returns the number of bytes written.
///
/// # Panics
/// Panics if `dst.len() < src.len() / 2`.
pub fn decode_buf(src: &[u8], dst: &mut [u8]) -> Result<usize, ManchesterError> {
    let pairs = src.len() / 2;
    assert!(dst.len() >= pairs, "Manchester dst too small");
    for i in 0..pairs {
        dst[i] = decode_pair(src[i * 2], src[i * 2 + 1])?;
    }
    Ok(pairs)
}
