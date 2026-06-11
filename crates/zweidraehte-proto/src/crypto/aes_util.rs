//! Shared AES-128 helpers for the two KNX CCM variants.
//!
//! Both KNX Data Secure (03/03/07 Annex A, 4-byte MAC) and KNX IP Secure
//! (03/08/09 §2.2.1.3.2, 16-byte MAC) build their CBC-MAC the same way:
//! `Y0 = AES(B0)`, then the byte stream `len(A) | A | P` is XOR-folded
//! into the chain in 16-byte blocks with zero padding only at the very
//! end (note: *no* block-boundary padding between A and P, unlike
//! standard RFC 3610 CCM). Only the B0/Ctr nonce layouts and the MAC
//! truncation differ, so those stay in the per-variant modules.

use aes::Aes128;
use aes::cipher::BlockEncrypt;

/// Encrypt a single 16-byte block with AES-128-ECB.
pub(crate) fn aes_encrypt_block(key: &Aes128, block: &mut [u8; 16]) {
    use aes::cipher::generic_array::GenericArray;
    let b = GenericArray::from_mut_slice(block);
    key.encrypt_block(b);
}

/// Helper that feeds byte streams into the CBC-MAC chain in 16-byte blocks,
/// handling cross-boundary buffering and padding.
pub(crate) struct ChainedXorFeeder<'a> {
    y: &'a mut [u8; 16],
    pos: usize, // position within current 16-byte block
}

impl<'a> ChainedXorFeeder<'a> {
    pub(crate) fn new(y: &'a mut [u8; 16]) -> Self {
        Self { y, pos: 0 }
    }

    /// Feed data into the chain. Processes complete blocks immediately.
    pub(crate) fn feed(&mut self, key: &Aes128, data: &[u8]) {
        for &byte in data {
            self.y[self.pos] ^= byte;
            self.pos += 1;
            if self.pos == 16 {
                aes_encrypt_block(key, self.y);
                self.pos = 0;
            }
        }
    }

    /// Pad the final partial block with zeros and encrypt.
    /// Does nothing if we're exactly on a block boundary.
    pub(crate) fn finish(&mut self, key: &Aes128) {
        if self.pos > 0 {
            // Remaining bytes in y[pos..16] are already XOR'd with 0 (no-op).
            aes_encrypt_block(key, self.y);
            self.pos = 0;
        }
    }
}
