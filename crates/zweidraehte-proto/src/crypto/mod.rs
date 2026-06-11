//! KNX security cryptographic primitives (`no_std` compatible).
//!
//! Two AES-128-CCM variants share their CBC-MAC core (`aes_util`):
//!
//! - [`ccm`] — KNX **Data Secure** (03/03/07 §5.1.3 / Annex A,
//!   4-byte MAC, frame-address nonce).
//! - [`ip_secure_ccm`] — **KNX IP Secure** (03/08/09 §2.2.1.3,
//!   16-byte MAC, sequence/serial/tag nonce).
//!
//! [`session_key`] (feature `ip-secure`) adds the Curve25519 + SHA-256
//! session-key agreement for the IP Secure handshake.
//!
//! # Algorithm Overview
//!
//! KNX uses AES-128 in CCM mode (Counter with CBC-MAC) with a 4-byte
//! MAC tag. The block construction is KNX-specific:
//!
//! - **B0**: `SeqNr(6) | SA(2) | DA(2) | 0x00 | AT(1) | TPCI/APCI(2) | 0x00 | q(1)`
//! - **Ctr_j**: `SeqNr(6) | SA(2) | DA(2) | 0x00..0x00 | 0x01 | j`
//!
//! Two modes:
//! - **Authentication only** (SCF bit 5 = 0): P = empty, A = SCF | 000000b | plain APDU.
//!   MAC = MSB32(Y_n) XOR MSB32(S0). Payload sent in clear + 4-byte MAC.
//! - **Authentication + Confidentiality** (SCF bit 5 = 1): A = SCF, P = 000000b | plain APDU.
//!   Ciphertext = P XOR MSB(S). MAC = MSB32(Y_n) XOR MSB32(S0).

mod aes_util;
pub mod ccm;
pub mod ip_secure_ccm;
pub mod scf;
#[cfg(feature = "ip-secure")]
pub mod session_key;
