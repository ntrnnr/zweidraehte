//! KNX Data Secure cryptographic primitives.
//!
//! Implements AES-128-CCM as specified in KNX spec 03/03/07 section 5.1.3
//! and Annex A. This module is `no_std` compatible.
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

pub mod ccm;
pub mod scf;
