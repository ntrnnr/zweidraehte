//! KNX IP Secure AES-128-CCM (03/08/09 §2.2.1.3.2).
//!
//! Sibling of the Data Secure CCM in [`super::ccm`] — same CBC-MAC
//! chaining (`Y0 = AES(B0)`, then `len(A) | A | P` zero-padded only at
//! the end), but with the IP-Secure nonce layout and a full 16-byte MAC
//! instead of the 4-byte truncation:
//!
//! - **B0**:    `SeqInfo(6) | SerialNr(6) | MessageTag(2) | Q(2, BE)`
//! - **Ctr_i**: `SeqInfo(6) | SerialNr(6) | MessageTag(2) | FFh | i`
//! - MAC = `Y_n XOR S0` (all 16 bytes), payload keystream starts at S1
//!   with full 16-byte blocks (unlike Data Secure, which carves the
//!   first 12 payload bytes out of S0).
//!
//! Three users, distinguished only by their nonce and associated data:
//!
//! - **SECURE_WRAPPER** (§2.2.1.3): key = session key (unicast) or
//!   backbone key (multicast), nonce from the wrapper's security
//!   information block, A = wrapper header(6) | session id(2),
//!   P = encapsulated KNXnet/IP frame.
//! - **SESSION_RESPONSE / SESSION_AUTHENTICATE** (§2.2.3.7.4 /
//!   §2.2.3.8.4): auth-only with an *all-zero* nonce, key = device
//!   authentication code resp. user password hash,
//!   A = frame header | id byte(s) | XOR(X, Y), P = empty.
//! - **TIMER_NOTIFY** (§2.2.2.4): auth-only, key = backbone key, nonce
//!   from timer value | serial | tag, A = the 6-byte frame header.
//!
//! All MAC verification uses constant-time comparison. Test vectors are
//! the binary examples from 03/08/09 Appendix A.

use aes::Aes128;
use aes::cipher::KeyInit;
use subtle::ConstantTimeEq;

use super::aes_util::{ChainedXorFeeder, aes_encrypt_block};
pub use super::ccm::CryptoError;

/// Length of the IP Secure MAC in bytes (full CBC-MAC block).
pub const MAC_LEN: usize = 16;

// ============================================================================
// Block construction
// ============================================================================

/// The 14-byte CCM nonce: sequence information, KNX serial number, and
/// message tag, exactly as they appear in the SECURE_WRAPPER /
/// TIMER_NOTIFY security information block.
///
/// For the auth-only session handshake MACs (SESSION_RESPONSE,
/// SESSION_AUTHENTICATE) all three components are zero.
#[derive(Debug, Clone, Copy, Default)]
pub struct IpSecureNonce {
    /// 6-byte sequence information (unicast: 48-bit session sequence
    /// number; multicast: 48-bit timer value).
    pub seq_info: [u8; 6],
    /// 6-byte KNX serial number of the sender.
    pub serial_number: [u8; 6],
    /// 2-byte message tag (`0000h` on unicast sessions).
    pub message_tag: [u8; 2],
}

impl IpSecureNonce {
    /// All-zero nonce used by the session-handshake auth-only MACs
    /// (§2.2.3.7.4 step 2: "B0 = 00 ... 00").
    pub const ZERO: Self = Self { seq_info: [0; 6], serial_number: [0; 6], message_tag: [0; 2] };
}

/// Build the B0 block (§2.2.1.3.2 Figure 8).
///
/// `Nonce(14) | Q(2, big-endian)` where Q is the payload length.
fn block_b0(nonce: &IpSecureNonce, payload_len: u16) -> [u8; 16] {
    let mut b0 = [0u8; 16];
    b0[0..6].copy_from_slice(&nonce.seq_info);
    b0[6..12].copy_from_slice(&nonce.serial_number);
    b0[12..14].copy_from_slice(&nonce.message_tag);
    b0[14..16].copy_from_slice(&payload_len.to_be_bytes());
    b0
}

/// Build the Ctr_i block (§2.2.1.3.2 Figure 9).
///
/// `Nonce(14) | FFh | i`.
fn block_ctr(nonce: &IpSecureNonce, i: u8) -> [u8; 16] {
    let mut ctr = [0u8; 16];
    ctr[0..6].copy_from_slice(&nonce.seq_info);
    ctr[6..12].copy_from_slice(&nonce.serial_number);
    ctr[12..14].copy_from_slice(&nonce.message_tag);
    ctr[14] = 0xFF;
    ctr[15] = i;
    ctr
}

// ============================================================================
// Core CCM primitives
// ============================================================================

/// CBC-MAC over `B0`, then `len(A)(2, BE) | A | P` zero-padded at the
/// end. `assoc` is fed as up to three concatenated fragments so callers
/// can splice headers and key material without staging buffers.
fn cbc_mac(key: &Aes128, b0: &[u8; 16], assoc: &[&[u8]], payload: &[u8]) -> [u8; 16] {
    let mut y = *b0;
    aes_encrypt_block(key, &mut y);

    let a_len: usize = assoc.iter().map(|f| f.len()).sum();
    let a_bytes = (a_len as u16).to_be_bytes();

    let mut chain = ChainedXorFeeder::new(&mut y);
    chain.feed(key, &a_bytes);
    for fragment in assoc {
        chain.feed(key, fragment);
    }
    chain.feed(key, payload);
    chain.finish(key);

    y
}

/// `S0 = AES_K(Ctr0)` — keystream block that encrypts the MAC.
fn compute_s0(key: &Aes128, nonce: &IpSecureNonce) -> [u8; 16] {
    let mut s0 = block_ctr(nonce, 0);
    aes_encrypt_block(key, &mut s0);
    s0
}

/// XOR `data` with the CTR keystream `S1 | S2 | ...` (full 16-byte
/// blocks from Ctr1 onwards; S0 is reserved for the MAC).
fn ctr_crypt(key: &Aes128, nonce: &IpSecureNonce, data: &mut [u8]) {
    let mut offset = 0;
    let mut i = 1u8;
    while offset < data.len() {
        let mut s = block_ctr(nonce, i);
        aes_encrypt_block(key, &mut s);
        let chunk_len = (data.len() - offset).min(16);
        for j in 0..chunk_len {
            data[offset + j] ^= s[j];
        }
        offset += chunk_len;
        i = i.wrapping_add(1);
    }
}

/// Compute the encrypted 16-byte MAC: `Y_n XOR S0`.
fn encrypted_mac(key: &Aes128, nonce: &IpSecureNonce, assoc: &[&[u8]], payload: &[u8], payload_len: u16) -> [u8; 16] {
    let b0 = block_b0(nonce, payload_len);
    let y_n = cbc_mac(key, &b0, assoc, payload);
    let s0 = compute_s0(key, nonce);
    let mut mac = [0u8; 16];
    for i in 0..16 {
        mac[i] = y_n[i] ^ s0[i];
    }
    mac
}

// ============================================================================
// SECURE_WRAPPER
// ============================================================================

/// Encrypt the encapsulated frame in place and compute the wrapper MAC.
///
/// - `key`: session key (unicast) or backbone key (multicast)
/// - `nonce`: sequence info / serial / tag from the wrapper being built
/// - `assoc`: the first 8 wrapper bytes — KNXnet/IP header(6) with the
///   *total* wrapper length, followed by the session identifier(2)
/// - `payload`: the plaintext encapsulated KNXnet/IP frame; encrypted
///   in place
///
/// Returns the 16-byte MAC that goes after the encrypted payload.
pub fn wrap_secure(key: &[u8; 16], nonce: &IpSecureNonce, assoc: &[u8; 8], payload: &mut [u8]) -> [u8; 16] {
    let cipher = Aes128::new(key.into());
    let mac = encrypted_mac(&cipher, nonce, &[assoc], payload, payload.len() as u16);
    ctr_crypt(&cipher, nonce, payload);
    mac
}

/// Verify the wrapper MAC and decrypt the encapsulated frame in place.
///
/// On MAC failure the payload buffer content is undefined (already
/// decrypted) — the caller must not use it.
pub fn unwrap_secure(
    key: &[u8; 16],
    nonce: &IpSecureNonce,
    assoc: &[u8; 8],
    payload: &mut [u8],
    received_mac: &[u8; 16],
) -> Result<(), CryptoError> {
    let cipher = Aes128::new(key.into());
    ctr_crypt(&cipher, nonce, payload);
    let expected = encrypted_mac(&cipher, nonce, &[assoc], payload, payload.len() as u16);
    if bool::from(expected.ct_eq(received_mac)) { Ok(()) } else { Err(CryptoError::MacMismatch) }
}

// ============================================================================
// Session handshake MACs (auth-only, zero nonce)
// ============================================================================

/// Fixed KNXnet/IP header of a SESSION_RESPONSE (service `0952h`,
/// total length always 56) — first part of the MAC's associated data.
const SESSION_RESPONSE_HEADER: [u8; 6] = [0x06, 0x10, 0x09, 0x52, 0x00, 0x38];

/// Fixed KNXnet/IP header of a SESSION_AUTHENTICATE (service `0953h`,
/// total length always 24).
const SESSION_AUTHENTICATE_HEADER: [u8; 6] = [0x06, 0x10, 0x09, 0x53, 0x00, 0x18];

/// XOR the two Curve25519 public values (client X, server Y) — the
/// shared component of both handshake MACs (§2.2.3.7.4 step 1).
pub fn xor_public_keys(x: &[u8; 32], y: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = x[i] ^ y[i];
    }
    out
}

/// Compute the SESSION_RESPONSE MAC (§2.2.3.7.4).
///
/// Key = device authentication code. A = response header(6) |
/// session id(2, BE) | XOR(X, Y)(32). P = empty, nonce = zero.
pub fn session_response_mac(device_authentication_code: &[u8; 16], session_id: u16, xor_xy: &[u8; 32]) -> [u8; 16] {
    let cipher = Aes128::new(device_authentication_code.into());
    let id = session_id.to_be_bytes();
    encrypted_mac(&cipher, &IpSecureNonce::ZERO, &[&SESSION_RESPONSE_HEADER, &id, xor_xy], &[], 0)
}

/// Verify a received SESSION_RESPONSE MAC (client side).
pub fn verify_session_response_mac(
    device_authentication_code: &[u8; 16],
    session_id: u16,
    xor_xy: &[u8; 32],
    received_mac: &[u8; 16],
) -> Result<(), CryptoError> {
    let expected = session_response_mac(device_authentication_code, session_id, xor_xy);
    if bool::from(expected.ct_eq(received_mac)) { Ok(()) } else { Err(CryptoError::MacMismatch) }
}

/// Compute the SESSION_AUTHENTICATE MAC (§2.2.3.8.4).
///
/// Key = the user's password hash. A = authenticate header(6) |
/// reserved 00h | user id(1) | XOR(X, Y)(32). P = empty, nonce = zero.
pub fn session_authenticate_mac(password_hash: &[u8; 16], user_id: u8, xor_xy: &[u8; 32]) -> [u8; 16] {
    let cipher = Aes128::new(password_hash.into());
    let ids = [0x00, user_id];
    encrypted_mac(&cipher, &IpSecureNonce::ZERO, &[&SESSION_AUTHENTICATE_HEADER, &ids, xor_xy], &[], 0)
}

/// Verify a received SESSION_AUTHENTICATE MAC (server side).
pub fn verify_session_authenticate_mac(
    password_hash: &[u8; 16],
    user_id: u8,
    xor_xy: &[u8; 32],
    received_mac: &[u8; 16],
) -> Result<(), CryptoError> {
    let expected = session_authenticate_mac(password_hash, user_id, xor_xy);
    if bool::from(expected.ct_eq(received_mac)) { Ok(()) } else { Err(CryptoError::MacMismatch) }
}

// ============================================================================
// TIMER_NOTIFY MAC (multicast — codec-level support only for now)
// ============================================================================

/// Fixed KNXnet/IP header of a TIMER_NOTIFY (service `0955h`, total
/// length always 36).
const TIMER_NOTIFY_HEADER: [u8; 6] = [0x06, 0x10, 0x09, 0x55, 0x00, 0x24];

/// Compute the TIMER_NOTIFY MAC (§2.2.2.4). Key = backbone key,
/// nonce = timer value | serial | tag, A = the frame header, P = empty.
pub fn timer_notify_mac(
    backbone_key: &[u8; 16],
    timer_value: &[u8; 6],
    serial_number: &[u8; 6],
    message_tag: &[u8; 2],
) -> [u8; 16] {
    let cipher = Aes128::new(backbone_key.into());
    let nonce = IpSecureNonce { seq_info: *timer_value, serial_number: *serial_number, message_tag: *message_tag };
    encrypted_mac(&cipher, &nonce, &[&TIMER_NOTIFY_HEADER], &[], 0)
}

/// Verify a received TIMER_NOTIFY MAC.
pub fn verify_timer_notify_mac(
    backbone_key: &[u8; 16],
    timer_value: &[u8; 6],
    serial_number: &[u8; 6],
    message_tag: &[u8; 2],
    received_mac: &[u8; 16],
) -> Result<(), CryptoError> {
    let expected = timer_notify_mac(backbone_key, timer_value, serial_number, message_tag);
    if bool::from(expected.ct_eq(received_mac)) { Ok(()) } else { Err(CryptoError::MacMismatch) }
}

// ============================================================================
// Tests using spec Appendix A test vectors
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace().map(|h| u8::from_str_radix(h, 16).expect("valid hex")).collect()
    }

    fn hex16(s: &str) -> [u8; 16] {
        hex(s).try_into().expect("16 bytes")
    }

    fn hex32(s: &str) -> [u8; 32] {
        hex(s).try_into().expect("32 bytes")
    }

    // Shared Appendix A fixtures.
    const SESSION_KEY: &str = "28 94 26 c2 91 25 35 ba 98 27 9a 4d 18 43 c4 87";
    const XOR_XY: &str =
        "b7 52 be 24 64 59 26 0f 6b 0c 48 01 fb d5 a6 75 99 f8 3b 40 57 b3 ef 1e 79 e4 69 ac 17 23 4e 15";

    #[test]
    fn appendix_a_xor_public_keys() {
        let x =
            hex32("0a a2 27 b4 fd 7a 32 31 9b a9 96 0a c0 36 ce 0e 5c 45 07 b5 ae 55 16 1f 10 78 b1 dc fb 3c b6 31");
        let y =
            hex32("bd f0 99 90 99 23 14 3e f0 a5 de 0b 3b e3 68 7b c5 bd 3c f5 f9 e6 f9 01 69 9c d8 70 ec 1f f8 24");
        assert_eq!(xor_public_keys(&x, &y), hex32(XOR_XY));
    }

    // ----------------------------------------------------------------
    // A.2.2 — SESSION_RESPONSE MAC (DAC for password "trustme")
    // ----------------------------------------------------------------
    #[test]
    fn appendix_a2_session_response_mac() {
        let dac = hex16("e1 58 e4 01 20 47 bd 6c c4 1a af bc 5c 04 c1 fc");
        let mac = session_response_mac(&dac, 0x0001, &hex32(XOR_XY));
        assert_eq!(mac, hex16("a9 22 50 5a aa 43 61 63 57 0b d5 49 4c 2d f2 a3"));

        verify_session_response_mac(&dac, 0x0001, &hex32(XOR_XY), &mac).expect("MAC just computed must verify");
        assert_eq!(
            verify_session_response_mac(&dac, 0x0002, &hex32(XOR_XY), &mac),
            Err(CryptoError::MacMismatch),
            "different session id must fail"
        );
    }

    // ----------------------------------------------------------------
    // A.3.1 — SESSION_AUTHENTICATE MAC (hash of password "secret")
    // ----------------------------------------------------------------
    #[test]
    fn appendix_a3_session_authenticate_mac() {
        let pw_hash = hex16("03 fc ed b6 66 60 25 1e c8 1a 1a 71 69 01 69 6a");
        let mac = session_authenticate_mac(&pw_hash, 0x01, &hex32(XOR_XY));
        assert_eq!(mac, hex16("1f 1d 59 ea 9f 12 a1 52 e5 d9 72 7f 08 46 2c de"));

        verify_session_authenticate_mac(&pw_hash, 0x01, &hex32(XOR_XY), &mac).expect("MAC just computed must verify");
        assert_eq!(
            verify_session_authenticate_mac(&pw_hash, 0x02, &hex32(XOR_XY), &mac),
            Err(CryptoError::MacMismatch),
            "different user id must fail"
        );
    }

    // ----------------------------------------------------------------
    // A.3.3 / A.3.4 — SECURE_WRAPPER around SESSION_AUTHENTICATE
    // ----------------------------------------------------------------
    #[test]
    fn appendix_a3_secure_wrapper() {
        let key = hex16(SESSION_KEY);
        let nonce = IpSecureNonce {
            seq_info: [0; 6],
            serial_number: [0x00, 0xfa, 0x12, 0x34, 0x56, 0x78],
            message_tag: [0xaf, 0xfe],
        };
        // A = wrapper header (total length 003Eh = 62) | session id 0001h.
        let assoc: [u8; 8] = [0x06, 0x10, 0x09, 0x50, 0x00, 0x3e, 0x00, 0x01];
        // P = the plain SESSION_AUTHENTICATE frame (24 bytes).
        let mut payload = hex("06 10 09 53 00 18 00 01 1f 1d 59 ea 9f 12 a1 52 e5 d9 72 7f 08 46 2c de");

        let mac = wrap_secure(&key, &nonce, &assoc, &mut payload);

        assert_eq!(
            payload,
            hex("79 15 a4 f3 6e 6e 42 08 d2 8b 4a 20 7d 8f 35 c0 d1 38 c2 6a 7b 5e 71 69"),
            "ciphertext mismatch"
        );
        assert_eq!(mac, hex16("52 db a8 e7 e4 bd 80 bd 7d 86 8a 3a e7 87 49 de"));

        // Round-trip: decrypt and verify.
        unwrap_secure(&key, &nonce, &assoc, &mut payload, &mac).expect("unwrap must verify");
        assert_eq!(
            payload,
            hex("06 10 09 53 00 18 00 01 1f 1d 59 ea 9f 12 a1 52 e5 d9 72 7f 08 46 2c de"),
            "plaintext mismatch after decryption"
        );
    }

    // ----------------------------------------------------------------
    // A.4.2 / A.4.3 — SECURE_WRAPPER around SESSION_STATUS
    // ----------------------------------------------------------------
    #[test]
    fn appendix_a4_secure_wrapper() {
        let key = hex16(SESSION_KEY);
        let nonce = IpSecureNonce {
            seq_info: [0; 6],
            serial_number: [0x00, 0xfa, 0xaa, 0xaa, 0xaa, 0xaa],
            message_tag: [0xaf, 0xfe],
        };
        // A = wrapper header (total length 002Eh = 46) | session id 0001h.
        let assoc: [u8; 8] = [0x06, 0x10, 0x09, 0x50, 0x00, 0x2e, 0x00, 0x01];
        // P = the plain SESSION_STATUS frame (8 bytes).
        let mut payload = hex("06 10 09 54 00 08 00 00");

        let mac = wrap_secure(&key, &nonce, &assoc, &mut payload);

        assert_eq!(payload, hex("26 15 6d b5 c7 49 88 8f"), "ciphertext mismatch");
        assert_eq!(mac, hex16("a3 73 c3 e0 b4 bd e4 49 7c 39 5e 4b 1c 2f 46 a1"));

        unwrap_secure(&key, &nonce, &assoc, &mut payload, &mac).expect("unwrap must verify");
        assert_eq!(payload, hex("06 10 09 54 00 08 00 00"));
    }

    #[test]
    fn tampered_wrapper_mac_rejected() {
        let key = hex16(SESSION_KEY);
        let nonce = IpSecureNonce {
            seq_info: [0; 6],
            serial_number: [0x00, 0xfa, 0xaa, 0xaa, 0xaa, 0xaa],
            message_tag: [0xaf, 0xfe],
        };
        let assoc: [u8; 8] = [0x06, 0x10, 0x09, 0x50, 0x00, 0x2e, 0x00, 0x01];
        let mut payload = hex("26 15 6d b5 c7 49 88 8f");
        let mut mac = hex16("a3 73 c3 e0 b4 bd e4 49 7c 39 5e 4b 1c 2f 46 a1");
        mac[0] ^= 0x01;

        assert_eq!(unwrap_secure(&key, &nonce, &assoc, &mut payload, &mac), Err(CryptoError::MacMismatch));
    }

    #[test]
    fn replayed_wrapper_with_wrong_seq_rejected() {
        // Same frame, but the receiver reconstructs the nonce with a
        // different sequence number — the MAC must not verify.
        let key = hex16(SESSION_KEY);
        let nonce = IpSecureNonce {
            seq_info: [0, 0, 0, 0, 0, 1],
            serial_number: [0x00, 0xfa, 0xaa, 0xaa, 0xaa, 0xaa],
            message_tag: [0xaf, 0xfe],
        };
        let assoc: [u8; 8] = [0x06, 0x10, 0x09, 0x50, 0x00, 0x2e, 0x00, 0x01];
        let mut payload = hex("26 15 6d b5 c7 49 88 8f");
        let mac = hex16("a3 73 c3 e0 b4 bd e4 49 7c 39 5e 4b 1c 2f 46 a1");

        assert_eq!(unwrap_secure(&key, &nonce, &assoc, &mut payload, &mac), Err(CryptoError::MacMismatch));
    }

    // ----------------------------------------------------------------
    // A.6.1 — TIMER_NOTIFY MAC
    // ----------------------------------------------------------------
    #[test]
    fn appendix_a6_timer_notify_mac() {
        let backbone_key = hex16("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f");
        let timer_value = [0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5];
        let serial = [0x00, 0xfa, 0x12, 0x34, 0x56, 0x78];
        let tag = [0xaf, 0xfe];

        let mac = timer_notify_mac(&backbone_key, &timer_value, &serial, &tag);
        assert_eq!(mac, hex16("ee 7b 9b 30 83 de b1 57 0e b3 8d 07 3a da d9 85"));

        verify_timer_notify_mac(&backbone_key, &timer_value, &serial, &tag, &mac)
            .expect("MAC just computed must verify");
    }
}
