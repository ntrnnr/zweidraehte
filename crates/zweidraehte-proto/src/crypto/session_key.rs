//! KNX IP Secure session-key agreement (03/08/09 §2.2.3.1.2).
//!
//! Curve25519 ECDH between the client's ephemeral public value X and
//! the server's ephemeral public value Y, then
//!
//! ```text
//! session_key = SHA-256(sharedSecret)[0..16]
//! ```
//!
//! Only available with the `ip-secure` cargo feature — curve25519 is a
//! heavy dependency that non-secure builds must not pay for.
//!
//! Password hashes and the device authentication code are *not*
//! derived here: their PBKDF2 derivation (§2.3.1.3/§2.3.1.4) happens in
//! the commissioning tool (ETS); the device only ever stores and uses
//! the finished 16-byte hashes.

use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

/// Generate an ephemeral Curve25519 keypair from caller-provided
/// entropy. Returns `(private_key, public_key)`.
///
/// The entropy must come from a cryptographically secure RNG; the
/// X25519 clamping of the scalar happens internally during the
/// Diffie-Hellman computation, so the raw entropy bytes double as the
/// stored private key.
pub fn generate_keypair(entropy: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::from(*entropy);
    let public = PublicKey::from(&secret);
    (secret.to_bytes(), *public.as_bytes())
}

/// Compute the X25519 shared secret `Curve25519(my_private, peer_public)`.
pub fn x25519_dh(my_private: &[u8; 32], peer_public: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*my_private);
    let public = PublicKey::from(*peer_public);
    *secret.diffie_hellman(&public).as_bytes()
}

/// Derive the AES-128 session key from the ECDH shared secret:
/// the first 16 bytes of its SHA-256 hash (§2.2.3.1.2).
pub fn derive_session_key(shared_secret: &[u8; 32]) -> [u8; 16] {
    let digest = Sha256::digest(shared_secret);
    let mut key = [0u8; 16];
    key.copy_from_slice(&digest[..16]);
    key
}

// ============================================================================
// Tests using spec Appendix A test vectors
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        s.split_whitespace()
            .map(|h| u8::from_str_radix(h, 16).expect("valid hex"))
            .collect::<Vec<_>>()
            .try_into()
            .expect("32 bytes")
    }

    // Appendix A.1.1 client keypair.
    const CLIENT_PRIVATE: &str =
        "b8 fa bd 62 66 5d 8b 9e 8a 9d 8b 1f 4b ca 42 c8 c2 78 9a 61 10 f5 0e 9d d7 85 b3 ed e8 83 f3 78";
    const CLIENT_PUBLIC: &str =
        "0a a2 27 b4 fd 7a 32 31 9b a9 96 0a c0 36 ce 0e 5c 45 07 b5 ae 55 16 1f 10 78 b1 dc fb 3c b6 31";

    // Appendix A.2.1 server keypair.
    const SERVER_PRIVATE: &str =
        "68 c1 74 48 13 f4 e6 5c f1 0c ca 67 1c aa 13 36 a7 96 b4 ac 40 cc 5c f2 65 56 74 22 5c 1e 52 64";
    const SERVER_PUBLIC: &str =
        "bd f0 99 90 99 23 14 3e f0 a5 de 0b 3b e3 68 7b c5 bd 3c f5 f9 e6 f9 01 69 9c d8 70 ec 1f f8 24";

    // Appendix A.2.4.
    const SHARED_SECRET: &str =
        "d8 01 52 52 17 61 8f 0d a9 0a 4f f2 21 48 ae e0 ff 4c 19 b4 30 e8 08 12 23 ff e9 9c 81 a9 8b 05";

    #[test]
    fn appendix_a1_client_keypair() {
        let (private, public) = generate_keypair(&hex32(CLIENT_PRIVATE));
        assert_eq!(private, hex32(CLIENT_PRIVATE));
        assert_eq!(public, hex32(CLIENT_PUBLIC));
    }

    #[test]
    fn appendix_a2_server_keypair() {
        let (_, public) = generate_keypair(&hex32(SERVER_PRIVATE));
        assert_eq!(public, hex32(SERVER_PUBLIC));
    }

    #[test]
    fn appendix_a2_shared_secret_both_directions() {
        let from_client = x25519_dh(&hex32(CLIENT_PRIVATE), &hex32(SERVER_PUBLIC));
        let from_server = x25519_dh(&hex32(SERVER_PRIVATE), &hex32(CLIENT_PUBLIC));
        assert_eq!(from_client, hex32(SHARED_SECRET));
        assert_eq!(from_server, hex32(SHARED_SECRET));
    }

    #[test]
    fn appendix_a2_session_key() {
        let key = derive_session_key(&hex32(SHARED_SECRET));
        assert_eq!(key, [
            0x28, 0x94, 0x26, 0xc2, 0x91, 0x25, 0x35, 0xba, 0x98, 0x27, 0x9a, 0x4d, 0x18, 0x43, 0xc4, 0x87
        ]);
    }
}
