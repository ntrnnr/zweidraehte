//! Owned secret bytes shared by bus access, file formats and persistence.

#![forbid(unsafe_code)]

use alloc::{string::String, vec::Vec};
use core::fmt;

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// A secret cannot be viewed as the requested fixed-width key.
///
/// Carries lengths only, so reporting the error never exposes the secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretLengthError {
    pub expected: usize,
    pub actual: usize,
}

impl fmt::Display for SecretLengthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "expected {} key bytes, got {}", self.expected, self.actual)
    }
}

impl core::error::Error for SecretLengthError {}

/// Owned bytes with redacted diagnostics and zeroization on drop.
///
/// Bytes are exposed explicitly through borrowed accessors. A copy returned by
/// [`Self::key16`] belongs to the caller and is not zeroized by this container.
/// Serialization and `Display` are intentionally absent: formats must choose
/// explicitly where and how to encode secret material.
///
/// ```
/// use zweidraehte_util::secret::SecretBytes;
///
/// let tool_key = SecretBytes::from([0x42; 16]);
/// assert_eq!(tool_key.key16_ref()?, &[0x42; 16]);
/// assert_eq!(format!("{tool_key:?}"), "SecretBytes([REDACTED])");
/// # Ok::<(), zweidraehte_util::secret::SecretLengthError>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Shorten a secret buffer while zeroizing the discarded suffix.
    pub fn truncate(&mut self, len: usize) {
        if len >= self.0.len() {
            return;
        }
        self.0[len..].zeroize();
        self.0.truncate(len);
    }

    /// Copy a 16-byte key out of this container.
    ///
    /// # Errors
    ///
    /// Returns [`SecretLengthError`] unless the secret contains exactly 16 bytes.
    pub fn key16(&self) -> Result<[u8; 16], SecretLengthError> {
        self.0.as_slice().try_into().map_err(|_| SecretLengthError { expected: 16, actual: self.0.len() })
    }

    /// Borrow a 16-byte key without making another copy of the secret.
    ///
    /// # Errors
    ///
    /// Returns [`SecretLengthError`] unless the secret contains exactly 16 bytes.
    pub fn key16_ref(&self) -> Result<&[u8; 16], SecretLengthError> {
        self.0.as_slice().try_into().map_err(|_| SecretLengthError { expected: 16, actual: self.0.len() })
    }

    /// Borrow a textual credential.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not valid UTF-8.
    pub fn as_str(&self) -> Result<&str, core::str::Utf8Error> {
        core::str::from_utf8(&self.0)
    }

    /// SHA-256 of the original bytes, shared with persisted key metadata.
    pub fn fingerprint(&self) -> [u8; 32] {
        Sha256::digest(&self.0).into()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes([REDACTED])")
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

impl From<String> for SecretBytes {
    fn from(value: String) -> Self {
        Self::new(value.into_bytes())
    }
}

impl<const N: usize> From<[u8; N]> for SecretBytes {
    fn from(value: [u8; N]) -> Self {
        Self::new(value)
    }
}

impl Zeroize for SecretBytes {
    fn zeroize(&mut self) {
        // Preserve the length so callers can verify or reuse an explicitly
        // cleared buffer. `Vec<u8>`'s blanket implementation also empties the
        // vector after clearing its allocation, which hides that postcondition.
        self.0.as_mut_slice().zeroize();
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_width_access_borrows_or_copies_only_complete_keys() {
        let key = SecretBytes::from([0x37; 16]);
        let borrowed = key.key16_ref().expect("sixteen-byte key");
        assert_eq!(borrowed.as_ptr(), key.as_slice().as_ptr());
        assert_eq!(key.key16().expect("sixteen-byte key"), *borrowed);

        for actual in [0, 15, 17] {
            let short_or_long = SecretBytes::new(vec![0x37; actual]);
            let expected = SecretLengthError { expected: 16, actual };
            assert_eq!(short_or_long.key16(), Err(expected));
            assert_eq!(short_or_long.key16_ref(), Err(expected));
            assert_eq!(expected.to_string(), format!("expected 16 key bytes, got {actual}"));
        }
    }

    #[test]
    fn fingerprint_keeps_the_existing_sha256_domain() {
        // Fixed witness: changing the hash or adding a domain prefix would
        // invalidate persisted key provenance and credential commitments.
        let secret = SecretBytes::from(String::from("abc"));
        assert_eq!(secret.fingerprint(), [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03,
            0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
        ]);
    }

    #[test]
    fn truncation_preserves_the_prefix_without_growing_secrets() {
        let mut secret = SecretBytes::from(String::from("credential-padding"));
        secret.truncate(10);
        assert_eq!(secret.as_str().expect("ASCII credential"), "credential");
        secret.truncate(20);
        assert_eq!(secret.len(), 10);
        secret.truncate(0);
        assert!(secret.is_empty());
    }

    #[test]
    fn secret_buffers_redact_and_zeroize_explicitly() {
        let canary = b"credential-canary";
        let mut secret = SecretBytes::new(canary.to_vec());
        let diagnostic = format!("{secret:?}");
        assert!(!diagnostic.contains("credential-canary"));

        secret.zeroize();
        assert_eq!(secret.as_slice(), vec![0; canary.len()]);
    }
}
