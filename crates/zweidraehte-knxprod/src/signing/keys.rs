//! RSA key management for KNX signing.
//!
//! Two keys are involved in KNX product signing:
//!
//! - **KNX Certification Key** — the public key used to *verify* officially
//!   certified products. Only the public modulus/exponent are needed.
//! - **Converter Key** — the RSA key pair used to *sign* converted legacy
//!   products. Its public modulus/exponent are embedded here (they are not
//!   sensitive), but the **private** components (`P`, `Q`, `D`) are loaded at
//!   runtime from a local `converter_key.xml` file at the workspace root (see
//!   [`converter_private_components`]). That file is not part of the repository —
//!   provide your own copy in the `.NET RSAKeyValue` XML format (`<P>`, `<Q>`,
//!   `<D>`, …).

use std::path::PathBuf;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use num_bigint_dig::BigUint;
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use rsa::{RsaPrivateKey, RsaPublicKey};

use super::SigningError;

/// KNX Certification public key.
/// Used for verifying officially certified products.
const KNX_CERT_MODULUS: &str = "iv+3sqx5QJie+bm8nWvUt/WHfiVu9ZDggfq887TETgj9SO6MMBFr18bZvVOg7U9NlcW2aLOFxhpk5CJbX+gR5GwjNeOydTxm3gFjGj1lZ0nxxPb4KyfkmcDVhVFUo3HpIIl7cybfrxhmWXyR2s3gYiSIsfnfF3M6Ga7o1Ryq0Es=";
const KNX_CERT_EXPONENT: &str = "AQAB";

/// Converter public key (from Knx.Ets.XmlSigning.dll - Knx.Ets.XmlSigning.XmlSigning.GetConverterRsaKey()).
/// Used for verifying converted legacy product definitions.
const CONVERTER_MODULUS: &str = "zSjrmVmM+ULXdrFHiSZZo7PEHo/sXBIkjxHkqQbxEI2YE1SBq0dbEfqW3eDSdjLlpMy5Yx9hcMSnrmVUWh3PgBBQmzMBZpr/yJRny8UzB1pqTPyisWyfg7+NiAd1Ize4r/bQxKE4BaJ2wqEDwH8ggg2faxJ2/WReGVrrzJL2u00=";
const CONVERTER_EXPONENT: &str = "AQAB";

/// Name of the converter private-key file, resolved relative to the workspace root.
const CONVERTER_KEY_FILE: &str = "converter_key.xml";

/// Convert base64-encoded string to BigUint.
fn b64_to_biguint(b64: &str) -> Result<BigUint, SigningError> {
    let bytes = BASE64.decode(b64.trim())?;
    Ok(BigUint::from_bytes_be(&bytes))
}

/// The private RSA components parsed from a `.NET RSAKeyValue` XML document.
///
/// Only the secret parts we need for signing are captured; the public
/// modulus/exponent live in the source above, and the CRT parameters (`DP`,
/// `DQ`, `InverseQ`) are recomputed by the `rsa` crate from the primes.
struct ConverterPrivateComponents {
    p: BigUint,
    q: BigUint,
    d: BigUint,
}

/// Parse the `<P>`, `<Q>`, and `<D>` elements out of a `.NET RSAKeyValue` XML
/// document.
///
/// The document looks like
/// `<RSAKeyValue><Modulus>…</Modulus>…<P>…</P><Q>…</Q>…<D>…</D></RSAKeyValue>`.
/// Each component is big-endian and base64-encoded, matching what
/// [`b64_to_biguint`] expects. Elements we do not need are ignored.
fn parse_private_components(xml: &str) -> Result<ConverterPrivateComponents, SigningError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let (mut p, mut q, mut d) = (None, None, None);
    // Which captured element we are currently inside, if any.
    let mut current: Option<&mut Option<String>> = None;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => {
                current = match e.name().as_ref() {
                    b"P" => Some(&mut p),
                    b"Q" => Some(&mut q),
                    b"D" => Some(&mut d),
                    _ => None,
                };
            }
            Event::Text(e) => {
                if let Some(slot) = current.as_mut() {
                    **slot = Some(e.unescape()?.into_owned());
                }
            }
            Event::End(_) => current = None,
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    let component = |value: Option<String>, name: &'static str| -> Result<BigUint, SigningError> {
        b64_to_biguint(&value.ok_or(SigningError::ConverterKeyComponentMissing(name))?)
    };

    Ok(ConverterPrivateComponents { p: component(p, "P")?, q: component(q, "Q")?, d: component(d, "D")? })
}

/// Candidate locations for the converter private-key file, in priority order.
///
/// The crate lives two directories below the workspace root
/// (`crates/zweidraehte-knxprod`), so the workspace-root copy resolves relative
/// to `CARGO_MANIFEST_DIR`. Binaries run from an arbitrary working directory
/// (e.g. a shipped tool) fall back to the current directory.
fn converter_key_candidates() -> [PathBuf; 2] {
    [
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").join(CONVERTER_KEY_FILE),
        PathBuf::from(CONVERTER_KEY_FILE),
    ]
}

/// Load and parse the converter private components from `converter_key.xml`.
///
/// Tries each [`converter_key_candidates`] path and uses the first that exists.
/// If none is found, the error names the last path tried.
fn converter_private_components() -> Result<ConverterPrivateComponents, SigningError> {
    let candidates = converter_key_candidates();
    let mut last_err = None;
    for path in &candidates {
        match std::fs::read_to_string(path) {
            Ok(xml) => return parse_private_components(&xml),
            Err(source) => {
                last_err = Some(SigningError::ConverterKeyFile { path: path.display().to_string(), source });
            }
        }
    }
    Err(last_err.expect("converter_key_candidates is never empty"))
}

/// Get the KNX Certification public key.
///
/// This key is used by officially certified KNX products.
/// We only support verification with this key, not signing.
pub fn get_knx_cert_public_key() -> Result<RsaPublicKey, SigningError> {
    let n = b64_to_biguint(KNX_CERT_MODULUS)?;
    let e = b64_to_biguint(KNX_CERT_EXPONENT)?;
    Ok(RsaPublicKey::new(n, e)?)
}

/// Get the Converter public key.
///
/// This key signs converted legacy product definitions.
pub fn get_converter_public_key() -> Result<RsaPublicKey, SigningError> {
    let n = b64_to_biguint(CONVERTER_MODULUS)?;
    let e = b64_to_biguint(CONVERTER_EXPONENT)?;
    Ok(RsaPublicKey::new(n, e)?)
}

/// Get the Converter private key.
///
/// This key signs converted legacy product definitions. The public
/// modulus/exponent are embedded; the private components are read from
/// `converter_key.xml`.
pub fn get_converter_private_key() -> Result<RsaPrivateKey, SigningError> {
    let n = b64_to_biguint(CONVERTER_MODULUS)?;
    let e = b64_to_biguint(CONVERTER_EXPONENT)?;
    let secret = converter_private_components()?;

    // Note: The rsa crate will compute dp, dq, qi from the primes.
    Ok(RsaPrivateKey::from_components(n, e, secret.d, vec![secret.p, secret.q])?)
}

/// Key type used for signing/verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// KNX Certification key (official products)
    KnxCert,
    /// Converter key (converted legacy product definitions)
    Converter,
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyType::KnxCert => write!(f, "knxcert"),
            KeyType::Converter => write!(f, "knxconv"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::traits::PublicKeyParts;

    #[test]
    fn test_load_knx_cert_public_key() {
        let key = get_knx_cert_public_key().expect("Failed to load KNX cert key");
        // Key should be 1024 bits
        assert_eq!(key.size() * 8, 1024);
    }

    #[test]
    fn test_load_converter_public_key() {
        let key = get_converter_public_key().expect("Failed to load converter public key");
        assert_eq!(key.size() * 8, 1024);
    }

    #[test]
    fn test_load_converter_private_key() {
        let key = get_converter_private_key().expect("Failed to load converter private key");
        assert_eq!(key.size() * 8, 1024);
    }
}
