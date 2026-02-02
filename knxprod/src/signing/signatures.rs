//! RSA signature creation and verification.
//!
//! Handles RSA-SHA1 signatures for:
//! - RegistrationInfo elements
//! - Directory signatures

use std::collections::HashMap;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use rsa::traits::PublicKeyParts;
use sha1::{Digest, Sha1};

use super::attributes::{serialize_element, REGISTRATION_INFO_ATTRS};
use super::hashes::{
    compute_hardware2program_hash, compute_hardware2program_hash_bytes, compute_product_hash,
    compute_product_hash_bytes, MapAttributeProvider,
};
use super::keys::{get_converter_private_key, get_converter_public_key, get_knx_cert_public_key, KeyType};
use super::{
    DirectorySignatureResult, Hardware2ProgramHashResult, HardwareVerificationResult, ProductHashResult,
    RegistrationSignatureResult, SigningError,
};

/// Sign data with RSA-PKCS1v15-SHA1.
///
/// Note: We use SHA1 for compatibility with ETS, even though SHA256 would be more secure.
fn sign_sha1(data: &[u8]) -> Result<Vec<u8>, SigningError> {
    let private_key = get_converter_private_key()?;

    // Hash with SHA1
    let mut hasher = Sha1::new();
    hasher.update(data);
    let hash = hasher.finalize();

    // Create the DigestInfo structure for SHA1 (PKCS#1 v1.5)
    // OID for SHA1: 1.3.14.3.2.26
    let digest_info: Vec<u8> = [
        // SEQUENCE tag + length
        0x30, 0x21, // AlgorithmIdentifier SEQUENCE
        0x30, 0x09, // OID tag + length + SHA1 OID
        0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, // NULL parameters
        0x05, 0x00, // OCTET STRING tag + length
        0x04, 0x14,
    ]
    .into_iter()
    .chain(hash.iter().copied())
    .collect();

    // Pad and sign
    let k = private_key.size();
    let em = pkcs1v15_pad(&digest_info, k)?;

    // Raw RSA operation (None for rng since we don't need blinding for signing)
    use rsa::hazmat::rsa_decrypt_and_check;
    let signature = rsa_decrypt_and_check::<rand::rngs::OsRng>(&private_key, None, &em)?;

    Ok(signature.to_bytes_be().to_vec())
}

/// PKCS#1 v1.5 padding for signature
fn pkcs1v15_pad(digest_info: &[u8], k: usize) -> Result<rsa::BigUint, SigningError> {
    let t_len = digest_info.len();
    if k < t_len + 11 {
        return Err(SigningError::Rsa(rsa::Error::MessageTooLong));
    }

    let ps_len = k - t_len - 3;
    let mut em = vec![0x00, 0x01];
    em.extend(std::iter::repeat(0xff).take(ps_len));
    em.push(0x00);
    em.extend_from_slice(digest_info);

    Ok(rsa::BigUint::from_bytes_be(&em))
}

/// Verify a signature with RSA-PKCS1v15-SHA1.
fn verify_sha1(data: &[u8], signature: &[u8], key_type: KeyType) -> Result<bool, SigningError> {
    let public_key = match key_type {
        KeyType::KnxCert => get_knx_cert_public_key()?,
        KeyType::Converter => get_converter_public_key()?,
    };

    // Hash with SHA1
    let mut hasher = Sha1::new();
    hasher.update(data);
    let hash = hasher.finalize();

    // Create DigestInfo
    let digest_info: Vec<u8> =
        [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14]
            .into_iter()
            .chain(hash.iter().copied())
            .collect();

    // Raw RSA verification
    use rsa::hazmat::rsa_encrypt;

    let signature_int = rsa::BigUint::from_bytes_be(signature);
    let em = rsa_encrypt(&public_key, &signature_int)?;

    let em_bytes = em.to_bytes_be();
    let k = public_key.size();

    // Reconstruct expected padded message
    let expected = pkcs1v15_pad(&digest_info, k)?;
    let expected_bytes = expected.to_bytes_be();

    // Compare (constant time would be better but not critical here)
    // Pad em_bytes to k bytes if needed
    let mut em_padded = vec![0u8; k.saturating_sub(em_bytes.len())];
    em_padded.extend_from_slice(&em_bytes);

    let mut expected_padded = vec![0u8; k.saturating_sub(expected_bytes.len())];
    expected_padded.extend_from_slice(&expected_bytes);

    Ok(em_padded == expected_padded)
}

/// Create a RegistrationSignature for a RegistrationInfo element.
///
/// The signature is computed over:
/// 1. Serialized RegistrationInfo attributes
/// 2. Parent element hash bytes (Product or Hardware2Program hash)
pub fn create_registration_signature(
    parent_hash_bytes: &[u8],
    registration_status: &str,
    registration_number: Option<&str>,
) -> Result<String, SigningError> {
    let mut reg_attrs = HashMap::new();
    reg_attrs.insert("RegistrationStatus".to_string(), registration_status.to_string());
    if let Some(num) = registration_number {
        reg_attrs.insert("RegistrationNumber".to_string(), num.to_string());
    }

    let reg_provider = MapAttributeProvider::new(&reg_attrs);
    let mut message = Vec::new();
    serialize_element(&mut message, &reg_provider, REGISTRATION_INFO_ATTRS).map_err(SigningError::Io)?;
    message.extend_from_slice(parent_hash_bytes);

    let signature = sign_sha1(&message)?;
    Ok(BASE64.encode(&signature))
}

/// Verify a RegistrationSignature.
pub fn verify_registration_signature(
    reg_attrs: &HashMap<String, String>,
    parent_hash_bytes: &[u8],
    signature_b64: &str,
) -> Result<KeyType, SigningError> {
    let signature = BASE64.decode(signature_b64)?;

    let reg_provider = MapAttributeProvider::new(reg_attrs);
    let mut message = Vec::new();
    serialize_element(&mut message, &reg_provider, REGISTRATION_INFO_ATTRS).map_err(SigningError::Io)?;
    message.extend_from_slice(parent_hash_bytes);

    // Try KNX cert key first
    if verify_sha1(&message, &signature, KeyType::KnxCert)? {
        return Ok(KeyType::KnxCert);
    }

    // Try converter key
    if verify_sha1(&message, &signature, KeyType::Converter)? {
        return Ok(KeyType::Converter);
    }

    Err(SigningError::VerificationFailed("Signature verification failed with both keys".to_string()))
}

/// Verify a directory signature.
pub fn verify_directory_signature(
    files: &[(String, &[u8])],
    signature_b64: &str,
) -> Result<DirectorySignatureResult, SigningError> {
    let signature = match BASE64.decode(signature_b64.trim()) {
        Ok(s) => s,
        Err(e) => {
            return Ok(DirectorySignatureResult {
                valid: false,
                key: None,
                files: 0,
                error: Some(format!("Invalid signature format: {}", e)),
            });
        }
    };

    // Build digest string using ICU collation
    let digest = build_digest_string(files)?;
    let digest_bytes = digest.as_bytes();

    // Try converter key
    if verify_sha1(digest_bytes, &signature, KeyType::Converter)? {
        return Ok(DirectorySignatureResult {
            valid: true,
            key: Some("knxconv".to_string()),
            files: files.len(),
            error: None,
        });
    }

    Ok(DirectorySignatureResult {
        valid: false,
        key: None,
        files: files.len(),
        error: Some("Signature verification failed".to_string()),
    })
}

/// Build the digest string from file hashes using ICU collation.
fn build_digest_string(files: &[(String, &[u8])]) -> Result<String, SigningError> {
    use icu::collator::{Collator, CollatorOptions};

    // Calculate SHA1 hash for each file
    let mut file_hashes: Vec<(String, String)> = files
        .iter()
        .map(|(path, content)| {
            let mut hasher = Sha1::new();
            hasher.update(content);
            let hash = BASE64.encode(hasher.finalize());
            // Convert path separators to Windows style
            let win_path = path.replace('/', "\\");
            (win_path, hash)
        })
        .collect();

    // Sort using ICU collation (root locale)
    let collator = Collator::try_new(Default::default(), CollatorOptions::default())
        .map_err(|e| SigningError::XmlWrite(format!("Failed to create collator: {:?}", e)))?;

    file_hashes.sort_by(|a, b| collator.compare(&a.0, &b.0));

    // Build digest string
    let digest = file_hashes.iter().map(|(path, hash)| format!("{}:{}", path, hash)).collect::<Vec<_>>().join(",");

    Ok(digest)
}

/// Sign directory contents and return base64 signature.
pub fn sign_directory_contents(files: &[(String, &[u8])]) -> Result<String, SigningError> {
    let digest = build_digest_string(files)?;
    let signature = sign_sha1(digest.as_bytes())?;
    Ok(BASE64.encode(&signature))
}

/// Verify all hashes and signatures in a Hardware.xml content string.
pub fn verify_hardware_xml(
    hardware_xml: &str,
    app_program_hashes: &HashMap<String, String>,
) -> Result<HardwareVerificationResult, SigningError> {
    let mut result =
        HardwareVerificationResult { products: vec![], hardware2programs: vec![], registration_signatures: vec![] };

    // Parse XML
    let mut reader = Reader::from_str(hardware_xml);
    reader.config_mut().trim_text(true);

    let mut current_hardware_attrs: Option<HashMap<String, String>> = None;
    let mut current_hardware_id = String::new();
    let mut in_products = false;
    let mut in_hardware2programs = false;
    let mut current_product_attrs: Option<HashMap<String, String>> = None;
    let mut current_h2p_attrs: Option<HashMap<String, String>> = None;
    let mut current_app_refs: Vec<String> = vec![];

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let local_name_bytes = e.local_name();
                let name = std::str::from_utf8(local_name_bytes.as_ref()).unwrap_or("");

                match name {
                    "Hardware" => {
                        let attrs = extract_attrs(&e);
                        let id = attrs.get("Id").cloned().unwrap_or_default();
                        // Skip Hardware2Program elements (they have _HP- in ID)
                        if !id.contains("_HP-") && id.contains("_H-") {
                            current_hardware_id = id;
                            current_hardware_attrs = Some(attrs);
                        }
                    }
                    "Products" => {
                        in_products = true;
                    }
                    "Hardware2Programs" => {
                        in_hardware2programs = true;
                    }
                    "Product" if in_products => {
                        current_product_attrs = Some(extract_attrs(&e));
                    }
                    "Hardware2Program" if in_hardware2programs => {
                        current_h2p_attrs = Some(extract_attrs(&e));
                        current_app_refs.clear();
                    }
                    "ApplicationProgramRef" if current_h2p_attrs.is_some() => {
                        let attrs = extract_attrs(&e);
                        if let Some(ref_id) = attrs.get("RefId") {
                            current_app_refs.push(ref_id.clone());
                        }
                    }
                    "RegistrationInfo" => {
                        let attrs = extract_attrs(&e);
                        if let Some(sig) = attrs.get("RegistrationSignature") {
                            // Determine parent type and verify
                            if let Some(ref prod_attrs) = current_product_attrs {
                                if let Some(ref hw_attrs) = current_hardware_attrs {
                                    let parent_hash = compute_product_hash_bytes(hw_attrs, prod_attrs);
                                    let parent_id = prod_attrs.get("Id").cloned().unwrap_or_default();

                                    let sig_result = match verify_registration_signature(&attrs, &parent_hash, sig) {
                                        Ok(key) => RegistrationSignatureResult {
                                            parent_id,
                                            parent_type: "Product".to_string(),
                                            status: attrs.get("RegistrationStatus").cloned(),
                                            date: attrs.get("RegistrationDate").cloned(),
                                            number: attrs.get("RegistrationNumber").cloned(),
                                            valid: true,
                                            key: Some(key.to_string()),
                                            error: None,
                                        },
                                        Err(e) => RegistrationSignatureResult {
                                            parent_id,
                                            parent_type: "Product".to_string(),
                                            status: attrs.get("RegistrationStatus").cloned(),
                                            date: attrs.get("RegistrationDate").cloned(),
                                            number: attrs.get("RegistrationNumber").cloned(),
                                            valid: false,
                                            key: None,
                                            error: Some(e.to_string()),
                                        },
                                    };
                                    result.registration_signatures.push(sig_result);
                                }
                            } else if let Some(ref h2p_attrs) = current_h2p_attrs {
                                if let Some(ref hw_attrs) = current_hardware_attrs {
                                    let h2p_app_hashes: Vec<String> = current_app_refs
                                        .iter()
                                        .filter_map(|r| app_program_hashes.get(r).cloned())
                                        .collect();

                                    let parent_hash = compute_hardware2program_hash_bytes(
                                        hw_attrs,
                                        h2p_attrs,
                                        &current_app_refs,
                                        if h2p_app_hashes.is_empty() { None } else { Some(&h2p_app_hashes) },
                                    );
                                    let parent_id = h2p_attrs.get("Id").cloned().unwrap_or_default();

                                    let sig_result = match verify_registration_signature(&attrs, &parent_hash, sig) {
                                        Ok(key) => RegistrationSignatureResult {
                                            parent_id,
                                            parent_type: "Hardware2Program".to_string(),
                                            status: attrs.get("RegistrationStatus").cloned(),
                                            date: attrs.get("RegistrationDate").cloned(),
                                            number: attrs.get("RegistrationNumber").cloned(),
                                            valid: true,
                                            key: Some(key.to_string()),
                                            error: None,
                                        },
                                        Err(e) => RegistrationSignatureResult {
                                            parent_id,
                                            parent_type: "Hardware2Program".to_string(),
                                            status: attrs.get("RegistrationStatus").cloned(),
                                            date: attrs.get("RegistrationDate").cloned(),
                                            number: attrs.get("RegistrationNumber").cloned(),
                                            valid: false,
                                            key: None,
                                            error: Some(e.to_string()),
                                        },
                                    };
                                    result.registration_signatures.push(sig_result);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::End(e)) => {
                let local_name_bytes = e.local_name();
                let name = std::str::from_utf8(local_name_bytes.as_ref()).unwrap_or("");
                match name {
                    "Hardware" => {
                        current_hardware_attrs = None;
                        current_hardware_id.clear();
                    }
                    "Products" => {
                        in_products = false;
                    }
                    "Hardware2Programs" => {
                        in_hardware2programs = false;
                    }
                    "Product" => {
                        // Verify product hash if present
                        if let (Some(hw_attrs), Some(prod_attrs)) = (&current_hardware_attrs, &current_product_attrs) {
                            if let Some(expected_hash) = prod_attrs.get("Hash") {
                                let computed_hash = compute_product_hash(hw_attrs, prod_attrs);
                                let id = prod_attrs.get("Id").cloned().unwrap_or_default();

                                result.products.push(ProductHashResult {
                                    id,
                                    hardware_id: current_hardware_id.clone(),
                                    expected: expected_hash.clone(),
                                    computed: computed_hash.clone(),
                                    valid: expected_hash == &computed_hash,
                                });
                            }
                        }
                        current_product_attrs = None;
                    }
                    "Hardware2Program" => {
                        // Verify H2P hash if present
                        if let (Some(hw_attrs), Some(h2p_attrs)) = (&current_hardware_attrs, &current_h2p_attrs) {
                            if let Some(expected_hash) = h2p_attrs.get("Hash") {
                                let h2p_app_hashes: Vec<String> = current_app_refs
                                    .iter()
                                    .filter_map(|r| app_program_hashes.get(r).cloned())
                                    .collect();

                                let computed_hash = compute_hardware2program_hash(
                                    hw_attrs,
                                    h2p_attrs,
                                    &current_app_refs,
                                    if h2p_app_hashes.is_empty() { None } else { Some(&h2p_app_hashes) },
                                );

                                let id = h2p_attrs.get("Id").cloned().unwrap_or_default();

                                result.hardware2programs.push(Hardware2ProgramHashResult {
                                    id,
                                    hardware_id: current_hardware_id.clone(),
                                    expected: expected_hash.clone(),
                                    computed: computed_hash.clone(),
                                    valid: expected_hash == &computed_hash,
                                    app_refs: current_app_refs.clone(),
                                    app_hashes_found: h2p_app_hashes.len(),
                                });
                            }
                        }
                        current_h2p_attrs = None;
                        current_app_refs.clear();
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(SigningError::XmlWrite(format!("XML parse error: {}", e))),
            _ => {}
        }
    }

    Ok(result)
}

/// Extract attributes from an XML element as a HashMap.
fn extract_attrs(e: &BytesStart) -> HashMap<String, String> {
    let mut attrs = HashMap::new();
    for attr in e.attributes().flatten() {
        if let (Ok(key), Ok(value)) = (std::str::from_utf8(attr.key.as_ref()), std::str::from_utf8(&attr.value)) {
            attrs.insert(key.to_string(), value.to_string());
        }
    }
    attrs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify_registration() {
        let parent_hash = vec![0u8; 20]; // Dummy hash

        let signature = create_registration_signature(&parent_hash, "Registered", None).expect("sign");

        // The signature should be valid base64
        assert!(BASE64.decode(&signature).is_ok());

        // Verify the signature
        let mut reg_attrs = HashMap::new();
        reg_attrs.insert("RegistrationStatus".to_string(), "Registered".to_string());

        let key = verify_registration_signature(&reg_attrs, &parent_hash, &signature).expect("verify");
        assert_eq!(key, KeyType::Converter);
    }

    #[test]
    fn test_sign_directory() {
        let files = vec![
            ("test.txt".to_string(), b"hello world".as_slice()),
            ("folder\\file.xml".to_string(), b"<xml/>".as_slice()),
        ];

        let signature = sign_directory_contents(&files).expect("sign");
        assert!(BASE64.decode(&signature).is_ok());

        // Verify
        let result = verify_directory_signature(&files, &signature).expect("verify");
        assert!(result.valid);
        assert_eq!(result.key.as_deref(), Some("knxconv"));
    }
}
