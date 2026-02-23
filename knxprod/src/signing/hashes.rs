//! Hash computation for KNX product elements.
//!
//! Computes SHA1 hashes for Product and Hardware2Program elements
//! following the ETS format.

use std::collections::HashMap;
use std::io::Write;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use sha1::{Digest, Sha1};

use super::attributes::{
    normalize_appl_prog_id, serialize_element, AttributeProvider, APPLICATION_PROGRAM_ATTRS, HARDWARE2PROGRAM_ATTRS,
    HARDWARE_ATTRS, PRODUCT_ATTRS,
};
use super::binary_writer::write_dotnet_string;

/// A simple attribute provider backed by a HashMap.
pub struct MapAttributeProvider<'a> {
    attrs: &'a HashMap<String, String>,
}

impl<'a> MapAttributeProvider<'a> {
    pub fn new(attrs: &'a HashMap<String, String>) -> Self {
        Self { attrs }
    }
}

impl<'a> AttributeProvider for MapAttributeProvider<'a> {
    fn get_attribute(&self, name: &str) -> Option<&str> {
        self.attrs.get(name).map(|s| s.as_str())
    }
}

/// Compute the SHA1 hash bytes for a Product element.
///
/// The hash is computed from:
/// 1. Serialized Hardware element attributes
/// 2. Serialized Product element attributes
pub fn compute_product_hash_bytes(
    hardware_attrs: &HashMap<String, String>,
    product_attrs: &HashMap<String, String>,
) -> Vec<u8> {
    let mut data = Vec::new();

    let hw_provider = MapAttributeProvider::new(hardware_attrs);
    let prod_provider = MapAttributeProvider::new(product_attrs);

    serialize_element(&mut data, &hw_provider, HARDWARE_ATTRS).expect("serialize hardware");
    serialize_element(&mut data, &prod_provider, PRODUCT_ATTRS).expect("serialize product");

    let mut hasher = Sha1::new();
    hasher.update(&data);
    hasher.finalize().to_vec()
}

/// Compute the SHA1 hash for a Product element as base64 string.
pub fn compute_product_hash(
    hardware_attrs: &HashMap<String, String>,
    product_attrs: &HashMap<String, String>,
) -> String {
    BASE64.encode(compute_product_hash_bytes(hardware_attrs, product_attrs))
}

/// Compute the SHA1 hash bytes for an ApplicationProgram element.
///
/// The hash is computed from the serialized ApplicationProgram element attributes.
pub fn compute_application_program_hash_bytes(app_program_attrs: &HashMap<String, String>) -> Vec<u8> {
    let mut data = Vec::new();

    let provider = MapAttributeProvider::new(app_program_attrs);
    serialize_element(&mut data, &provider, APPLICATION_PROGRAM_ATTRS).expect("serialize application program");

    let mut hasher = Sha1::new();
    hasher.update(&data);
    hasher.finalize().to_vec()
}

/// Compute the SHA1 hash for an ApplicationProgram element as base64 string.
pub fn compute_application_program_hash(app_program_attrs: &HashMap<String, String>) -> String {
    BASE64.encode(compute_application_program_hash_bytes(app_program_attrs))
}

/// Serialize an ApplicationProgramRef element with ID normalization.
fn serialize_app_ref(ref_id: &str) -> Vec<u8> {
    let mut data = Vec::new();
    write_dotnet_string(&mut data, Some("R")).expect("write short name");
    let normalized = normalize_appl_prog_id(ref_id);
    write_dotnet_string(&mut data, Some(&normalized)).expect("write ref id");
    data
}

/// Compute the SHA1 hash bytes for a Hardware2Program element.
///
/// The correct order is:
/// 1. Hardware element serialization
/// 2. Application Program hashes (as UTF-16LE encoded strings)
/// 3. Hardware2Program element serialization
/// 4. ApplicationProgramRef elements (with normalized IDs, sorted)
pub fn compute_hardware2program_hash_bytes(
    hardware_attrs: &HashMap<String, String>,
    h2p_attrs: &HashMap<String, String>,
    app_ref_ids: &[String],
    app_program_hashes: Option<&[String]>,
) -> Vec<u8> {
    let mut data = Vec::new();

    // 1. Hardware element
    let hw_provider = MapAttributeProvider::new(hardware_attrs);
    serialize_element(&mut data, &hw_provider, HARDWARE_ATTRS).expect("serialize hardware");

    // 2. Application Program hashes (UTF-16LE encoding, like .NET Encoding.Unicode)
    if let Some(hashes) = app_program_hashes {
        for hash_str in hashes {
            // Encode as UTF-16LE
            for ch in hash_str.encode_utf16() {
                data.write_all(&ch.to_le_bytes()).expect("write utf16");
            }
        }
    }

    // 3. Hardware2Program element
    let h2p_provider = MapAttributeProvider::new(h2p_attrs);
    serialize_element(&mut data, &h2p_provider, HARDWARE2PROGRAM_ATTRS).expect("serialize h2p");

    // 4. ApplicationProgramRef elements sorted by normalized RefId
    let mut sorted_refs: Vec<_> = app_ref_ids.iter().collect();
    sorted_refs.sort_by_key(|a| normalize_appl_prog_id(a));

    for ref_id in sorted_refs {
        data.extend(serialize_app_ref(ref_id));
    }

    let mut hasher = Sha1::new();
    hasher.update(&data);
    hasher.finalize().to_vec()
}

/// Compute the SHA1 hash for a Hardware2Program element as base64 string.
pub fn compute_hardware2program_hash(
    hardware_attrs: &HashMap<String, String>,
    h2p_attrs: &HashMap<String, String>,
    app_ref_ids: &[String],
    app_program_hashes: Option<&[String]>,
) -> String {
    BASE64.encode(compute_hardware2program_hash_bytes(hardware_attrs, h2p_attrs, app_ref_ids, app_program_hashes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_product_hash() {
        let mut hw_attrs = HashMap::new();
        hw_attrs.insert("Id".to_string(), "M-0083_H-009B-14-E59D".to_string());
        hw_attrs.insert("SerialNumber".to_string(), "KP BE 01".to_string());
        hw_attrs.insert("VersionNumber".to_string(), "14".to_string());
        hw_attrs.insert("HasIndividualAddress".to_string(), "1".to_string());
        hw_attrs.insert("HasApplicationProgram".to_string(), "1".to_string());

        let mut prod_attrs = HashMap::new();
        prod_attrs.insert("Id".to_string(), "M-0083_H-009B-14-E59D_P-KP-BE-01".to_string());
        prod_attrs.insert("OrderNumber".to_string(), "BE-TA55P6.G1".to_string());

        let hash = compute_product_hash(&hw_attrs, &prod_attrs);
        // The hash should be a valid base64 string
        assert!(BASE64.decode(&hash).is_ok());
        // SHA1 produces 20 bytes = 28 base64 chars (with padding)
        assert_eq!(hash.len(), 28);
    }

    #[test]
    fn test_compute_hardware2program_hash() {
        let mut hw_attrs = HashMap::new();
        hw_attrs.insert("Id".to_string(), "M-0083_H-009B-14-E59D".to_string());
        hw_attrs.insert("SerialNumber".to_string(), "KP BE 01".to_string());
        hw_attrs.insert("VersionNumber".to_string(), "14".to_string());
        hw_attrs.insert("HasIndividualAddress".to_string(), "1".to_string());
        hw_attrs.insert("HasApplicationProgram".to_string(), "1".to_string());

        let mut h2p_attrs = HashMap::new();
        h2p_attrs.insert("Id".to_string(), "M-0083_H-009B-14-E59D_HP-009B-14-E59D".to_string());

        let app_refs = vec!["M-0083_A-009B-14-E59D".to_string()];
        let app_hashes = vec!["abc123==".to_string()];

        let hash = compute_hardware2program_hash(&hw_attrs, &h2p_attrs, &app_refs, Some(&app_hashes));
        // The hash should be a valid base64 string
        assert!(BASE64.decode(&hash).is_ok());
        assert_eq!(hash.len(), 28);
    }
}
