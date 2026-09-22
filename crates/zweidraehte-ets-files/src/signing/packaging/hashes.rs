//! Hash computation for KNX product elements.
//!
//! Computes SHA1 hashes for Product and Hardware2Program elements
//! following the ETS format.

use std::collections::HashMap;
use std::io::Write;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use sha1::{Digest, Sha1};

use super::attributes::{
    APPLICATION_PROGRAM_ATTRS, AttributeProvider, HARDWARE_ATTRS, HARDWARE2PROGRAM_ATTRS, PRODUCT_ATTRS,
    normalize_appl_prog_id, serialize_element, write_attribute,
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
    compute_product_hash_bytes_for_schema(hardware_attrs, product_attrs, None)
}

pub(super) fn compute_product_hash_bytes_for_schema(
    hardware_attrs: &HashMap<String, String>,
    product_attrs: &HashMap<String, String>,
    schema_version: Option<u16>,
) -> Vec<u8> {
    let mut data = Vec::new();

    let hw_provider = MapAttributeProvider::new(hardware_attrs);
    let prod_provider = MapAttributeProvider::new(product_attrs);

    serialize_hardware(&mut data, &hw_provider, schema_version).expect("serialize hardware");
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
    compute_hardware2program_hash_bytes_for_schema(hardware_attrs, h2p_attrs, app_ref_ids, app_program_hashes, None)
}

pub(super) fn compute_hardware2program_hash_bytes_for_schema(
    hardware_attrs: &HashMap<String, String>,
    h2p_attrs: &HashMap<String, String>,
    app_ref_ids: &[String],
    app_program_hashes: Option<&[String]>,
    schema_version: Option<u16>,
) -> Vec<u8> {
    let mut data = Vec::new();

    // 1. Hardware element
    let hw_provider = MapAttributeProvider::new(hardware_attrs);
    serialize_hardware(&mut data, &hw_provider, schema_version).expect("serialize hardware");

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
    serialize_hardware2program(&mut data, &h2p_provider, schema_version).expect("serialize h2p");

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

fn serialize_hardware<W: Write, E: AttributeProvider>(
    writer: &mut W,
    hardware: &E,
    schema_version: Option<u16>,
) -> std::io::Result<()> {
    for attribute in HARDWARE_ATTRS {
        // KNX changed the registration stream together with the RF hardware
        // model. Project/12..19 use the legacy device-mode pair; project/20
        // replaces it with separate Rx/Tx capabilities. These absent values
        // are still serialized as null/defaults, so mixing the two models
        // changes every Product and H2P hash even for an ordinary TP device.
        let relevant = match attribute.xml_name {
            "IsRFRetransmitter" => schema_version.is_none_or(|version| version >= 12),
            "RFDeviceMode" | "RuntimeUnidirectional" => {
                schema_version.is_some_and(|version| (12..20).contains(&version))
            }
            "RFRxCapabilities" | "RFTxCapabilities" => schema_version.is_none_or(|version| version >= 20),
            _ => true,
        };
        if !relevant {
            continue;
        }
        write_attribute(writer, attribute, hardware.get_attribute(attribute.xml_name))?;
    }
    Ok(())
}

fn serialize_hardware2program<W: Write, E: AttributeProvider>(
    writer: &mut W,
    relation: &E,
    schema_version: Option<u16>,
) -> std::io::Result<()> {
    for attribute in HARDWARE2PROGRAM_ATTRS {
        // CheckSums/LoadedImage entered the stream in project/11, while
        // CouplerCapabilities did not enter it until project/20.
        let relevant = match attribute.xml_name {
            "CheckSums" | "LoadedImage" => schema_version.is_none_or(|version| version >= 11),
            "CouplerCapabilities" => schema_version.is_none_or(|version| version >= 20),
            _ => true,
        };
        if !relevant {
            continue;
        }
        write_attribute(writer, attribute, relation.get_attribute(attribute.xml_name))?;
    }
    Ok(())
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

    #[test]
    fn registration_attributes_follow_schema_versions() {
        let attrs = HashMap::new();
        let provider = MapAttributeProvider::new(&attrs);
        let serialize_hardware_for = |version| {
            let mut bytes = Vec::new();
            serialize_hardware(&mut bytes, &provider, Some(version)).expect("attributes serialize");
            bytes
        };
        let serialize_h2p_for = |version| {
            let mut bytes = Vec::new();
            serialize_hardware2program(&mut bytes, &provider, Some(version)).expect("attributes serialize");
            bytes
        };
        let contains = |bytes: &[u8], value: &[u8]| bytes.windows(value.len()).any(|window| window == value);

        let version_10 = serialize_hardware_for(10);
        assert!(!contains(&version_10, b"RFR"));
        assert!(!contains(&version_10, b"DM"));
        assert!(!contains(&version_10, b"RU"));
        assert!(!contains(&version_10, b"Rx"));
        assert!(!contains(&version_10, b"Tx"));

        let version_11 = serialize_hardware_for(11);
        assert!(!contains(&version_11, b"RFR"));
        assert!(!contains(&version_11, b"DM"));
        assert!(!contains(&version_11, b"RU"));
        assert!(!contains(&version_11, b"Rx"));
        assert!(!contains(&version_11, b"Tx"));

        let version_12 = serialize_hardware_for(12);
        assert!(contains(&version_12, b"RFR"));
        assert!(contains(&version_12, b"DM"));
        assert!(contains(&version_12, b"RU"));
        assert!(!contains(&version_12, b"Rx"));
        assert!(!contains(&version_12, b"Tx"));

        let version_20 = serialize_hardware_for(20);
        assert!(contains(&version_20, b"RFR"));
        assert!(!contains(&version_20, b"DM"));
        assert!(!contains(&version_20, b"RU"));
        assert!(contains(&version_20, b"Rx"));
        assert!(contains(&version_20, b"Tx"));

        let version_10_h2p = serialize_h2p_for(10);
        assert!(!contains(&version_10_h2p, b"C"));
        assert!(!contains(&version_10_h2p, b"L"));
        assert!(!contains(&version_10_h2p, b"CC"));

        let version_11_h2p = serialize_h2p_for(11);
        assert!(contains(&version_11_h2p, b"C"));
        assert!(contains(&version_11_h2p, b"L"));
        assert!(!contains(&version_11_h2p, b"CC"));

        let version_20_h2p = serialize_h2p_for(20);
        assert!(contains(&version_20_h2p, b"C"));
        assert!(contains(&version_20_h2p, b"L"));
        assert!(contains(&version_20_h2p, b"CC"));
    }

    #[test]
    fn project_14_merten_hashes_match_signed_values() {
        let hardware_attrs = HashMap::from([
            ("Id".to_string(), "M-000C_H-649804-1".to_string()),
            ("SerialNumber".to_string(), "649804".to_string()),
            ("VersionNumber".to_string(), "1".to_string()),
            ("HasIndividualAddress".to_string(), "true".to_string()),
            ("HasApplicationProgram".to_string(), "true".to_string()),
        ]);
        let product_attrs = HashMap::from([
            ("Id".to_string(), "M-000C_H-649804-1_P-649802".to_string()),
            ("OrderNumber".to_string(), "649802".to_string()),
        ]);

        let product_hash = compute_product_hash_bytes_for_schema(&hardware_attrs, &product_attrs, Some(14));
        assert_eq!(BASE64.encode(product_hash), "b9ER3oEFTfzKxxoZDP0raAfuNgM=");

        let h2p_attrs = HashMap::new();
        let app_refs = vec!["M-000C_A-5700-11-5075".to_string()];
        let app_hashes = vec!["UIRCqLVwc3efuKT+m4Y+dQ==".to_string()];
        let h2p_hash = compute_hardware2program_hash_bytes_for_schema(
            &hardware_attrs,
            &h2p_attrs,
            &app_refs,
            Some(&app_hashes),
            Some(14),
        );
        assert_eq!(BASE64.encode(h2p_hash), "Gd7/DSdaXPZVTnlvtausC6/ttRU=");
    }
}
