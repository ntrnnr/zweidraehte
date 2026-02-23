//! ZIP packaging and directory signing for .knxprod files.

use std::collections::HashMap;
use std::fs;
use std::io::{Cursor, Write};
use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, Writer};
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

use super::{KnxSchemaVersion, MasterDataSource, SigningConfig, SigningError};

/// Get or download the KNX master data.
pub fn get_master_data(source: &MasterDataSource) -> Result<String, SigningError> {
    match source {
        MasterDataSource::Download => download_and_cache_master_data(KnxSchemaVersion::default()),
        MasterDataSource::DownloadVersion(version) => download_and_cache_master_data(*version),
        MasterDataSource::File(path) => Ok(fs::read_to_string(path)?),
        MasterDataSource::Content(content) => Ok(content.clone()),
    }
}

/// Download master data and cache it locally.
fn download_and_cache_master_data(version: KnxSchemaVersion) -> Result<String, SigningError> {
    // Cache filename includes version to support multiple versions
    let cache_filename = format!("knx_master_v{}.xml", version.as_str());

    // Check cache first
    if let Some(cache_dir) = get_cache_dir() {
        let cache_path = cache_dir.join(&cache_filename);
        if cache_path.exists()
            && let Ok(content) = fs::read_to_string(&cache_path) {
                log::info!("Using cached {} from {:?}", cache_filename, cache_path);
                return Ok(content);
            }
    }

    // Download
    let url = version.master_data_url();
    log::info!("Downloading knx_master.xml from {}", url);
    let response = reqwest::blocking::get(&url)?;
    let content = response.text()?;

    // Cache for future use
    if let Some(cache_dir) = get_cache_dir() {
        let _ = fs::create_dir_all(&cache_dir);
        let cache_path = cache_dir.join(&cache_filename);
        if let Err(e) = fs::write(&cache_path, &content) {
            log::warn!("Failed to cache {}: {}", cache_filename, e);
        } else {
            log::info!("Cached {} to {:?}", cache_filename, cache_path);
        }
    }

    Ok(content)
}

/// Get the cache directory for KNX data.
fn get_cache_dir() -> Option<PathBuf> {
    directories::ProjectDirs::from("org", "knx", "knxprod").map(|dirs| dirs.cache_dir().to_path_buf())
}

/// Sign Hardware.xml in-place (updates Hash and RegistrationInfo).
///
/// Returns the modified XML content with:
/// - Hash attributes added to Product and Hardware2Program elements
/// - RegistrationInfo child elements added with registration signatures
pub fn sign_hardware_xml(
    hardware_xml: &str,
    app_program_hashes: &HashMap<String, String>,
) -> Result<String, SigningError> {
    use super::hashes::{compute_hardware2program_hash_bytes, compute_product_hash, compute_product_hash_bytes};
    use super::signatures::create_registration_signature;
    use quick_xml::events::BytesEnd;

    let mut reader = Reader::from_str(hardware_xml);
    reader.config_mut().trim_text(false); // Preserve whitespace

    let mut writer = Writer::new(Cursor::new(Vec::new()));

    // Track current context
    let mut current_hardware_attrs: Option<HashMap<String, String>> = None;
    let mut in_products = false;
    let mut in_hardware2programs = false;
    let mut current_h2p_attrs: Option<HashMap<String, String>> = None;
    let mut current_app_refs: Vec<String> = Vec::new();
    let mut pending_product_registration: Option<(String, String)> = None; // (hash, signature)
    let mut in_h2p_element = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let local_name_bytes = e.local_name();
                let name = std::str::from_utf8(local_name_bytes.as_ref()).unwrap_or("");

                match name {
                    "Hardware" => {
                        let attrs = extract_attrs_from_event(&e);
                        let id = attrs.get("Id").cloned().unwrap_or_default();
                        // Only track actual Hardware elements, not Hardware2Program
                        if !id.contains("_HP-") && id.contains("_H-") {
                            current_hardware_attrs = Some(attrs);
                        }
                        writer.write_event(Event::Start(e)).map_err(|e| SigningError::XmlWrite(e.to_string()))?;
                    }
                    "Products" => {
                        in_products = true;
                        writer.write_event(Event::Start(e)).map_err(|e| SigningError::XmlWrite(e.to_string()))?;
                    }
                    "Hardware2Programs" => {
                        in_hardware2programs = true;
                        writer.write_event(Event::Start(e)).map_err(|e| SigningError::XmlWrite(e.to_string()))?;
                    }
                    "Product" if in_products => {
                        let attrs = extract_attrs_from_event(&e);

                        // Compute hash if we have hardware context
                        if let Some(ref hw_attrs) = current_hardware_attrs {
                            let hash = compute_product_hash(hw_attrs, &attrs);
                            let hash_bytes = compute_product_hash_bytes(hw_attrs, &attrs);
                            let signature = create_registration_signature(&hash_bytes, "Registered", None)?;

                            // Add Hash attribute to the element
                            let mut new_elem = BytesStart::new("Product");
                            for attr in e.attributes().flatten() {
                                new_elem.push_attribute((
                                    std::str::from_utf8(attr.key.as_ref()).unwrap_or(""),
                                    std::str::from_utf8(&attr.value).unwrap_or(""),
                                ));
                            }
                            new_elem.push_attribute(("Hash", hash.as_str()));

                            writer
                                .write_event(Event::Start(new_elem))
                                .map_err(|e| SigningError::XmlWrite(e.to_string()))?;
                            pending_product_registration = Some((hash, signature));
                        } else {
                            writer.write_event(Event::Start(e)).map_err(|e| SigningError::XmlWrite(e.to_string()))?;
                        }
                    }
                    "Hardware2Program" if in_hardware2programs => {
                        let attrs = extract_attrs_from_event(&e);
                        current_h2p_attrs = Some(attrs.clone());
                        current_app_refs.clear();
                        in_h2p_element = true;
                        // Don't write the element yet - we'll write it at the end with Hash added
                    }
                    _ => {
                        if !in_h2p_element {
                            writer.write_event(Event::Start(e)).map_err(|e| SigningError::XmlWrite(e.to_string()))?;
                        }
                        // Skip writing anything while inside H2P - we'll reconstruct it at the end
                    }
                }
            }
            Ok(Event::Empty(e)) => {
                let local_name_bytes = e.local_name();
                let name = std::str::from_utf8(local_name_bytes.as_ref()).unwrap_or("");

                match name {
                    "Product" if in_products => {
                        let attrs = extract_attrs_from_event(&e);

                        // Compute hash if we have hardware context
                        if let Some(ref hw_attrs) = current_hardware_attrs {
                            let hash = compute_product_hash(hw_attrs, &attrs);
                            let hash_bytes = compute_product_hash_bytes(hw_attrs, &attrs);
                            let signature = create_registration_signature(&hash_bytes, "Registered", None)?;

                            // Convert empty element to start+content+end so we can add RegistrationInfo
                            let mut new_elem = BytesStart::new("Product");
                            for attr in e.attributes().flatten() {
                                new_elem.push_attribute((
                                    std::str::from_utf8(attr.key.as_ref()).unwrap_or(""),
                                    std::str::from_utf8(&attr.value).unwrap_or(""),
                                ));
                            }
                            new_elem.push_attribute(("Hash", hash.as_str()));

                            writer
                                .write_event(Event::Start(new_elem))
                                .map_err(|e| SigningError::XmlWrite(e.to_string()))?;

                            // Add RegistrationInfo
                            let mut reg_elem = BytesStart::new("RegistrationInfo");
                            reg_elem.push_attribute(("RegistrationStatus", "Registered"));
                            reg_elem.push_attribute(("RegistrationSignature", signature.as_str()));
                            writer
                                .write_event(Event::Empty(reg_elem))
                                .map_err(|e| SigningError::XmlWrite(e.to_string()))?;

                            writer
                                .write_event(Event::End(BytesEnd::new("Product")))
                                .map_err(|e| SigningError::XmlWrite(e.to_string()))?;
                        } else {
                            writer.write_event(Event::Empty(e)).map_err(|e| SigningError::XmlWrite(e.to_string()))?;
                        }
                    }
                    "ApplicationProgramRef" if in_h2p_element => {
                        // Collect ApplicationProgramRef - we reconstruct these when writing H2P
                        let attrs = extract_attrs_from_event(&e);
                        if let Some(ref_id) = attrs.get("RefId") {
                            current_app_refs.push(ref_id.clone());
                        }
                        // Don't write - we'll reconstruct at the end of Hardware2Program
                    }
                    "RegistrationInfo" if in_h2p_element => {
                        // Skip existing RegistrationInfo inside H2P - we'll add our own
                    }
                    "RegistrationInfo" => {
                        // Skip existing RegistrationInfo elements outside H2P too
                    }
                    _ => {
                        if !in_h2p_element {
                            writer.write_event(Event::Empty(e)).map_err(|e| SigningError::XmlWrite(e.to_string()))?;
                        }
                        // Skip any other empty elements inside H2P - they shouldn't exist normally
                    }
                }
            }
            Ok(Event::End(e)) => {
                let local_name_bytes = e.local_name();
                let name = std::str::from_utf8(local_name_bytes.as_ref()).unwrap_or("");

                match name {
                    "Hardware" => {
                        current_hardware_attrs = None;
                        writer.write_event(Event::End(e)).map_err(|er| SigningError::XmlWrite(er.to_string()))?;
                    }
                    "Products" => {
                        in_products = false;
                        writer.write_event(Event::End(e)).map_err(|er| SigningError::XmlWrite(er.to_string()))?;
                    }
                    "Hardware2Programs" => {
                        in_hardware2programs = false;
                        writer.write_event(Event::End(e)).map_err(|er| SigningError::XmlWrite(er.to_string()))?;
                    }
                    "Product" if in_products => {
                        // Add RegistrationInfo before closing the element
                        if let Some((_, signature)) = pending_product_registration.take() {
                            let mut reg_elem = BytesStart::new("RegistrationInfo");
                            reg_elem.push_attribute(("RegistrationStatus", "Registered"));
                            reg_elem.push_attribute(("RegistrationSignature", signature.as_str()));
                            writer
                                .write_event(Event::Empty(reg_elem))
                                .map_err(|er| SigningError::XmlWrite(er.to_string()))?;
                        }
                        writer.write_event(Event::End(e)).map_err(|er| SigningError::XmlWrite(er.to_string()))?;
                    }
                    "Hardware2Program" if in_hardware2programs => {
                        // Now we have all ApplicationProgramRefs, compute hash and write element with Hash
                        if let (Some(hw_attrs), Some(h2p_attrs)) = (&current_hardware_attrs, &current_h2p_attrs) {
                            let h2p_app_hashes: Vec<String> =
                                current_app_refs.iter().filter_map(|r| app_program_hashes.get(r).cloned()).collect();

                            let hash_bytes = compute_hardware2program_hash_bytes(
                                hw_attrs,
                                h2p_attrs,
                                &current_app_refs,
                                if h2p_app_hashes.is_empty() { None } else { Some(&h2p_app_hashes) },
                            );
                            let hash = BASE64.encode(&hash_bytes);

                            let signature = create_registration_signature(&hash_bytes, "Registered", None)?;

                            // Write the Hardware2Program start tag with all original attrs plus Hash
                            let mut new_elem = BytesStart::new("Hardware2Program");
                            for (key, value) in h2p_attrs.iter() {
                                new_elem.push_attribute((key.as_str(), value.as_str()));
                            }
                            new_elem.push_attribute(("Hash", hash.as_str()));
                            writer
                                .write_event(Event::Start(new_elem))
                                .map_err(|er| SigningError::XmlWrite(er.to_string()))?;

                            // Write ApplicationProgramRef elements
                            for ref_id in &current_app_refs {
                                let mut ref_elem = BytesStart::new("ApplicationProgramRef");
                                ref_elem.push_attribute(("RefId", ref_id.as_str()));
                                writer
                                    .write_event(Event::Empty(ref_elem))
                                    .map_err(|er| SigningError::XmlWrite(er.to_string()))?;
                            }

                            // Add RegistrationInfo before closing
                            let mut reg_elem = BytesStart::new("RegistrationInfo");
                            reg_elem.push_attribute(("RegistrationStatus", "Registered"));
                            reg_elem.push_attribute(("RegistrationSignature", signature.as_str()));
                            writer
                                .write_event(Event::Empty(reg_elem))
                                .map_err(|er| SigningError::XmlWrite(er.to_string()))?;
                        }

                        in_h2p_element = false;
                        current_h2p_attrs = None;
                        current_app_refs.clear();
                        writer.write_event(Event::End(e)).map_err(|er| SigningError::XmlWrite(er.to_string()))?;
                    }
                    _ => {
                        if !in_h2p_element {
                            writer.write_event(Event::End(e)).map_err(|er| SigningError::XmlWrite(er.to_string()))?;
                        }
                        // Skip end tags inside H2P - we reconstruct the whole element
                    }
                }
            }
            Ok(Event::Text(e)) => {
                if !in_h2p_element {
                    writer.write_event(Event::Text(e)).map_err(|e| SigningError::XmlWrite(e.to_string()))?;
                }
                // Skip text inside H2P - Hardware2Program should only contain ApplicationProgramRef elements
            }
            Ok(Event::Comment(e)) => {
                if !in_h2p_element {
                    writer.write_event(Event::Comment(e)).map_err(|e| SigningError::XmlWrite(e.to_string()))?;
                }
            }
            Ok(Event::CData(e)) => {
                if !in_h2p_element {
                    writer.write_event(Event::CData(e)).map_err(|e| SigningError::XmlWrite(e.to_string()))?;
                }
            }
            Ok(Event::Decl(e)) => {
                writer.write_event(Event::Decl(e)).map_err(|e| SigningError::XmlWrite(e.to_string()))?;
            }
            Ok(Event::PI(e)) => {
                writer.write_event(Event::PI(e)).map_err(|e| SigningError::XmlWrite(e.to_string()))?;
            }
            Ok(Event::DocType(e)) => {
                writer.write_event(Event::DocType(e)).map_err(|e| SigningError::XmlWrite(e.to_string()))?;
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(SigningError::XmlWrite(format!("XML parse error: {}", e))),
        }
    }

    let result = writer.into_inner().into_inner();
    String::from_utf8(result).map_err(|e| SigningError::XmlWrite(format!("UTF-8 error: {}", e)))
}

/// Extract attributes from an XML event.
fn extract_attrs_from_event(e: &BytesStart) -> HashMap<String, String> {
    let mut attrs = HashMap::new();
    for attr in e.attributes().flatten() {
        if let (Ok(key), Ok(value)) = (std::str::from_utf8(attr.key.as_ref()), std::str::from_utf8(&attr.value)) {
            attrs.insert(key.to_string(), value.to_string());
        }
    }
    attrs
}

/// Sign ApplicationProgram XML by adding Hash attribute.
///
/// Returns the modified XML content with Hash attribute added to the ApplicationProgram element.
pub fn sign_application_program_xml(app_xml: &str) -> Result<String, SigningError> {
    use super::hashes::compute_application_program_hash;

    let mut reader = Reader::from_str(app_xml);
    reader.config_mut().trim_text(false);

    let mut writer = Writer::new(Cursor::new(Vec::new()));

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let local_name_bytes = e.local_name();
                let name = std::str::from_utf8(local_name_bytes.as_ref()).unwrap_or("");

                if name == "ApplicationProgram" {
                    let attrs = extract_attrs_from_event(&e);

                    // Compute hash from attributes
                    let hash = compute_application_program_hash(&attrs);

                    // Write element with Hash attribute added
                    let mut new_elem = BytesStart::new("ApplicationProgram");
                    for attr in e.attributes().flatten() {
                        let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
                        // Skip existing Hash attribute
                        if key != "Hash" {
                            new_elem.push_attribute((key, std::str::from_utf8(&attr.value).unwrap_or("")));
                        }
                    }
                    new_elem.push_attribute(("Hash", hash.as_str()));
                    writer.write_event(Event::Start(new_elem)).map_err(|e| SigningError::XmlWrite(e.to_string()))?;
                } else {
                    writer.write_event(Event::Start(e)).map_err(|e| SigningError::XmlWrite(e.to_string()))?;
                }
            }
            Ok(Event::Empty(e)) => {
                let local_name_bytes = e.local_name();
                let name = std::str::from_utf8(local_name_bytes.as_ref()).unwrap_or("");

                if name == "ApplicationProgram" {
                    let attrs = extract_attrs_from_event(&e);

                    // Compute hash from attributes
                    let hash = compute_application_program_hash(&attrs);

                    // Write element with Hash attribute added
                    let mut new_elem = BytesStart::new("ApplicationProgram");
                    for attr in e.attributes().flatten() {
                        let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
                        if key != "Hash" {
                            new_elem.push_attribute((key, std::str::from_utf8(&attr.value).unwrap_or("")));
                        }
                    }
                    new_elem.push_attribute(("Hash", hash.as_str()));
                    writer.write_event(Event::Empty(new_elem)).map_err(|e| SigningError::XmlWrite(e.to_string()))?;
                } else {
                    writer.write_event(Event::Empty(e)).map_err(|e| SigningError::XmlWrite(e.to_string()))?;
                }
            }
            Ok(Event::End(e)) => {
                writer.write_event(Event::End(e)).map_err(|e| SigningError::XmlWrite(e.to_string()))?;
            }
            Ok(Event::Text(e)) => {
                writer.write_event(Event::Text(e)).map_err(|e| SigningError::XmlWrite(e.to_string()))?;
            }
            Ok(Event::Comment(e)) => {
                writer.write_event(Event::Comment(e)).map_err(|e| SigningError::XmlWrite(e.to_string()))?;
            }
            Ok(Event::CData(e)) => {
                writer.write_event(Event::CData(e)).map_err(|e| SigningError::XmlWrite(e.to_string()))?;
            }
            Ok(Event::Decl(e)) => {
                writer.write_event(Event::Decl(e)).map_err(|e| SigningError::XmlWrite(e.to_string()))?;
            }
            Ok(Event::PI(e)) => {
                writer.write_event(Event::PI(e)).map_err(|e| SigningError::XmlWrite(e.to_string()))?;
            }
            Ok(Event::DocType(e)) => {
                writer.write_event(Event::DocType(e)).map_err(|e| SigningError::XmlWrite(e.to_string()))?;
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(SigningError::XmlWrite(format!("XML parse error: {}", e))),
        }
    }

    let result = writer.into_inner().into_inner();
    String::from_utf8(result).map_err(|e| SigningError::XmlWrite(format!("UTF-8 error: {}", e)))
}

/// Create a signed .knxprod ZIP archive.
pub fn create_knxprod(config: &SigningConfig, master_data: MasterDataSource) -> Result<Vec<u8>, SigningError> {
    use super::signatures::sign_directory_contents;

    let manuf_dir = format!("M-{}", config.manufacturer_id);

    // Get master data
    let master_xml = get_master_data(&master_data)?;

    // Sign ApplicationProgram XML (add Hash attribute)
    let signed_app_program = sign_application_program_xml(&config.application_program)?;

    // Get ApplicationProgram hash from the signed XML
    let app_program_hashes = extract_app_program_hashes(&signed_app_program)?;

    // Sign Hardware.xml
    let signed_hardware = sign_hardware_xml(&config.hardware, &app_program_hashes)?;

    // Collect files for the manufacturer directory
    let mut dir_files: Vec<(String, Vec<u8>)> = vec![
        (format!("{}.xml", config.application_program_id), signed_app_program.as_bytes().to_vec()),
        ("Hardware.xml".to_string(), signed_hardware.as_bytes().to_vec()),
        ("Catalog.xml".to_string(), config.catalog.as_bytes().to_vec()),
    ];

    // Add baggage files
    for (path, content) in &config.baggage_files {
        dir_files.push((path.clone(), content.clone()));
    }

    // Create directory signature
    let files_for_signing: Vec<(String, Vec<u8>)> = dir_files.clone();
    let files_refs: Vec<(String, &[u8])> = files_for_signing.iter().map(|(p, c)| (p.clone(), c.as_slice())).collect();
    let dir_signature = sign_directory_contents(&files_refs)?;

    // Create ZIP archive
    let mut zip_buffer = Cursor::new(Vec::new());
    {
        let mut zip = ZipWriter::new(&mut zip_buffer);
        let file_options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .compression_level(Some(6));

        // Add knx_master.xml at root
        zip.start_file("knx_master.xml", file_options)?;
        zip.write_all(master_xml.as_bytes())?;

        // Add manufacturer directory files (no explicit directory entries - matches working knxprod format)
        for (filename, content) in &dir_files {
            let path = format!("{}/{}", manuf_dir, filename);
            zip.start_file(&path, file_options)?;
            zip.write_all(content)?;
        }

        // Add directory signature file (with UTF-8 BOM)
        let sig_filename = format!("{}.signature", manuf_dir);
        zip.start_file(&sig_filename, file_options)?;
        // Write UTF-8 BOM
        zip.write_all(&[0xEF, 0xBB, 0xBF])?;
        zip.write_all(dir_signature.as_bytes())?;

        zip.finish()?;
    }

    Ok(zip_buffer.into_inner())
}

/// Extract ApplicationProgram Hash attribute from XML.
fn extract_app_program_hashes(xml: &str) -> Result<HashMap<String, String>, SigningError> {
    let mut hashes = HashMap::new();
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let local_name_bytes = e.local_name();
                let local_name = std::str::from_utf8(local_name_bytes.as_ref()).unwrap_or("");
                if local_name == "ApplicationProgram" {
                    let attrs = extract_attrs_from_event(&e);
                    if let (Some(id), Some(hash)) = (attrs.get("Id"), attrs.get("Hash")) {
                        hashes.insert(id.clone(), hash.clone());
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(SigningError::XmlWrite(format!("XML parse error: {}", e))),
            _ => {}
        }
    }

    Ok(hashes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_app_program_hashes() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
        <ApplicationProgram Id="M-0083_A-009B-14-E59D" Hash="abc123==" Name="Test">
        </ApplicationProgram>"#;

        let hashes = extract_app_program_hashes(xml).expect("parse");
        assert_eq!(hashes.get("M-0083_A-009B-14-E59D"), Some(&"abc123==".to_string()));
    }

    #[test]
    fn test_get_cache_dir() {
        // Just verify it returns something or None, doesn't panic
        let _ = get_cache_dir();
    }
}
