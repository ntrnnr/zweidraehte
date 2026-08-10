//! ZIP packaging and directory signing for .knxprod files.

use std::collections::HashMap;
use std::io::{Cursor, Seek, Write};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, Writer};
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

use super::SigningConfig;
use crate::signing::master_data::get_master_data;
use crate::signing::{MasterDataSource, SigningError};

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

/// Configuration for a project to embed in a `.knxproj` archive.
pub struct ProjectConfig {
    /// Project ID (e.g., "P-0001").
    pub project_id: String,
    /// Content of `project.xml` (metadata: name, GUID, Puid counter).
    pub project_xml: String,
    /// Content of `0.xml` (topology with device instances).
    pub topology_xml: String,
}

/// Sign all manufacturer files and return the signed directory contents
/// together with the directory signature.
///
/// When `include_catalog` is false, `Catalog.xml` is omitted from the
/// directory — this matches the ETS convention for `.knxproj` archives
/// which embed a project instead.
fn sign_manufacturer_files(
    config: &SigningConfig,
    include_catalog: bool,
) -> Result<(Vec<(String, Vec<u8>)>, String), SigningError> {
    use super::signatures::sign_directory_contents;

    // Sign each ApplicationProgram XML (add Hash attribute) and collect
    // all app program hashes for Hardware.xml signing.
    let mut all_app_hashes: HashMap<String, String> = HashMap::new();
    let mut signed_app_programs: Vec<(String, Vec<u8>)> = Vec::new();

    for (program_id, program_xml) in &config.application_programs {
        let signed_xml = sign_application_program_xml(program_xml)?;
        let hashes = extract_app_program_hashes(&signed_xml)?;
        all_app_hashes.extend(hashes);
        signed_app_programs.push((format!("{}.xml", program_id), signed_xml.into_bytes()));
    }

    // Sign Hardware.xml using the collected hashes from all app programs.
    let signed_hardware = sign_hardware_xml(&config.hardware, &all_app_hashes)?;

    // Collect files for the manufacturer directory.
    let mut dir_files: Vec<(String, Vec<u8>)> = Vec::new();
    dir_files.extend(signed_app_programs);
    dir_files.push(("Hardware.xml".to_string(), signed_hardware.into_bytes()));
    if include_catalog {
        dir_files.push(("Catalog.xml".to_string(), config.catalog.as_bytes().to_vec()));
    }

    // Add baggage files.
    for (path, content) in &config.baggage_files {
        dir_files.push((path.clone(), content.clone()));
    }

    // Create directory signature.
    let files_refs: Vec<(String, &[u8])> = dir_files.iter().map(|(p, c)| (p.clone(), c.as_slice())).collect();
    let dir_signature = sign_directory_contents(&files_refs)?;

    Ok((dir_files, dir_signature))
}

/// Write a signed directory into a ZIP: the directory's files under
/// `{dir_name}/` and a `{dir_name}.signature` file with UTF-8 BOM.
fn write_signed_directory<W: Write + Seek>(
    zip: &mut ZipWriter<W>,
    dir_name: &str,
    files: &[(String, Vec<u8>)],
    signature: &str,
    options: SimpleFileOptions,
) -> Result<(), SigningError> {
    for (filename, content) in files {
        let path = format!("{}/{}", dir_name, filename);
        zip.start_file(&path, options)?;
        zip.write_all(content)?;
    }

    let sig_filename = format!("{}.signature", dir_name);
    zip.start_file(&sig_filename, options)?;
    // UTF-8 BOM, matching the ETS convention.
    zip.write_all(&[0xEF, 0xBB, 0xBF])?;
    zip.write_all(signature.as_bytes())?;

    Ok(())
}

/// Create a signed `.knxprod` ZIP archive.
pub fn create_knxprod(config: &SigningConfig, master_data: MasterDataSource) -> Result<Vec<u8>, SigningError> {
    let manuf_dir = format!("M-{}", config.manufacturer_id);
    let master_xml = get_master_data(&master_data)?;
    let (dir_files, dir_signature) = sign_manufacturer_files(config, true)?;

    let mut zip_buffer = Cursor::new(Vec::new());
    {
        let mut zip = ZipWriter::new(&mut zip_buffer);
        let file_options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .compression_level(Some(6));

        zip.start_file("knx_master.xml", file_options)?;
        zip.write_all(master_xml.as_bytes())?;

        write_signed_directory(&mut zip, &manuf_dir, &dir_files, &dir_signature, file_options)?;

        zip.finish()?;
    }

    Ok(zip_buffer.into_inner())
}

/// Create a signed `.knxproj` ZIP archive.
///
/// A `.knxproj` is a superset of `.knxprod`: it contains the same signed
/// manufacturer directory and master data, plus a project directory
/// (`P-XXXX/`) with `project.xml` and `0.xml`, signed with its own
/// directory signature.
pub fn create_knxproj(
    config: &SigningConfig,
    project: &ProjectConfig,
    master_data: MasterDataSource,
) -> Result<Vec<u8>, SigningError> {
    use super::signatures::sign_directory_contents;

    let manuf_dir = format!("M-{}", config.manufacturer_id);
    let master_xml = get_master_data(&master_data)?;
    let (manuf_files, manuf_signature) = sign_manufacturer_files(config, false)?;

    // Sign the project directory.
    let project_files: Vec<(String, Vec<u8>)> = vec![
        ("project.xml".to_string(), project.project_xml.as_bytes().to_vec()),
        ("0.xml".to_string(), project.topology_xml.as_bytes().to_vec()),
    ];
    let project_refs: Vec<(String, &[u8])> = project_files.iter().map(|(p, c)| (p.clone(), c.as_slice())).collect();
    let project_signature = sign_directory_contents(&project_refs)?;

    // Build the ZIP archive.
    let mut zip_buffer = Cursor::new(Vec::new());
    {
        let mut zip = ZipWriter::new(&mut zip_buffer);
        let file_options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .compression_level(Some(6));

        zip.start_file("knx_master.xml", file_options)?;
        zip.write_all(master_xml.as_bytes())?;

        write_signed_directory(&mut zip, &manuf_dir, &manuf_files, &manuf_signature, file_options)?;
        write_signed_directory(&mut zip, &project.project_id, &project_files, &project_signature, file_options)?;

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
}
