//! Baggage generation utilities.
//!
//! This module provides the `BaggageGenerator` for creating Baggages.xml manifest files,
//! as well as helper functions for baggage ID encoding and file handling.
//!
//! # Baggage ID Format
//!
//! Baggage IDs follow the pattern: `M-{ManufId}_BG-{EncodedTargetPath}-{EncodedFilename}`
//!
//! Where:
//! - `ManufId` is the 4-digit hex manufacturer ID (e.g., "0083")
//! - `EncodedTargetPath` is the target directory path with special chars encoded (empty if no path)
//! - `EncodedFilename` has special characters encoded:
//!   - `.` becomes `.2E`
//!   - `_` becomes `.5F`
//!   - `\` becomes `.5C`
//!   - Other special chars follow similar hex encoding
//!
//! When target path is empty, the ID has a double hyphen: `M-{ManufId}_BG--{EncodedFilename}`
//!
//! # Example
//!
//! ```rust,ignore
//! use knxprod::BaggageGenerator;
//! use knxprod::schema::BaggageDef;
//!
//! let baggages = [BaggageDef::embedded("icon.png", &PNG_BYTES)];
//! let xml = BaggageGenerator::generate(0x00FA, Some(&baggages), None)?;
//! ```

use super::GeneratorError;
use crate::signing::KnxSchemaVersion;

// Re-export for external use
pub use crate::schema::{BaggageContent, BaggageDef, BaggageRef};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::io::{self, Write};

// ============================================================================
// BaggageGenerator
// ============================================================================

/// Generator for creating Baggages.xml manifest files.
///
/// This follows the same pattern as `MtxmlGenerator`, `HardwareGenerator`, and `CatalogGenerator`.
///
/// # Example
///
/// ```rust,ignore
/// use knxprod::BaggageGenerator;
///
/// let xml = BaggageGenerator::generate(0x00FA, Some(&baggages), None)?;
/// ```
pub struct BaggageGenerator;

impl BaggageGenerator {
    /// Generate a complete Baggages.xml manifest.
    ///
    /// Returns `Ok(None)` if `baggages` is `None` or empty.
    /// Returns `Ok(Some(xml))` with the XML content if baggages are present.
    ///
    /// The `schema_version` parameter controls the xmlns namespace and tool version
    /// in the generated XML. If `None`, defaults to V20.
    pub fn generate(
        manufacturer_id: u16,
        baggages: Option<&[BaggageDef<'_>]>,
        schema_version: Option<KnxSchemaVersion>,
    ) -> Result<Option<String>, GeneratorError> {
        let Some(baggages) = baggages else {
            return Ok(None);
        };

        if baggages.is_empty() {
            return Ok(None);
        }

        let version = schema_version.unwrap_or(KnxSchemaVersion::V20);
        let xml = Self::generate_xml(manufacturer_id, baggages, version);
        Ok(Some(xml))
    }

    /// Generate Baggages.xml content from baggage definitions.
    ///
    /// This is a lower-level method for when you have the individual parameters
    /// rather than an `ApplicationProgramConfig`.
    ///
    /// # Arguments
    ///
    /// * `manufacturer_id` - The KNX manufacturer ID (e.g., 0x0083)
    /// * `baggages` - Slice of baggage definitions
    /// * `schema_version` - The KNX schema version (determines namespace and tool version)
    ///
    /// # Returns
    ///
    /// The XML content as a String.
    pub fn generate_xml(manufacturer_id: u16, baggages: &[BaggageDef<'_>], schema_version: KnxSchemaVersion) -> String {
        let schema_namespace = schema_version.namespace_url();
        let tool_version = schema_version.tool_version();

        // Build baggage entries
        let items: Vec<BaggageXmlEntry> = baggages
            .iter()
            .map(|b| {
                let id = make_baggage_id_with_path(manufacturer_id, b.target_path, b.name);
                BaggageXmlEntry {
                    target_path: b.target_path.to_string(),
                    name: b.name.to_string(),
                    id,
                    file_info: FileInfo {
                        // Use current timestamp in KNX standard format: ISO 8601 with 7 decimal places
                        time_info: format_knx_timestamp(Utc::now()),
                    },
                }
            })
            .collect();

        let knx = BaggagesKnx {
            xmlns_xsi: "http://www.w3.org/2001/XMLSchema-instance",
            xmlns_xsd: "http://www.w3.org/2001/XMLSchema",
            created_by: "zweidraehte",
            tool_version,
            xmlns: schema_namespace.to_string(),
            manufacturer_data: BaggagesManufacturerData {
                manufacturer: BaggagesManufacturer {
                    ref_id: format!("M-{:04X}", manufacturer_id),
                    baggages: BaggagesList { items },
                },
            },
        };

        // Serialize to XML with XML declaration and proper indentation
        let mut buffer = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");

        // Use quick_xml serializer with indentation
        let mut serializer = quick_xml::se::Serializer::new(&mut buffer);
        serializer.indent(' ', 2);

        if let Err(e) = serde::Serialize::serialize(&knx, serializer) {
            log::error!("Failed to serialize Baggages.xml: {}", e);
        }

        buffer
    }

    /// Write baggage files to a directory.
    ///
    /// This writes the actual baggage file contents to the Baggages/ subdirectory.
    ///
    /// # Arguments
    ///
    /// * `base_dir` - The output directory (e.g., "M-0083/")
    /// * `baggages` - Baggage definitions to write
    ///
    /// # Errors
    ///
    /// Returns an error if file operations fail.
    pub fn write_files(base_dir: &std::path::Path, baggages: &[BaggageDef<'_>]) -> io::Result<()> {
        if baggages.is_empty() {
            return Ok(());
        }

        let baggages_dir = base_dir.join("Baggages");
        std::fs::create_dir_all(&baggages_dir)?;

        for baggage in baggages {
            let target_dir = if baggage.target_path.is_empty() {
                baggages_dir.clone()
            } else {
                let dir = baggages_dir.join(baggage.target_path);
                std::fs::create_dir_all(&dir)?;
                dir
            };

            let file_path = target_dir.join(baggage.name);
            let content = match &baggage.content {
                BaggageContent::Embedded(bytes) => bytes.to_vec(),
                BaggageContent::External(path) => std::fs::read(path)?,
            };

            let mut file = std::fs::File::create(&file_path)?;
            file.write_all(&content)?;
        }

        Ok(())
    }

    /// Get baggage file contents for signing.
    ///
    /// Returns a Vec of (path, content) pairs for inclusion in a .knxprod package.
    /// The paths are relative to the manufacturer directory (e.g., "Baggages/licht.png").
    /// This includes both the baggage files themselves and the Baggages.xml manifest.
    ///
    /// # Arguments
    ///
    /// * `manufacturer_id` - The KNX manufacturer ID
    /// * `baggages` - Baggage definitions
    /// * `schema_version` - The KNX schema version (if None, defaults to V20)
    ///
    /// # Returns
    ///
    /// A vector of (relative_path, file_content) pairs.
    pub fn get_files_for_signing(
        manufacturer_id: u16,
        baggages: &[BaggageDef<'_>],
        schema_version: Option<KnxSchemaVersion>,
    ) -> io::Result<Vec<(String, Vec<u8>)>> {
        if baggages.is_empty() {
            return Ok(Vec::new());
        }

        let version = schema_version.unwrap_or(KnxSchemaVersion::V20);

        let mut files = Vec::with_capacity(baggages.len() + 1);

        // Add Baggages.xml manifest (note: .xml not .mtxml in the knxprod package)
        let baggages_xml = Self::generate_xml(manufacturer_id, baggages, version);
        files.push(("Baggages.xml".to_string(), baggages_xml.into_bytes()));

        // Add individual baggage files
        for baggage in baggages {
            let path = if baggage.target_path.is_empty() {
                format!("Baggages/{}", baggage.name)
            } else {
                format!("Baggages/{}/{}", baggage.target_path, baggage.name)
            };

            let content = match &baggage.content {
                BaggageContent::Embedded(bytes) => bytes.to_vec(),
                BaggageContent::External(file_path) => std::fs::read(file_path)?,
            };

            files.push((path, content));
        }

        Ok(files)
    }
}

// ============================================================================
// Baggages.xml schema types
// ============================================================================

/// Root element for Baggages.xml
#[derive(Debug, Serialize)]
#[serde(rename = "KNX")]
struct BaggagesKnx<'a> {
    #[serde(rename = "@xmlns:xsi")]
    xmlns_xsi: &'static str,
    #[serde(rename = "@xmlns:xsd")]
    xmlns_xsd: &'static str,
    #[serde(rename = "@CreatedBy")]
    created_by: &'static str,
    #[serde(rename = "@ToolVersion")]
    tool_version: &'a str,
    #[serde(rename = "@xmlns")]
    xmlns: String,

    #[serde(rename = "ManufacturerData")]
    manufacturer_data: BaggagesManufacturerData,
}

#[derive(Debug, Serialize)]
struct BaggagesManufacturerData {
    #[serde(rename = "Manufacturer")]
    manufacturer: BaggagesManufacturer,
}

#[derive(Debug, Serialize)]
struct BaggagesManufacturer {
    #[serde(rename = "@RefId")]
    ref_id: String,

    #[serde(rename = "Baggages")]
    baggages: BaggagesList,
}

#[derive(Debug, Serialize)]
struct BaggagesList {
    #[serde(rename = "Baggage")]
    items: Vec<BaggageXmlEntry>,
}

#[derive(Debug, Serialize)]
struct BaggageXmlEntry {
    #[serde(rename = "@TargetPath")]
    target_path: String,
    #[serde(rename = "@Name")]
    name: String,
    #[serde(rename = "@Id")]
    id: String,

    #[serde(rename = "FileInfo")]
    file_info: FileInfo,
}

#[derive(Debug, Serialize)]
struct FileInfo {
    #[serde(rename = "@TimeInfo")]
    time_info: String,
}

// ============================================================================
// Helper functions
// ============================================================================

/// Format a timestamp in KNX standard format: ISO 8601 with 7 decimal places.
/// Example: "2026-01-30T14:30:00.0000000Z"
fn format_knx_timestamp(dt: DateTime<Utc>) -> String {
    // KNX uses 7 decimal places for sub-second precision
    let nanos = dt.timestamp_subsec_nanos();
    let subsec = nanos / 100; // Convert to 100ns units (7 decimal places)
    format!("{}.{:07}Z", dt.format("%Y-%m-%dT%H:%M:%S"), subsec)
}

/// Encode a filename for use in a baggage ID.
///
/// Special characters are encoded as `.XX` where XX is the hex value:
/// - `.` (0x2E) becomes `.2E`
/// - `_` (0x5F) becomes `.5F`
/// - `/` (0x2F) becomes `.2F`
/// - ` ` (0x20) becomes `.20`
///
/// # Example
///
/// ```rust
/// use knxprod::encode_baggage_filename;
///
/// assert_eq!(encode_baggage_filename("licht.png"), "licht.2Epng");
/// assert_eq!(encode_baggage_filename("socket_on.png"), "socket.5Fon.2Epng");
/// ```
pub fn encode_baggage_filename(name: &str) -> String {
    let mut result = String::with_capacity(name.len() * 2);
    for c in name.chars() {
        match c {
            '.' => result.push_str(".2E"),
            '_' => result.push_str(".5F"),
            '/' => result.push_str(".2F"),
            '\\' => result.push_str(".5C"),
            ' ' => result.push_str(".20"),
            '-' => result.push_str(".2D"),
            // Pass through alphanumeric characters
            c if c.is_ascii_alphanumeric() => result.push(c),
            // Encode other characters
            c => {
                if c.is_ascii() {
                    result.push_str(&format!(".{:02X}", c as u8));
                } else {
                    // For non-ASCII, just pass through (rare in baggage names)
                    result.push(c);
                }
            }
        }
    }
    result
}

/// Generate a baggage ID from manufacturer ID and filename.
///
/// The ID format is: `M-{ManufId}_BG-{EncodedFilename}`
///
/// # Example
///
/// ```rust
/// use knxprod::make_baggage_id;
///
/// assert_eq!(make_baggage_id(0x0083, "licht.png"), "M-0083_BG--licht.2Epng");
/// assert_eq!(make_baggage_id(0x00FA, "icon.png"), "M-00FA_BG--icon.2Epng");
/// ```
pub fn make_baggage_id(manufacturer_id: u16, filename: &str) -> String {
    // Format: M-{manuf}_BG--{encoded_filename} (double hyphen for empty target path)
    format!("M-{:04X}_BG--{}", manufacturer_id, encode_baggage_filename(filename))
}

/// Generate baggage ID including target path if present.
///
/// Format: `M-{manuf}_BG-{encoded_target_path}-{encoded_filename}`
/// When target_path is empty: `M-{manuf}_BG--{encoded_filename}` (double hyphen)
/// When target_path is "A0\30": `M-{manuf}_BG-A0.5C30-{encoded_filename}`
pub fn make_baggage_id_with_path(manufacturer_id: u16, target_path: &str, filename: &str) -> String {
    if target_path.is_empty() {
        make_baggage_id(manufacturer_id, filename)
    } else {
        // Encode target path (backslash becomes .5C, etc.) and append filename with hyphen separator
        format!(
            "M-{:04X}_BG-{}-{}",
            manufacturer_id,
            encode_baggage_filename(target_path),
            encode_baggage_filename(filename)
        )
    }
}

/// Convert a slice of BaggageDefs to BaggageRefs for the Extension section.
pub fn baggages_to_refs(manufacturer_id: u16, baggages: &[BaggageDef<'_>]) -> Vec<BaggageRef> {
    baggages
        .iter()
        .map(|b| BaggageRef { ref_id: make_baggage_id_with_path(manufacturer_id, b.target_path, b.name) })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_simple_filename() {
        assert_eq!(encode_baggage_filename("icon.png"), "icon.2Epng");
    }

    #[test]
    fn test_encode_underscore() {
        assert_eq!(encode_baggage_filename("socket_on.png"), "socket.5Fon.2Epng");
    }

    #[test]
    fn test_encode_multiple_dots() {
        assert_eq!(encode_baggage_filename("file.tar.gz"), "file.2Etar.2Egz");
    }

    #[test]
    fn test_encode_complex_name() {
        assert_eq!(encode_baggage_filename("lock_closed_green.png"), "lock.5Fclosed.5Fgreen.2Epng");
    }

    #[test]
    fn test_make_baggage_id() {
        // Double hyphen for empty target path
        assert_eq!(make_baggage_id(0x0083, "licht.png"), "M-0083_BG--licht.2Epng");
    }

    #[test]
    fn test_make_baggage_id_different_manufacturer() {
        assert_eq!(make_baggage_id(0x00FA, "icon.png"), "M-00FA_BG--icon.2Epng");
    }

    #[test]
    fn test_make_baggage_id_with_underscore() {
        assert_eq!(make_baggage_id(0x0083, "socket_on.png"), "M-0083_BG--socket.5Fon.2Epng");
    }

    #[test]
    fn test_make_baggage_id_with_path() {
        // Target path with backslash gets encoded
        assert_eq!(make_baggage_id_with_path(0x00FA, "A0\\30", "ets.png"), "M-00FA_BG-A0.5C30-ets.2Epng");
    }

    #[test]
    fn test_baggages_to_refs() {
        let baggages = [BaggageDef::embedded("light.png", &[]), BaggageDef::embedded("heat.png", &[])];
        let refs = baggages_to_refs(0x0083, &baggages);
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].ref_id, "M-0083_BG--light.2Epng");
        assert_eq!(refs[1].ref_id, "M-0083_BG--heat.2Epng");
    }

    #[test]
    fn test_generate_baggages_xml() {
        let baggages = [BaggageDef::embedded("test.png", &[1, 2, 3])];
        let xml = BaggageGenerator::generate_xml(0x0083, &baggages, KnxSchemaVersion::V20);

        assert!(xml.contains("M-0083"));
        assert!(xml.contains("M-0083_BG--test.2Epng"));
        assert!(xml.contains("Name=\"test.png\""));
        assert!(xml.contains("<Baggages>"));
        // Tool version comes from knxprod crate version
        assert!(xml.contains(&format!("ToolVersion=\"{}\"", env!("CARGO_PKG_VERSION"))));
    }
}
