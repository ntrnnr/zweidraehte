//! Catalog MTXML Generator - Creates Catalog.mtxml files.

use crate::schema::{CatalogItem, CatalogKnx, CatalogSection};

use super::{ApplicationProgramConfig, GeneratorError};

/// Generator for creating Catalog MTXML files.
pub struct CatalogGenerator;

impl CatalogGenerator {
    /// Generate a complete Catalog MTXML document from the configuration.
    pub fn generate(config: &ApplicationProgramConfig) -> Result<String, GeneratorError> {
        let knx = Self::build_catalog_knx(config);
        Self::serialize(&knx)
    }

    /// Build the complete Catalog KNX document structure.
    fn build_catalog_knx(config: &ApplicationProgramConfig) -> CatalogKnx {
        let manufacturer_id = format!("M-{:04X}", config.device.manufacturer_id);
        let serial_hex = config
            .serial_number
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<String>();

        // Hardware ID: M-XXXX_H-<serial>-<version>
        let hardware_id = format!(
            "{}_H-{}-{}",
            manufacturer_id, serial_hex, config.hardware_version
        );

        // Application hash suffix (defaults to 0000)
        let app_hash = config.application_hash.unwrap_or("0000");

        // Hardware2Program ID - must match Hardware2Program ID in Hardware.xml
        let h2p_id = format!(
            "{}_HP-{:04X}-{:02X}-{}",
            hardware_id, config.device.application_id, config.device.application_version, app_hash
        );

        // Product ID - must be URL-encoded for ID convention compliance
        let product_id = format!(
            "{}_P-{}",
            hardware_id,
            super::mtxml::MtxmlGenerator::encode_id(config.order_number)
        );

        // Catalog Section ID
        let section_id = format!("{}_CS-1", manufacturer_id);

        // Catalog Item ID: <h2p_id>_CI-<order_number>-1
        // Order number must be URL-encoded for ID convention compliance
        let catalog_item_id = format!(
            "{}_CI-{}-1",
            h2p_id,
            super::mtxml::MtxmlGenerator::encode_id(config.order_number)
        );

        let mut knx = CatalogKnx::default();
        // Set schema version namespace and tool version if specified
        if let Some(version) = config.schema_version {
            knx.xmlns = version.namespace_url();
            knx.tool_version = version.tool_version().to_string();
        }
        knx.manufacturer_data.manufacturer.ref_id = manufacturer_id;
        knx.manufacturer_data.manufacturer.catalog.catalog_section = CatalogSection {
            id: section_id,
            name: config.catalog_section.to_string(),
            number: "1".to_string(),
            default_language: "en-US".to_string(),
            catalog_item: CatalogItem {
                id: catalog_item_id,
                name: config.product_name.to_string(),
                number: "1".to_string(),
                product_ref_id: product_id,
                hardware2program_ref_id: h2p_id,
                default_language: "en-US".to_string(),
            },
        };

        knx
    }

    /// Serialize the Catalog KNX document to XML string.
    fn serialize(knx: &CatalogKnx) -> Result<String, GeneratorError> {
        let mut buffer = String::new();
        buffer.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");

        let mut serializer = quick_xml::se::Serializer::new(&mut buffer);
        serializer.indent(' ', 2);

        serde::Serialize::serialize(knx, serializer)
            .map_err(|e| GeneratorError::Serialization(e.to_string()))?;

        Ok(buffer)
    }
}
