//! Hardware MTXML Generator - Creates Hardware.mtxml files.

use crate::schema::{
    ApplicationProgramRef, Hardware, Hardware2Program, Hardware2Programs, HardwareKnx, Product,
    Products,
};

use super::{medium_type_from_mask, ApplicationProgramConfig, GeneratorError};

/// Generator for creating Hardware MTXML files.
pub struct HardwareGenerator;

impl HardwareGenerator {
    /// Generate a complete Hardware MTXML document from the configuration.
    pub fn generate(config: &ApplicationProgramConfig) -> Result<String, GeneratorError> {
        let knx = Self::build_hardware_knx(config);
        Self::serialize(&knx)
    }

    /// Build the complete Hardware KNX document structure.
    fn build_hardware_knx(config: &ApplicationProgramConfig) -> HardwareKnx {
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

        // Application ID for reference - must match ApplicationProgram ID
        let app_id = format!(
            "{}_A-{:04X}-{:02X}-{}",
            manufacturer_id, config.device.application_id, config.device.application_version, app_hash
        );

        // Hardware2Program ID: <hardware_id>_HP-<app_number>-<app_version>-<hash>
        let h2p_id = format!(
            "{}_HP-{:04X}-{:02X}-{}",
            hardware_id, config.device.application_id, config.device.application_version, app_hash
        );

        // Product ID: <hardware_id>_P-<order_number>
        // Order number must be URL-encoded for ID convention compliance
        let product_id = format!(
            "{}_P-{}",
            hardware_id,
            super::mtxml::MtxmlGenerator::encode_id(config.order_number)
        );

        let mut knx = HardwareKnx::default();
        // Set schema version namespace and tool version if specified
        if let Some(version) = config.schema_version {
            knx.xmlns = version.namespace_url();
            knx.tool_version = version.tool_version().to_string();
        }
        knx.manufacturer_data.manufacturer.ref_id = manufacturer_id;
        knx.manufacturer_data.manufacturer.hardware.hardware = Hardware {
            id: hardware_id,
            name: config.hardware_name.to_string(),
            serial_number: serial_hex,
            version_number: config.hardware_version,
            has_individual_address: true,
            has_application_program: true,
            products: Products {
                product: Product {
                    id: product_id,
                    text: config.product_name.to_string(),
                    order_number: config.order_number.to_string(),
                    is_rail_mounted: config.is_rail_mounted,
                    default_language: "en-US".to_string(),
                },
            },
            hardware2programs: Hardware2Programs {
                hardware2program: Hardware2Program {
                    id: h2p_id,
                    medium_types: medium_type_from_mask(config.device.mask_version).to_string(),
                    application_program_ref: ApplicationProgramRef { ref_id: app_id },
                },
            },
        };

        knx
    }

    /// Serialize the Hardware KNX document to XML string.
    fn serialize(knx: &HardwareKnx) -> Result<String, GeneratorError> {
        let mut buffer = String::new();
        buffer.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");

        let mut serializer = quick_xml::se::Serializer::new(&mut buffer);
        serializer.indent(' ', 2);

        serde::Serialize::serialize(knx, serializer)
            .map_err(|e| GeneratorError::Serialization(e.to_string()))?;

        Ok(buffer)
    }
}
